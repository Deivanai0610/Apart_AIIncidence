from __future__ import annotations

import json
import math
import re
import time
import asyncio
from collections import deque
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Literal, Protocol

import httpx
from pydantic import ValidationError

from chimera.budget import AccountingError, BudgetLedger, Reservation, UsageRecord
from chimera.schemas import ActionResult, AttackerAction, TerminationReason


OPENROUTER_ORIGIN = "https://openrouter.ai"
ANTHROPIC_ORIGIN = "https://api.anthropic.com"
_BROKER_HANDLE = re.compile(r"^cred-[0-9a-f]{12}-[0-9]{4}$")
_SAFE_REASONS = frozenset(
    {
        "actor_quarantined",
        "unknown_credential_handle",
        "canary_use",
        "credential_route_mismatch",
        "transport_failure",
        "range_request_failed",
        "invalid_range_response",
        "missing_inspect_web",
        "missing_route_probe",
        "missing_config_read",
    }
)
_SAFE_KINDS = frozenset({"routes", "probe", "config", "token", "data"})
REQUEST_FRAMING_TOKEN_UPPER_BOUND = 256
_FAILURE_STATUSES = frozenset({"timeout", "transport_error", "http_error", "malformed_response", "missing_usage", "invalid_usage", "client_exception", "provider_mismatch", "cancelled", "provider_response"})


def normalize_provider_failure_status(value: object) -> str:
    if type(value) is str:
        if re.fullmatch(r"http_[0-9]{3}", value):
            return "http_error"
        if value in _FAILURE_STATUSES:
            return value
    return "provider_response"


@dataclass(frozen=True)
class ModelMessage:
    role: Literal["system", "user", "assistant"]
    content: str


@dataclass(frozen=True)
class ModelRequest:
    model: str
    messages: tuple[ModelMessage, ...]
    max_output_tokens: int


@dataclass(frozen=True)
class ModelReply:
    provider: str
    model: str
    text: str
    input_tokens: int
    output_tokens: int
    latency_ms: int
    routed_provider: str | None = None
    finish_reason: str | None = None


def request_token_upper_bound(request: ModelRequest) -> int:
    """Conservative local bound: each UTF-8 byte may require one token plus framing."""
    serialized = json.dumps(
        {"model": request.model, "messages": [message.__dict__ for message in request.messages]},
        separators=(",", ":"),
    ).encode("utf-8")
    return len(serialized) + REQUEST_FRAMING_TOKEN_UPPER_BOUND


class ModelClient(Protocol):
    provider: str

    async def complete(self, request: ModelRequest) -> ModelReply: ...


class ModelProviderFailure(RuntimeError):
    def __init__(
        self,
        provider: str,
        status: str,
        *,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        model: str | None = None,
        latency_ms: int | None = None,
        routed_provider: str | None = None,
        http_status: int | None = None,
        detail: str | None = None,
    ) -> None:
        self.provider = provider
        self.status = status
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.model = model
        self.latency_ms = latency_ms
        self.routed_provider = routed_provider
        self.http_status = http_status
        self.detail = detail
        super().__init__(f"{provider} provider failure: {status}")


@dataclass(frozen=True)
class ProviderFailureDetail:
    """Diagnostic record for one failed provider request.

    Kept separate from ``UsageRecord`` so the accounting artifact keeps its
    exact evaluator-validated shape. ``detail`` is a redacted excerpt of the
    provider's error message, never request content.
    """

    status: str
    http_status: int | None
    detail: str | None
    model: str | None
    latency_ms: int | None


_ERROR_DETAIL_LIMIT = 300
_ROUTING_STEP_LIMIT = 64
_KNOWN_OUTPUT_KEYS = frozenset(
    {
        "kind", "route", "credential_id", "refusal",
        "suspicious", "reason_code", "action", "target", "canary_location", "evidence_event_ids",
    }
)
_KNOWN_KIND_VALUES = frozenset(
    {"inspect_web", "route_probe", "config_read", "token_exchange", "query_data"}
)
_KNOWN_ROUTE_VALUES = frozenset({"api", "internal"})


_VALIDATION_ENTRY_LIMIT = 6
_VALIDATION_TOKEN = re.compile(r"[^A-Za-z0-9_.]")


def validation_error_summary(error: ValidationError) -> str:
    """Field paths and error types from a pydantic failure, no input values.

    ``loc`` and ``type`` are schema-derived identifiers, so they are safe to
    persist; ``msg``, ``input``, and ``ctx`` can echo model text and are dropped.
    """
    entries: list[str] = []
    for item in error.errors():
        loc = ".".join(str(part) for part in item.get("loc", ())) or "_"
        kind = str(item.get("type", "unknown"))
        entries.append(
            f"{_VALIDATION_TOKEN.sub('', loc)[:64]}:{_VALIDATION_TOKEN.sub('', kind)[:64]}"
        )
    entries = sorted(set(entries))
    overflow = len(entries) - _VALIDATION_ENTRY_LIMIT
    entries = entries[:_VALIDATION_ENTRY_LIMIT]
    if overflow > 0:
        entries.append(f"+{overflow}")
    return ";".join(entries)


def invalid_output_summary(text: object) -> str | None:
    """Content-free shape summary of a model reply that failed validation.

    Artifacts must never carry raw model text (see the runner's artifact audit),
    so this reports only structure: length, whether the reply was fenced, whether
    it parsed as JSON, which allow-listed keys were present, how many unknown
    keys appeared, and allow-listed values for ``kind`` and ``route``. That is
    enough to diagnose the common failures (wrong key name, code fences, prose)
    without persisting anything the model wrote.
    """
    if type(text) is not str:
        return None
    parts = [f"length={len(text)}"]
    candidate = text.strip()
    if candidate.startswith("```"):
        parts.append("fenced=true")
        candidate = candidate[3:]
        newline = candidate.find("\n")
        candidate = candidate[newline + 1 :] if newline >= 0 else ""
        candidate = candidate.rstrip()
        if candidate.endswith("```"):
            candidate = candidate[:-3].rstrip()
    try:
        value, index = json.JSONDecoder().raw_decode(candidate)
    except (json.JSONDecodeError, ValueError):
        parts.append("json=none")
        return " ".join(parts)
    if index != len(candidate):
        parts.append("json=trailing_text")
    elif isinstance(value, dict):
        parts.append("json=object")
    else:
        parts.append(f"json={type(value).__name__}")
    if isinstance(value, dict):
        known = sorted(key for key in value if key in _KNOWN_OUTPUT_KEYS)
        unknown = sum(1 for key in value if key not in _KNOWN_OUTPUT_KEYS)
        parts.append(f"known_keys={','.join(known) if known else '-'}")
        parts.append(f"unknown_keys={unknown}")
        kind = value.get("kind")
        if "kind" in value:
            parts.append(f"kind={kind if kind in _KNOWN_KIND_VALUES else 'unknown'}")
        route = value.get("route")
        if "route" in value:
            parts.append(f"route={route if route in _KNOWN_ROUTE_VALUES else 'unknown'}")
    return " ".join(parts)


_KNOWN_RESPONSE_KEYS = frozenset(
    {"id", "object", "created", "model", "provider", "choices", "usage", "error", "openrouter_metadata"}
)
_KNOWN_FINISH_REASONS = frozenset({"stop", "length", "error", "content_filter", "tool_calls"})


def response_shape_summary(body: object) -> str | None:
    """Content-free summary of a 2xx provider body that failed to parse.

    OpenRouter can answer 200 with an ``error`` object or with a choice that
    carries ``finish_reason: error`` when the upstream fails mid-request. This
    records which known keys were present, the bounded provider error message
    if any, and allow-listed finish reasons, never model text.
    """
    if not isinstance(body, dict):
        return None
    known = sorted(key for key in body if key in _KNOWN_RESPONSE_KEYS)
    parts = [f"keys={','.join(known) if known else '-'}"]
    error = body.get("error")
    if isinstance(error, dict):
        message = error.get("message")
        if type(message) is str and message.strip():
            parts.append(
                "error=" + "".join(char for char in message if char.isprintable())[:_ERROR_DETAIL_LIMIT]
            )
        code = error.get("code")
        if type(code) in {int, str} and len(str(code)) <= 16:
            parts.append(f"error_code={code}")
    choices = body.get("choices")
    if isinstance(choices, list):
        parts.append(f"choices={len(choices)}")
        first = choices[0] if choices and isinstance(choices[0], dict) else None
        if first is not None:
            for field in ("finish_reason", "native_finish_reason"):
                value = first.get(field)
                if type(value) is str:
                    parts.append(f"{field}={value if value in _KNOWN_FINISH_REASONS else 'other'}")
            choice_error = first.get("error")
            if isinstance(choice_error, dict) and type(choice_error.get("message")) is str:
                parts.append(
                    "choice_error="
                    + "".join(char for char in choice_error["message"] if char.isprintable())[:_ERROR_DETAIL_LIMIT]
                )
            message = first.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                parts.append(f"content={'null' if content is None else type(content).__name__}")
    return " ".join(parts)


def redacted_error_detail(body: bytes) -> str | None:
    """Extract a bounded, printable excerpt from a provider error body.

    Only the provider's own ``error.message`` and, when present, the
    ``failed_routing_step`` hint are kept. Anything else is dropped so the
    persisted artifact cannot echo prompts, credentials, or headers.
    """
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    error = parsed.get("error")
    if not isinstance(error, dict):
        return None
    message = error.get("message")
    if type(message) is not str or not message.strip():
        return None
    excerpt = "".join(char for char in message if char.isprintable())[:_ERROR_DETAIL_LIMIT]
    metadata = error.get("metadata")
    if isinstance(metadata, dict):
        step = metadata.get("failed_routing_step")
        if type(step) is str and step.strip():
            step_excerpt = "".join(char for char in step if char.isprintable())[:_ROUTING_STEP_LIMIT]
            excerpt = f"{excerpt} [failed_routing_step={step_excerpt}]"
    return excerpt


class PolicyError(RuntimeError):
    pass


class ProviderPolicyError(PolicyError):
    def __init__(self, failure: ModelProviderFailure) -> None:
        self.failure = failure
        super().__init__(str(failure))


class InvalidOutputPolicyError(PolicyError):
    termination_reason = TerminationReason.INVALID_OUTPUT


class RefusalPolicyError(PolicyError):
    termination_reason = TerminationReason.TERMINAL_REFUSAL


class StrictJSONError(ValueError):
    pass


class MockModelClient:
    def __init__(
        self,
        replies: tuple[ModelReply | Exception, ...] = (),
        *,
        provider: Literal["openrouter", "anthropic"] = "openrouter",
    ) -> None:
        self.provider = provider
        self._replies = deque(replies)
        self.requests: list[ModelRequest] = []

    async def complete(self, request: ModelRequest) -> ModelReply:
        self.requests.append(request)
        if not self._replies:
            raise ModelProviderFailure(self.provider, "no_reply")
        reply = self._replies.popleft()
        if isinstance(reply, Exception):
            raise reply
        return reply


class _HttpModelClient:
    provider: Literal["openrouter", "anthropic"]
    origin: str

    def __init__(
        self,
        *,
        api_key: str,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_seconds: float = 20.0,
        total_timeout_seconds: float = 150.0,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        if (
            type(total_timeout_seconds) is bool
            or not isinstance(total_timeout_seconds, (int, float))
            or not math.isfinite(total_timeout_seconds)
            or total_timeout_seconds <= 0
        ):
            raise ValueError("total_timeout_seconds must be positive")
        self._client = httpx.AsyncClient(
            base_url=self.origin,
            transport=transport,
            timeout=httpx.Timeout(timeout_seconds),
            trust_env=False,
            follow_redirects=False,
        )
        self._api_key = api_key
        # Per-operation timeouts alone do not bound a request: OpenRouter pads
        # non-streaming responses with keep-alive whitespace, so a stalled
        # upstream never trips the read timeout. The overall deadline is a
        # safety net, not a latency policy: of 496 successful attacker calls
        # observed live, p99 latency was 26 s and the maximum 90 s.
        self._total_timeout_seconds = float(total_timeout_seconds)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _post(
        self,
        path: str,
        *,
        headers: dict[str, str],
        payload: dict[str, object],
        requested_model: str,
    ) -> tuple[dict[str, object], int]:
        started = time.perf_counter()
        try:
            response = await asyncio.wait_for(
                self._client.post(path, headers=headers, json=payload),
                timeout=self._total_timeout_seconds,
            )
        except (httpx.TimeoutException, TimeoutError) as error:
            raise ModelProviderFailure(
                self.provider,
                "timeout",
                model=requested_model,
                latency_ms=int((time.perf_counter() - started) * 1000),
                detail=(
                    "total_deadline" if isinstance(error, TimeoutError) and not isinstance(error, httpx.TimeoutException)
                    else "transport_timeout"
                ),
            ) from error
        except httpx.HTTPError as error:
            raise ModelProviderFailure(self.provider, "transport_error", model=requested_model, latency_ms=int((time.perf_counter() - started) * 1000)) from error
        latency_ms = int((time.perf_counter() - started) * 1000)
        if not response.is_success:
            raise ModelProviderFailure(
                self.provider,
                f"http_{response.status_code}",
                model=requested_model,
                latency_ms=latency_ms,
                http_status=response.status_code,
                detail=redacted_error_detail(response.content),
            )
        try:
            body = response.json()
        except (UnicodeError, ValueError) as error:
            raise ModelProviderFailure(
                self.provider,
                "malformed_response",
                model=requested_model,
                latency_ms=latency_ms,
                http_status=response.status_code,
                detail=f"non_json length={len(response.content)}",
            ) from error
        if not isinstance(body, dict):
            raise ModelProviderFailure(
                self.provider,
                "malformed_response",
                model=requested_model,
                latency_ms=latency_ms,
                http_status=response.status_code,
                detail=f"json={type(body).__name__} length={len(response.content)}",
            )
        return body, latency_ms

    @staticmethod
    def _usage(
        body: dict[str, object],
        input_key: str,
        output_key: str,
        max_output_tokens: int,
    ) -> tuple[int, int]:
        usage = body.get("usage")
        if not isinstance(usage, dict) or input_key not in usage or output_key not in usage:
            raise ModelProviderFailure("provider", "missing_usage")
        input_tokens = usage[input_key]
        output_tokens = usage[output_key]
        if (
            type(input_tokens) is not int
            or type(output_tokens) is not int
            or input_tokens < 0
            or output_tokens < 0
        ):
            raise ModelProviderFailure("provider", "invalid_usage")
        return input_tokens, output_tokens


class OpenRouterClient(_HttpModelClient):
    provider = "openrouter"
    origin = OPENROUTER_ORIGIN

    def __init__(
        self,
        *,
        api_key: str,
        provider_slug: str | None = None,
        expected_provider_name: str | None = None,
        expected_endpoint_model: str | None = None,
        max_prompt_price: Decimal | None = None,
        max_completion_price: Decimal | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_seconds: float = 20.0,
        total_timeout_seconds: float = 150.0,
    ) -> None:
        controls = (
            provider_slug,
            expected_provider_name,
            expected_endpoint_model,
            max_prompt_price,
            max_completion_price,
        )
        if any(value is not None for value in controls) and not all(
            value is not None for value in controls
        ):
            raise ValueError("all OpenRouter routing controls are required together")
        if all(value is not None for value in controls):
            if not all(
                isinstance(value, str) and value.strip()
                for value in (
                    provider_slug,
                    expected_provider_name,
                    expected_endpoint_model,
                )
            ):
                raise ValueError("OpenRouter routing identities are invalid")
            if not all(
                isinstance(value, Decimal) and value.is_finite() and value > 0
                for value in (max_prompt_price, max_completion_price)
            ):
                raise ValueError("OpenRouter maximum prices are invalid")
        self._provider_slug = provider_slug
        self._expected_provider_name = expected_provider_name
        self._expected_endpoint_model = expected_endpoint_model
        self._max_prompt_price = max_prompt_price
        self._max_completion_price = max_completion_price
        super().__init__(
            api_key=api_key,
            transport=transport,
            timeout_seconds=timeout_seconds,
            total_timeout_seconds=total_timeout_seconds,
        )

    async def complete(self, request: ModelRequest) -> ModelReply:
        if self._provider_slug is None:
            raise ModelProviderFailure(
                self.provider, "provider_mismatch", model=request.model
            )
        assert self._max_prompt_price is not None
        assert self._max_completion_price is not None
        body, latency_ms = await self._post(
            "/api/v1/chat/completions",
            headers={
                "authorization": f"Bearer {self._api_key}",
                "content-type": "application/json",
                "x-openrouter-metadata": "enabled",
            },
            payload={
                "model": request.model,
                "messages": [
                    {"role": message.role, "content": message.content}
                    for message in request.messages
                ],
                # OpenRouter's `require_parameters` filter matches this name
                # literally against each endpoint's supported_parameters list,
                # which advertises `max_tokens`, not `max_completion_tokens`.
                # Verified live on 2026-09-13: the latter yields HTTP 404
                # "failed_routing_step: Filter by Parameters".
                "max_tokens": request.max_output_tokens,
                "provider": {
                    "only": [self._provider_slug],
                    "order": [self._provider_slug],
                    "allow_fallbacks": False,
                    "require_parameters": True,
                    "sort": "price",
                    "max_price": {
                        "prompt": float(self._max_prompt_price),
                        "completion": float(self._max_completion_price),
                    },
                },
                "reasoning": {"effort": "low"},
            },
            requested_model=request.model,
        )
        try:
            returned_model = body.get("model")
            input_tokens, output_tokens = self._usage(
                body, "prompt_tokens", "completion_tokens", request.max_output_tokens
            )
            if output_tokens > request.max_output_tokens:
                raise ModelProviderFailure(
                    self.provider, "invalid_usage", input_tokens=input_tokens,
                    output_tokens=output_tokens, model=request.model, latency_ms=latency_ms,
                )
            if not isinstance(returned_model, str):
                raise TypeError
            model = returned_model
            choices = body["choices"]
            if not isinstance(choices, list) or not choices:
                raise TypeError
            message = choices[0]["message"]
            text = message["content"]
            finish_reason = choices[0].get("finish_reason")
            if type(finish_reason) is not str or finish_reason not in _KNOWN_FINISH_REASONS:
                finish_reason = None
            if text is None and finish_reason in {"length", "content_filter", "stop"}:
                # The model produced no content within its allowance (for
                # example reasoning consumed the whole output cap). That is the
                # model's reply, so it is handed on as an empty reply and judged
                # as invalid output by the caller, not as a provider fault.
                text = ""
            if not isinstance(text, str):
                raise TypeError
            routed_provider = self._validate_routing_metadata(body, request)
            if model != request.model:
                raise ModelProviderFailure(
                    self.provider,
                    "provider_mismatch",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    model=model,
                    latency_ms=latency_ms,
                    routed_provider=routed_provider,
                )
        except ModelProviderFailure as error:
            raise ModelProviderFailure(
                self.provider,
                error.status,
                input_tokens=(locals().get("input_tokens") if "input_tokens" in locals() else error.input_tokens),
                output_tokens=(locals().get("output_tokens") if "output_tokens" in locals() else error.output_tokens),
                model=locals().get("model", body.get("model") if isinstance(body.get("model"), str) else request.model),
                latency_ms=latency_ms,
                routed_provider=locals().get("routed_provider", error.routed_provider),
                http_status=error.http_status if error.http_status is not None else 200,
                detail=error.detail if error.detail is not None else response_shape_summary(body),
            ) from error
        except (KeyError, IndexError, TypeError) as error:
            raise ModelProviderFailure(
                self.provider, "malformed_response", input_tokens=locals().get("input_tokens"),
                output_tokens=locals().get("output_tokens"), model=request.model, latency_ms=latency_ms,
                routed_provider=None,
                http_status=200,
                detail=response_shape_summary(body),
            ) from error
        return ModelReply(
            self.provider,
            model,
            text,
            input_tokens,
            output_tokens,
            latency_ms,
            routed_provider,
            finish_reason,
        )

    def _validate_routing_metadata(
        self, body: dict[str, object], request: ModelRequest
    ) -> str:
        metadata = body.get("openrouter_metadata")
        routed_provider: str | None = None

        def reject() -> None:
            raise ModelProviderFailure(
                self.provider,
                "provider_mismatch",
                model=(
                    body.get("model")
                    if isinstance(body.get("model"), str)
                    else request.model
                ),
                routed_provider=routed_provider,
            )

        if not isinstance(metadata, dict):
            reject()
        if (
            metadata.get("requested") != request.model
            or metadata.get("strategy") != "direct"
            or type(metadata.get("attempt")) is not int
            or metadata.get("attempt") != 1
        ):
            reject()
        endpoints = metadata.get("endpoints")
        if not isinstance(endpoints, dict):
            reject()
        available = endpoints.get("available")
        if not isinstance(available, list) or not available:
            reject()
        selected_endpoints: list[dict[str, object]] = []
        for endpoint in available:
            if (
                not isinstance(endpoint, dict)
                or not isinstance(endpoint.get("provider"), str)
                or not isinstance(endpoint.get("model"), str)
                or type(endpoint.get("selected")) is not bool
            ):
                reject()
            if endpoint["selected"] is True:
                selected_endpoints.append(endpoint)
        if len(selected_endpoints) != 1:
            reject()
        selected = selected_endpoints[0]
        routed_provider = selected["provider"]
        if (
            routed_provider != self._expected_provider_name
            or selected["model"] != self._expected_endpoint_model
        ):
            reject()
        if "attempts" in metadata:
            attempts = metadata["attempts"]
            if (
                not isinstance(attempts, list)
                or len(attempts) != 1
                or not isinstance(attempts[0], dict)
            ):
                reject()
            attempt = attempts[0]
            if (
                attempt.get("provider") != routed_provider
                or attempt.get("model") != self._expected_endpoint_model
                or type(attempt.get("status")) is not int
                or attempt.get("status") != 200
            ):
                reject()
        return routed_provider


class AnthropicClient(_HttpModelClient):
    provider = "anthropic"
    origin = ANTHROPIC_ORIGIN
    _VERSION = "2023-06-01"

    async def complete(self, request: ModelRequest) -> ModelReply:
        systems = [message.content for message in request.messages if message.role == "system"]
        if len(systems) > 1:
            raise ValueError("at most one system message is permitted")
        messages = [message for message in request.messages if message.role != "system"]
        body, latency_ms = await self._post(
            "/v1/messages",
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": self._VERSION,
                "content-type": "application/json",
            },
            payload={
                "model": request.model,
                **({"system": systems[0]} if systems else {}),
                "messages": [
                    {
                        "role": message.role,
                        "content": [{"type": "text", "text": message.content}],
                    }
                    for message in messages
                ],
                "max_tokens": request.max_output_tokens,
                "thinking": {"type": "disabled"},
                "service_tier": "standard_only",
            },
            requested_model=request.model,
        )
        try:
            returned_model = body.get("model")
            input_tokens, output_tokens = self._usage(
                body, "input_tokens", "output_tokens", request.max_output_tokens
            )
            if output_tokens > request.max_output_tokens:
                raise ModelProviderFailure(
                    self.provider, "invalid_usage", input_tokens=input_tokens,
                    output_tokens=output_tokens, model=request.model, latency_ms=latency_ms,
                )
            if not isinstance(returned_model, str):
                raise TypeError
            model = returned_model
            content = body["content"]
            if not isinstance(content, list):
                raise TypeError
            text_parts = [
                block["text"]
                for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            ]
            if not text_parts or not all(isinstance(text, str) for text in text_parts):
                raise TypeError
            if model != request.model:
                raise ModelProviderFailure(
                    self.provider,
                    "provider_mismatch",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    model=model,
                    latency_ms=latency_ms,
                    routed_provider="Anthropic",
                )
        except ModelProviderFailure as error:
            raise ModelProviderFailure(
                self.provider,
                error.status,
                input_tokens=(locals().get("input_tokens") if "input_tokens" in locals() else error.input_tokens),
                output_tokens=(locals().get("output_tokens") if "output_tokens" in locals() else error.output_tokens),
                model=locals().get("model", body.get("model") if isinstance(body.get("model"), str) else request.model),
                latency_ms=latency_ms,
                routed_provider="Anthropic",
            ) from error
        except (KeyError, TypeError) as error:
            raise ModelProviderFailure(
                self.provider, "malformed_response", input_tokens=locals().get("input_tokens"),
                output_tokens=locals().get("output_tokens"), model=request.model, latency_ms=latency_ms,
                routed_provider="Anthropic",
            ) from error
        return ModelReply(
            self.provider,
            model,
            "".join(text_parts),
            input_tokens,
            output_tokens,
            latency_ms,
            "Anthropic",
        )


def strict_json_object(text: str) -> dict[str, object]:
    if not isinstance(text, str):
        raise StrictJSONError("model output must be text")

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        output: dict[str, object] = {}
        for key, value in pairs:
            if key in output:
                raise StrictJSONError("duplicate object key")
            output[key] = value
        return output

    def invalid_constant(value: str) -> object:
        raise StrictJSONError(f"invalid JSON constant: {value}")

    decoder = json.JSONDecoder(object_pairs_hook=no_duplicates, parse_constant=invalid_constant)
    try:
        value, index = decoder.raw_decode(text)
    except (json.JSONDecodeError, StrictJSONError) as error:
        raise StrictJSONError("output must be exactly one JSON object") from error
    if index != len(text) or not isinstance(value, dict):
        raise StrictJSONError("output must be exactly one JSON object")
    _reject_non_finite(value)
    return value


def _reject_non_finite(value: object) -> None:
    if type(value) is float and not math.isfinite(value):
        raise StrictJSONError("JSON numbers must be finite")
    if isinstance(value, list):
        for item in value:
            _reject_non_finite(item)
    elif isinstance(value, dict):
        for item in value.values():
            _reject_non_finite(item)


def parse_attacker_action(text: str) -> AttackerAction:
    try:
        return AttackerAction.model_validate(strict_json_object(text))
    except (StrictJSONError, ValidationError) as error:
        raise StrictJSONError("invalid attacker action") from error


@dataclass
class AttackerPolicy:
    client: ModelClient
    model: str
    system_prompt: str
    max_output_tokens: int
    ledger: BudgetLedger | None = None
    max_input_tokens: int = 8_000
    history_limit: int = 8
    usage: list[UsageRecord] = field(default_factory=list)
    provider_failures: list[ProviderFailureDetail] = field(default_factory=list)

    def __post_init__(self) -> None:
        if getattr(self.client, "provider", None) != "openrouter":
            raise ValueError("attacker client provider must be openrouter")
        if self.ledger is not None and self.ledger.provider != "openrouter":
            raise ValueError("attacker ledger provider must be openrouter")
        if not 1 <= self.history_limit <= 64:
            raise ValueError("history_limit must be between 1 and 64")
        if self.max_input_tokens < 1 or self.max_output_tokens < 1:
            raise ValueError("token limits must be positive")

    async def next_action(self, history: tuple[ActionResult, ...]) -> AttackerAction:
        messages = (
            ModelMessage(role="system", content=self.system_prompt),
            ModelMessage(role="user", content=self._history_message(history)),
        )
        for attempt in range(2):
            reply, reservation = await self._request(
                ModelRequest(self.model, messages, self.max_output_tokens)
            )
            try:
                payload = strict_json_object(reply.text)
            except StrictJSONError:
                self._settle(reservation, reply, status="invalid_output")
                self._record_invalid_output(reply, reason="invalid_json")
                if attempt == 1:
                    raise InvalidOutputPolicyError("attacker emitted invalid output twice")
                messages = (*messages, ModelMessage(
                    role="user",
                    content="Your prior response was invalid. Return exactly one valid action JSON object.",
                ))
                continue
            if payload == {"refusal": True}:
                self._settle(reservation, reply, status="refusal")
                raise RefusalPolicyError("attacker refused the bounded workflow")
            try:
                action = AttackerAction.model_validate(payload)
            except ValidationError as error:
                self._settle(reservation, reply, status="invalid_output")
                self._record_invalid_output(
                    reply, reason="invalid_action", validation=validation_error_summary(error)
                )
                if attempt == 1:
                    raise InvalidOutputPolicyError("attacker emitted invalid output twice")
                messages = (*messages, ModelMessage(
                    role="user",
                    content="Your prior response was invalid. Return exactly one valid action JSON object.",
                ))
                continue
            self._settle(reservation, reply, status="success")
            return action
        raise AssertionError("unreachable")

    def _record_invalid_output(
        self, reply: ModelReply, *, reason: str, validation: str | None = None
    ) -> None:
        detail = f"{invalid_output_summary(reply.text)} reason={reason}"
        if validation:
            detail = f"{detail} validation={validation}"
        if reply.finish_reason is not None:
            detail = f"{detail} finish_reason={reply.finish_reason}"
        self.provider_failures.append(
            ProviderFailureDetail(
                status="invalid_output",
                http_status=None,
                detail=detail,
                model=self.model,
                latency_ms=reply.latency_ms,
            )
        )

    async def _request(self, request: ModelRequest) -> tuple[ModelReply, Reservation | None]:
        self._preflight(request)
        reservation = self._reserve()
        started = time.perf_counter()
        try:
            reply = await self.client.complete(request)
        except asyncio.CancelledError:
            self._fail(
                reservation,
                "cancelled",
                model=self.model,
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
            raise
        except ModelProviderFailure as error:
            self._finalize_provider_failure(
                reservation, error, measured_latency_ms=int((time.perf_counter() - started) * 1000)
            )
            raise ProviderPolicyError(error) from error
        except Exception as error:
            failure = ModelProviderFailure("openrouter", "client_exception")
            self._fail(reservation, failure.status, model=self.model, latency_ms=int((time.perf_counter() - started) * 1000))
            raise ProviderPolicyError(failure) from error
        try:
            self._validate_reply(reply)
        except ModelProviderFailure as error:
            self._finalize_provider_failure(
                reservation, error, measured_latency_ms=int((time.perf_counter() - started) * 1000)
            )
            raise ProviderPolicyError(error) from error
        if reply.provider != "openrouter":
            self._settle(reservation, reply, status="provider_mismatch")
            raise ProviderPolicyError(ModelProviderFailure(reply.provider, "provider_mismatch"))
        return reply, reservation

    @staticmethod
    def _validate_reply(reply: ModelReply) -> None:
        if (
            not isinstance(reply.text, str)
            or not isinstance(reply.model, str)
            or type(reply.input_tokens) is not int
            or type(reply.output_tokens) is not int
            or reply.input_tokens < 0
            or reply.output_tokens < 0
            or type(reply.latency_ms) is not int
            or reply.latency_ms < 0
        ):
            raise ModelProviderFailure(reply.provider, "invalid_usage")

    def _preflight(self, request: ModelRequest) -> None:
        if request_token_upper_bound(request) > self.max_input_tokens:
            raise PolicyError("input_limit")

    def _finalize_provider_failure(
        self,
        reservation: Reservation | None,
        failure: ModelProviderFailure,
        *,
        measured_latency_ms: int,
    ) -> None:
        latency_ms = (
            failure.latency_ms
            if type(failure.latency_ms) is int and failure.latency_ms >= 0
            else measured_latency_ms
        )
        status = normalize_provider_failure_status(failure.status)
        self.provider_failures.append(
            ProviderFailureDetail(
                status=status,
                http_status=failure.http_status if type(failure.http_status) is int else None,
                detail=failure.detail if type(failure.detail) is str else None,
                model=self.model,
                latency_ms=latency_ms,
            )
        )
        if reservation is None:
            return
        known_usage = (
            type(failure.input_tokens) is int
            and type(failure.output_tokens) is int
            and failure.input_tokens >= 0
            and failure.output_tokens >= 0
        )
        if known_usage:
            self._settle(
                reservation,
                ModelReply(
                    provider="openrouter",
                    model=self.model,
                    text="",
                    input_tokens=failure.input_tokens,
                    output_tokens=failure.output_tokens,
                    latency_ms=latency_ms or 0,
                    routed_provider=failure.routed_provider,
                ),
                status=status,
            )
            return
        self._fail(
            reservation,
            "invalid_usage"
            if (failure.input_tokens is not None or failure.output_tokens is not None)
            else status,
            model=self.model,
            latency_ms=latency_ms,
            routed_provider=failure.routed_provider,
        )

    def _reserve(self) -> Reservation | None:
        if self.ledger is None:
            return None
        return self.ledger.reserve(
            max_input_tokens=self.max_input_tokens,
            max_output_tokens=self.max_output_tokens,
        )

    def _settle(self, reservation: Reservation | None, reply: ModelReply, *, status: str) -> None:
        if reservation is None:
            return
        try:
            self.usage.append(
                reservation.settle(
                    reply.input_tokens,
                    reply.output_tokens,
                    status=status,
                    model=reply.model,
                    latency_ms=reply.latency_ms,
                    routed_provider=reply.routed_provider,
                )
            )
        except AccountingError as error:
            self.usage.append(error.record)
            raise

    def _fail(
        self,
        reservation: Reservation | None,
        status: str,
        *,
        model: str | None = None,
        latency_ms: int | None = None,
        routed_provider: str | None = None,
    ) -> None:
        if reservation is not None:
            self.usage.append(
                reservation.fail(
                    status,
                    model=model,
                    latency_ms=latency_ms,
                    routed_provider=routed_provider,
                )
            )

    def _history_message(self, history: tuple[ActionResult, ...]) -> str:
        safe_history = [self._project_action_result(result) for result in history[-self.history_limit :]]
        return json.dumps({"history": safe_history}, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def _project_action_result(result: ActionResult) -> dict[str, object]:
        projected: dict[str, object] = {
            "action": result.action.model_dump(mode="json"),
            "accepted": result.accepted,
        }
        if result.reason in _SAFE_REASONS:
            projected["reason"] = result.reason
        safe_result: dict[str, object] = {}
        raw = result.result
        kind = raw.get("kind")
        if type(kind) is str and kind in _SAFE_KINDS:
            safe_result["kind"] = kind
        status_class = raw.get("status_class")
        if type(status_class) is int and 0 <= status_class <= 5:
            safe_result["status_class"] = status_class
        if type(raw.get("reachable")) is bool:
            safe_result["reachable"] = raw["reachable"]
        routes = raw.get("routes")
        if isinstance(routes, list) and len(routes) <= 2 and all(type(route) is str and route in {"api", "internal"} for route in routes):
            safe_result["routes"] = routes
        if raw.get("configuration") == {"access": "brokered"}:
            safe_result["configuration"] = {"access": "brokered"}
        credential_id = raw.get("credential_id")
        if isinstance(credential_id, str) and _BROKER_HANDLE.fullmatch(credential_id):
            safe_result["credential_id"] = credential_id
        if safe_result:
            projected["result"] = safe_result
        return projected
