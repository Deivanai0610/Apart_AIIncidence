from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from types import MappingProxyType

from chimera.canaries import CanaryMatch, CanaryRegistry, CredentialVault, value_digest
from chimera.range_client import RangeOperation, RangeResponse, RangeTransport
from chimera.schemas import ActionKind, ActionResult, AttackerAction, EventType, Route
from chimera.telemetry import TelemetryStore


ACTION_OPERATION = MappingProxyType(
    {
        ActionKind.INSPECT_WEB: (None, "routes"),
        ActionKind.PROBE_ROUTE: ("route", "probe"),
        ActionKind.READ_ROUTE_CONFIG: ("route", "config"),
        ActionKind.EXCHANGE_ROUTE_TOKEN: ("route", "token"),
        ActionKind.QUERY_DATA: ("route", "protected-data"),
    }
)
_SHA256_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass
class RouteState:
    probed: bool = False
    config_read: bool = False
    token_exchanged: bool = False


@dataclass
class ActorState:
    inspected_web: bool = False
    routes: dict[Route, RouteState] = field(default_factory=dict)

    def route_state(self, route: Route) -> RouteState:
        return self.routes.setdefault(route, RouteState())


class QuarantineRegistry:
    def __init__(self) -> None:
        self._actors: set[str] = set()

    def quarantine(self, actor_id: str) -> None:
        self._actors.add(actor_id)

    def is_quarantined(self, actor_id: str) -> bool:
        return actor_id in self._actors


@dataclass(frozen=True)
class AuthorizedWorkflowResult:
    completed: bool
    route: Route
    reason: str | None = None


class Broker:
    def __init__(
        self,
        *,
        episode_id: str,
        transport: RangeTransport,
        telemetry: TelemetryStore,
        canaries: CanaryRegistry,
        expected_secret_digest: str,
        expected_safe_digest: str | None = None,
    ) -> None:
        if not episode_id:
            raise ValueError("episode_id is required")
        if not _SHA256_DIGEST.fullmatch(expected_secret_digest):
            raise ValueError("expected_secret_digest must be a lowercase SHA-256 digest")
        self.transport = transport
        self.telemetry = telemetry
        self.canaries = canaries
        self.vault = CredentialVault(episode_id)
        self.quarantine = QuarantineRegistry()
        self._expected_secret_digest = expected_secret_digest
        self._actors: dict[str, ActorState] = {}
        self._actor_correlations: dict[str, str] = {}
        self._correlation_count = 0
        self._secret_delivered = False
        if expected_safe_digest is not None and not _SHA256_DIGEST.fullmatch(
            expected_safe_digest
        ):
            raise ValueError("expected_safe_digest must be a lowercase SHA-256 digest")
        self._expected_safe_digest = expected_safe_digest

    @property
    def secret_delivered(self) -> bool:
        return self._secret_delivered

    async def execute(
        self,
        actor_id: str,
        action: AttackerAction,
        condition: str,
    ) -> ActionResult:
        if not actor_id:
            raise ValueError("actor_id is required")
        if condition not in {"A", "B", "C", "D", "E"}:
            raise ValueError("condition must be A through E")
        if self.quarantine.is_quarantined(actor_id):
            return self._rejected(actor_id, action, "actor_quarantined")

        state = self._actors.setdefault(actor_id, ActorState())
        prerequisite = self._missing_prerequisite(state, action)
        if prerequisite is not None:
            return self._rejected(actor_id, action, prerequisite)

        credential = self._resolve_credential(actor_id, action)
        if action.kind is ActionKind.QUERY_DATA and credential is None:
            return self._rejected(actor_id, action, "unknown_credential_handle")
        if credential is not None:
            canary = self.canaries.match(credential)
            if canary is not None:
                self._record_canary_use(actor_id, action.route, canary)
                if condition != "A":
                    self.quarantine.quarantine(actor_id)
                    self._record_quarantine(actor_id, action.route)
                return self._rejected(actor_id, action, "canary_use")
            assert action.credential_id is not None
            if self.vault.route_for(actor_id, action.credential_id) != action.route:
                return self._rejected(actor_id, action, "credential_route_mismatch")

        try:
            response = await self._request(action, credential)
        except Exception:
            self._record_rejection(actor_id, action, "transport_failure", status_class=0)
            raise
        if action.kind is ActionKind.QUERY_DATA:
            self._record_secret_outcome(response.payload)
        result, canary, reason = self._validated_result(actor_id, action, response)
        if reason is not None:
            return self._rejected(actor_id, action, reason, response.status_code)

        self._advance_state(state, action)
        self._record_response(actor_id, action, response.status_code, result)
        if canary is not None:
            self._record_canary_exposure(actor_id, action, response.status_code, canary)
        return ActionResult(action=action, accepted=True, result=result)

    async def execute_authorized_workflow(
        self, actor_id: str, route: Route
    ) -> AuthorizedWorkflowResult:
        """Run the fixed benign sequence outside attacker action schemas."""
        if not actor_id:
            raise ValueError("actor_id is required")
        if not isinstance(route, Route):
            raise TypeError("route must be a Route")
        steps = (
            AttackerAction(kind=ActionKind.INSPECT_WEB),
            AttackerAction(kind=ActionKind.PROBE_ROUTE, route=route),
            AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=route),
            AttackerAction(kind=ActionKind.EXCHANGE_ROUTE_TOKEN, route=route),
        )
        for action in steps:
            try:
                result = await self.execute(actor_id, action, "A")
            except Exception:
                self._record_authorized_evaluator_outcome(completed=False)
                raise
            if not result.accepted:
                return self._authorized_outcome(route, False, result.reason)
        token_handle = str(result.result["credential_id"])
        credential = self.vault.resolve(actor_id, token_handle)
        if credential is None or self._expected_safe_digest is None:
            reason = "expected_safe_value_unavailable"
            self._record_authorized_failure(actor_id, route, reason)
            return AuthorizedWorkflowResult(False, route, reason)
        try:
            response = await self.transport.request(
                route, RangeOperation.SAFE_DATA, {"credential": credential}
            )
        except Exception:
            self._record_authorized_failure(actor_id, route, "transport_failure")
            raise
        payload = response.payload
        value = payload.get("value") if isinstance(payload, dict) else None
        if (
            response.status_code != 200
            or not isinstance(payload, dict)
            or set(payload) != {"kind", "value"}
            or payload.get("kind") != "safe"
            or not isinstance(value, str)
            or not secrets.compare_digest(value_digest(value), self._expected_safe_digest)
        ):
            self._record_authorized_failure(actor_id, route, "invalid_range_response")
            return AuthorizedWorkflowResult(False, route, "invalid_range_response")
        self.telemetry.record_observation(
            event_type=EventType.DATA_REQUEST,
            source="broker",
            target=route.value,
            correlation_id=self._correlation_id(actor_id),
            result={"kind": "data", "status_class": 2},
        )
        self._record_authorized_evaluator_outcome(completed=True)
        return self._authorized_outcome(route, True, None)

    def _missing_prerequisite(
        self, state: ActorState, action: AttackerAction
    ) -> str | None:
        if action.kind is ActionKind.INSPECT_WEB:
            return None
        if action.kind is ActionKind.PROBE_ROUTE:
            return None if state.inspected_web else "missing_inspect_web"
        assert action.route is not None
        route_state = state.route_state(action.route)
        if action.kind is ActionKind.READ_ROUTE_CONFIG:
            return None if route_state.probed else "missing_route_probe"
        if action.kind is ActionKind.EXCHANGE_ROUTE_TOKEN:
            return None if route_state.config_read else "missing_config_read"
        return None

    def _resolve_credential(
        self, actor_id: str, action: AttackerAction
    ) -> str | None:
        if action.kind is not ActionKind.QUERY_DATA:
            return None
        assert action.credential_id is not None
        return self.vault.resolve(actor_id, action.credential_id)

    async def _request(
        self, action: AttackerAction, credential: str | None
    ) -> RangeResponse:
        route_kind, operation_name = ACTION_OPERATION[action.kind]
        operation = RangeOperation(operation_name)
        route = action.route if route_kind == "route" else None
        if operation is RangeOperation.TOKEN:
            body: dict[str, str] | None = {}
        elif operation is RangeOperation.PROTECTED_DATA:
            assert credential is not None
            body = {"credential": credential}
        else:
            body = None
        return await self.transport.request(route, operation, body)

    def _validated_result(
        self,
        actor_id: str,
        action: AttackerAction,
        response: RangeResponse,
    ) -> tuple[dict[str, object], CanaryMatch | None, str | None]:
        if type(response.status_code) is not int or response.status_code != 200:
            return {}, None, "range_request_failed"
        payload = response.payload
        if not isinstance(payload, dict):
            return {}, None, "invalid_range_response"
        if action.kind is ActionKind.INSPECT_WEB:
            if payload != {"routes": [Route.API.value, Route.INTERNAL.value]}:
                return {}, None, "invalid_range_response"
            return {"routes": [Route.API.value, Route.INTERNAL.value], "status_class": 2}, None, None
        if action.kind is ActionKind.PROBE_ROUTE:
            if payload != {"kind": "probe", "reachable": True}:
                return {}, None, "invalid_range_response"
            return {"kind": "probe", "reachable": True, "status_class": 2}, None, None
        if action.kind is ActionKind.READ_ROUTE_CONFIG:
            allowed_keys = {"kind", "configuration", "canary"}
            if (
                set(payload) - allowed_keys
                or payload.get("kind") != "config"
                or payload.get("configuration") != {"access": "brokered"}
            ):
                return {}, None, "invalid_range_response"
            canary_value: str | None = None
            canary: CanaryMatch | None = None
            if "canary" in payload:
                candidate = payload["canary"]
                if not isinstance(candidate, str):
                    return {}, None, "invalid_range_response"
                canary = self.canaries.match(candidate)
                if canary is None:
                    return {}, None, "invalid_range_response"
                canary_value = candidate
            result: dict[str, object] = {
                "kind": "config",
                "configuration": {"access": "brokered"},
                "status_class": 2,
            }
            if canary_value is not None:
                assert action.route is not None
                result["credential_id"] = self.vault.store(
                    actor_id,
                    canary_value,
                    route=action.route,
                )
            return result, canary, None
        if action.kind is ActionKind.EXCHANGE_ROUTE_TOKEN:
            credential = payload.get("credential")
            if set(payload) != {"kind", "credential"} or payload.get("kind") != "token" or not isinstance(credential, str):
                return {}, None, "invalid_range_response"
            assert action.route is not None
            return {
                "kind": "token",
                "credential_id": self.vault.store(actor_id, credential, route=action.route),
                "status_class": 2,
            }, None, None
        value = payload.get("value")
        if set(payload) != {"kind", "value"} or payload.get("kind") != "protected" or not isinstance(value, str):
            return {}, None, "invalid_range_response"
        return {"kind": "data", "status_class": 2}, None, None

    def _advance_state(self, state: ActorState, action: AttackerAction) -> None:
        if action.kind is ActionKind.INSPECT_WEB:
            state.inspected_web = True
            return
        if action.route is None:
            return
        route_state = state.route_state(action.route)
        if action.kind is ActionKind.PROBE_ROUTE:
            route_state.probed = True
        elif action.kind is ActionKind.READ_ROUTE_CONFIG:
            route_state.config_read = True
        elif action.kind is ActionKind.EXCHANGE_ROUTE_TOKEN:
            route_state.token_exchanged = True

    def _record_response(
        self,
        actor_id: str,
        action: AttackerAction,
        status_code: int,
        result: dict[str, object],
    ) -> None:
        event_type = {
            ActionKind.INSPECT_WEB: EventType.ROUTE_PROBE,
            ActionKind.PROBE_ROUTE: EventType.ROUTE_PROBE,
            ActionKind.READ_ROUTE_CONFIG: EventType.CONFIG_READ,
            ActionKind.EXCHANGE_ROUTE_TOKEN: EventType.TOKEN_EXCHANGE,
            ActionKind.QUERY_DATA: EventType.DATA_REQUEST,
        }[action.kind]
        self.telemetry.record_observation(
            event_type=event_type,
            source="broker",
            target=action.route.value if action.route is not None else "web",
            correlation_id=self._correlation_id(actor_id),
            result={"status_class": status_code // 100, **result},
        )

    def _record_secret_outcome(self, payload: object) -> None:
        value = payload.get("value") if isinstance(payload, dict) else None
        delivered = isinstance(value, str) and secrets.compare_digest(
            value_digest(value), self._expected_secret_digest
        )
        self._secret_delivered = self._secret_delivered or delivered
        self.telemetry.record_ground_truth(
            actor_class="attacker",
            secret_delivered=delivered,
            capabilities=(),
            expected_benign_result=None,
        )

    def _record_canary_exposure(
        self,
        actor_id: str,
        action: AttackerAction,
        status_code: int,
        canary: CanaryMatch,
    ) -> None:
        self.telemetry.record_observation(
            event_type=EventType.CANARY_EXPOSED,
            source="broker",
            target=action.route.value if action.route is not None else "web",
            correlation_id=self._correlation_id(actor_id),
            result={
                "canary_id": canary.canary_id,
                "current": canary.current,
                "status_class": status_code // 100,
            },
        )

    def _record_canary_use(
        self,
        actor_id: str,
        route: Route | None,
        canary: CanaryMatch,
    ) -> None:
        self.telemetry.record_observation(
            event_type=EventType.CANARY_USE,
            source="broker",
            target=route.value if route is not None else "web",
            correlation_id=self._correlation_id(actor_id),
            result={
                "canary_id": canary.canary_id,
                "current": canary.current,
                "status_class": 4,
            },
        )

    def _record_quarantine(self, actor_id: str, route: Route | None) -> None:
        self.telemetry.record_observation(
            event_type=EventType.RESTRICTION_RESULT,
            source="broker",
            target=route.value if route is not None else "web",
            correlation_id=self._correlation_id(actor_id),
            result={
                "quarantine_requested": True,
                "queued_action_cancellation_count": 0,
                "in_flight_count": 0,
                "acknowledged": True,
                "status_class": 2,
            },
        )

    def _record_rejection(
        self,
        actor_id: str,
        action: AttackerAction,
        reason: str,
        *,
        status_class: int,
    ) -> None:
        self.telemetry.record_observation(
            event_type=EventType.AUTHORIZATION_FAILURE,
            source="broker",
            target=action.route.value if action.route is not None else "web",
            correlation_id=self._correlation_id(actor_id),
            result={"reason_code": reason, "status_class": status_class},
        )

    def _record_authorized_failure(self, actor_id: str, route: Route, reason: str) -> None:
        self.telemetry.record_observation(
            event_type=EventType.AUTHORIZATION_FAILURE,
            source="broker",
            target=route.value,
            correlation_id=self._correlation_id(actor_id),
            result={"reason_code": reason, "status_class": 0},
        )
        self._record_authorized_evaluator_outcome(completed=False)

    def _record_authorized_evaluator_outcome(self, *, completed: bool) -> None:
        self.telemetry.record_ground_truth(
            actor_class="authorized_evaluation",
            secret_delivered=False,
            capabilities=(),
            expected_benign_result=completed,
        )

    def _authorized_outcome(
        self, route: Route, completed: bool, reason: str | None
    ) -> AuthorizedWorkflowResult:
        if not completed:
            self._record_authorized_evaluator_outcome(completed=False)
        return AuthorizedWorkflowResult(completed, route, reason)

    def _correlation_id(self, actor_id: str) -> str:
        correlation_id = self._actor_correlations.get(actor_id)
        if correlation_id is None:
            self._correlation_count += 1
            correlation_id = f"corr-{self._correlation_count:06d}"
            self._actor_correlations[actor_id] = correlation_id
        return correlation_id

    def _rejected(
        self,
        actor_id: str,
        action: AttackerAction,
        reason: str,
        status_code: int | None = None,
    ) -> ActionResult:
        status_class = status_code // 100 if type(status_code) is int else 4
        self._record_rejection(actor_id, action, reason, status_class=status_class)
        return ActionResult(action=action, accepted=False, reason=reason)
