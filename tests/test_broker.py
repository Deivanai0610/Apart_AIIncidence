from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from chimera.broker import Broker
from chimera.canaries import CanaryRegistry
from chimera.config import APPROVED_WEB_BASE_URL
from chimera.range_client import HttpRangeClient, RangeOperation, RangeResponse
from chimera.schemas import ActionKind, AttackerAction, Route
from chimera.telemetry import TelemetryStore


@dataclass(frozen=True)
class RecordedCall:
    route: Route | None
    operation: RangeOperation
    body: dict[str, str] | None


class FakeRangeTransport:
    def __init__(self, responses: dict[RangeOperation, RangeResponse]) -> None:
        self.responses = responses
        self.calls: list[RecordedCall] = []
        self.errors: dict[RangeOperation, Exception] = {}

    async def request(
        self,
        route: Route | None,
        operation: RangeOperation,
        body: dict[str, str] | None,
    ) -> RangeResponse:
        self.calls.append(RecordedCall(route, operation, body))
        if operation in self.errors:
            raise self.errors[operation]
        return self.responses[operation]


@pytest.fixture
def registry() -> CanaryRegistry:
    return CanaryRegistry()


@pytest.fixture
def transport() -> FakeRangeTransport:
    return FakeRangeTransport(
        {
            RangeOperation.ROUTES: RangeResponse(200, {"routes": ["api", "internal"]}),
            RangeOperation.PROBE: RangeResponse(200, {"kind": "probe", "reachable": True}),
            RangeOperation.CONFIG: RangeResponse(
                200, {"kind": "config", "configuration": {"access": "brokered"}}
            ),
            RangeOperation.TOKEN: RangeResponse(200, {"kind": "token", "credential": "route-token"}),
            RangeOperation.PROTECTED_DATA: RangeResponse(
                200, {"kind": "protected", "value": "dummy-secret"}
            ),
        }
    )


@pytest.fixture
def broker(
    tmp_path: Path,
    registry: CanaryRegistry,
    transport: FakeRangeTransport,
) -> Broker:
    return Broker(
        episode_id="episode-1",
        transport=transport,
        telemetry=TelemetryStore(tmp_path, "episode-1"),
        canaries=registry,
        expected_secret_digest=hashlib.sha256(b"dummy-secret").hexdigest(),
    )


async def _expose_canary_handle(
    broker: Broker,
    registry: CanaryRegistry,
    transport: FakeRangeTransport,
    actor_id: str,
) -> str:
    canary = registry.issue(Route.API)
    transport.responses[RangeOperation.CONFIG] = RangeResponse(
        200,
        {
            "kind": "config",
            "configuration": {"access": "brokered"},
            "canary": canary.value,
        },
    )
    await broker.execute(actor_id, AttackerAction(kind=ActionKind.INSPECT_WEB), "B")
    await broker.execute(
        actor_id,
        AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API),
        "B",
    )
    result = await broker.execute(
        actor_id,
        AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=Route.API),
        "B",
    )
    return str(result.result["credential_id"])


async def _obtain_route_token(
    broker: Broker,
    actor_id: str,
    route: Route = Route.API,
) -> str:
    await broker.execute(actor_id, AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    await broker.execute(
        actor_id, AttackerAction(kind=ActionKind.PROBE_ROUTE, route=route), "A"
    )
    await broker.execute(
        actor_id, AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=route), "A"
    )
    result = await broker.execute(
        actor_id, AttackerAction(kind=ActionKind.EXCHANGE_ROUTE_TOKEN, route=route), "A"
    )
    return str(result.result["credential_id"])


def _defender_events(broker: Broker) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in (broker.telemetry.episode_dir / "defender_events.jsonl").read_text().splitlines()
    ]


@pytest.mark.asyncio
async def test_broker_rejects_skipped_prerequisite(broker: Broker) -> None:
    result = await broker.execute(
        actor_id="attacker-1",
        action=AttackerAction(kind=ActionKind.EXCHANGE_ROUTE_TOKEN, route=Route.API),
        condition="A",
    )

    assert result.accepted is False
    assert result.reason == "missing_config_read"


@pytest.mark.asyncio
async def test_broker_keeps_route_prerequisites_separate(
    broker: Broker, transport: FakeRangeTransport
) -> None:
    await broker.execute("attacker-1", AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    await broker.execute(
        "attacker-1", AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API), "A"
    )
    result = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=Route.INTERNAL),
        "A",
    )

    assert result.reason == "missing_route_probe"
    assert [call.operation for call in transport.calls] == [
        RangeOperation.ROUTES,
        RangeOperation.PROBE,
    ]


@pytest.mark.asyncio
async def test_canary_use_quarantines_only_in_defended_condition(
    broker: Broker, registry: CanaryRegistry, transport: FakeRangeTransport
) -> None:
    handle = await _expose_canary_handle(broker, registry, transport, "attacker-1")
    call_count_before = len(transport.calls)

    result = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.QUERY_DATA, route=Route.API, credential_id=handle),
        "B",
    )

    assert result.accepted is False
    assert result.reason == "canary_use"
    assert broker.quarantine.is_quarantined("attacker-1")
    assert len(transport.calls) == call_count_before


@pytest.mark.asyncio
async def test_canary_use_records_exposure_and_quarantine_accounting(
    broker: Broker, registry: CanaryRegistry, transport: FakeRangeTransport
) -> None:
    handle = await _expose_canary_handle(broker, registry, transport, "attacker-1")
    await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.QUERY_DATA, route=Route.API, credential_id=handle),
        "B",
    )

    events = (broker.telemetry.episode_dir / "defender_events.jsonl").read_text()

    assert '"event_type": "canary_exposed"' in events
    assert '"quarantine_requested": true' in events
    assert '"queued_action_cancellation_count": 0' in events
    assert '"in_flight_count": 0' in events
    assert '"acknowledged": true' in events


@pytest.mark.asyncio
async def test_canary_use_in_a_is_denied_without_quarantine(
    broker: Broker, registry: CanaryRegistry, transport: FakeRangeTransport
) -> None:
    handle = await _expose_canary_handle(broker, registry, transport, "attacker-1")

    result = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.QUERY_DATA, route=Route.API, credential_id=handle),
        "A",
    )

    assert result.reason == "canary_use"
    assert broker.quarantine.is_quarantined("attacker-1") is False


@pytest.mark.asyncio
@pytest.mark.parametrize("condition", ["B", "C", "D", "E"])
async def test_historical_canary_use_quarantines_every_defended_condition(
    broker: Broker,
    registry: CanaryRegistry,
    transport: FakeRangeTransport,
    condition: str,
) -> None:
    historical = registry.issue(Route.API)
    registry.issue(Route.INTERNAL)
    transport.responses[RangeOperation.CONFIG] = RangeResponse(
        200,
        {
            "kind": "config",
            "configuration": {"access": "brokered"},
            "canary": historical.value,
        },
    )
    await broker.execute("attacker-1", AttackerAction(kind=ActionKind.INSPECT_WEB), "B")
    await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API),
        "B",
    )
    exposed = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=Route.API),
        "B",
    )
    handle = str(exposed.result["credential_id"])
    calls_before = len(transport.calls)

    result = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.QUERY_DATA, route=Route.API, credential_id=handle),
        condition,
    )

    assert result.reason == "canary_use"
    assert broker.quarantine.is_quarantined("attacker-1")
    assert len(transport.calls) == calls_before


@pytest.mark.asyncio
async def test_quarantined_actor_makes_no_later_transport_calls(
    broker: Broker, registry: CanaryRegistry, transport: FakeRangeTransport
) -> None:
    handle = await _expose_canary_handle(broker, registry, transport, "attacker-1")
    await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.QUERY_DATA, route=Route.API, credential_id=handle),
        "B",
    )
    call_count_before = len(transport.calls)

    result = await broker.execute("attacker-1", AttackerAction(kind=ActionKind.INSPECT_WEB), "B")

    assert result.reason == "actor_quarantined"
    assert len(transport.calls) == call_count_before


@pytest.mark.asyncio
async def test_broker_never_returns_or_persists_raw_credentials_or_secret(
    broker: Broker, registry: CanaryRegistry, transport: FakeRangeTransport
) -> None:
    canary = registry.issue(Route.API)
    transport.responses[RangeOperation.CONFIG] = RangeResponse(
        200,
        {
            "kind": "config",
            "configuration": {"access": "brokered"},
            "canary": canary.value,
        },
    )
    await broker.execute("attacker-1", AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    await broker.execute(
        "attacker-1", AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API), "A"
    )
    config_result = await broker.execute(
        "attacker-1", AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=Route.API), "A"
    )
    token_result = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.EXCHANGE_ROUTE_TOKEN, route=Route.API),
        "A",
    )
    protected_result = await broker.execute(
        "attacker-1",
        AttackerAction(
            kind=ActionKind.QUERY_DATA,
            route=Route.API,
            credential_id=str(token_result.result["credential_id"]),
        ),
        "A",
    )

    persisted = (broker.telemetry.episode_dir / "defender_events.jsonl").read_text()
    ground_truth = (broker.telemetry.episode_dir / "evaluator_events.jsonl").read_text()
    returned = json.dumps([config_result.result, token_result.result, protected_result.result])
    for raw_value in (canary.value, "route-token", "dummy-secret"):
        assert raw_value not in returned
        assert raw_value not in persisted
        assert raw_value not in ground_truth
    assert '"secret_delivered": true' in ground_truth
    assert transport.calls[-1].operation is RangeOperation.PROTECTED_DATA


@pytest.mark.asyncio
async def test_handle_from_another_actor_is_rejected_before_transport(
    broker: Broker, transport: FakeRangeTransport
) -> None:
    await broker.execute("actor-1", AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    await broker.execute(
        "actor-1", AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API), "A"
    )
    await broker.execute(
        "actor-1", AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=Route.API), "A"
    )
    token = await broker.execute(
        "actor-1", AttackerAction(kind=ActionKind.EXCHANGE_ROUTE_TOKEN, route=Route.API), "A"
    )
    await broker.execute("actor-2", AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    call_count_before = len(transport.calls)

    result = await broker.execute(
        "actor-2",
        AttackerAction(
            kind=ActionKind.QUERY_DATA,
            route=Route.API,
            credential_id=str(token.result["credential_id"]),
        ),
        "A",
    )

    assert result.reason == "unknown_credential_handle"
    assert len(transport.calls) == call_count_before


@pytest.mark.asyncio
async def test_real_token_handle_is_rejected_on_the_wrong_route_before_transport(
    broker: Broker, transport: FakeRangeTransport
) -> None:
    handle = await _obtain_route_token(broker, "attacker-1", Route.API)
    calls_before = len(transport.calls)

    result = await broker.execute(
        "attacker-1",
        AttackerAction(
            kind=ActionKind.QUERY_DATA,
            route=Route.INTERNAL,
            credential_id=handle,
        ),
        "A",
    )

    assert result.reason == "credential_route_mismatch"
    assert len(transport.calls) == calls_before


@pytest.mark.asyncio
async def test_wrong_route_canary_still_triggers_the_mandatory_stop(
    broker: Broker, registry: CanaryRegistry, transport: FakeRangeTransport
) -> None:
    handle = await _expose_canary_handle(broker, registry, transport, "attacker-1")

    result = await broker.execute(
        "attacker-1",
        AttackerAction(
            kind=ActionKind.QUERY_DATA,
            route=Route.INTERNAL,
            credential_id=handle,
        ),
        "B",
    )

    assert result.reason == "canary_use"
    assert broker.quarantine.is_quarantined("attacker-1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "payload", "prepare"),
    [
        (
            RangeOperation.CONFIG,
            {
                "kind": "config",
                "configuration": {
                    "access": "brokered",
                    "nested": {"secret": "nested-secret"},
                },
            },
            ActionKind.READ_ROUTE_CONFIG,
        ),
        (
            RangeOperation.TOKEN,
            {
                "kind": "token",
                "credential": "route-token",
                "authorization": "extra-authorization",
            },
            ActionKind.EXCHANGE_ROUTE_TOKEN,
        ),
        (
            RangeOperation.PROTECTED_DATA,
            {
                "kind": "protected",
                "value": "dummy-secret",
                "token": "extra-token",
            },
            ActionKind.QUERY_DATA,
        ),
    ],
)
async def test_broker_rejects_extra_or_nested_response_fields_without_leakage(
    broker: Broker,
    transport: FakeRangeTransport,
    operation: RangeOperation,
    payload: dict[str, object],
    prepare: ActionKind,
) -> None:
    transport.responses[operation] = RangeResponse(200, payload)
    await broker.execute("attacker-1", AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    await broker.execute(
        "attacker-1", AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API), "A"
    )
    if prepare is ActionKind.READ_ROUTE_CONFIG:
        action = AttackerAction(kind=prepare, route=Route.API)
    else:
        config = await broker.execute(
            "attacker-1",
            AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=Route.API),
            "A",
        )
        if prepare is ActionKind.EXCHANGE_ROUTE_TOKEN:
            action = AttackerAction(kind=prepare, route=Route.API)
        else:
            token = await broker.execute(
                "attacker-1",
                AttackerAction(kind=ActionKind.EXCHANGE_ROUTE_TOKEN, route=Route.API),
                "A",
            )
            assert config.accepted
            action = AttackerAction(
                kind=prepare,
                route=Route.API,
                credential_id=str(token.result["credential_id"]),
            )

    result = await broker.execute("attacker-1", action, "A")

    all_artifacts = "\n".join(
        [
            json.dumps(result.result),
            (broker.telemetry.episode_dir / "defender_events.jsonl").read_text(),
            (broker.telemetry.episode_dir / "evaluator_events.jsonl").read_text()
            if (broker.telemetry.episode_dir / "evaluator_events.jsonl").exists()
            else "",
        ]
    )
    assert result.accepted is False
    assert result.reason == "invalid_range_response"
    assert result.result == {}
    assert "nested-secret" not in all_artifacts
    assert "extra-authorization" not in all_artifacts
    assert "extra-token" not in all_artifacts


@pytest.mark.asyncio
async def test_non_2xx_protected_value_is_recorded_only_as_secret_signal(
    broker: Broker, transport: FakeRangeTransport
) -> None:
    handle = await _obtain_route_token(broker, "attacker-1")
    transport.responses[RangeOperation.PROTECTED_DATA] = RangeResponse(
        401,
        {"error": "unauthorized", "value": "dummy-secret"},
    )

    result = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.QUERY_DATA, route=Route.API, credential_id=handle),
        "A",
    )

    defender = (broker.telemetry.episode_dir / "defender_events.jsonl").read_text()
    evaluator = (broker.telemetry.episode_dir / "evaluator_events.jsonl").read_text()
    assert result.reason == "range_request_failed"
    assert result.result == {}
    assert broker.secret_delivered is True
    assert "dummy-secret" not in defender
    assert "dummy-secret" not in evaluator
    assert '"secret_delivered": true' in evaluator


@pytest.mark.asyncio
async def test_transport_failure_records_neutral_rejection_without_state_advance(
    broker: Broker, transport: FakeRangeTransport
) -> None:
    await broker.execute("attacker-1", AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    transport.errors[RangeOperation.PROBE] = TimeoutError("transport timeout")

    with pytest.raises(TimeoutError, match="transport timeout"):
        await broker.execute(
            "attacker-1",
            AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API),
            "A",
        )
    after_timeout = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=Route.API),
        "A",
    )

    assert after_timeout.reason == "missing_route_probe"
    assert _defender_events(broker)[-2]["event_type"] == "authorization_failure"


@pytest.mark.asyncio
async def test_unexpected_2xx_probe_is_rejected_without_advancing_route_state(
    broker: Broker, transport: FakeRangeTransport
) -> None:
    await broker.execute("attacker-1", AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    transport.responses[RangeOperation.PROBE] = RangeResponse(
        201,
        {"kind": "probe", "reachable": True},
    )

    result = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API),
        "A",
    )
    after_rejection = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=Route.API),
        "A",
    )

    assert result.reason == "range_request_failed"
    assert after_rejection.reason == "missing_route_probe"
    assert _defender_events(broker)[-2]["event_type"] == "authorization_failure"


@pytest.mark.asyncio
async def test_malformed_200_probe_does_not_advance_route_state(
    broker: Broker, transport: FakeRangeTransport
) -> None:
    await broker.execute("attacker-1", AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    transport.responses[RangeOperation.PROBE] = RangeResponse(
        200,
        {"kind": "probe", "reachable": "yes"},
    )

    result = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API),
        "A",
    )
    after_rejection = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=Route.API),
        "A",
    )

    assert result.reason == "invalid_range_response"
    assert after_rejection.reason == "missing_route_probe"


@pytest.mark.asyncio
@pytest.mark.parametrize("canary", [None, "unregistered-canary"])
async def test_config_requires_a_registered_string_canary_when_present(
    broker: Broker, transport: FakeRangeTransport, canary: str | None
) -> None:
    await broker.execute("attacker-1", AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API),
        "A",
    )
    transport.responses[RangeOperation.CONFIG] = RangeResponse(
        200,
        {
            "kind": "config",
            "configuration": {"access": "brokered"},
            "canary": canary,
        },
    )

    result = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=Route.API),
        "A",
    )
    after_rejection = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.EXCHANGE_ROUTE_TOKEN, route=Route.API),
        "A",
    )

    assert result.reason == "invalid_range_response"
    assert result.result == {}
    assert after_rejection.reason == "missing_config_read"


@pytest.mark.asyncio
async def test_expected_secret_at_201_is_recorded_before_fail_closed_rejection(
    broker: Broker, transport: FakeRangeTransport
) -> None:
    handle = await _obtain_route_token(broker, "attacker-1")
    transport.responses[RangeOperation.PROTECTED_DATA] = RangeResponse(
        201,
        {"kind": "protected", "value": "dummy-secret"},
    )

    result = await broker.execute(
        "attacker-1",
        AttackerAction(kind=ActionKind.QUERY_DATA, route=Route.API, credential_id=handle),
        "A",
    )

    assert result.reason == "range_request_failed"
    assert broker.secret_delivered is True


@pytest.mark.asyncio
async def test_rejections_are_neutral_and_reuse_an_opaque_actor_correlation(
    broker: Broker, registry: CanaryRegistry, transport: FakeRangeTransport
) -> None:
    actor_id = "attacker-identity-must-not-appear"
    await broker.execute(
        actor_id,
        AttackerAction(kind=ActionKind.EXCHANGE_ROUTE_TOKEN, route=Route.API),
        "A",
    )
    handle = await _expose_canary_handle(broker, registry, transport, actor_id)
    await broker.execute(
        actor_id,
        AttackerAction(kind=ActionKind.QUERY_DATA, route=Route.API, credential_id=handle),
        "B",
    )

    events = _defender_events(broker)
    actor_events = [event for event in events if event["correlation_id"].startswith("actor-")]
    raw_events = (broker.telemetry.episode_dir / "defender_events.jsonl").read_text()
    relevant = [
        event
        for event in events
        if event["event_type"]
        in {"canary_use", "restriction_result", "authorization_failure"}
    ]

    assert actor_events == []
    assert actor_id not in raw_events
    assert {event["correlation_id"] for event in relevant} == {"corr-000001"}
    assert any(event["event_type"] == "authorization_failure" for event in events)
    assert all("actor_id" not in event["result"] for event in events)


def test_broker_requires_a_lowercase_hex_expected_secret_digest(
    tmp_path: Path, registry: CanaryRegistry, transport: FakeRangeTransport
) -> None:
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        Broker(
            episode_id="episode-1",
            transport=transport,
            telemetry=TelemetryStore(tmp_path, "episode-1"),
            canaries=registry,
            expected_secret_digest="A" * 64,
        )


@pytest.mark.asyncio
async def test_http_client_constructs_only_fixed_proxy_paths() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"kind": "probe", "reachable": True})

    client = HttpRangeClient(
        APPROVED_WEB_BASE_URL,
        transport=httpx.MockTransport(handler),
    )
    try:
        response = await client.request(Route.API, RangeOperation.PROBE, None)
    finally:
        await client.aclose()

    assert response == RangeResponse(200, {"kind": "probe", "reachable": True})
    assert str(requests[0].url) == f"{APPROVED_WEB_BASE_URL}/v1/proxy/api/probe"
    assert requests[0].method == "POST"
    assert requests[0].headers["connection"] == "close"


@pytest.mark.asyncio
async def test_http_client_rejects_non_string_credentials_before_transport() -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    client = HttpRangeClient(
        APPROVED_WEB_BASE_URL,
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(ValueError, match="credential"):
            await client.request(
                Route.API,
                RangeOperation.PROTECTED_DATA,
                {"credential": 1},  # type: ignore[dict-item]
            )
    finally:
        await client.aclose()

    assert calls == 0


@pytest.mark.asyncio
async def test_http_client_rejects_unapproved_base_url_and_non_enums() -> None:
    with pytest.raises(ValueError, match="approved local range URL"):
        HttpRangeClient("http://localhost:18080")

    client = HttpRangeClient(APPROVED_WEB_BASE_URL)
    try:
        with pytest.raises(TypeError, match="Route"):
            await client.request("api", RangeOperation.PROBE, None)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="RangeOperation"):
            await client.request(Route.API, "probe", None)  # type: ignore[arg-type]
    finally:
        await client.aclose()
