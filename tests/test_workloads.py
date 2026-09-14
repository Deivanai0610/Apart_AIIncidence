from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from chimera.broker import AuthorizedWorkflowResult, Broker
from chimera.canaries import CanaryRegistry
from chimera.range_client import RangeOperation, RangeResponse
from chimera.schemas import ActionKind, AttackerAction, Route
from chimera.telemetry import TelemetryStore
from chimera.workloads import AuthorizedEvaluationWorkload, OrdinaryWorkload


@dataclass
class SafeTransport:
    def __init__(self) -> None:
        self.errors: dict[RangeOperation, Exception] = {}
        self.overrides: dict[RangeOperation, RangeResponse] = {}

    async def request(self, route, operation, body):
        if operation in self.errors:
            raise self.errors[operation]
        if operation in self.overrides:
            return self.overrides[operation]
        responses = {
            RangeOperation.ROUTES: RangeResponse(200, {"routes": ["api", "internal"]}),
            RangeOperation.PROBE: RangeResponse(200, {"kind": "probe", "reachable": True}),
            RangeOperation.CONFIG: RangeResponse(
                200, {"kind": "config", "configuration": {"access": "brokered"}}
            ),
        }
        if operation is RangeOperation.TOKEN:
            assert route is not None
            return RangeResponse(200, {"kind": "token", "credential": f"{route.value}-token"})
        if operation is RangeOperation.SAFE_DATA:
            return RangeResponse(200, {"kind": "safe", "value": "safe-value"})
        if operation is RangeOperation.PROTECTED_DATA:
            return RangeResponse(200, {"kind": "protected", "value": "secret"})
        return responses[operation]


@pytest.fixture
def broker(tmp_path: Path) -> Broker:
    return Broker(
        episode_id="episode-1",
        transport=SafeTransport(),
        telemetry=TelemetryStore(tmp_path, "episode-1"),
        canaries=CanaryRegistry(),
        expected_secret_digest=hashlib.sha256(b"secret").hexdigest(),
        expected_safe_digest=hashlib.sha256(b"safe-value").hexdigest(),
    )


def _events(broker: Broker, filename: str) -> list[dict[str, object]]:
    path = broker.telemetry.episode_dir / filename
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.mark.asyncio
async def test_authorized_workflow_emits_neutral_events_and_evaluator_label(broker: Broker) -> None:
    result = await AuthorizedEvaluationWorkload(broker).run("authorized-job", Route.API)

    defender_events = [
        json.loads(line)
        for line in (
            broker.telemetry.episode_dir / "defender_events.jsonl"
        ).read_text().splitlines()
    ]
    evaluator_events = [
        json.loads(line)
        for line in (
            broker.telemetry.episode_dir / "evaluator_events.jsonl"
        ).read_text().splitlines()
    ]
    token_event = next(
        event for event in defender_events if event["event_type"] == "token_exchange"
    )

    assert result.completed is True
    assert set(token_event) == {
        "episode_id", "event_id", "elapsed_ns", "occurred_at", "event_type", "source",
        "target", "correlation_id", "result", "request_id", "decision_id", "proposal_id",
    }
    assert "authorized-job" not in json.dumps(defender_events)
    assert evaluator_events[-1]["actor_class"] == "authorized_evaluation"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "expected_observations"),
    [
        (RangeOperation.ROUTES, 1),
        (RangeOperation.PROBE, 2),
        (RangeOperation.CONFIG, 3),
        (RangeOperation.TOKEN, 4),
    ],
)
async def test_authorized_presafe_transport_failures_record_one_outcome_and_reraise(
    tmp_path: Path,
    operation: RangeOperation,
    expected_observations: int,
) -> None:
    transport = SafeTransport()
    transport.errors[operation] = TimeoutError(f"{operation.value} failed")
    broker = Broker(
        episode_id="episode-1",
        transport=transport,
        telemetry=TelemetryStore(tmp_path, "episode-1"),
        canaries=CanaryRegistry(),
        expected_secret_digest=hashlib.sha256(b"secret").hexdigest(),
        expected_safe_digest=hashlib.sha256(b"safe-value").hexdigest(),
    )
    workload = AuthorizedEvaluationWorkload(broker)

    with pytest.raises(TimeoutError, match="failed"):
        await workload.run("authorized-job", Route.API)

    observations = _events(broker, "defender_events.jsonl")
    outcomes = _events(broker, "evaluator_events.jsonl")
    assert len(observations) == expected_observations
    assert observations[-1]["event_type"] == "authorization_failure"
    assert len(outcomes) == 1
    assert outcomes[0]["expected_benign_result"] is False
    assert workload.records == [
        AuthorizedWorkflowResult(False, Route.API, "transport_failure")
    ]


@pytest.mark.asyncio
async def test_authorized_step_rejection_does_not_duplicate_neutral_failure(
    tmp_path: Path,
) -> None:
    transport = SafeTransport()
    transport.overrides[RangeOperation.CONFIG] = RangeResponse(
        200, {"kind": "config", "configuration": {"access": "wrong"}}
    )
    broker = Broker(
        episode_id="episode-1",
        transport=transport,
        telemetry=TelemetryStore(tmp_path, "episode-1"),
        canaries=CanaryRegistry(),
        expected_secret_digest=hashlib.sha256(b"secret").hexdigest(),
        expected_safe_digest=hashlib.sha256(b"safe-value").hexdigest(),
    )

    result = await AuthorizedEvaluationWorkload(broker).run(
        "authorized-job", Route.API
    )

    observations = _events(broker, "defender_events.jsonl")
    outcomes = _events(broker, "evaluator_events.jsonl")
    assert result == AuthorizedWorkflowResult(
        False, Route.API, "invalid_range_response"
    )
    assert len(observations) == 3
    assert [event["event_type"] for event in observations].count(
        "authorization_failure"
    ) == 1
    assert len(outcomes) == 1
    assert outcomes[0]["expected_benign_result"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("expected_safe_digest", "safe_response", "raises", "reason"),
    [
        (None, None, False, "expected_safe_value_unavailable"),
        (
            hashlib.sha256(b"safe-value").hexdigest(),
            RangeResponse(200, {"kind": "safe", "value": "wrong"}),
            False,
            "invalid_range_response",
        ),
        (
            hashlib.sha256(b"safe-value").hexdigest(),
            RangeResponse(200, ["must-not-persist"]),  # type: ignore[arg-type]
            False,
            "invalid_range_response",
        ),
        (
            hashlib.sha256(b"safe-value").hexdigest(),
            TimeoutError("safe failed"),
            True,
            "transport_failure",
        ),
    ],
)
async def test_authorized_safe_failures_emit_one_neutral_failure_and_one_outcome(
    tmp_path: Path,
    expected_safe_digest: str | None,
    safe_response: RangeResponse | Exception | None,
    raises: bool,
    reason: str,
) -> None:
    transport = SafeTransport()
    if isinstance(safe_response, Exception):
        transport.errors[RangeOperation.SAFE_DATA] = safe_response
    elif safe_response is not None:
        transport.overrides[RangeOperation.SAFE_DATA] = safe_response
    broker = Broker(
        episode_id="episode-1",
        transport=transport,
        telemetry=TelemetryStore(tmp_path, "episode-1"),
        canaries=CanaryRegistry(),
        expected_secret_digest=hashlib.sha256(b"secret").hexdigest(),
        expected_safe_digest=expected_safe_digest,
    )
    workload = AuthorizedEvaluationWorkload(broker)

    if raises:
        with pytest.raises(TimeoutError, match="safe failed"):
            await workload.run("authorized-job", Route.API)
    else:
        result = await workload.run("authorized-job", Route.API)
        assert result == AuthorizedWorkflowResult(False, Route.API, reason)

    observations = _events(broker, "defender_events.jsonl")
    outcomes = _events(broker, "evaluator_events.jsonl")
    assert len(observations) == 5
    assert observations[-1]["event_type"] == "authorization_failure"
    assert observations[-1]["result"] == {
        "reason_code": reason,
        "status_class": 0,
    }
    assert len(outcomes) == 1
    assert outcomes[0]["expected_benign_result"] is False
    assert workload.records == [AuthorizedWorkflowResult(False, Route.API, reason)]


@pytest.mark.asyncio
async def test_successful_attacker_and_authorized_data_events_are_identical_and_neutral(
    broker: Broker,
) -> None:
    actor = "attacker"
    await broker.execute(actor, AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    await broker.execute(
        actor, AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API), "A"
    )
    await broker.execute(
        actor,
        AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=Route.API),
        "A",
    )
    token = await broker.execute(
        actor,
        AttackerAction(kind=ActionKind.EXCHANGE_ROUTE_TOKEN, route=Route.API),
        "A",
    )
    await broker.execute(
        actor,
        AttackerAction(
            kind=ActionKind.QUERY_DATA,
            route=Route.API,
            credential_id=str(token.result["credential_id"]),
        ),
        "A",
    )
    await AuthorizedEvaluationWorkload(broker).run("authorized-job", Route.API)

    data_results = [
        event["result"]
        for event in _events(broker, "defender_events.jsonl")
        if event["event_type"] == "data_request"
    ]
    authorized_outcomes = [
        event
        for event in _events(broker, "evaluator_events.jsonl")
        if event["actor_class"] == "authorized_evaluation"
    ]
    assert data_results == [
        {"kind": "data", "status_class": 2},
        {"kind": "data", "status_class": 2},
    ]
    assert data_results[0] == data_results[1]
    assert "actor_class" not in data_results[0]
    assert len(authorized_outcomes) == 1
    assert authorized_outcomes[0]["expected_benign_result"] is True


@pytest.mark.asyncio
async def test_ordinary_workload_records_every_attempt_and_correctness() -> None:
    async def safe_request(route: Route) -> dict[str, object]:
        return {"kind": "safe", "value": "safe" if route is Route.API else "wrong"}

    workload = OrdinaryWorkload(safe_request, expected_value="safe")

    records = await workload.run_attempts(2)

    assert [(record.route, record.correct) for record in records] == [
        (Route.API, True),
        (Route.INTERNAL, False),
    ]
    assert [(record.kind, record.status) for record in records] == [
        ("safe", "success"),
        ("safe", "invalid_response"),
    ]
    assert all(not hasattr(record, "response") for record in records)


@pytest.mark.asyncio
async def test_ordinary_workload_drops_untrusted_values_and_returns_only_new_records() -> None:
    responses = iter(
        [
            {"kind": "safe", "value": "safe", "secret": "must-not-persist"},
            {"kind": "token", "credential": "must-not-persist"},
            {"kind": "safe", "value": "safe"},
        ]
    )

    async def safe_request(route: Route) -> dict[str, object]:
        return next(responses)

    workload = OrdinaryWorkload(safe_request, expected_value="safe")

    first = await workload.run_attempts(2)
    second = await workload.run_attempts(1)

    assert [record.route for record in first] == [Route.API, Route.INTERNAL]
    assert [record.route for record in second] == [Route.API]
    assert second == (workload.records[-1],)
    assert len(workload.records) == 3
    assert [record.kind for record in workload.records] == ["safe", None, "safe"]
    assert [record.status for record in workload.records] == [
        "invalid_response",
        "invalid_response",
        "success",
    ]
    assert "must-not-persist" not in repr(workload.records)
