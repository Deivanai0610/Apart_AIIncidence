import math

import pytest
from pydantic import ValidationError

from chimera.schemas import (
    ActuationResult,
    ActionKind,
    AttackerAction,
    ContainmentAction,
    EventType,
    GroundTruthEvent,
    ObservationEvent,
    Route,
)


def test_query_data_requires_route_and_credential() -> None:
    with pytest.raises(ValidationError):
        AttackerAction(kind=ActionKind.QUERY_DATA, route=Route.API)


def test_query_data_requires_a_broker_credential_handle() -> None:
    with pytest.raises(ValidationError, match="credential_id"):
        AttackerAction(
            kind=ActionKind.QUERY_DATA,
            route=Route.API,
            credential_id="credential-1",
        )

    action = AttackerAction(
        kind=ActionKind.QUERY_DATA,
        route=Route.API,
        credential_id="cred-0123abcdefab-0001",
    )

    assert action.credential_id == "cred-0123abcdefab-0001"


def test_inspect_web_rejects_route_and_credential() -> None:
    with pytest.raises(ValidationError):
        AttackerAction(
            kind=ActionKind.INSPECT_WEB,
            route=Route.API,
            credential_id="credential-1",
        )


def test_observation_schema_rejects_ground_truth() -> None:
    with pytest.raises(ValidationError):
        ObservationEvent(
            episode_id="ep-1",
            event_id="obs-000001",
            elapsed_ns=10,
            occurred_at="2026-09-12T10:00:00Z",
            event_type=EventType.ROUTE_PROBE,
            source="web",
            target="api",
            correlation_id="corr-1",
            result={"status_class": 2},
            attacker=True,
        )


@pytest.mark.parametrize(
    "evaluator_key",
    [
        "actor_class",
        "secret_delivered",
        "capabilities",
        "expected_benign_result",
        "attacker",
        "compromised",
    ],
)
def test_observation_result_rejects_evaluator_fields_at_any_depth(
    evaluator_key: str,
) -> None:
    with pytest.raises(ValidationError, match="evaluator-only"):
        ObservationEvent(
            episode_id="ep-1",
            event_id="obs-000001",
            elapsed_ns=10,
            occurred_at="2026-09-12T10:00:00Z",
            event_type=EventType.ROUTE_PROBE,
            source="web",
            target="api",
            correlation_id="corr-1",
            result={"nested": [{"deeper": {evaluator_key: True}}]},
        )


def test_event_streams_reject_each_others_identifiers() -> None:
    observation = {
        "episode_id": "ep-1",
        "event_id": "gt-000001",
        "elapsed_ns": 10,
        "occurred_at": "2026-09-12T10:00:00Z",
        "event_type": EventType.ROUTE_PROBE,
        "source": "web",
        "target": "api",
        "correlation_id": "corr-1",
        "result": {"status_class": 2},
    }
    ground_truth = {
        **observation,
        "event_id": "obs-000001",
        "actor_class": "attacker",
        "capabilities": ["route:api:probed"],
        "secret_delivered": False,
        "expected_benign_result": None,
    }

    with pytest.raises(ValidationError):
        ObservationEvent(**observation)
    with pytest.raises(ValidationError):
        GroundTruthEvent(**ground_truth)


@pytest.mark.parametrize("result", [{"value": object()}, {"nested": [math.nan]}])
def test_events_reject_non_json_compatible_results(result: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ObservationEvent(
            episode_id="ep-1",
            event_id="obs-000001",
            elapsed_ns=10,
            occurred_at="2026-09-12T10:00:00Z",
            event_type=EventType.ROUTE_PROBE,
            source="web",
            target="api",
            correlation_id="corr-1",
            result=result,
        )


def test_containment_constructors_accept_only_approved_targets() -> None:
    assert ContainmentAction.block_edge("web_api").target == "web_api"
    assert ContainmentAction.isolate_service("web").target == "web"

    with pytest.raises(ValidationError):
        ContainmentAction.block_edge("public-internet")


def test_actuation_result_retains_each_command_exit_code() -> None:
    result = ActuationResult(
        action=ContainmentAction.isolate_service("api"),
        attempted=True,
        applied=False,
        effective=True,
        command_exit_code=-1,
        command_exit_codes=(0, -1),
        probe_event_ids=("gt-000001", "gt-000002"),
        reason="docker_command_exception",
    )

    assert result.command_exit_code == -1
    assert result.command_exit_codes == (0, -1)


def test_defender_decision_requires_enumerated_reason_and_consistent_evidence() -> None:
    from chimera.schemas import DefenderDecision

    with pytest.raises(ValidationError):
        DefenderDecision(suspicious=False, reason_code="x")
    with pytest.raises(ValidationError):
        DefenderDecision(suspicious=False, reason_code="route_pattern")
    with pytest.raises(ValidationError):
        DefenderDecision(
            suspicious=True,
            reason_code="route_pattern",
            evidence_event_ids=("obs-000001", "obs-000001"),
        )
    with pytest.raises(ValidationError):
        DefenderDecision(
            suspicious=False,
            reason_code="route_pattern",
            action=ContainmentAction.block_edge("web_api"),
            evidence_event_ids=("obs-000001",),
        )
