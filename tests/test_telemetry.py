import json
import stat
from datetime import UTC
from pathlib import Path

import pytest

from chimera.schemas import (
    EVALUATOR_ONLY_RESULT_KEYS,
    EventType,
    GroundTruthEvent,
    ObservationEvent,
)
from chimera.telemetry import DefenderBatcher, EpisodeClock, TelemetryStore


def test_ground_truth_never_enters_defender_jsonl(tmp_path: Path) -> None:
    store = TelemetryStore(tmp_path, "ep-1")
    store.record_ground_truth(actor_class="attacker", secret_delivered=True)
    store.record_observation(
        event_type=EventType.DATA_REQUEST,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"status_class": 2},
    )

    visible = (store.episode_dir / "defender_events.jsonl").read_text()

    assert "secret_delivered" not in visible
    assert "actor_class" not in visible


def test_evaluator_fields_never_enter_defender_event_records(tmp_path: Path) -> None:
    store = TelemetryStore(tmp_path, "ep-1")
    store.record_ground_truth(
        actor_class="attacker",
        secret_delivered=True,
        capabilities=("api_probed",),
        expected_benign_result=False,
    )
    store.record_observation(
        event_type=EventType.DATA_REQUEST,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"status_class": 2},
    )

    defender_record = json.loads(
        (store.episode_dir / "defender_events.jsonl").read_text()
    )

    assert EVALUATOR_ONLY_RESULT_KEYS.isdisjoint(defender_record)
    assert EVALUATOR_ONLY_RESULT_KEYS.isdisjoint(defender_record["result"])


def test_ground_truth_uses_the_evaluator_artifact_name(tmp_path: Path) -> None:
    store = TelemetryStore(tmp_path, "ep-1")
    store.record_ground_truth(actor_class="attacker", secret_delivered=False)

    assert (store.episode_dir / "evaluator_events.jsonl").is_file()
    assert not (store.episode_dir / "ground_truth_events.jsonl").exists()


def test_restriction_probe_persists_route_availability(tmp_path: Path) -> None:
    store = TelemetryStore(tmp_path, "ep-1")

    event = store.record_restriction_probe(
        source="actuator",
        target="api",
        correlation_id="restriction-api",
        available=False,
    )

    persisted = json.loads(
        (store.episode_dir / "evaluator_events.jsonl").read_text()
    )
    assert event.event_id == "gt-000001"
    assert persisted["event_id"] == event.event_id
    assert persisted["event_type"] == "restriction_result"
    assert persisted["result"] == {"route_available": False}


def test_episode_directory_has_owner_only_mode(tmp_path: Path) -> None:
    store = TelemetryStore(tmp_path, "ep-1")

    assert store.episode_dir.stat().st_mode & 0o777 == 0o700


def test_telemetry_rejects_symlinked_output_root_before_creating_episode(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    original_mode = stat.S_IMODE(target.stat().st_mode)
    output_root = tmp_path / "output"
    output_root.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        TelemetryStore(output_root, "episode-1")

    assert stat.S_IMODE(target.stat().st_mode) == original_mode
    assert list(target.iterdir()) == []


@pytest.mark.parametrize(
    "episode_id",
    ["../outside", "/absolute-outside", "nested/episode", r"nested\episode"],
)
def test_telemetry_rejects_unsafe_episode_ids_before_creating_paths(
    tmp_path: Path, episode_id: str
) -> None:
    output_root = tmp_path / "output"
    outside = tmp_path / "outside"
    if episode_id == "/absolute-outside":
        episode_id = str(outside)

    with pytest.raises(ValueError, match="episode_id"):
        TelemetryStore(output_root, episode_id)

    assert not output_root.exists()
    assert not outside.exists()


def test_telemetry_empty_directory_ownership_rejects_mode_changes(tmp_path: Path) -> None:
    store = TelemetryStore(tmp_path, "episode-1")
    store.episode_dir.chmod(0o777)

    assert store.owns_empty_episode_directory() is False


def test_telemetry_empty_directory_ownership_rejects_replacement(tmp_path: Path) -> None:
    store = TelemetryStore(tmp_path, "episode-1")
    store.episode_dir.rmdir()
    store.episode_dir.mkdir(mode=0o700)

    assert store.owns_empty_episode_directory() is False


def test_event_ids_do_not_reveal_hidden_ground_truth_gaps(tmp_path: Path) -> None:
    store = TelemetryStore(tmp_path, "ep-1")
    first = store.record_observation(
        event_type=EventType.ROUTE_PROBE,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"status_class": 2},
    )
    hidden = store.record_ground_truth(
        actor_class="attacker",
        secret_delivered=False,
        capabilities=("api_probed",),
        expected_benign_result=None,
    )
    second = store.record_observation(
        event_type=EventType.CONFIG_READ,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"status_class": 2},
    )

    assert (first.event_id, second.event_id) == ("obs-000001", "obs-000002")
    assert hidden.event_id == "gt-000001"


def test_events_have_monotonic_elapsed_time_and_utc_timestamps(tmp_path: Path) -> None:
    clock = EpisodeClock()
    first_elapsed, first_timestamp = clock.capture()
    second_elapsed, second_timestamp = clock.capture()
    store = TelemetryStore(tmp_path, "ep-1", clock=clock)
    event = store.record_observation(
        event_type=EventType.ROUTE_PROBE,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={},
    )

    assert second_elapsed >= first_elapsed
    assert first_timestamp.tzinfo is UTC
    assert second_timestamp.tzinfo is UTC
    assert event.elapsed_ns >= second_elapsed
    assert event.occurred_at.tzinfo is UTC


def test_observation_persistence_recursively_redacts_sensitive_values(
    tmp_path: Path,
) -> None:
    store = TelemetryStore(tmp_path, "ep-1")
    store.record_observation(
        event_type=EventType.DATA_REQUEST,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={
            "credential": "raw-credential",
            "token": "raw-token",
            "secret": "raw-secret",
            "api_key": "raw-api-key",
            "prompt": "raw-prompt",
            "authorization": "raw-authorization",
            "credential_id": "credential-7",
            "nested": [{"token": "nested-token"}],
        },
    )

    persisted = (store.episode_dir / "defender_events.jsonl").read_text()

    for value in (
        "raw-credential",
        "raw-token",
        "raw-secret",
        "raw-api-key",
        "raw-prompt",
        "raw-authorization",
        "nested-token",
    ):
        assert value not in persisted
    assert persisted.count("[REDACTED]") == 7
    assert "credential-7" in persisted


def test_observation_redaction_does_not_mutate_the_caller_result(tmp_path: Path) -> None:
    result = {"nested": [{"token": "raw-token"}], "status_class": 2}
    store = TelemetryStore(tmp_path, "ep-1")

    store.record_observation(
        event_type=EventType.DATA_REQUEST,
        source="web",
        target="api",
        correlation_id="corr-1",
        result=result,
    )

    assert result == {"nested": [{"token": "raw-token"}], "status_class": 2}


def test_only_evaluator_records_are_fsynced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fsync_calls: list[int] = []
    monkeypatch.setattr("chimera.telemetry.os.fsync", fsync_calls.append)
    store = TelemetryStore(tmp_path, "ep-1")

    store.record_observation(
        event_type=EventType.DATA_REQUEST,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"status_class": 2},
    )

    assert fsync_calls == []

    store.record_ground_truth(actor_class="attacker", secret_delivered=False)

    assert len(fsync_calls) == 1


def test_record_observation_rejects_non_event_type_values(tmp_path: Path) -> None:
    store = TelemetryStore(tmp_path, "ep-1")

    with pytest.raises(TypeError, match="EventType"):
        store.record_observation(
            event_type="data_request",  # type: ignore[arg-type]
            source="web",
            target="api",
            correlation_id="corr-1",
            result={"status_class": 2},
        )


def test_observation_sink_receives_only_persisted_observations(tmp_path: Path) -> None:
    received: list[ObservationEvent] = []
    store = TelemetryStore(tmp_path, "ep-1", observation_sink=received.append)

    observation = store.record_observation(
        event_type=EventType.DATA_REQUEST,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"status_class": 2},
    )
    store.record_ground_truth(actor_class="attacker", secret_delivered=True)

    assert received == [observation]
    assert observation.event_id in (store.episode_dir / "defender_events.jsonl").read_text()


def test_jsonl_contains_one_json_observation_per_line(tmp_path: Path) -> None:
    store = TelemetryStore(tmp_path, "ep-1")
    store.record_observation(
        event_type=EventType.ROUTE_PROBE,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"status_class": 2},
    )
    store.record_observation(
        event_type=EventType.CONFIG_READ,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"status_class": 2},
    )

    lines = (store.episode_dir / "defender_events.jsonl").read_text().splitlines()

    assert [json.loads(line)["event_id"] for line in lines] == [
        "obs-000001",
        "obs-000002",
    ]


def test_batcher_drain_preserves_original_events_and_eligible_ids(
    tmp_path: Path,
) -> None:
    store = TelemetryStore(tmp_path, "ep-1")
    first = store.record_observation(
        event_type=EventType.ROUTE_PROBE,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"status_class": 2},
    )
    second = store.record_observation(
        event_type=EventType.DATA_REQUEST,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"status_class": 2},
    )
    batcher = DefenderBatcher(observation_window=2)

    batcher.add(first)
    batcher.add(second)

    assert batcher.eligible_ids() == frozenset()
    assert batcher.drain() == (first, second)
    assert batcher.eligible_ids() == frozenset({first.event_id, second.event_id})
    assert batcher.drain() == ()


def test_batcher_keeps_required_events_and_evicts_old_delivered_evidence(
    tmp_path: Path,
) -> None:
    store = TelemetryStore(tmp_path, "ep-1")
    health = store.record_observation(
        event_type=EventType.ROUTE_PROBE,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"health_only": True, "status_class": 2},
    )
    repeated_health = store.record_observation(
        event_type=EventType.ROUTE_PROBE,
        source="web",
        target="api",
        correlation_id="corr-2",
        result={"health_only": True, "status_class": 2},
    )
    canary_use = store.record_observation(
        event_type=EventType.CANARY_USE,
        source="web",
        target="api",
        correlation_id="corr-3",
        result={"health_only": True, "status_class": 2},
    )
    data_request = store.record_observation(
        event_type=EventType.DATA_REQUEST,
        source="web",
        target="api",
        correlation_id="corr-4",
        result={"health_only": True, "status_class": 2},
    )
    batcher = DefenderBatcher(observation_window=2)

    batcher.add(health)
    batcher.add(repeated_health)
    batcher.add(canary_use)
    batcher.add(data_request)

    assert batcher.drain() == (health, canary_use, data_request)
    assert batcher.eligible_ids() == frozenset({canary_use.event_id, data_request.event_id})


def test_batcher_coalesces_health_only_events_per_pending_window(
    tmp_path: Path,
) -> None:
    store = TelemetryStore(tmp_path, "ep-1")
    first = store.record_observation(
        event_type=EventType.ROUTE_PROBE,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"health_only": True, "status_class": 2},
    )
    next_window_first = store.record_observation(
        event_type=EventType.ROUTE_PROBE,
        source="web",
        target="api",
        correlation_id="corr-2",
        result={"health_only": True, "status_class": 2},
    )
    next_window_repeat = store.record_observation(
        event_type=EventType.ROUTE_PROBE,
        source="web",
        target="api",
        correlation_id="corr-3",
        result={"health_only": True, "status_class": 2},
    )
    batcher = DefenderBatcher()

    batcher.add(first)
    assert batcher.drain() == (first,)

    batcher.add(next_window_first)
    batcher.add(next_window_repeat)

    assert batcher.drain() == (next_window_first,)


def test_batcher_preserves_other_required_security_events(tmp_path: Path) -> None:
    store = TelemetryStore(tmp_path, "ep-1")
    authorization_failure = store.record_observation(
        event_type=EventType.AUTHORIZATION_FAILURE,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"health_only": True, "status_class": 4},
    )
    restriction_result = store.record_observation(
        event_type=EventType.RESTRICTION_RESULT,
        source="web",
        target="api",
        correlation_id="corr-2",
        result={"health_only": True, "status_class": 2},
    )
    batcher = DefenderBatcher()

    batcher.add(authorization_failure)
    batcher.add(restriction_result)

    assert batcher.drain() == (authorization_failure, restriction_result)


def test_batcher_rejects_raw_observation_dictionaries() -> None:
    batcher = DefenderBatcher()

    with pytest.raises(TypeError, match="ObservationEvent"):
        batcher.add({})  # type: ignore[arg-type]


def test_batcher_rejects_ground_truth_events(tmp_path: Path) -> None:
    store = TelemetryStore(tmp_path, "ep-1")
    ground_truth = store.record_ground_truth(
        actor_class="attacker",
        secret_delivered=False,
    )
    batcher = DefenderBatcher()

    assert isinstance(ground_truth, GroundTruthEvent)
    with pytest.raises(TypeError, match="ObservationEvent"):
        batcher.add(ground_truth)  # type: ignore[arg-type]


def test_batcher_keeps_health_event_when_it_introduces_a_new_route(
    tmp_path: Path,
) -> None:
    store = TelemetryStore(tmp_path, "ep-1")
    api_health = store.record_observation(
        event_type=EventType.ROUTE_PROBE,
        source="web",
        target="api",
        correlation_id="corr-1",
        result={"health_only": True, "status_class": 2},
    )
    internal_health = store.record_observation(
        event_type=EventType.ROUTE_PROBE,
        source="web",
        target="internal",
        correlation_id="corr-2",
        result={"health_only": True, "status_class": 2},
    )
    batcher = DefenderBatcher()

    batcher.add(api_health)
    batcher.add(internal_health)

    assert batcher.drain() == (api_health, internal_health)


def test_ground_truth_and_observation_records_are_thread_safe(tmp_path: Path) -> None:
    import json as _json
    from concurrent.futures import ThreadPoolExecutor

    store = TelemetryStore(tmp_path, "episode-threads")

    def probe(index: int) -> str:
        return store.record_restriction_probe(
            source="actuator", target="api" if index % 2 else "internal",
            correlation_id=f"probe-{index}", available=bool(index % 2),
        ).event_id

    def observe(index: int) -> str:
        return store.record_observation(
            EventType.ROUTE_PROBE, "broker", "api", f"corr-{index}", {"status_class": 2}
        ).event_id

    with ThreadPoolExecutor(max_workers=8) as pool:
        gt_ids = list(pool.map(probe, range(200)))
        obs_ids = list(pool.map(observe, range(200)))

    assert len(set(gt_ids)) == 200 and len(set(obs_ids)) == 200
    gt_lines = [_json.loads(l) for l in (store.episode_dir / "evaluator_events.jsonl").read_text().splitlines()]
    obs_lines = [_json.loads(l) for l in (store.episode_dir / "defender_events.jsonl").read_text().splitlines()]
    assert [r["event_id"] for r in gt_lines] == [f"gt-{i:06d}" for i in range(1, 201)]
    assert [r["event_id"] for r in obs_lines] == [f"obs-{i:06d}" for i in range(1, 201)]
    assert all(store.has_ground_truth_event_id(event_id) for event_id in gt_ids)
