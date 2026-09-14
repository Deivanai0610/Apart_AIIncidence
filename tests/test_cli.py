from __future__ import annotations

import asyncio
import json
import os
from dataclasses import asdict
from decimal import Decimal
from types import MappingProxyType, SimpleNamespace
from pathlib import Path

import pytest

from chimera.config import ExperimentConfig, config_digest, load_config
from chimera.schedule import build_schedule


@pytest.fixture
def frozen_config(monkeypatch: pytest.MonkeyPatch) -> ExperimentConfig:
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")
    payload = load_config(Path("configs/experiment.yaml")).model_dump(mode="json")
    payload["status"] = "frozen"
    for role in ("attacker", "defender"):
        payload["models"][role].update(
            {
                "pinned_provider_slug": f"verified-{role}",
                "expected_provider_name": f"Verified {role.title()}",
                "expected_endpoint_model": f"provider/{role}-v1",
            }
        )
        payload["budgets"]["openrouter"][role]["input_per_million_usd"] = 1.0
        payload["budgets"]["openrouter"][role]["output_per_million_usd"] = 1.0
    return ExperimentConfig.model_validate(payload)


@pytest.fixture
def complete_candidate_config(frozen_config: ExperimentConfig) -> ExperimentConfig:
    payload = frozen_config.model_dump(mode="json")
    payload["status"] = "candidate"
    return ExperimentConfig.model_validate(payload)


@pytest.fixture(autouse=True)
def isolated_live_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from chimera import cli

    monkeypatch.setattr(cli, "PILOT_RUN_ROOT", tmp_path / "pilot")
    monkeypatch.setattr(cli, "CONTROL_RUN_ROOT", tmp_path / "control")
    monkeypatch.setattr(cli, "LIVE_BUDGET_ROOT", tmp_path / "provider-budget")
    monkeypatch.setattr(cli, "LIVE_RANGE_LEASE_PATH", tmp_path / ".live-range.lock")


def _invoke(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, object]]:
    from chimera import cli

    exit_code = cli.main(argv)
    output = capsys.readouterr()
    return exit_code, json.loads(output.out)


def _stamp_payload(
    cli,
    digest: str,
    *,
    success: bool = True,
    check_count: int | None = None,
    code_revision: str | None = None,
    source_tree_digest: str | None = None,
    model_ids: dict[str, str | None] | None = None,
) -> dict[str, object]:
    commands = [
        {
            "check_id": check_id,
            "command": list(command),
            "exit_code": 0 if success else 1,
            "started_at": "2026-09-12T12:00:00+00:00",
            "ended_at": "2026-09-12T12:00:01+00:00",
        }
        for check_id, command in cli.REQUIRED_CHECKS[:check_count]
    ]
    return {
        "schema_version": 1,
        "kind": "chimera_local_verification",
        "success": success,
        "configuration_digest": digest,
        "code_revision": code_revision,
        "source_tree_digest": source_tree_digest or cli.current_source_tree_digest(),
        "model_ids": model_ids
        or {
            "attacker": os.getenv("OPENROUTER_ATTACKER_MODEL") or None,
            "defender": os.getenv("OPENROUTER_DEFENDER_MODEL") or None,
        },
        "commands": commands,
    }


def _write_stamp(cli, root: Path, payload: dict[str, object]) -> Path:
    digest = str(payload["configuration_digest"])
    root.mkdir(parents=True)
    path = root / f"{digest}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_run_defaults_to_mock(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    from chimera import cli

    monkeypatch.setattr(
        cli,
        "run_mock_episode",
        lambda **kwargs: {"model_mode": "mock", **kwargs},
    )

    exit_code, metadata = _invoke(
        ["run", "--condition", "A", "--instruction", "U"], capsys
    )

    assert exit_code == 0
    assert metadata["model_mode"] == "mock"
    assert metadata["condition"] == "A"
    assert metadata["instruction"] == "U"


def test_demo_prints_redacted_episode_flow_without_provider_calls(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    from chimera import cli

    mock_root = tmp_path / "typed" / "mock"
    monkeypatch.setattr(cli, "MOCK_RUN_ROOT", mock_root)

    exit_code = cli.main(["demo", "--horizon-seconds", "0.03"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "CHIMERA LOCAL CONTAINMENT DEMO" in output
    assert "Pipeline: test agent -> broker -> telemetry -> defender -> actuator -> evaluator" in output
    assert "[ACTION] inspect_web -> accepted" in output
    assert "[TELEMETRY] canary_exposed on api" in output
    assert "[DECISION] block_edge web_api" in output
    assert "[ENFORCEMENT] applied=yes effective=yes" in output
    assert "[PROBE] api=blocked internal=available" in output
    assert "[OUTCOME] secret_delivered=no" in output
    assert "[COST] provider_requests=0" in output
    assert "credential_id" not in output
    assert "canary-0001" not in output
    metadata_paths = list(mock_root.glob("*/metadata.json"))
    assert len(metadata_paths) == 1
    metadata = json.loads(metadata_paths[0].read_text(encoding="utf-8"))
    assert metadata["provider_requests"] == 0


def test_docker_demo_runs_containment_checks_before_printing_episode(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    from chimera import cli

    commands: list[list[str]] = []
    monkeypatch.setattr(cli, "MOCK_RUN_ROOT", tmp_path / "typed" / "mock")
    monkeypatch.setattr(
        cli,
        "run_command",
        lambda command: commands.append(command) or 0,
    )

    exit_code = cli.main(
        ["demo", "--docker", "--horizon-seconds", "0.03"]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert commands == [
        list(cli.REQUIRED_CHECKS[2][1]),
        list(cli.REQUIRED_CHECKS[3][1]),
    ]
    assert "[DOCKER] CT3 canary stop: PASS" in output
    assert "[DOCKER] CT4 stop effect: PASS" in output
    assert output.index("[DOCKER] CT4 stop effect: PASS") < output.index("[ACTION]")


def test_docker_demo_failure_skips_the_synthetic_episode(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    from chimera import cli

    mock_root = tmp_path / "typed" / "mock"
    monkeypatch.setattr(cli, "MOCK_RUN_ROOT", mock_root)
    monkeypatch.setattr(cli, "run_command", lambda command: 1)

    exit_code = cli.main(
        ["demo", "--docker", "--horizon-seconds", "0.03"]
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "[DOCKER] CT3 canary stop: FAIL" in output
    assert "[ABORT] synthetic episode skipped because a Docker check failed" in output
    assert not list(mock_root.glob("*/metadata.json"))


def test_range_up_initializes_route_state_before_compose(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chimera import cli

    order: list[str] = []
    monkeypatch.setattr(
        cli,
        "initialize_route_states",
        lambda path: order.append(f"state:{path.name}"),
        raising=False,
    )
    monkeypatch.setattr(
        cli, "run_command", lambda command: order.append("compose") or 0
    )
    monkeypatch.setattr(cli, "_emit", lambda payload: None)

    assert cli._range_command("up") == 0
    assert order == ["state:runtime", "compose"]


def test_range_up_state_failure_prevents_compose(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chimera import cli

    compose_calls: list[list[str]] = []

    def fail(path: Path) -> None:
        raise ValueError("unsafe route state")

    monkeypatch.setattr(cli, "initialize_route_states", fail, raising=False)
    monkeypatch.setattr(
        cli, "run_command", lambda command: compose_calls.append(command) or 0
    )

    with pytest.raises(ValueError, match="unsafe"):
        cli._range_command("up")

    assert compose_calls == []


def test_live_run_starts_range_before_provider_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chimera import cli

    order: list[str] = []
    commands: list[list[str]] = []
    monkeypatch.setattr(
        cli,
        "initialize_route_states",
        lambda path: order.append(f"state:{path.name}"),
    )

    def run(command: list[str]) -> int:
        order.append("compose")
        commands.append(command)
        return 0

    monkeypatch.setattr(cli, "run_command", run)

    cli._ensure_live_range()

    assert order == ["state:runtime", "compose"]
    assert commands == [[*cli._COMPOSE, "up", "--build", "--wait"]]


def test_live_run_stops_before_provider_clients_when_range_startup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chimera import cli

    monkeypatch.setattr(cli, "initialize_route_states", lambda path: None)
    monkeypatch.setattr(cli, "run_command", lambda command: 1)

    with pytest.raises(RuntimeError, match="range startup"):
        cli._ensure_live_range()


@pytest.mark.parametrize("action", ["up", "down", "reset"])
def test_range_commands_hold_live_range_lease(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    from chimera import cli

    order: list[str] = []

    class Lease:
        def __init__(self, path: Path) -> None:
            assert path == cli.LIVE_RANGE_LEASE_PATH

        def __enter__(self):
            order.append("lease")
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            order.append("release")

    monkeypatch.setattr(cli, "LiveRangeLease", Lease)
    monkeypatch.setattr(
        cli,
        "initialize_route_states",
        lambda path: order.append("state"),
    )
    monkeypatch.setattr(
        cli,
        "run_command",
        lambda command: order.append("command") or 0,
    )
    monkeypatch.setattr(cli, "_emit", lambda payload: None)

    assert cli._range_command(action) == 0
    assert order[0] == "lease"
    assert order[-1] == "release"
    assert order.count("command") == (2 if action == "reset" else 1)


@pytest.mark.parametrize(
    ("argv", "allow_paid"),
    [
        (["run", "--live"], "1"),
        (["run", "--live", "--confirm-paid"], None),
        (["run", "--live", "--confirm-paid"], "0"),
    ],
)
def test_live_requires_both_paid_gates_before_client_construction(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    argv: list[str],
    allow_paid: str | None,
) -> None:
    from chimera import cli

    constructed: list[object] = []
    monkeypatch.setattr(cli, "construct_live_clients", lambda config: constructed.append(config))
    if allow_paid is None:
        monkeypatch.delenv("CHIMERA_ALLOW_PAID", raising=False)
    else:
        monkeypatch.setenv("CHIMERA_ALLOW_PAID", allow_paid)

    with pytest.raises(SystemExit, match="2"):
        cli.main(argv)

    assert "paid execution is disabled" in capsys.readouterr().err.lower()
    assert constructed == []


def test_measured_live_requires_schedule_metadata_before_client_construction(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    constructions: list[object] = []
    monkeypatch.setattr(cli, "load_config", lambda path: frozen_config)
    monkeypatch.setattr(cli, "require_local_verification_stamp", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        cli, "construct_live_clients", lambda config: constructions.append(config)
    )
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    with pytest.raises(SystemExit, match="2"):
        cli.main(["run", "--live", "--confirm-paid"])

    assert "schedule" in capsys.readouterr().err.lower()
    assert constructions == []


def test_measured_live_uses_exact_schedule_row(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    schedule_root = tmp_path / "schedules"
    schedule_root.mkdir()
    rows = build_schedule(frozen_config)
    selected = rows[11]
    path = schedule_root / "schedule.json"
    path.write_text(
        json.dumps(
            {
                "configuration_digest": config_digest(frozen_config),
                "rows": [asdict(row) for row in rows],
            }
        ),
        encoding="utf-8",
    )
    observed: dict[str, object] = {}
    monkeypatch.setattr(cli, "SCHEDULE_OUTPUT_ROOT", schedule_root)
    monkeypatch.setattr(cli, "MEASURED_RUN_ROOT", tmp_path / "measured")
    monkeypatch.setattr(cli, "load_config", lambda config_path: frozen_config)
    monkeypatch.setattr(cli, "require_local_verification_stamp", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        cli,
        "run_live_episode",
        lambda **kwargs: observed.update(kwargs)
        or {"model_mode": "live", "run_kind": "measured"},
    )
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    exit_code, _ = _invoke(
        [
            "run",
            "--live",
            "--confirm-paid",
            "--schedule",
            str(path),
            "--schedule-episode-id",
            selected.episode_id,
        ],
        capsys,
    )

    assert exit_code == 0
    assert observed["schedule_item"] == selected
    assert observed["condition"] == selected.condition
    assert observed["instruction"] == selected.instruction
    assert observed["run_kind"] == "measured"


def test_measured_live_rejects_used_schedule_row_before_clients(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    schedule_root = tmp_path / "schedules"
    schedule_root.mkdir()
    rows = build_schedule(frozen_config)
    selected = rows[0]
    schedule_path = schedule_root / "schedule.json"
    schedule_path.write_text(
        json.dumps(
            {
                "configuration_digest": config_digest(frozen_config),
                "rows": [asdict(row) for row in rows],
            }
        ),
        encoding="utf-8",
    )
    measured_root = tmp_path / "measured"
    manifest = cli.Manifest(
        measured_root / "manifest.jsonl", expected_run_kind="measured"
    )
    manifest.append({**asdict(selected), "run_kind": "measured", "status": "starting"})
    constructions: list[object] = []
    monkeypatch.setattr(cli, "SCHEDULE_OUTPUT_ROOT", schedule_root)
    monkeypatch.setattr(cli, "MEASURED_RUN_ROOT", measured_root)
    monkeypatch.setattr(cli, "load_config", lambda path: frozen_config)
    monkeypatch.setattr(
        cli, "construct_live_clients", lambda config: constructions.append(config)
    )
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    with pytest.raises(SystemExit, match="2"):
        cli.main(
            [
                "run",
                "--live",
                "--confirm-paid",
                "--schedule",
                str(schedule_path),
                "--schedule-episode-id",
                selected.episode_id,
            ]
        )

    assert "already been used" in capsys.readouterr().err
    assert constructions == []


def test_live_pilot_is_explicit_and_uses_separate_run_kind(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    complete_candidate_config: ExperimentConfig,
) -> None:
    from chimera import cli

    observed: dict[str, object] = {}
    monkeypatch.setattr(cli, "load_config", lambda path: complete_candidate_config)
    monkeypatch.setattr(cli, "require_local_verification_stamp", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        cli,
        "run_live_episode",
        lambda **kwargs: observed.update(kwargs)
        or {"model_mode": "live", "run_kind": "pilot"},
    )
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    exit_code, _ = _invoke(
        [
            "run",
            "--live",
            "--pilot",
            "--confirm-paid",
            "--condition",
            "E",
            "--instruction",
            "W",
        ],
        capsys,
    )

    assert exit_code == 0
    assert observed["run_kind"] == "pilot"
    assert observed["schedule_item"] is None
    assert observed["condition"] == "E"
    assert observed["instruction"] == "W"


@pytest.mark.parametrize("invalid_kind", ["null_pricing", "missing_model"])
def test_live_rejects_invalid_configuration_before_client_construction(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    frozen_config: ExperimentConfig,
    invalid_kind: str,
) -> None:
    from chimera import cli

    payload = frozen_config.model_dump(mode="json")
    if invalid_kind == "null_pricing":
        payload["budgets"]["openrouter"]["attacker"][
            "input_per_million_usd"
        ] = None
    config = ExperimentConfig.model_validate(payload)
    monkeypatch.setattr(cli, "load_config", lambda path: config)
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    if invalid_kind == "missing_model":
        monkeypatch.delenv("OPENROUTER_ATTACKER_MODEL", raising=False)
    else:
        monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "test-attacker")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "test-defender")
    constructed: list[object] = []
    monkeypatch.setattr(cli, "construct_live_clients", lambda value: constructed.append(value))

    with pytest.raises(SystemExit, match="2"):
        cli.main(["run", "--live", "--pilot", "--confirm-paid"])

    capsys.readouterr()
    assert constructed == []


@pytest.mark.parametrize("stamp_kind", ["stale", "partial", "failed"])
def test_live_rejects_invalid_stamp_before_client_construction(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
    stamp_kind: str,
) -> None:
    from chimera import cli

    digest = config_digest(frozen_config)
    verification_root = tmp_path / "verification"
    payload = _stamp_payload(cli, digest)
    if stamp_kind == "stale":
        payload["configuration_digest"] = "0" * 64
        _write_stamp(cli, verification_root, payload)
    elif stamp_kind == "partial":
        payload = _stamp_payload(cli, digest, check_count=len(cli.REQUIRED_CHECKS) - 1)
        _write_stamp(cli, verification_root, payload)
    else:
        payload = _stamp_payload(cli, digest, success=False)
        _write_stamp(cli, verification_root, payload)
    monkeypatch.setattr(cli, "VERIFICATION_ROOT", verification_root)
    monkeypatch.setattr(cli, "load_config", lambda path: frozen_config)
    monkeypatch.setattr(cli, "current_code_revision", lambda: None)
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "test-attacker")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "test-defender")
    constructed: list[object] = []
    monkeypatch.setattr(cli, "construct_live_clients", lambda value: constructed.append(value))

    with pytest.raises(SystemExit, match="2"):
        cli.main(["run", "--live", "--pilot", "--confirm-paid"])

    capsys.readouterr()
    assert constructed == []


@pytest.mark.parametrize("unsafe_kind", ["malformed", "oversized", "symlink", "revision"])
def test_verification_stamp_rejects_unsafe_or_mismatched_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    from chimera import cli

    digest = "a" * 64
    verification_root = tmp_path / "verification"
    verification_root.mkdir()
    stamp = verification_root / f"{digest}.json"
    if unsafe_kind == "malformed":
        stamp.write_text('{"success":true,"success":true}', encoding="utf-8")
    elif unsafe_kind == "oversized":
        stamp.write_bytes(b" " * (cli.MAX_STAMP_BYTES + 1))
    elif unsafe_kind == "symlink":
        target = tmp_path / "target.json"
        target.write_text(json.dumps(_stamp_payload(cli, digest)), encoding="utf-8")
        stamp.symlink_to(target)
    else:
        payload = _stamp_payload(cli, digest)
        payload["code_revision"] = "1" * 40
        stamp.write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setattr(cli, "current_code_revision", lambda: "2" * 40)
    monkeypatch.setattr(cli, "VERIFICATION_ROOT", verification_root)

    with pytest.raises(ValueError, match="verification stamp"):
        cli.require_local_verification_stamp(digest)


@pytest.mark.parametrize(
    ("field", "value"),
    [("schema_version", True), ("exit_code", False)],
)
def test_verification_stamp_rejects_boolean_integer_fields(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
    field: str,
    value: bool,
) -> None:
    from chimera import cli

    digest = config_digest(frozen_config)
    verification_root = tmp_path / "verification"
    monkeypatch.setattr(cli, "VERIFICATION_ROOT", verification_root)
    monkeypatch.setattr(cli, "current_code_revision", lambda: None)
    payload = _stamp_payload(cli, digest)
    if field == "schema_version":
        payload[field] = value
    else:
        payload["commands"][0][field] = value
    _write_stamp(cli, verification_root, payload)

    with pytest.raises(ValueError, match="verification stamp"):
        cli.require_local_verification_stamp(digest, config=frozen_config)


def test_verification_stamp_requires_revision_when_repository_has_one(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    digest = config_digest(frozen_config)
    verification_root = tmp_path / "verification"
    monkeypatch.setattr(cli, "VERIFICATION_ROOT", verification_root)
    monkeypatch.setattr(cli, "current_code_revision", lambda: "a" * 40)
    _write_stamp(cli, verification_root, _stamp_payload(cli, digest, code_revision=None))

    with pytest.raises(ValueError, match="verification stamp"):
        cli.require_local_verification_stamp(digest, config=frozen_config)


def test_source_tree_mutation_invalidates_verification_stamp(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    repository = tmp_path / "repo"
    source = repository / "chimera" / "control.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n", encoding="utf-8")
    (repository / "range").mkdir()
    (repository / "prompts").mkdir()
    (repository / "tests").mkdir()
    (repository / "configs").mkdir()
    (repository / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    verification_root = repository / "artifacts" / "runs" / "verification"
    digest = config_digest(frozen_config)
    monkeypatch.setattr(cli, "REPO_ROOT", repository)
    monkeypatch.setattr(cli, "VERIFICATION_ROOT", verification_root)
    monkeypatch.setattr(cli, "current_code_revision", lambda: None)
    payload = _stamp_payload(cli, digest)
    _write_stamp(cli, verification_root, payload)

    source.write_text("VALUE = 2\n", encoding="utf-8")

    with pytest.raises(ValueError, match="verification stamp"):
        cli.require_local_verification_stamp(digest, config=frozen_config)


def test_changed_model_id_invalidates_verification_stamp(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    digest = config_digest(frozen_config)
    verification_root = tmp_path / "verification"
    monkeypatch.setattr(cli, "VERIFICATION_ROOT", verification_root)
    monkeypatch.setattr(cli, "current_code_revision", lambda: None)
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "model-at-check-time")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")
    _write_stamp(cli, verification_root, _stamp_payload(cli, digest))
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "changed-model")

    with pytest.raises(ValueError, match="verification stamp"):
        cli.require_local_verification_stamp(digest, config=frozen_config)


def test_live_missing_shared_api_key_constructs_no_provider_client_or_runtime(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    monkeypatch.setattr(cli, "load_config", lambda path: frozen_config)
    monkeypatch.setattr(cli, "PILOT_RUN_ROOT", tmp_path / "missing-key")
    monkeypatch.setattr(cli, "require_local_verification_stamp", lambda *args, **kwargs: {})
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    constructions: list[str] = []
    runtime_calls: list[str] = []
    monkeypatch.setattr(
        cli,
        "OpenRouterClient",
        lambda **kwargs: constructions.append("openrouter"),
    )

    async def run_runtime(**kwargs):
        runtime_calls.append("run")

    monkeypatch.setattr(
        cli,
        "_run_live_episode_with_clients",
        run_runtime,
        raising=False,
    )

    with pytest.raises(SystemExit, match="2"):
        cli.main(["run", "--live", "--pilot", "--confirm-paid"])

    capsys.readouterr()
    assert constructions == []
    assert runtime_calls == []
    records = cli.Manifest(cli.PILOT_RUN_ROOT / "manifest.jsonl").records()
    assert [record["status"] for record in records] == [
        "starting",
        "infrastructure_failure",
    ]


def test_live_clients_receive_frozen_routing_and_price_controls(
    monkeypatch: pytest.MonkeyPatch,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    constructions: list[dict[str, object]] = []

    def openrouter(**kwargs):
        constructions.append(kwargs)
        return object()

    monkeypatch.setattr(cli, "OpenRouterClient", openrouter)
    monkeypatch.setenv("OPENROUTER_API_KEY", "shared-key")

    cli.construct_live_clients(frozen_config)

    assert constructions == [
        {
            "api_key": "shared-key",
            "provider_slug": "verified-attacker",
            "expected_provider_name": "Verified Attacker",
            "expected_endpoint_model": "provider/attacker-v1",
            "max_prompt_price": Decimal("1.0"),
            "max_completion_price": Decimal("1.0"),
        },
        {
            "api_key": "shared-key",
            "provider_slug": "verified-defender",
            "expected_provider_name": "Verified Defender",
            "expected_endpoint_model": "provider/defender-v1",
            "max_prompt_price": Decimal("1.0"),
            "max_completion_price": Decimal("1.0"),
        },
    ]


def test_live_all_gates_precede_construction_and_execution(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    order: list[str] = []
    original_validation = ExperimentConfig.validate_for_pilot_run

    def validate(config: ExperimentConfig) -> None:
        order.append("validate")
        original_validation(config)

    class Client:
        def __init__(self, role: str) -> None:
            self.role = role

        async def aclose(self) -> None:
            order.append(f"close_{self.role}")

    clients = (Client("attacker"), Client("defender"))
    original_append = cli.Manifest.append

    def append(manifest, record):
        if record["status"] == "starting":
            order.append("claim")
        return original_append(manifest, record)

    monkeypatch.setattr(ExperimentConfig, "validate_for_pilot_run", validate)
    monkeypatch.setattr(cli, "load_config", lambda path: frozen_config)
    monkeypatch.setattr(cli, "PILOT_RUN_ROOT", tmp_path / "pilot")
    monkeypatch.setattr(cli, "LIVE_RANGE_LEASE_PATH", tmp_path / ".range.lock", raising=False)
    monkeypatch.setattr(cli.Manifest, "append", append)

    class Lease:
        def __init__(self, path: Path) -> None:
            assert path == cli.LIVE_RANGE_LEASE_PATH

        def __enter__(self):
            order.append("lease")
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            order.append("release")

    monkeypatch.setattr(cli, "LiveRangeLease", Lease, raising=False)
    monkeypatch.setattr(
        cli,
        "require_local_verification_stamp",
        lambda digest, config=None: order.append("stamp") or {},
    )
    monkeypatch.setattr(
        cli,
        "_construct_live_ledgers",
        lambda config: order.append("budgets") or (object(), object()),
        raising=False,
    )
    monkeypatch.setattr(
        cli,
        "_ensure_live_range",
        lambda: order.append("range"),
        raising=False,
    )
    monkeypatch.setattr(
        cli,
        "construct_live_clients",
        lambda config: order.append("clients") or clients,
        raising=False,
    )

    async def run_runtime(**kwargs):
        order.append("runtime")
        return {
            "model_mode": "live",
            "execution_started": True,
            "provider_requests": 0,
        }

    monkeypatch.setattr(
        cli, "_run_live_episode_with_clients", run_runtime, raising=False
    )
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")
    monkeypatch.setenv("OPENROUTER_API_KEY", "shared-key")

    exit_code, metadata = _invoke(
        ["run", "--live", "--pilot", "--confirm-paid"], capsys
    )

    assert exit_code == 0
    assert metadata["execution_started"] is True
    assert order == [
        "validate",
        "stamp",
        "claim",
        "lease",
        "budgets",
        "range",
        "clients",
        "runtime",
        "close_attacker",
        "close_defender",
        "release",
    ]


def test_measured_claim_precedes_provider_and_range_client_construction_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    monkeypatch.setattr(cli, "_ensure_live_range", lambda: None)

    item = build_schedule(frozen_config)[0]
    order: list[str] = []
    original_append = cli.Manifest.append

    def append(manifest, record):
        if record["status"] == "starting":
            order.append("claim")
        return original_append(manifest, record)

    class Client:
        def __init__(self, role: str) -> None:
            self.role = role

        async def aclose(self) -> None:
            order.append(f"close_{self.role}")

    def construct_clients(config):
        order.append("providers")
        return Client("attacker"), Client("defender")

    def fail_range_client(base_url):
        order.append("range")
        raise RuntimeError("range client construction failed")

    class Lease:
        def __init__(self, path: Path) -> None:
            pass

        def __enter__(self):
            order.append("lease")
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            order.append("release")

    original_finalize = cli.Manifest.finalize_infrastructure_failure

    def finalize(manifest, episode_id):
        order.append("finalize")
        return original_finalize(manifest, episode_id)

    monkeypatch.setattr(cli, "MEASURED_RUN_ROOT", tmp_path / "measured", raising=False)
    monkeypatch.setattr(cli, "LIVE_RANGE_LEASE_PATH", tmp_path / ".range.lock", raising=False)
    monkeypatch.setattr(cli.Manifest, "append", append)
    monkeypatch.setattr(cli.Manifest, "finalize_infrastructure_failure", finalize)
    monkeypatch.setattr(cli, "LiveRangeLease", Lease, raising=False)
    monkeypatch.setattr(cli, "construct_live_clients", construct_clients)
    monkeypatch.setattr(cli, "HttpRangeClient", fail_range_client)

    with pytest.raises(RuntimeError, match="range client construction failed"):
        cli.run_live_episode(
            config=frozen_config,
            condition=item.condition,
            instruction=item.instruction,
            horizon_seconds=300.0,
            schedule_item=item,
            run_kind="measured",
        )

    assert order == [
        "claim",
        "lease",
        "providers",
        "range",
        "close_attacker",
        "close_defender",
        "finalize",
        "release",
    ]
    records = cli.Manifest(cli.MEASURED_RUN_ROOT / "manifest.jsonl").records()
    assert [record["status"] for record in records] == [
        "starting",
        "infrastructure_failure",
    ]
    assert records[-1]["termination_reason"] == "infrastructure_failure"


def test_measured_execution_rejects_model_drift_before_claim_or_clients(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    item = build_schedule(frozen_config)[0]
    constructions: list[str] = []
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "changed-attacker-model")
    monkeypatch.setattr(cli, "MEASURED_RUN_ROOT", tmp_path / "measured", raising=False)
    monkeypatch.setattr(
        cli,
        "construct_live_clients",
        lambda config: constructions.append("clients"),
    )

    with pytest.raises(ValueError, match="metadata|provenance"):
        cli.run_live_episode(
            config=frozen_config,
            condition=item.condition,
            instruction=item.instruction,
            horizon_seconds=300.0,
            schedule_item=item,
            run_kind="measured",
        )

    assert constructions == []
    assert not (tmp_path / "measured" / "manifest.jsonl").exists()


@pytest.mark.parametrize("drift", ["model", "source"])
def test_live_revalidates_claimed_provenance_after_acquiring_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
    drift: str,
) -> None:
    from chimera import cli

    item = build_schedule(frozen_config)[0]
    order: list[str] = []
    original_append = cli.Manifest.append
    original_finalize = cli.Manifest.finalize_infrastructure_failure

    def append(manifest, record):
        if record["status"] == "starting":
            order.append("claim")
        return original_append(manifest, record)

    def finalize(manifest, episode_id):
        order.append("finalize")
        return original_finalize(manifest, episode_id)

    class Lease:
        def __init__(self, path: Path) -> None:
            pass

        def __enter__(self):
            order.append("lease")
            if drift == "model":
                monkeypatch.setenv(
                    "OPENROUTER_ATTACKER_MODEL", "queued-model-drift"
                )
            else:
                monkeypatch.setattr(
                    cli,
                    "current_source_tree_digest",
                    lambda: "f" * 64,
                )
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            order.append("release")

    monkeypatch.setattr(cli, "MEASURED_RUN_ROOT", tmp_path / "measured")
    monkeypatch.setattr(cli.Manifest, "append", append)
    monkeypatch.setattr(cli.Manifest, "finalize_infrastructure_failure", finalize)
    monkeypatch.setattr(cli, "LiveRangeLease", Lease)
    monkeypatch.setattr(
        cli,
        "construct_live_clients",
        lambda config: order.append("clients") or (_ for _ in ()).throw(
            AssertionError("clients constructed after queued provenance drift")
        ),
    )

    with pytest.raises(ValueError, match="provenance"):
        cli.run_live_episode(
            config=frozen_config,
            condition=item.condition,
            instruction=item.instruction,
            horizon_seconds=300.0,
            schedule_item=item,
            run_kind="measured",
        )

    assert order == ["claim", "lease", "finalize", "release"]


def test_measured_output_root_is_typed_and_distinct_from_legacy_live_trace() -> None:
    from chimera import cli

    assert cli.MEASURED_RUN_ROOT == cli.RUNS_ROOT / "measured"
    assert cli.MEASURED_RUN_ROOT != cli.RUNS_ROOT / "live"


def test_mock_output_root_is_typed_and_distinct_from_legacy_mock_trace() -> None:
    from chimera import cli

    assert cli.MOCK_RUN_ROOT == cli.RUNS_ROOT / "typed" / "mock"
    assert cli.MOCK_RUN_ROOT != cli.RUNS_ROOT / "mock"
    args = cli._parser().parse_args(["summarize"])
    assert args.runs == "artifacts/runs/typed/mock"


def test_live_uses_frozen_configuration_horizon_when_not_overridden(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    observed: dict[str, object] = {}
    monkeypatch.setattr(cli, "load_config", lambda path: frozen_config)
    monkeypatch.setattr(cli, "require_local_verification_stamp", lambda *args, **kwargs: {})
    monkeypatch.setattr(cli, "construct_live_clients", lambda config: (object(), object()))
    monkeypatch.setattr(cli, "_close_live_clients", lambda clients: None)

    def run_live_episode(**kwargs):
        observed.update(kwargs)
        return {"model_mode": "live", "execution_started": True}

    monkeypatch.setattr(cli, "run_live_episode", run_live_episode)
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    exit_code, _ = _invoke(
        ["run", "--live", "--pilot", "--confirm-paid"], capsys
    )

    assert exit_code == 0
    assert observed["horizon_seconds"] == float(frozen_config.horizon_seconds)


def test_live_rejects_horizon_that_differs_from_frozen_configuration(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    constructed: list[object] = []
    monkeypatch.setattr(cli, "load_config", lambda path: frozen_config)
    monkeypatch.setattr(
        cli, "construct_live_clients", lambda config: constructed.append(config)
    )
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    with pytest.raises(SystemExit, match="2"):
        cli.main(
            [
                "run",
                "--live",
                "--pilot",
                "--confirm-paid",
                "--horizon-seconds",
                "1",
            ]
        )

    assert "frozen configuration horizon" in capsys.readouterr().err
    assert constructed == []


def test_live_execution_success_uses_and_closes_clients_on_the_creation_loop(
    monkeypatch: pytest.MonkeyPatch,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    monkeypatch.setattr(cli, "_ensure_live_range", lambda: None)

    class Client:
        def __init__(self) -> None:
            self.loop = asyncio.get_running_loop()
            self.closed = False

        async def aclose(self) -> None:
            assert asyncio.get_running_loop() is self.loop
            self.closed = True

    clients: tuple[Client, Client] | None = None

    def construct(config):
        nonlocal clients
        clients = (Client(), Client())
        return clients

    async def run_runtime(**kwargs):
        assert clients is not None
        assert all(client.loop is asyncio.get_running_loop() for client in clients)
        return {"execution_started": True}

    monkeypatch.setattr(cli, "construct_live_clients", construct)
    monkeypatch.setattr(cli, "_run_live_episode_with_clients", run_runtime, raising=False)
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    metadata = cli.run_live_episode(
        config=frozen_config,
        condition="A",
        instruction="U",
        horizon_seconds=300.0,
        schedule_item=None,
        run_kind="pilot",
    )

    assert metadata["execution_started"] is True
    assert clients is not None and all(client.closed for client in clients)


def test_live_execution_failure_closes_clients_on_the_creation_loop(
    monkeypatch: pytest.MonkeyPatch,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    monkeypatch.setattr(cli, "_ensure_live_range", lambda: None)

    class Client:
        def __init__(self) -> None:
            self.loop = asyncio.get_running_loop()
            self.closed = False

        async def aclose(self) -> None:
            assert asyncio.get_running_loop() is self.loop
            self.closed = True

    clients: tuple[Client, Client] | None = None

    def construct(config):
        nonlocal clients
        clients = (Client(), Client())
        return clients

    async def fail_runtime(**kwargs):
        assert clients is not None
        assert all(client.loop is asyncio.get_running_loop() for client in clients)
        raise RuntimeError("live runner failed")

    monkeypatch.setattr(cli, "construct_live_clients", construct)
    monkeypatch.setattr(cli, "_run_live_episode_with_clients", fail_runtime, raising=False)
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    with pytest.raises(RuntimeError, match="live runner failed"):
        cli.run_live_episode(
            config=frozen_config,
            condition="A",
            instruction="U",
            horizon_seconds=300.0,
            schedule_item=None,
            run_kind="pilot",
        )

    assert clients is not None and all(client.closed for client in clients)


def test_live_episode_assembles_reset_backed_runtime_without_provider_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli
    from chimera.canaries import CanaryRegistry, value_digest
    from chimera.controllers import LLMDefenderController
    from chimera.range_manager import EpisodeFixtures
    from chimera.schemas import Route, TerminationReason

    monkeypatch.setattr(cli, "_ensure_live_range", lambda: None)

    class ProviderClient:
        def __init__(self, provider: str) -> None:
            self.provider = provider
            self.requests = 0

        async def complete(self, request):
            self.requests += 1
            raise AssertionError("provider request is forbidden in assembly test")

    class RangeClient:
        def __init__(self, base_url: str) -> None:
            assert base_url == "http://127.0.0.1:18080"
            self.closed = False

        async def request(self, route, operation, body):
            raise AssertionError("fake runner must not make range requests")

        async def aclose(self) -> None:
            self.closed = True

    class Actuator:
        def __init__(self, command_runner, *, route_probe) -> None:
            self.command_runner = command_runner
            self.route_probe = route_probe

    class Manager:
        def __init__(self, **kwargs) -> None:
            assert kwargs["runtime_dir"] == cli.REPO_ROOT / "range" / "runtime"
            self.kwargs = kwargs
            self.reset_calls: list[tuple[str, Route]] = []

        async def reset(
            self, episode_id: str, *, canary_route: Route, seed: int | None
        ):
            self.reset_calls.append((episode_id, canary_route, seed))
            registry = CanaryRegistry()
            canary = registry.issue(canary_route)
            return EpisodeFixtures(
                episode_id=episode_id,
                secret_digest=value_digest("secret"),
                canary_digest=canary.digest,
                canary_id=canary.canary_id,
                canary_route=canary_route,
                api_state_path=cli.REPO_ROOT
                / "range"
                / "runtime"
                / "api"
                / "route.json",
                internal_state_path=cli.REPO_ROOT
                / "range"
                / "runtime"
                / "internal"
                / "route.json",
                route_tokens=MappingProxyType(
                    {Route.API: "api-token", Route.INTERNAL: "internal-token"}
                ),
                safe_value="safe",
                canaries=registry,
            )

    observed: dict[str, object] = {}

    class Runner:
        def __init__(self, *, output_dir: Path, runtime_factory, lifecycle_observer) -> None:
            observed["output_dir"] = output_dir
            observed["runtime_factory"] = runtime_factory
            self.runtime_factory = runtime_factory
            self.lifecycle_observer = lifecycle_observer

        async def run(self, spec):
            self.lifecycle_observer(
                {"status": "starting", "episode_id": spec.episode_id}
            )
            observed["spec"] = spec
            runtime = await self.runtime_factory(spec)
            self.lifecycle_observer(
                {"status": "running", "episode_id": spec.episode_id}
            )
            observed["runtime"] = runtime
            result = SimpleNamespace(
                episode_id=spec.episode_id,
                termination_reason=TerminationReason.ATTACKER_CALL_CAP,
            )
            self.lifecycle_observer(
                {
                    "status": "terminal",
                    "episode_id": spec.episode_id,
                    "termination_reason": result.termination_reason.value,
                }
            )
            return result

    range_client = RangeClient("http://127.0.0.1:18080")
    managers: list[Manager] = []
    monkeypatch.setattr(
        cli,
        "MEASURED_RUN_ROOT",
        tmp_path / "artifacts" / "runs" / "measured",
        raising=False,
    )
    monkeypatch.setattr(cli, "HttpRangeClient", lambda base_url: range_client, raising=False)
    monkeypatch.setattr(cli, "SubprocessDockerCommandRunner", lambda: object(), raising=False)
    monkeypatch.setattr(cli, "DockerActuator", Actuator, raising=False)
    monkeypatch.setattr(
        cli,
        "RangeManager",
        lambda **kwargs: managers.append(Manager(**kwargs)) or managers[-1],
        raising=False,
    )
    monkeypatch.setattr(cli, "EpisodeRunner", Runner)
    attacker_client = ProviderClient("openrouter")
    defender_client = ProviderClient("openrouter")
    prompt_reads: list[str] = []

    def read_prompt(filename: str) -> str:
        prompt_reads.append(filename)
        return f"captured:{filename}"

    def construct_clients(config):
        assert prompt_reads == [
            f"attacker_{schedule_item.instruction.lower()}.txt",
            "defender.txt",
        ]
        monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "changed-after-capture")
        monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "changed-after-capture")
        monkeypatch.setattr(
            cli,
            "_read_live_prompt",
            lambda filename: (_ for _ in ()).throw(
                AssertionError("live prompt was reread after capture")
            ),
        )
        return attacker_client, defender_client

    monkeypatch.setattr(cli, "_read_live_prompt", read_prompt)
    monkeypatch.setattr(cli, "construct_live_clients", construct_clients)
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    schedule_item = next(
        item for item in build_schedule(frozen_config) if item.condition == "D"
    )
    metadata = cli.run_live_episode(
        config=frozen_config,
        condition=schedule_item.condition,
        instruction=schedule_item.instruction,
        horizon_seconds=300.0,
        schedule_item=schedule_item,
        run_kind="measured",
    )

    assert metadata["execution_started"] is True
    assert observed["output_dir"] == cli.MEASURED_RUN_ROOT
    spec = observed["spec"]
    assert spec.synthetic is False
    assert spec.experiment_config == frozen_config
    assert spec.episode_id == schedule_item.episode_id
    assert spec.seed == schedule_item.seed
    assert spec.run_kind == "measured"
    runtime = observed["runtime"]
    assert runtime.range_manager is managers[0]
    assert runtime.actuator.command_runner is managers[0].kwargs["command_runner"]
    assert runtime.broker.transport is range_client
    assert runtime.attacker_policy.client is attacker_client
    assert runtime.attacker_policy.model == "attacker-model"
    assert runtime.attacker_policy.system_prompt == (
        f"captured:attacker_{schedule_item.instruction.lower()}.txt"
    )
    assert runtime.attacker_policy.ledger.max_calls == frozen_config.models.attacker.max_calls
    assert isinstance(runtime.controller, LLMDefenderController)
    assert runtime.controller._client is defender_client
    assert runtime.controller._model == "defender-model"
    assert runtime.controller._system_prompt == "captured:defender.txt"
    assert runtime.controller._ledger.max_calls == frozen_config.models.defender.max_calls
    assert runtime.ordinary_workload is not None
    assert runtime.authorized_workload is not None
    assert managers[0].reset_calls == [
        (
            spec.episode_id,
            frozen_config.static_policy.initial_canary_route,
            spec.seed,
        )
    ]
    assert range_client.closed is True
    assert attacker_client.requests == defender_client.requests == 0
    records = cli.Manifest(
        cli.MEASURED_RUN_ROOT / "manifest.jsonl", expected_run_kind="measured"
    ).records()
    assert [record["status"] for record in records] == [
        "starting",
        "running",
        "terminal",
    ]
    assert all(record["run_kind"] == "measured" for record in records)
    assert records[0]["seed"] == schedule_item.seed
    assert records[0]["block"] == schedule_item.block
    assert metadata["run_kind"] == "measured"
    assert records[-1]["termination_reason"] == "attacker_call_cap"


def test_live_episode_closes_range_transport_when_runner_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    monkeypatch.setattr(cli, "_ensure_live_range", lambda: None)

    class RangeClient:
        closed = False

        async def aclose(self) -> None:
            self.closed = True

    class Runner:
        def __init__(self, *, lifecycle_observer, **kwargs) -> None:
            self.lifecycle_observer = lifecycle_observer

        async def run(self, spec):
            self.lifecycle_observer(
                {"status": "starting", "episode_id": spec.episode_id}
            )
            raise RuntimeError("runner failed")

    range_client = RangeClient()
    monkeypatch.setattr(cli, "PILOT_RUN_ROOT", tmp_path / "pilot", raising=False)
    monkeypatch.setattr(cli, "HttpRangeClient", lambda base_url: range_client, raising=False)
    monkeypatch.setattr(cli, "SubprocessDockerCommandRunner", lambda: object(), raising=False)
    monkeypatch.setattr(cli, "DockerActuator", lambda *args, **kwargs: object(), raising=False)
    monkeypatch.setattr(cli, "RangeManager", lambda **kwargs: object(), raising=False)
    monkeypatch.setattr(cli, "EpisodeRunner", Runner)
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")
    clients = (
        SimpleNamespace(provider="openrouter"),
        SimpleNamespace(provider="openrouter"),
    )
    monkeypatch.setattr(cli, "construct_live_clients", lambda config: clients)

    with pytest.raises(RuntimeError, match="runner failed"):
        cli.run_live_episode(
            config=frozen_config,
            condition="A",
            instruction="U",
            horizon_seconds=300.0,
            schedule_item=None,
            run_kind="pilot",
        )

    assert range_client.closed is True
    records = cli.Manifest(cli.PILOT_RUN_ROOT / "manifest.jsonl").records()
    assert [record["status"] for record in records] == [
        "starting",
        "infrastructure_failure",
    ]
    assert records[-1]["termination_reason"] == "infrastructure_failure"


def test_live_episode_closes_range_transport_when_assembly_fails(
    monkeypatch: pytest.MonkeyPatch,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    monkeypatch.setattr(cli, "_ensure_live_range", lambda: None)

    class RangeClient:
        closed = False

        async def aclose(self) -> None:
            self.closed = True

    range_client = RangeClient()
    monkeypatch.setattr(cli, "HttpRangeClient", lambda base_url: range_client)
    monkeypatch.setattr(cli, "SubprocessDockerCommandRunner", lambda: object())
    monkeypatch.setattr(cli, "DockerActuator", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        cli,
        "RangeManager",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("assembly failed")),
    )
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")
    clients = (
        SimpleNamespace(provider="openrouter"),
        SimpleNamespace(provider="openrouter"),
    )
    monkeypatch.setattr(cli, "construct_live_clients", lambda config: clients)

    with pytest.raises(RuntimeError, match="assembly failed"):
        cli.run_live_episode(
            config=frozen_config,
            condition="A",
            instruction="U",
            horizon_seconds=300.0,
            schedule_item=None,
            run_kind="pilot",
        )

    assert range_client.closed is True


def test_live_reset_failure_records_starting_then_infrastructure_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli
    from chimera.schemas import TerminationReason

    monkeypatch.setattr(cli, "_ensure_live_range", lambda: None)

    class RangeClient:
        async def aclose(self) -> None:
            pass

    class Manager:
        async def reset(self, episode_id, *, canary_route, seed):
            raise RuntimeError("reset failed")

    class Runner:
        def __init__(self, *, output_dir, runtime_factory, lifecycle_observer) -> None:
            self.runtime_factory = runtime_factory
            self.lifecycle_observer = lifecycle_observer

        async def run(self, spec):
            self.lifecycle_observer(
                {"status": "starting", "episode_id": spec.episode_id}
            )
            try:
                return await self.runtime_factory(spec)
            except RuntimeError:
                self.lifecycle_observer(
                    {
                        "status": "infrastructure_failure",
                        "episode_id": spec.episode_id,
                    }
                )
                return SimpleNamespace(
                    episode_id=spec.episode_id,
                    termination_reason=TerminationReason.INFRASTRUCTURE_FAILURE,
                )

    clients = (
        SimpleNamespace(provider="openrouter"),
        SimpleNamespace(provider="openrouter"),
    )
    monkeypatch.setattr(cli, "PILOT_RUN_ROOT", tmp_path / "pilot")
    monkeypatch.setattr(cli, "construct_live_clients", lambda config: clients)
    monkeypatch.setattr(cli, "HttpRangeClient", lambda base_url: RangeClient())
    monkeypatch.setattr(cli, "SubprocessDockerCommandRunner", lambda: object())
    monkeypatch.setattr(cli, "DockerActuator", lambda *args, **kwargs: object())
    monkeypatch.setattr(cli, "RangeManager", lambda **kwargs: Manager())
    monkeypatch.setattr(cli, "EpisodeRunner", Runner)
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    metadata = cli.run_live_episode(
        config=frozen_config,
        condition="A",
        instruction="U",
        horizon_seconds=300.0,
        schedule_item=None,
        run_kind="pilot",
    )

    assert metadata["execution_started"] is False
    assert metadata["termination_reason"] == "infrastructure_failure"
    records = cli.Manifest(cli.PILOT_RUN_ROOT / "manifest.jsonl").records()
    assert [record["status"] for record in records] == [
        "starting",
        "infrastructure_failure",
    ]
    assert records[-1]["termination_reason"] == "infrastructure_failure"


def test_live_failure_after_runtime_verification_records_terminal_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    monkeypatch.setattr(cli, "_ensure_live_range", lambda: None)

    class RangeClient:
        async def aclose(self) -> None:
            pass

    class RuntimeFactory:
        def __init__(self, **kwargs) -> None:
            pass

        async def __call__(self, spec):
            return object()

    class Runner:
        def __init__(self, *, output_dir, runtime_factory, lifecycle_observer) -> None:
            self.runtime_factory = runtime_factory
            self.lifecycle_observer = lifecycle_observer

        async def run(self, spec):
            self.lifecycle_observer(
                {"status": "starting", "episode_id": spec.episode_id}
            )
            await self.runtime_factory(spec)
            self.lifecycle_observer(
                {"status": "running", "episode_id": spec.episode_id}
            )
            raise RuntimeError("post-start failure")

    clients = (
        SimpleNamespace(provider="openrouter"),
        SimpleNamespace(provider="openrouter"),
    )
    monkeypatch.setattr(cli, "PILOT_RUN_ROOT", tmp_path / "pilot")
    monkeypatch.setattr(cli, "construct_live_clients", lambda config: clients)
    monkeypatch.setattr(cli, "HttpRangeClient", lambda base_url: RangeClient())
    monkeypatch.setattr(cli, "SubprocessDockerCommandRunner", lambda: object())
    monkeypatch.setattr(cli, "DockerActuator", lambda *args, **kwargs: object())
    monkeypatch.setattr(cli, "RangeManager", lambda **kwargs: object())
    monkeypatch.setattr(cli, "RangeEpisodeRuntimeFactory", RuntimeFactory)
    monkeypatch.setattr(cli, "EpisodeRunner", Runner)
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    with pytest.raises(RuntimeError, match="post-start failure"):
        cli.run_live_episode(
            config=frozen_config,
            condition="A",
            instruction="U",
            horizon_seconds=300.0,
            schedule_item=None,
            run_kind="pilot",
        )

    records = cli.Manifest(cli.PILOT_RUN_ROOT / "manifest.jsonl").records()
    assert [record["status"] for record in records] == [
        "starting",
        "running",
        "terminal",
    ]
    assert records[-1]["termination_reason"] == "infrastructure_failure"


def test_live_running_manifest_failure_prevents_role_launch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    monkeypatch.setattr(cli, "_ensure_live_range", lambda: None)

    class RangeClient:
        async def aclose(self) -> None:
            pass

    class RuntimeFactory:
        def __init__(self, **kwargs) -> None:
            pass

        async def __call__(self, spec):
            return object()

    role_launches: list[str] = []

    class Runner:
        def __init__(self, *, lifecycle_observer, **kwargs) -> None:
            self.lifecycle_observer = lifecycle_observer

        async def run(self, spec):
            self.lifecycle_observer(
                {"status": "starting", "episode_id": spec.episode_id}
            )
            self.lifecycle_observer(
                {"status": "running", "episode_id": spec.episode_id}
            )
            role_launches.append("launched")
            raise AssertionError("roles must not launch")

    original_append = cli.Manifest.append

    def append(manifest, record):
        if record["status"] == "running":
            raise RuntimeError("manifest failed")
        return original_append(manifest, record)

    clients = (
        SimpleNamespace(provider="openrouter"),
        SimpleNamespace(provider="openrouter"),
    )
    monkeypatch.setattr(cli, "PILOT_RUN_ROOT", tmp_path / "pilot")
    monkeypatch.setattr(cli, "construct_live_clients", lambda config: clients)
    monkeypatch.setattr(cli, "HttpRangeClient", lambda base_url: RangeClient())
    monkeypatch.setattr(cli, "SubprocessDockerCommandRunner", lambda: object())
    monkeypatch.setattr(cli, "DockerActuator", lambda *args, **kwargs: object())
    monkeypatch.setattr(cli, "RangeManager", lambda **kwargs: object())
    monkeypatch.setattr(cli, "RangeEpisodeRuntimeFactory", RuntimeFactory)
    monkeypatch.setattr(cli, "EpisodeRunner", Runner)
    monkeypatch.setattr(cli.Manifest, "append", append)
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    with pytest.raises(RuntimeError, match="manifest failed"):
        cli.run_live_episode(
            config=frozen_config,
            condition="A",
            instruction="U",
            horizon_seconds=300.0,
            schedule_item=None,
            run_kind="pilot",
        )

    assert role_launches == []
    records = cli.Manifest(cli.PILOT_RUN_ROOT / "manifest.jsonl").records()
    assert [record["status"] for record in records] == [
        "starting",
        "infrastructure_failure",
    ]


@pytest.mark.parametrize("provider", ["openrouter", "anthropic"])
def test_live_budget_uses_configured_per_million_rates(provider: str) -> None:
    from chimera import cli

    budget = SimpleNamespace(
        ceiling_usd=10,
        input_per_million_usd=2,
        output_per_million_usd=3,
    )
    ledger = cli._live_budget_ledger(provider=provider, budget=budget, max_calls=2)

    reservation = ledger.reserve(max_input_tokens=1_000, max_output_tokens=2_000)
    record = reservation.settle(1_000, 2_000)

    expected = (
        Decimal(1_000) * Decimal("2") + Decimal(2_000) * Decimal("3")
    ) / Decimal(1_000_000)
    assert ledger.input_rate == Decimal("2")
    assert ledger.output_rate == Decimal("3")
    assert record.actual_usd == expected


def test_live_budget_passes_shared_account_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chimera import cli

    captured: dict[str, object] = {}
    scope = object()
    authority = object()
    monkeypatch.setattr(
        cli,
        "BudgetLedger",
        lambda **kwargs: captured.update(kwargs) or object(),
    )

    cli._live_budget_ledger(
        provider="openrouter",
        budget=SimpleNamespace(
            ceiling_usd=0.2,
            input_per_million_usd=0.936,
            output_per_million_usd=3.168,
        ),
        max_calls=12,
        cumulative_authority=authority,
        cumulative_scope=scope,
    )

    assert captured["cumulative_authority"] is authority
    assert captured["cumulative_scope"] is scope


def test_construct_live_ledgers_binds_both_roles_to_configuration_authorization(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    budget_root = tmp_path / "provider-budget"
    monkeypatch.setattr(cli, "LIVE_BUDGET_ROOT", budget_root)

    attacker, defender = cli._construct_live_ledgers(frozen_config)

    assert attacker.provider == defender.provider == "openrouter"
    assert attacker.ceiling_usd == Decimal("0.2")
    assert defender.ceiling_usd == Decimal("0.05")
    state = json.loads(
        (budget_root / "provider-budget.json").read_text(encoding="utf-8")
    )
    account = state["accounts"]["openrouter"]
    authorization = account["authorizations"][config_digest(frozen_config)]
    assert set(authorization["profiles"]) == {"attacker", "defender"}
    assert Decimal(account["project_ceiling_usd"]) == Decimal("20")
    assert Decimal(authorization["ceiling_usd"]) == Decimal("3.00")


def test_checks_writes_complete_stamp_only_after_all_commands_succeed(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
) -> None:
    from chimera import cli

    verification_root = tmp_path / "verification"
    monkeypatch.setattr(cli, "VERIFICATION_ROOT", verification_root)
    monkeypatch.setattr(cli, "current_code_revision", lambda: "a" * 40)
    seen: list[list[str]] = []

    def succeed(command: list[str]):
        seen.append(command)
        return 0

    monkeypatch.setattr(cli, "run_command", succeed)

    exit_code, metadata = _invoke(["checks"], capsys)

    assert exit_code == 0
    assert seen == [list(command) for _, command in cli.REQUIRED_CHECKS]
    stamp = verification_root / f"{metadata['configuration_digest']}.json"
    persisted = json.loads(stamp.read_text(encoding="utf-8"))
    assert persisted["success"] is True
    assert len(persisted["commands"]) == len(cli.REQUIRED_CHECKS)


def test_checks_hold_live_range_lease_for_complete_sequence(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
) -> None:
    from chimera import cli

    order: list[str] = []

    class Lease:
        def __init__(self, path: Path) -> None:
            assert path == cli.LIVE_RANGE_LEASE_PATH

        def __enter__(self):
            order.append("lease")
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            order.append("release")

    monkeypatch.setattr(cli, "VERIFICATION_ROOT", tmp_path / "verification")
    monkeypatch.setattr(cli, "current_code_revision", lambda: "a" * 40)
    monkeypatch.setattr(cli, "LiveRangeLease", Lease)
    monkeypatch.setattr(
        cli,
        "run_command",
        lambda command: order.append("check") or 0,
    )

    exit_code, _ = _invoke(["checks"], capsys)

    assert exit_code == 0
    assert order == [
        "lease",
        *("check" for _ in cli.REQUIRED_CHECKS),
        "release",
    ]


def test_checks_failure_does_not_write_a_success_stamp(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
) -> None:
    from chimera import cli

    verification_root = tmp_path / "verification"
    monkeypatch.setattr(cli, "VERIFICATION_ROOT", verification_root)
    monkeypatch.setattr(cli, "run_command", lambda command: 1)

    exit_code, metadata = _invoke(["checks"], capsys)

    assert exit_code == 1
    assert metadata["success"] is False
    assert not verification_root.exists()


def test_range_down_uses_fixed_compose_command_without_volumes(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    from chimera import cli

    commands: list[list[str]] = []
    monkeypatch.setattr(cli, "run_command", lambda command: commands.append(command) or 0)

    exit_code, _ = _invoke(["range", "down"], capsys)

    assert exit_code == 0
    assert commands == [["docker", "compose", "-f", "range/compose.yaml", "-p", "chimera", "down"]]
    assert "--volumes" not in commands[0]


def test_range_reset_recreates_fixed_compose_topology_without_deleting_volumes(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
) -> None:
    from chimera import cli

    commands: list[list[str]] = []
    monkeypatch.setattr(cli, "RANGE_RUNTIME_ROOT", tmp_path / "runtime")
    monkeypatch.setattr(cli, "run_command", lambda command: commands.append(command) or 0)

    exit_code, _ = _invoke(["range", "reset"], capsys)

    assert exit_code == 0
    assert commands == [
        ["docker", "compose", "-f", "range/compose.yaml", "-p", "chimera", "down"],
        [
            "docker",
            "compose",
            "-f",
            "range/compose.yaml",
            "-p",
            "chimera",
            "up",
            "--build",
            "--wait",
        ],
    ]
    assert all("--volumes" not in command for command in commands)


def test_schedule_rejects_candidate_but_writes_frozen_forty_rows(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    config_root = tmp_path / "configs"
    output_root = tmp_path / "schedules"
    config_root.mkdir()
    candidate = config_root / "candidate.yaml"
    candidate.write_text(
        Path("configs/experiment.yaml")
        .read_text(encoding="utf-8")
        .replace("status: frozen", "status: candidate", 1),
        encoding="utf-8",
    )
    frozen = config_root / "frozen.yaml"
    frozen.write_text(
        __import__("yaml").safe_dump(frozen_config.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "CONFIG_ROOT", config_root)
    monkeypatch.setattr(cli, "SCHEDULE_OUTPUT_ROOT", output_root)

    with pytest.raises(SystemExit, match="2"):
        cli.main(["schedule", "--config", str(candidate), "--output", str(output_root / "candidate.json")])
    capsys.readouterr()

    exit_code, metadata = _invoke(
        ["schedule", "--config", str(frozen), "--output", str(output_root / "frozen.json")],
        capsys,
    )

    assert exit_code == 0
    schedule = json.loads((output_root / "frozen.json").read_text(encoding="utf-8"))
    assert metadata["row_count"] == 40
    assert schedule["configuration_digest"] == config_digest(frozen_config)
    assert len(schedule["rows"]) == 40


def test_schedule_and_summary_reject_traversal_and_symlink_escape(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
) -> None:
    from chimera import cli

    config_root = tmp_path / "configs"
    output_root = tmp_path / "schedules"
    runs_root = tmp_path / "runs"
    outside = tmp_path / "outside"
    config_root.mkdir()
    output_root.mkdir()
    runs_root.mkdir()
    outside.mkdir()
    (runs_root / "link").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(cli, "CONFIG_ROOT", config_root)
    monkeypatch.setattr(cli, "SCHEDULE_OUTPUT_ROOT", output_root)
    monkeypatch.setattr(cli, "RUNS_ROOT", runs_root)

    for argv in (
        ["schedule", "--config", "../experiment.yaml", "--output", str(output_root / "x.json")],
        ["schedule", "--config", str(config_root / "x.yaml"), "--output", "../x.json"],
        ["summarize", "--runs", str(runs_root / "link")],
    ):
        with pytest.raises(SystemExit, match="2"):
            cli.main(argv)
        capsys.readouterr()


def test_mock_run_uses_episode_runner_and_writes_manifest_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from chimera import cli

    mock_root = tmp_path / "artifacts" / "runs" / "mock"
    monkeypatch.setattr(cli, "MOCK_RUN_ROOT", mock_root)

    metadata = cli.run_mock_episode(condition="E", instruction="W", horizon_seconds=0.03)

    episode_dir = Path(str(metadata["artifact_dir"]))
    assert metadata["model_mode"] == "mock"
    assert episode_dir.parent == mock_root
    assert json.loads((episode_dir / "metadata.json").read_text(encoding="utf-8"))["model_mode"] == "mock"
    records = [json.loads(line) for line in (mock_root / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [record["status"] for record in records] == ["starting", "running", "terminal"]
    assert (episode_dir / "terminal.jsonl").is_file()


@pytest.mark.parametrize("condition", ["B", "C"])
def test_mock_active_conditions_use_in_process_enforcement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    condition: str,
) -> None:
    from chimera import cli

    mock_root = tmp_path / "artifacts" / "runs" / "mock"
    monkeypatch.setattr(cli, "MOCK_RUN_ROOT", mock_root)

    metadata = cli.run_mock_episode(
        condition=condition,
        instruction="U",
        horizon_seconds=0.03,
    )

    assert metadata["termination_reason"] != "infrastructure_failure"


def test_mock_enforcement_records_valid_probe_evidence_and_availability_effect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from chimera import cli
    from chimera.evaluate import summarize_runs

    mock_root = tmp_path / "artifacts" / "runs" / "mock"
    monkeypatch.setattr(cli, "MOCK_RUN_ROOT", mock_root)

    cli.run_mock_episode(condition="B", instruction="U", horizon_seconds=0.13)
    summary = summarize_runs(mock_root)
    attempt = summary["attempts"][0]

    assert "invalid_actuation_evidence" not in attempt["evidence_issues"]
    assert attempt["availability_successes"] < attempt["availability_attempts"]


def test_mock_artifacts_record_canary_exposure_without_sensitive_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from chimera import cli
    from chimera.evaluate import summarize_runs

    mock_root = tmp_path / "artifacts" / "runs" / "mock"
    generated = iter(
        (
            "generated-secret-value",
            "generated-safe-value",
            "generated-api-token",
            "generated-internal-token",
            "generated-canary-value",
        )
    )
    monkeypatch.setattr(cli, "MOCK_RUN_ROOT", mock_root)
    monkeypatch.setattr(cli.secrets, "token_urlsafe", lambda length: next(generated))
    monkeypatch.setenv("OPENROUTER_API_KEY", "not-a-real-openrouter-key")

    cli.run_mock_episode(condition="A", instruction="U", horizon_seconds=0.03)
    summary = summarize_runs(mock_root)
    artifact_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in mock_root.rglob("*")
        if path.is_file()
    )

    assert summary["counts"]["canary_exposed"] == 1
    for sensitive in (
        "generated-secret-value",
        "generated-safe-value",
        "generated-api-token",
        "generated-internal-token",
        "generated-canary-value",
        "not-a-real-openrouter-key",
    ):
        assert sensitive not in artifact_text


def test_horizon_override_is_positive_and_bounded(capsys) -> None:
    from chimera import cli

    for value in ("0", "-1", "61", "nan"):
        with pytest.raises(SystemExit, match="2"):
            cli.main(["run", "--horizon-seconds", value])
        capsys.readouterr()


def _write_schedule_file(tmp_path: Path, frozen_config: ExperimentConfig):
    schedule_root = tmp_path / "schedules"
    schedule_root.mkdir(exist_ok=True)
    rows = build_schedule(frozen_config)
    schedule_path = schedule_root / "schedule.json"
    schedule_path.write_text(
        json.dumps(
            {
                "configuration_digest": config_digest(frozen_config),
                "rows": [asdict(row) for row in rows],
            }
        ),
        encoding="utf-8",
    )
    return schedule_root, schedule_path, rows


def test_measured_rerun_is_allowed_only_after_infrastructure_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    schedule_root, schedule_path, rows = _write_schedule_file(tmp_path, frozen_config)
    selected = rows[3]
    measured_root = tmp_path / "measured"
    manifest = cli.Manifest(measured_root / "manifest.jsonl", expected_run_kind="measured")
    base = {**asdict(selected), "run_kind": "measured"}
    manifest.append({**base, "status": "starting"})
    manifest.append({**base, "status": "running"})
    manifest.append({**base, "status": "terminal", "termination_reason": "secret_retrieved"})
    constructions: list[object] = []
    monkeypatch.setattr(cli, "SCHEDULE_OUTPUT_ROOT", schedule_root)
    monkeypatch.setattr(cli, "MEASURED_RUN_ROOT", measured_root)
    monkeypatch.setattr(cli, "load_config", lambda path: frozen_config)
    monkeypatch.setattr(cli, "require_local_verification_stamp", lambda *args, **kwargs: {})
    monkeypatch.setattr(cli, "construct_live_clients", lambda config: constructions.append(config))
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    with pytest.raises(SystemExit, match="2"):
        cli.main(
            [
                "run", "--live", "--confirm-paid",
                "--schedule", str(schedule_path),
                "--schedule-episode-id", selected.episode_id,
                "--rerun-of", selected.episode_id,
            ]
        )

    assert "infrastructure_failure" in capsys.readouterr().err
    assert constructions == []


def test_measured_rerun_after_infrastructure_failure_gets_linked_new_id(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    schedule_root, schedule_path, rows = _write_schedule_file(tmp_path, frozen_config)
    selected = rows[7]
    measured_root = tmp_path / "measured"
    manifest = cli.Manifest(measured_root / "manifest.jsonl", expected_run_kind="measured")
    base = {**asdict(selected), "run_kind": "measured"}
    manifest.append({**base, "status": "starting"})
    manifest.append(
        {**base, "status": "infrastructure_failure", "termination_reason": "infrastructure_failure"}
    )
    observed: dict[str, object] = {}
    monkeypatch.setattr(cli, "SCHEDULE_OUTPUT_ROOT", schedule_root)
    monkeypatch.setattr(cli, "MEASURED_RUN_ROOT", measured_root)
    monkeypatch.setattr(cli, "load_config", lambda path: frozen_config)
    monkeypatch.setattr(cli, "require_local_verification_stamp", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        cli,
        "run_live_episode",
        lambda **kwargs: observed.update(kwargs) or {"model_mode": "live", "run_kind": "measured"},
    )
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    exit_code, _ = _invoke(
        [
            "run", "--live", "--confirm-paid",
            "--schedule", str(schedule_path),
            "--schedule-episode-id", selected.episode_id,
            "--rerun-of", selected.episode_id,
        ],
        capsys,
    )

    assert exit_code == 0
    assert observed["schedule_item"] == selected
    assert observed["rerun_of"] == selected.episode_id
    assert observed["run_kind"] == "measured"

    # The claim itself records the linked ID and keeps the original attempt.
    first_rerun_id = cli._rerun_episode_id(selected, selected.episode_id)
    assert first_rerun_id == f"{selected.episode_id}-r2"
    claim = cli._claim_live_run(
        config=frozen_config,
        condition=selected.condition,
        instruction=selected.instruction,
        schedule_item=selected,
        run_kind="measured",
        rerun_of=selected.episode_id,
        rerun_episode_id=first_rerun_id,
    )
    records = claim.manifest.records()
    assert records[-1]["episode_id"] == first_rerun_id
    assert records[-1]["rerun_of"] == selected.episode_id
    assert records[-1]["status"] == "starting"
    assert [r["episode_id"] for r in records[:2]] == [selected.episode_id] * 2

    # A second rerun must chain from the failed first rerun, not the row.
    manifest.append(
        {
            **base,
            "episode_id": first_rerun_id,
            "rerun_of": selected.episode_id,
            "status": "infrastructure_failure",
            "termination_reason": "infrastructure_failure",
        }
    )
    with pytest.raises(ValueError, match="latest attempt"):
        cli._rerun_episode_id(selected, selected.episode_id)
    assert cli._rerun_episode_id(selected, first_rerun_id) == f"{selected.episode_id}-r3"


def test_rerun_flag_requires_measured_schedule_context(capsys) -> None:
    from chimera import cli

    with pytest.raises(SystemExit, match="2"):
        cli.main(["run", "--mock", "--rerun-of", "x"])
    assert "--rerun-of" in capsys.readouterr().err


def test_rerun_closes_an_abandoned_claim_when_no_run_holds_the_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli
    from chimera.live_lease import LiveRangeLease

    _, _, rows = _write_schedule_file(tmp_path, frozen_config)
    selected = rows[5]
    measured_root = tmp_path / "measured"
    manifest = cli.Manifest(measured_root / "manifest.jsonl", expected_run_kind="measured")
    base = {**asdict(selected), "run_kind": "measured"}
    manifest.append({**base, "status": "starting"})  # interrupted before execution
    lease_path = tmp_path / ".live-range.lock"
    monkeypatch.setattr(cli, "MEASURED_RUN_ROOT", measured_root)
    monkeypatch.setattr(cli, "LIVE_RANGE_LEASE_PATH", lease_path)

    with LiveRangeLease(lease_path):
        with pytest.raises(ValueError, match="lease"):
            cli._rerun_episode_id(selected, selected.episode_id)
    assert [r["status"] for r in manifest.records()] == ["starting"]

    assert cli._rerun_episode_id(selected, selected.episode_id) == f"{selected.episode_id}-r2"
    records = manifest.records()
    assert [r["status"] for r in records] == ["starting", "infrastructure_failure"]
    assert records[-1]["termination_reason"] == "infrastructure_failure"
    assert records[-1]["episode_id"] == selected.episode_id


def test_rerun_refuses_to_close_a_claim_that_has_terminal_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    _, _, rows = _write_schedule_file(tmp_path, frozen_config)
    selected = rows[6]
    measured_root = tmp_path / "measured"
    manifest = cli.Manifest(measured_root / "manifest.jsonl", expected_run_kind="measured")
    base = {**asdict(selected), "run_kind": "measured"}
    manifest.append({**base, "status": "starting"})
    manifest.append({**base, "status": "running"})
    (measured_root / selected.episode_id).mkdir()
    (measured_root / selected.episode_id / "terminal.jsonl").write_text("{}\n")
    monkeypatch.setattr(cli, "MEASURED_RUN_ROOT", measured_root)
    monkeypatch.setattr(cli, "LIVE_RANGE_LEASE_PATH", tmp_path / ".live-range.lock")

    with pytest.raises(ValueError, match="inspect manually"):
        cli._rerun_episode_id(selected, selected.episode_id)
    assert [r["status"] for r in manifest.records()] == ["starting", "running"]


# --- benign-only control runs (protocol section 5) ---


def test_benign_only_live_run_is_a_control_run_with_frozen_configuration(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    observed: dict[str, object] = {}
    monkeypatch.setattr(cli, "load_config", lambda path: frozen_config)
    monkeypatch.setattr(cli, "require_local_verification_stamp", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        cli,
        "run_live_episode",
        lambda **kwargs: observed.update(kwargs)
        or {"model_mode": "live", "run_kind": "control"},
    )
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    exit_code, _ = _invoke(
        ["run", "--live", "--confirm-paid", "--benign-only", "--condition", "D"],
        capsys,
    )

    assert exit_code == 0
    assert observed["run_kind"] == "control"
    assert observed["schedule_item"] is None
    assert observed["rerun_of"] is None
    assert observed["condition"] == "D"
    assert observed["instruction"] == "U"
    assert observed["horizon_seconds"] == float(frozen_config.horizon_seconds)


@pytest.mark.parametrize(
    "argv",
    [
        ["run", "--live", "--confirm-paid", "--benign-only"],
        ["run", "--live", "--confirm-paid", "--benign-only", "--pilot", "--condition", "B"],
        [
            "run", "--live", "--confirm-paid", "--benign-only", "--condition", "B",
            "--schedule", "artifacts/runs/schedules/main.json", "--schedule-episode-id", "x",
        ],
    ],
)
def test_benign_only_rejects_missing_condition_pilot_and_schedule_rows(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    frozen_config: ExperimentConfig,
    argv: list[str],
) -> None:
    from chimera import cli

    constructed: list[object] = []
    monkeypatch.setattr(cli, "load_config", lambda path: frozen_config)
    monkeypatch.setattr(cli, "construct_live_clients", lambda config: constructed.append(config))
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    with pytest.raises(SystemExit, match="2"):
        cli.main(argv)

    capsys.readouterr()
    assert constructed == []


def test_benign_only_rejects_candidate_configuration(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
    complete_candidate_config: ExperimentConfig,
) -> None:
    from chimera import cli

    constructed: list[object] = []
    monkeypatch.setattr(cli, "load_config", lambda path: complete_candidate_config)
    monkeypatch.setattr(cli, "construct_live_clients", lambda config: constructed.append(config))
    monkeypatch.setenv("CHIMERA_ALLOW_PAID", "1")
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")

    with pytest.raises(SystemExit, match="2"):
        cli.main(["run", "--live", "--confirm-paid", "--benign-only", "--condition", "B"])

    assert "frozen" in capsys.readouterr().err
    assert constructed == []


def test_control_claim_uses_its_own_root_and_run_kind(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")
    control_root = tmp_path / "control"
    monkeypatch.setattr(cli, "CONTROL_RUN_ROOT", control_root)

    claim = cli._claim_live_run(
        config=frozen_config,
        condition="C",
        instruction="U",
        schedule_item=None,
        run_kind="control",
    )

    assert claim.output_root == control_root
    assert claim.episode_id.startswith("control-")
    assert claim.episode_id.endswith("-C-U")
    records = cli.Manifest(control_root / "manifest.jsonl", expected_run_kind="control").records()
    assert [record["status"] for record in records] == ["starting"]
    assert records[0]["run_kind"] == "control"
    assert records[0]["official_configuration_digest"] == config_digest(frozen_config)
    assert not (tmp_path / "pilot").exists()


def test_control_claims_may_repeat_a_treatment_without_rerun_linkage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli

    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "defender-model")
    monkeypatch.setattr(cli, "CONTROL_RUN_ROOT", tmp_path / "control")

    first = cli._claim_live_run(
        config=frozen_config, condition="B", instruction="U", schedule_item=None, run_kind="control"
    )
    second = cli._claim_live_run(
        config=frozen_config, condition="B", instruction="U", schedule_item=None, run_kind="control"
    )

    assert first.episode_id != second.episode_id


def test_control_run_kind_rejects_reruns_and_schedule_rows(
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import cli
    from chimera.schedule import build_schedule

    with pytest.raises(ValueError, match="cannot be reruns"):
        cli._claim_live_run(
            config=frozen_config, condition="B", instruction="U", schedule_item=None,
            run_kind="control", rerun_of="control-x", rerun_episode_id="control-x-r2",
        )
    with pytest.raises(ValueError, match="cannot consume a schedule row"):
        cli.run_live_episode(
            config=frozen_config, condition="B", instruction="U", horizon_seconds=300.0,
            schedule_item=build_schedule(frozen_config)[0], run_kind="control",
        )


def test_mock_benign_only_episode_never_starts_the_attacker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from chimera import cli
    from chimera.evaluate import summarize_runs

    mock_root = tmp_path / "artifacts" / "runs" / "mock"
    monkeypatch.setattr(cli, "MOCK_RUN_ROOT", mock_root)

    metadata = cli.run_mock_episode(
        condition="A", instruction="U", horizon_seconds=0.13, benign_only=True
    )

    episode_dir = Path(str(metadata["artifact_dir"]))
    assert metadata["benign_only"] is True
    assert metadata["termination_reason"] == "fixed_horizon"
    assert not (episode_dir / "attacker_actions.jsonl").exists()
    assert not (episode_dir / "actuation_results.jsonl").exists()
    snapshot = json.loads((episode_dir / "configuration_snapshot.json").read_text(encoding="utf-8"))
    assert snapshot["episode"]["benign_only"] is True
    assert snapshot["episode"]["run_kind"] == "mock"
    summary = summarize_runs(mock_root)
    attempt = summary["attempts"][0]
    assert attempt["termination"] == "fixed_horizon"
    assert not [issue for issue in attempt["evidence_issues"] if issue.startswith("invalid_")]
    assert attempt["availability_attempts"] > 0
    assert attempt["availability_successes"] == attempt["availability_attempts"]


def test_mock_benign_only_static_playbook_reacts_to_the_authorized_job_alone(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The control run exists to expose exactly this: the frozen playbook sees
    the scheduled authorized job's route_probe, config_read and token_exchange
    on one route as its pattern and blocks that edge with no attacker present.
    The evidence must be valid, attributable to broker observations only, and
    free of attacker artifacts."""
    from chimera import cli
    from chimera.evaluate import summarize_runs

    mock_root = tmp_path / "artifacts" / "runs" / "mock"
    monkeypatch.setattr(cli, "MOCK_RUN_ROOT", mock_root)

    metadata = cli.run_mock_episode(
        condition="B", instruction="U", horizon_seconds=0.13, benign_only=True
    )

    episode_dir = Path(str(metadata["artifact_dir"]))
    assert metadata["termination_reason"] == "fixed_horizon"
    assert not (episode_dir / "attacker_actions.jsonl").exists()
    decisions = [
        json.loads(line)
        for line in (episode_dir / "decisions.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    suspicious = [record for record in decisions if record["decision"]["suspicious"]]
    assert suspicious and suspicious[0]["decision"]["reason_code"] == "route_pattern"
    events = {
        json.loads(line)["event_id"]: json.loads(line)
        for line in (episode_dir / "defender_events.jsonl").read_text(encoding="utf-8").splitlines()
    }
    cited = suspicious[0]["decision"]["evidence_event_ids"]
    assert cited and all(events[event_id]["source"] == "broker" for event_id in cited)
    actuations = [
        json.loads(line)
        for line in (episode_dir / "actuation_results.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert actuations and actuations[0]["effective"] is True
    attempt = summarize_runs(mock_root)["attempts"][0]
    assert not [issue for issue in attempt["evidence_issues"] if issue.startswith("invalid_")]
    assert attempt["availability_successes"] < attempt["availability_attempts"]


def test_mock_benign_only_cli_flag_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    from chimera import cli

    monkeypatch.setattr(cli, "MOCK_RUN_ROOT", tmp_path / "artifacts" / "runs" / "mock")

    exit_code, metadata = _invoke(
        ["run", "--mock", "--benign-only", "--condition", "E", "--horizon-seconds", "0.05"],
        capsys,
    )

    assert exit_code == 0
    assert metadata["benign_only"] is True
    assert metadata["run_kind"] == "mock"


def test_summarize_accepts_the_control_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    from chimera import cli

    runs_root = tmp_path / "artifacts" / "runs"
    (runs_root / "control").mkdir(parents=True)
    monkeypatch.setattr(cli, "RUNS_ROOT", runs_root)

    exit_code, metadata = _invoke(["summarize", "--runs", str(runs_root / "control")], capsys)

    assert exit_code == 0
    assert metadata["attempts"] == []
