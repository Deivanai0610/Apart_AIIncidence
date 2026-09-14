from __future__ import annotations

import argparse
import fcntl
import asyncio
import json
import math
import os
import re
import secrets
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Literal, Sequence

import httpx

from chimera.actuator import DockerActuator, ProbeResult, SubprocessDockerCommandRunner
from chimera.broker import Broker
from chimera.budget import (
    BudgetLedger,
    CallCapExceeded,
    CumulativeBudgetScope,
    FileBudgetAuthority,
)
from chimera.canaries import CanaryRegistry, value_digest
from chimera.config import (
    ExperimentConfig,
    OpenRouterModelConfig,
    RoleBudget,
    config_digest,
    load_config,
)
from chimera.controllers import (
    HeuristicPlacementController,
    LLMDefenderController,
    PassiveController,
    StaticController,
)
from chimera.evaluate import summarize_runs
from chimera.live_lease import LiveRangeLease, live_range_lease_subprocess_options
from chimera.models import AttackerPolicy, MockModelClient, ModelReply, OpenRouterClient
from chimera.provenance import (
    current_model_ids,
    current_source_tree_digest as _current_source_tree_digest,
)
from chimera.range_client import HttpRangeClient, RangeOperation, RangeResponse
from chimera.range_manager import EpisodeFixtures, RangeManager
from chimera.route_state import initialize_route_states
from chimera.runner import EpisodeRunner, EpisodeSpec, RangeEpisodeRuntimeFactory
from chimera.schedule import Manifest, ScheduleItem, build_schedule, load_schedule_item
from chimera.schemas import (
    ActionKind,
    ActionResult,
    ActuationResult,
    AttackerAction,
    ContainmentAction,
    Route,
)
from chimera.telemetry import TelemetryStore
from chimera.workloads import AuthorizedEvaluationWorkload, OrdinaryWorkload


REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_ROOT = REPO_ROOT / "configs"
CONFIG_PATH = CONFIG_ROOT / "experiment.yaml"
RUNS_ROOT = REPO_ROOT / "artifacts" / "runs"
MOCK_RUN_ROOT = RUNS_ROOT / "typed" / "mock"
PILOT_RUN_ROOT = RUNS_ROOT / "pilot"
MEASURED_RUN_ROOT = RUNS_ROOT / "measured"
CONTROL_RUN_ROOT = RUNS_ROOT / "control"
LIVE_BUDGET_ROOT = RUNS_ROOT / "provider-budget"
LIVE_RANGE_LEASE_PATH = RUNS_ROOT / ".live-range.lock"
SCHEDULE_OUTPUT_ROOT = RUNS_ROOT / "schedules"
VERIFICATION_ROOT = RUNS_ROOT / "verification"
PROMPT_ROOT = REPO_ROOT / "prompts"
RANGE_RUNTIME_ROOT = REPO_ROOT / "range" / "runtime"
MAX_STAMP_BYTES = 64 * 1024
MAX_MOCK_HORIZON_SECONDS = 60.0

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{7,64}\Z")
_COMPOSE = ("docker", "compose", "-f", "range/compose.yaml", "-p", "chimera")
REQUIRED_CHECKS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "CT1",
        (
            sys.executable,
            "-m",
            "pytest",
            "tests/docker/test_controls.py::test_ct1_scope",
            "-q",
        ),
    ),
    (
        "CT2",
        (
            sys.executable,
            "-m",
            "pytest",
            "tests/docker/test_controls.py::test_ct2_credentials",
            "-q",
        ),
    ),
    (
        "CT3",
        (
            sys.executable,
            "-m",
            "pytest",
            "tests/docker/test_controls.py::test_ct3_canary_stop",
            "-q",
        ),
    ),
    (
        "CT4",
        (
            sys.executable,
            "-m",
            "pytest",
            "tests/docker/test_controls.py::test_ct4_stop_effect",
            "-q",
        ),
    ),
    (
        "CT5",
        (
            sys.executable,
            "-m",
            "pytest",
            "tests/test_models.py::test_ct5_provider_failure_fallback",
            "-q",
        ),
    ),
)
DEMO_DOCKER_CHECKS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("CT3", "canary stop", REQUIRED_CHECKS[2][1]),
    ("CT4", "stop effect", REQUIRED_CHECKS[3][1]),
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chimera")
    subcommands = parser.add_subparsers(dest="command", required=True)

    range_parser = subcommands.add_parser("range")
    range_parser.add_argument("action", choices=("up", "down", "reset"))

    subcommands.add_parser("checks")

    demo_parser = subcommands.add_parser("demo")
    demo_parser.add_argument("--docker", action="store_true")
    demo_parser.add_argument("--horizon-seconds", type=_bounded_horizon, default=1.0)

    schedule_parser = subcommands.add_parser("schedule")
    schedule_parser.add_argument("--config", default="configs/experiment.yaml")
    schedule_parser.add_argument(
        "--output", default="artifacts/runs/schedules/schedule.json"
    )

    run_parser = subcommands.add_parser("run")
    modes = run_parser.add_mutually_exclusive_group()
    modes.add_argument("--mock", action="store_true")
    modes.add_argument("--live", action="store_true")
    run_parser.add_argument("--confirm-paid", action="store_true")
    run_parser.add_argument("--pilot", action="store_true")
    run_parser.add_argument("--schedule")
    run_parser.add_argument("--schedule-episode-id")
    run_parser.add_argument("--rerun-of")
    run_parser.add_argument("--benign-only", action="store_true")
    run_parser.add_argument("--condition", choices=tuple("ABCDE"))
    run_parser.add_argument("--instruction", choices=("U", "W"))
    run_parser.add_argument(
        "--horizon-seconds", type=_bounded_horizon
    )

    summarize_parser = subcommands.add_parser("summarize")
    summarize_parser.add_argument("--runs", default="artifacts/runs/typed/mock")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "range":
            return _range_command(args.action)
        if args.command == "checks":
            return run_checks()
        if args.command == "demo":
            return run_demo(
                docker=args.docker,
                horizon_seconds=args.horizon_seconds,
            )
        if args.command == "schedule":
            metadata = write_schedule(args.config, args.output)
        elif args.command == "summarize":
            runs = _existing_directory_under(args.runs, RUNS_ROOT)
            run_kind = runs.name
            if run_kind not in {"mock", "pilot", "measured", "control"}:
                raise ValueError("summary root is not a typed run root")
            metadata = summarize_runs(runs, expected_run_kind=run_kind)
        elif args.command == "run":
            metadata = _run_command(args, parser)
        else:
            raise ValueError("unsupported command")
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    _emit(metadata)
    return 0


def _run_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> dict[str, object]:
    if args.confirm_paid and not args.live:
        parser.error("--confirm-paid requires --live")
    if args.pilot and not args.live:
        parser.error("--pilot requires --live")
    if (args.schedule is not None or args.schedule_episode_id is not None) and not args.live:
        parser.error("schedule selection requires --live")
    if args.rerun_of is not None and (not args.live or args.pilot or args.schedule is None):
        parser.error("--rerun-of requires a measured live run with --schedule")
    if args.benign_only and (
        args.pilot
        or args.schedule is not None
        or args.schedule_episode_id is not None
        or args.rerun_of is not None
    ):
        parser.error("--benign-only is a control run: no --pilot, schedule row, or rerun")
    if args.benign_only and args.live and args.condition is None:
        parser.error("--benign-only requires an explicit --condition")
    if args.live:
        if not args.confirm_paid or os.getenv("CHIMERA_ALLOW_PAID") != "1":
            parser.error("paid execution is disabled")
        config = load_config(CONFIG_PATH)
        if config.range.compose_file != "range/compose.yaml":
            raise ValueError("live range compose file must be range/compose.yaml")
        if (
            args.horizon_seconds is not None
            and args.horizon_seconds != float(config.horizon_seconds)
        ):
            raise ValueError("live horizon must match the frozen configuration horizon")
        schedule_item: ScheduleItem | None
        run_kind: Literal["pilot", "measured", "control"]
        if args.benign_only:
            # Protocol section 5: benign-only control, one per active defense.
            # Same frozen configuration and stamp as a measured run; no
            # schedule row because the attacker is absent.
            config.validate_for_measured_run()
            schedule_item = None
            run_kind = "control"
            condition = args.condition
            instruction = args.instruction or "U"
        elif args.pilot:
            config.validate_for_pilot_run()
            if args.schedule is not None or args.schedule_episode_id is not None:
                raise ValueError("pilot runs cannot consume a measured schedule")
            schedule_item = None
            run_kind = "pilot"
            condition = args.condition or "A"
            instruction = args.instruction or "U"
        else:
            config.validate_for_measured_run()
            if args.schedule is None or args.schedule_episode_id is None:
                raise ValueError(
                    "measured live runs require --schedule and --schedule-episode-id"
                )
            if args.condition is not None or args.instruction is not None:
                raise ValueError("measured treatment must come from the schedule row")
            schedule_item = load_schedule_item(
                _argument_path(args.schedule),
                episode_id=args.schedule_episode_id,
                config=config,
                allowed_root=SCHEDULE_OUTPUT_ROOT,
            )
            if args.rerun_of is None:
                _reject_used_measured_schedule_item(schedule_item)
            else:
                _validate_measured_rerun(schedule_item, args.rerun_of)
            run_kind = "measured"
            condition = schedule_item.condition
            instruction = schedule_item.instruction
        require_local_verification_stamp(config_digest(config), config=config)
        return run_live_episode(
            config=config,
            condition=condition,
            instruction=instruction,
            horizon_seconds=(
                float(config.horizon_seconds)
                if args.horizon_seconds is None
                else args.horizon_seconds
            ),
            schedule_item=schedule_item,
            run_kind=run_kind,
            rerun_of=args.rerun_of,
        )
    return run_mock_episode(
        condition=args.condition or "A",
        instruction=args.instruction or "U",
        horizon_seconds=(1.0 if args.horizon_seconds is None else args.horizon_seconds),
        benign_only=args.benign_only,
    )


def _reject_used_measured_schedule_item(item: ScheduleItem) -> None:
    manifest = Manifest(
        MEASURED_RUN_ROOT / "manifest.jsonl", expected_run_kind="measured"
    )
    if any(record["episode_id"] == item.episode_id for record in manifest.records()):
        raise ValueError("measured schedule row has already been used")
    artifact_dir = MEASURED_RUN_ROOT / item.episode_id
    if artifact_dir.exists() or artifact_dir.is_symlink():
        raise ValueError("measured schedule row artifact already exists")


def _rerun_episode_id(item: ScheduleItem, rerun_of: str) -> str:
    """Return the linked ID for a rerun of ``item`` after ``rerun_of``.

    The protocol allows a rerun only for an attempt that ended as an
    infrastructure failure, and every attempt stays in the manifest. The new
    ID is the schedule row ID with a ``-r<N>`` suffix, N counting from 2.
    """
    manifest = Manifest(
        MEASURED_RUN_ROOT / "manifest.jsonl", expected_run_kind="measured"
    )
    records = manifest.records()
    family_starts = [
        record["episode_id"]
        for record in records
        if record["status"] == "starting"
        and (
            record["episode_id"] == item.episode_id
            or str(record["episode_id"]).startswith(f"{item.episode_id}-r")
        )
    ]
    if not family_starts:
        raise ValueError("rerun_of does not name a recorded measured attempt")
    if rerun_of != family_starts[-1]:
        raise ValueError(
            "rerun_of must name the latest attempt for the selected schedule row"
        )
    original = [record for record in records if record["episode_id"] == rerun_of]
    last = original[-1]
    if last["status"] in {"starting", "running"}:
        # An interrupted launch leaves a claim with no terminal record. Close it
        # as an infrastructure failure so the manifest history stays complete,
        # but only when nothing could still be executing it.
        if (MEASURED_RUN_ROOT / str(rerun_of) / "terminal.jsonl").exists():
            raise ValueError(
                "attempt has terminal artifacts but no terminal manifest record; inspect manually"
            )
        if not _live_range_lease_is_free(LIVE_RANGE_LEASE_PATH):
            raise ValueError(
                "a live run holds the range lease; the attempt may still be executing"
            )
        closing = {
            key: value
            for key, value in original[0].items()
            if key not in {"status", "termination_reason"}
        }
        manifest.append(
            {
                **closing,
                "status": "infrastructure_failure" if last["status"] == "starting" else "terminal",
                "termination_reason": "infrastructure_failure",
            }
        )
        records = manifest.records()
        last = [record for record in records if record["episode_id"] == rerun_of][-1]
    if (
        last["status"] not in {"terminal", "infrastructure_failure"}
        or last.get("termination_reason") != "infrastructure_failure"
    ):
        raise ValueError(
            "only an attempt that ended as infrastructure_failure may be rerun"
        )
    attempts = 1 + sum(
        1
        for record in records
        if record["status"] == "starting"
        and record["episode_id"].startswith(f"{item.episode_id}-r")
    )
    episode_id = f"{item.episode_id}-r{attempts + 1}"
    if any(record["episode_id"] == episode_id for record in records):
        raise ValueError("rerun episode ID has already been used")
    artifact_dir = MEASURED_RUN_ROOT / episode_id
    if artifact_dir.exists() or artifact_dir.is_symlink():
        raise ValueError("rerun artifact already exists")
    return episode_id


def _validate_measured_rerun(item: ScheduleItem, rerun_of: str) -> str:
    return _rerun_episode_id(item, rerun_of)


def _live_range_lease_is_free(path: Path) -> bool:
    """Probe the live-range lease without blocking; True when nobody holds it."""
    if not path.exists() or path.is_symlink():
        return True
    descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return True
    finally:
        os.close(descriptor)


def _range_command(action: str) -> int:
    with LiveRangeLease(LIVE_RANGE_LEASE_PATH):
        return _range_command_with_lease(action)


def _range_command_with_lease(action: str) -> int:
    commands = {
        "up": [[*_COMPOSE, "up", "--build", "--wait"]],
        "down": [[*_COMPOSE, "down"]],
        "reset": [
            [*_COMPOSE, "down"],
            [*_COMPOSE, "up", "--build", "--wait"],
        ],
    }
    exit_codes: list[int] = []
    for command in commands[action]:
        if "up" in command:
            initialize_route_states(RANGE_RUNTIME_ROOT)
        exit_code = run_command(command)
        exit_codes.append(exit_code)
        if exit_code != 0:
            break
    exit_code = exit_codes[-1]
    _emit(
        {
            "action": action,
            "commands": commands[action][: len(exit_codes)],
            "exit_codes": exit_codes,
        }
    )
    return exit_code


def run_command(command: list[str]) -> int:
    lease_environment, pass_fds = live_range_lease_subprocess_options()
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        check=False,
        shell=False,
        env={"PATH": os.environ.get("PATH", ""), **lease_environment},
        pass_fds=pass_fds,
    )
    return completed.returncode


def run_demo(*, docker: bool, horizon_seconds: float) -> int:
    print("CHIMERA LOCAL CONTAINMENT DEMO")
    print("Safety: local synthetic data; no real targets or credentials")
    print(
        "Pipeline: test agent -> broker -> telemetry -> defender -> actuator -> evaluator"
    )
    if docker and not _run_demo_docker_checks():
        print("[ABORT] synthetic episode skipped because a Docker check failed")
        return 1
    print("Mode: no-cost synthetic Condition C episode")
    metadata = run_mock_episode(
        condition="C",
        instruction="U",
        horizon_seconds=horizon_seconds,
    )
    _print_demo_timeline(Path(str(metadata["artifact_dir"])), metadata)
    return 0


def _run_demo_docker_checks() -> bool:
    with LiveRangeLease(LIVE_RANGE_LEASE_PATH):
        for check_id, description, command in DEMO_DOCKER_CHECKS:
            print(f"[DOCKER] {check_id} {description}: RUNNING", flush=True)
            if run_command(list(command)) != 0:
                print(f"[DOCKER] {check_id} {description}: FAIL", flush=True)
                return False
            print(f"[DOCKER] {check_id} {description}: PASS", flush=True)
    return True


def _print_demo_timeline(
    artifact_dir: Path, metadata: dict[str, object]
) -> None:
    attacker = next(
        (
            row
            for row in _read_jsonl(artifact_dir / "attacker_actions.jsonl")
            if row.get("status") == "completed"
        ),
        {},
    )
    action = attacker.get("action")
    action_kind = action.get("kind") if isinstance(action, dict) else None
    accepted = attacker.get("accepted") is True
    print(
        f"[ACTION] {_demo_value(action_kind, {'inspect_web', 'route_probe', 'config_read', 'token_exchange', 'data_query'})}"
        f" -> {'accepted' if accepted else 'rejected'}"
    )

    canary = next(
        (
            row
            for row in _read_jsonl(artifact_dir / "defender_events.jsonl")
            if row.get("event_type") == "canary_exposed"
        ),
        {},
    )
    print(f"[TELEMETRY] canary_exposed on {_demo_value(canary.get('target'), {'api', 'internal'})}")

    suspicious = next(
        (
            row
            for row in _read_jsonl(artifact_dir / "decisions.jsonl")
            if isinstance(row.get("decision"), dict)
            and row["decision"].get("suspicious") is True
        ),
        {},
    )
    decision = suspicious.get("decision")
    containment = decision.get("action") if isinstance(decision, dict) else None
    containment_kind = containment.get("kind") if isinstance(containment, dict) else None
    containment_target = containment.get("target") if isinstance(containment, dict) else None
    print(
        f"[DECISION] {_demo_value(containment_kind, {'block_edge', 'quarantine'})} "
        f"{_demo_value(containment_target, {'web', 'web_api', 'web_internal', 'api', 'internal', 'api_db', 'internal_db'})}"
    )

    actuation = next(iter(_read_jsonl(artifact_dir / "actuation_results.jsonl")), {})
    print(
        f"[ENFORCEMENT] applied={_yes_no(actuation.get('applied'))} "
        f"effective={_yes_no(actuation.get('effective'))}"
    )

    route_availability: dict[str, bool] = {}
    for row in _read_jsonl(artifact_dir / "evaluator_events.jsonl"):
        result = row.get("result")
        target = row.get("target")
        if (
            row.get("event_type") == "restriction_result"
            and target in {"api", "internal"}
            and isinstance(result, dict)
            and type(result.get("route_available")) is bool
        ):
            route_availability[str(target)] = bool(result["route_available"])
    print(
        "[PROBE] "
        f"api={_availability_label(route_availability.get('api'))} "
        f"internal={_availability_label(route_availability.get('internal'))}"
    )

    availability = _read_jsonl(artifact_dir / "availability_attempts.jsonl")
    successful = sum(row.get("status") == "success" for row in availability)
    print(f"[BENIGN] successful_transactions={successful}/{len(availability)}")

    terminal = next(iter(_read_jsonl(artifact_dir / "terminal.jsonl")), {})
    print(f"[OUTCOME] secret_delivered={_yes_no(terminal.get('secret_delivered'))}")
    print(f"[COST] provider_requests={int(metadata.get('provider_requests', 0))}")
    print(f"[ARTIFACTS] {artifact_dir}")


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        payload = json.loads(line)
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _demo_value(value: object, allowed: set[str]) -> str:
    return str(value) if isinstance(value, str) and value in allowed else "unknown"


def _yes_no(value: object) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def _availability_label(value: bool | None) -> str:
    if value is True:
        return "available"
    if value is False:
        return "blocked"
    return "unknown"


def run_checks() -> int:
    with LiveRangeLease(LIVE_RANGE_LEASE_PATH):
        return _run_checks_with_lease()


def _run_checks_with_lease() -> int:
    config = load_config(CONFIG_PATH)
    digest = config_digest(config)
    revision = current_code_revision()
    source_tree_digest = current_source_tree_digest()
    model_ids = current_model_ids(config)
    results: list[dict[str, object]] = []
    for check_id, command in REQUIRED_CHECKS:
        started_at = datetime.now(UTC)
        exit_code = run_command(list(command))
        ended_at = datetime.now(UTC)
        results.append(
            {
                "check_id": check_id,
                "command": list(command),
                "exit_code": exit_code,
                "started_at": started_at.isoformat(),
                "ended_at": ended_at.isoformat(),
            }
        )
    success = all(result["exit_code"] == 0 for result in results)
    success = success and current_source_tree_digest() == source_tree_digest
    payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "chimera_local_verification",
        "success": success,
        "configuration_digest": digest,
        "code_revision": revision,
        "source_tree_digest": source_tree_digest,
        "model_ids": model_ids,
        "commands": results,
    }
    if success:
        _atomic_json_write(VERIFICATION_ROOT / f"{digest}.json", payload)
    _emit(payload)
    return 0 if success else 1


def require_local_verification_stamp(
    digest: str,
    *,
    config: ExperimentConfig | None = None,
) -> dict[str, object]:
    if _DIGEST.fullmatch(digest) is None:
        raise ValueError("verification stamp digest is invalid")
    root = VERIFICATION_ROOT.absolute()
    if _contains_symlink(root) or not root.is_dir() or root.resolve(strict=True) != root:
        raise ValueError("verification stamp directory is unsafe or missing")
    path = root / f"{digest}.json"
    try:
        file_stat = path.lstat()
    except OSError as error:
        raise ValueError("verification stamp is missing") from error
    if (
        stat.S_ISLNK(file_stat.st_mode)
        or not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_size > MAX_STAMP_BYTES
        or path.resolve(strict=True) != path
    ):
        raise ValueError("verification stamp is unsafe")
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant {token}")
            ),
        )
        _validate_stamp(payload, digest, config or load_config(CONFIG_PATH))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise ValueError("verification stamp is malformed or stale") from error
    return payload


def _validate_stamp(
    payload: object,
    digest: str,
    config: ExperimentConfig,
) -> None:
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "kind",
        "success",
        "configuration_digest",
        "code_revision",
        "source_tree_digest",
        "model_ids",
        "commands",
    }:
        raise ValueError("invalid verification stamp shape")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or payload["kind"] != "chimera_local_verification"
        or payload["success"] is not True
        or payload["configuration_digest"] != digest
    ):
        raise ValueError("verification stamp does not represent a successful current check")
    revision = payload["code_revision"]
    if revision is not None and (
        type(revision) is not str or _REVISION.fullmatch(revision) is None
    ):
        raise ValueError("verification stamp revision is invalid")
    current_revision = current_code_revision()
    if current_revision is not None and revision != current_revision:
        raise ValueError("verification stamp revision is stale")
    source_tree_digest = payload["source_tree_digest"]
    if (
        type(source_tree_digest) is not str
        or _DIGEST.fullmatch(source_tree_digest) is None
        or source_tree_digest != current_source_tree_digest()
    ):
        raise ValueError("verification stamp source tree is stale")
    model_ids = payload["model_ids"]
    if (
        not isinstance(model_ids, dict)
        or set(model_ids) != {"attacker", "defender"}
        or any(
            value is not None
            and (
                type(value) is not str
                or not value.strip()
                or len(value) > 512
            )
            for value in model_ids.values()
        )
        or model_ids != current_model_ids(config)
    ):
        raise ValueError("verification stamp model IDs are stale")
    commands = payload["commands"]
    if not isinstance(commands, list) or len(commands) != len(REQUIRED_CHECKS):
        raise ValueError("verification stamp check set is incomplete")
    for result, (check_id, expected_command) in zip(commands, REQUIRED_CHECKS, strict=True):
        if not isinstance(result, dict) or set(result) != {
            "check_id",
            "command",
            "exit_code",
            "started_at",
            "ended_at",
        }:
            raise ValueError("verification stamp command shape is invalid")
        if (
            result["check_id"] != check_id
            or result["command"] != list(expected_command)
            or type(result["exit_code"]) is not int
            or result["exit_code"] != 0
        ):
            raise ValueError("verification stamp command result is invalid")
        started_at = _utc_timestamp(result["started_at"])
        ended_at = _utc_timestamp(result["ended_at"])
        if ended_at < started_at:
            raise ValueError("verification stamp command timestamps are invalid")


def current_code_revision() -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            check=False,
            shell=False,
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except OSError:
        return None
    revision = completed.stdout.strip().lower()
    if completed.returncode != 0 or _REVISION.fullmatch(revision) is None:
        return None
    return revision


def current_source_tree_digest() -> str:
    return _current_source_tree_digest(REPO_ROOT)


def construct_live_clients(
    config: ExperimentConfig,
) -> tuple[OpenRouterClient, OpenRouterClient]:
    api_key = os.getenv(config.models.attacker.api_key_env, "").strip()
    if not api_key:
        raise ValueError("live provider API keys are required")
    return (
        _construct_openrouter_client(
            config.models.attacker,
            config.budgets.openrouter.attacker,
            api_key,
        ),
        _construct_openrouter_client(
            config.models.defender,
            config.budgets.openrouter.defender,
            api_key,
        ),
    )


def _construct_openrouter_client(
    role: OpenRouterModelConfig,
    budget: RoleBudget,
    api_key: str,
) -> OpenRouterClient:
    if (
        role.pinned_provider_slug is None
        or role.expected_provider_name is None
        or role.expected_endpoint_model is None
        or budget.input_per_million_usd is None
        or budget.output_per_million_usd is None
    ):
        raise ValueError("verified OpenRouter routing and pricing are required")
    return OpenRouterClient(
        api_key=api_key,
        provider_slug=role.pinned_provider_slug,
        expected_provider_name=role.expected_provider_name,
        expected_endpoint_model=role.expected_endpoint_model,
        max_prompt_price=Decimal(str(budget.input_per_million_usd)),
        max_completion_price=Decimal(str(budget.output_per_million_usd)),
    )


async def _close_live_clients(clients: object) -> None:
    if not isinstance(clients, tuple):
        return
    for client in clients:
        closer = getattr(client, "aclose", None)
        if closer is not None:
            await closer()


def run_live_episode(
    *,
    config: ExperimentConfig,
    condition: str,
    instruction: str,
    horizon_seconds: float,
    schedule_item: ScheduleItem | None,
    run_kind: Literal["pilot", "measured", "control"],
    rerun_of: str | None = None,
) -> dict[str, object]:
    if condition not in set("ABCDE") or instruction not in {"U", "W"}:
        raise ValueError("live condition or instruction is invalid")
    if config.range.compose_file != "range/compose.yaml":
        raise ValueError("live range compose file must be range/compose.yaml")
    rerun_episode_id: str | None = None
    if run_kind == "measured":
        if schedule_item is None:
            raise ValueError("measured live runs require a schedule row")
        if (
            condition != schedule_item.condition
            or instruction != schedule_item.instruction
            or schedule_item.official_configuration_digest != config_digest(config)
            or schedule_item not in build_schedule(config)
        ):
            raise ValueError("measured live metadata differs from the schedule row")
        if rerun_of is None:
            _reject_used_measured_schedule_item(schedule_item)
        else:
            rerun_episode_id = _rerun_episode_id(schedule_item, rerun_of)
    elif run_kind in {"pilot", "control"}:
        if schedule_item is not None:
            raise ValueError(f"{run_kind} runs cannot consume a schedule row")
        if rerun_of is not None:
            raise ValueError(f"{run_kind} runs cannot be reruns")
        if run_kind == "control" and config.status != "frozen":
            raise ValueError("control runs require the frozen configuration")
    else:
        raise ValueError("live run_kind is invalid")
    claim = _claim_live_run(
        config=config,
        condition=condition,
        instruction=instruction,
        schedule_item=schedule_item,
        run_kind=run_kind,
        rerun_of=rerun_of,
        rerun_episode_id=rerun_episode_id,
    )
    lease_acquired = False
    try:
        with LiveRangeLease(LIVE_RANGE_LEASE_PATH):
            lease_acquired = True
            try:
                execution_inputs = _capture_live_execution_inputs(
                    config=config,
                    instruction=instruction,
                    claim=claim,
                )
                return asyncio.run(
                    _construct_run_and_close_live_clients(
                        config=config,
                        condition=condition,
                        instruction=instruction,
                        horizon_seconds=horizon_seconds,
                        schedule_item=schedule_item,
                        run_kind=run_kind,
                        claim=claim,
                        execution_inputs=execution_inputs,
                    )
                )
            except Exception:
                claim.manifest.finalize_infrastructure_failure(claim.episode_id)
                raise
    except Exception:
        if not lease_acquired:
            claim.manifest.finalize_infrastructure_failure(claim.episode_id)
        raise


@dataclass(frozen=True)
class _LiveRunClaim:
    output_root: Path
    manifest: Manifest
    manifest_base: dict[str, object]

    @property
    def episode_id(self) -> str:
        episode_id = self.manifest_base["episode_id"]
        assert isinstance(episode_id, str)
        return episode_id


@dataclass(frozen=True)
class _LiveExecutionInputs:
    source_tree_digest: str
    attacker_model_id: str
    defender_model_id: str
    attacker_prompt: str
    defender_prompt: str


def _capture_live_execution_inputs(
    *,
    config: ExperimentConfig,
    instruction: str,
    claim: _LiveRunClaim,
) -> _LiveExecutionInputs:
    claimed_source_digest = claim.manifest_base.get("source_tree_digest")
    claimed_model_ids = {
        "attacker": claim.manifest_base.get("attacker_model_id"),
        "defender": claim.manifest_base.get("defender_model_id"),
    }
    if (
        not isinstance(claimed_source_digest, str)
        or not isinstance(claimed_model_ids["attacker"], str)
        or not isinstance(claimed_model_ids["defender"], str)
        or current_source_tree_digest() != claimed_source_digest
        or current_model_ids(config) != claimed_model_ids
    ):
        raise ValueError("live provenance changed after the manifest claim")
    attacker_prompt = _read_live_prompt(f"attacker_{instruction.lower()}.txt")
    defender_prompt = _read_live_prompt("defender.txt")
    if (
        current_source_tree_digest() != claimed_source_digest
        or current_model_ids(config) != claimed_model_ids
    ):
        raise ValueError("live provenance changed while capturing execution inputs")
    return _LiveExecutionInputs(
        source_tree_digest=claimed_source_digest,
        attacker_model_id=claimed_model_ids["attacker"],
        defender_model_id=claimed_model_ids["defender"],
        attacker_prompt=attacker_prompt,
        defender_prompt=defender_prompt,
    )


def _claim_live_run(
    *,
    config: ExperimentConfig,
    condition: str,
    instruction: str,
    schedule_item: ScheduleItem | None,
    run_kind: Literal["pilot", "measured", "control"],
    rerun_of: str | None = None,
    rerun_episode_id: str | None = None,
) -> _LiveRunClaim:
    if run_kind == "measured":
        if schedule_item is None:
            raise ValueError("measured live runs require a schedule row")
        if (rerun_of is None) != (rerun_episode_id is None):
            raise ValueError("rerun linkage requires both the original and the new episode ID")
        output_root = MEASURED_RUN_ROOT
        manifest_base = {**asdict(schedule_item), "run_kind": "measured"}
        if rerun_of is not None and rerun_episode_id is not None:
            manifest_base["episode_id"] = rerun_episode_id
            manifest_base["rerun_of"] = rerun_of
    else:
        if rerun_of is not None or rerun_episode_id is not None:
            raise ValueError(f"{run_kind} runs cannot be reruns")
        if run_kind not in {"pilot", "control"}:
            raise ValueError("live run_kind is invalid")
        output_root = PILOT_RUN_ROOT if run_kind == "pilot" else CONTROL_RUN_ROOT
        episode_id = (
            f"{run_kind}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%f')}-"
            f"{secrets.token_hex(4)}-{condition}-{instruction}"
        )
        model_ids = current_model_ids(config)
        attacker_model_id = model_ids["attacker"]
        defender_model_id = model_ids["defender"]
        if not isinstance(attacker_model_id, str) or not isinstance(
            defender_model_id, str
        ):
            raise ValueError("live model IDs are required")
        manifest_base = {
            "episode_id": episode_id,
            "block": 1,
            "repetition": 1,
            "condition": condition,
            "instruction": instruction,
            "seed": secrets.randbits(63),
            "schedule_seed": config.schedule.seed,
            "official_configuration_digest": config_digest(config),
            "source_tree_digest": current_source_tree_digest(),
            "attacker_model_id": attacker_model_id,
            "defender_model_id": defender_model_id,
            "run_kind": run_kind,
        }
    manifest = Manifest(output_root / "manifest.jsonl", expected_run_kind=run_kind)
    manifest.append({**manifest_base, "status": "starting"})
    return _LiveRunClaim(output_root, manifest, manifest_base)


def _construct_live_ledgers(
    config: ExperimentConfig,
) -> tuple[BudgetLedger, BudgetLedger]:
    authority = FileBudgetAuthority(LIVE_BUDGET_ROOT)
    account_budget = config.budgets.openrouter
    authorization_id = config_digest(config)

    def scope(profile: str) -> CumulativeBudgetScope:
        return CumulativeBudgetScope(
            account="openrouter",
            authorization_id=authorization_id,
            profile=profile,
            project_ceiling_usd=Decimal(str(account_budget.project_ceiling_usd)),
            authorization_ceiling_usd=Decimal(
                str(account_budget.authorization_ceiling_usd)
            ),
        )

    return (
        _live_budget_ledger(
            provider="openrouter",
            budget=account_budget.attacker,
            max_calls=config.models.attacker.max_calls,
            cumulative_authority=authority,
            cumulative_scope=scope("attacker"),
        ),
        _live_budget_ledger(
            provider="openrouter",
            budget=account_budget.defender,
            max_calls=config.models.defender.max_calls,
            cumulative_authority=authority,
            cumulative_scope=scope("defender"),
        ),
    )


def _ensure_live_range() -> None:
    initialize_route_states(RANGE_RUNTIME_ROOT)
    if run_command([*_COMPOSE, "up", "--build", "--wait"]) != 0:
        raise RuntimeError("live range startup failed")


async def _construct_run_and_close_live_clients(
    *,
    config: ExperimentConfig,
    condition: str,
    instruction: str,
    horizon_seconds: float,
    schedule_item: ScheduleItem | None,
    run_kind: Literal["pilot", "measured", "control"],
    claim: _LiveRunClaim,
    execution_inputs: _LiveExecutionInputs,
) -> dict[str, object]:
    ledgers = _construct_live_ledgers(config)
    _ensure_live_range()
    clients = construct_live_clients(config)
    try:
        return await _run_live_episode_with_clients(
            config=config,
            condition=condition,
            instruction=instruction,
            horizon_seconds=horizon_seconds,
            clients=clients,
            ledgers=ledgers,
            schedule_item=schedule_item,
            run_kind=run_kind,
            claim=claim,
            execution_inputs=execution_inputs,
        )
    finally:
        await _close_live_clients(clients)


async def _run_live_episode_with_clients(
    *,
    config: ExperimentConfig,
    condition: str,
    instruction: str,
    horizon_seconds: float,
    clients: tuple[object, object],
    ledgers: tuple[BudgetLedger, BudgetLedger],
    schedule_item: ScheduleItem | None,
    run_kind: Literal["pilot", "measured", "control"],
    claim: _LiveRunClaim,
    execution_inputs: _LiveExecutionInputs,
) -> dict[str, object]:
    range_transport = HttpRangeClient(config.range.web_base_url)
    try:
        return await _run_live_episode_with_transport(
            config=config,
            condition=condition,
            instruction=instruction,
            horizon_seconds=horizon_seconds,
            clients=clients,
            ledgers=ledgers,
            range_transport=range_transport,
            schedule_item=schedule_item,
            run_kind=run_kind,
            claim=claim,
            execution_inputs=execution_inputs,
        )
    finally:
        await range_transport.aclose()


async def _run_live_episode_with_transport(
    *,
    config: ExperimentConfig,
    condition: str,
    instruction: str,
    horizon_seconds: float,
    clients: tuple[object, object],
    ledgers: tuple[BudgetLedger, BudgetLedger],
    range_transport: HttpRangeClient,
    schedule_item: ScheduleItem | None,
    run_kind: Literal["pilot", "measured", "control"],
    claim: _LiveRunClaim,
    execution_inputs: _LiveExecutionInputs,
) -> dict[str, object]:
    attacker_client, defender_client = clients
    attacker_ledger, defender_ledger = ledgers
    attacker_model = execution_inputs.attacker_model_id
    defender_model = execution_inputs.defender_model_id

    command_runner = SubprocessDockerCommandRunner()
    telemetry_holder: dict[str, TelemetryStore] = {}

    def route_probe(route: Route) -> ProbeResult:
        token = _read_live_route_token(route)
        try:
            with httpx.Client(
                base_url=config.range.web_base_url,
                timeout=httpx.Timeout(3.0),
                trust_env=False,
                headers={"Connection": "close"},
            ) as client:
                response = client.post(
                    f"/v1/proxy/{route.value}/protected-data",
                    json={"credential": token},
                )
            payload = response.json() if response.status_code == 200 else {}
            available = (
                response.status_code == 200
                and isinstance(payload, dict)
                and set(payload) == {"kind", "value"}
                and payload.get("kind") == "protected"
                and isinstance(payload.get("value"), str)
            )
        except (httpx.HTTPError, ValueError):
            available = False
        telemetry = telemetry_holder.get("current")
        if telemetry is None:
            raise RuntimeError("live telemetry is unavailable for restriction probing")
        event = telemetry.record_restriction_probe(
            source="actuator",
            target=route.value,
            correlation_id=f"actuator-probe-{route.value}",
            available=available,
        )
        return ProbeResult(available=available, event_id=event.event_id)

    actuator = DockerActuator(command_runner, route_probe=route_probe)

    async def health_check() -> bool:
        try:
            async with httpx.AsyncClient(
                base_url=config.range.web_base_url,
                timeout=httpx.Timeout(3.0),
                trust_env=False,
                headers={"Connection": "close"},
            ) as client:
                response = await client.get("/health")
            return response.status_code == 200 and response.json() == {"status": "ok"}
        except (httpx.HTTPError, ValueError):
            return False

    async def route_verifier(
        route: Route,
        token: str,
        safe_value: str,
        secret_digest: str,
    ) -> bool:
        try:
            safe = await range_transport.request(
                route, RangeOperation.SAFE_DATA, {"credential": token}
            )
            protected = await range_transport.request(
                route, RangeOperation.PROTECTED_DATA, {"credential": token}
            )
        except Exception:
            return False
        protected_value = protected.payload.get("value")
        return (
            safe == RangeResponse(200, {"kind": "safe", "value": safe_value})
            and protected.status_code == 200
            and set(protected.payload) == {"kind", "value"}
            and protected.payload.get("kind") == "protected"
            and isinstance(protected_value, str)
            and value_digest(protected_value) == secret_digest
        )

    async def canary_verifier(route: Route, expected_digest: str | None) -> bool:
        try:
            response = await range_transport.request(route, RangeOperation.CONFIG, None)
        except Exception:
            return False
        if response.status_code != 200:
            return False
        canary = response.payload.get("canary")
        if expected_digest is None:
            return "canary" not in response.payload
        return isinstance(canary, str) and value_digest(canary) == expected_digest

    manager = RangeManager(
        runtime_dir=REPO_ROOT / "range" / "runtime",
        actuator=actuator,
        command_runner=command_runner,
        stop_new_work=lambda: True,
        clear_host_state=lambda: True,
        health_check=health_check,
        route_verifier=route_verifier,
        canary_verifier=canary_verifier,
    )
    attacker_prompt = execution_inputs.attacker_prompt
    defender_prompt = execution_inputs.defender_prompt

    output_root = claim.output_root

    def telemetry_factory(episode_id: str) -> TelemetryStore:
        telemetry = TelemetryStore(output_root, episode_id)
        telemetry_holder["current"] = telemetry
        return telemetry

    def broker_factory(fixtures: EpisodeFixtures, telemetry: TelemetryStore) -> Broker:
        return Broker(
            episode_id=fixtures.episode_id,
            transport=range_transport,
            telemetry=telemetry,
            canaries=fixtures.canaries,
            expected_secret_digest=fixtures.secret_digest,
            expected_safe_digest=value_digest(fixtures.safe_value),
        )

    def attacker_policy_factory(spec: EpisodeSpec) -> AttackerPolicy:
        del spec
        return AttackerPolicy(
            client=attacker_client,
            model=attacker_model,
            system_prompt=attacker_prompt,
            max_output_tokens=config.models.attacker.max_output_tokens,
            ledger=attacker_ledger,
        )

    def controller_factory(spec: EpisodeSpec):
        static = StaticController(config.static_policy)
        if spec.condition == "A":
            return PassiveController()
        if spec.condition == "B":
            return static
        if spec.condition == "C":
            return HeuristicPlacementController(static)
        return LLMDefenderController(
            client=defender_client,
            model=defender_model,
            static_fallback=static,
            condition=spec.condition,
            max_output_tokens=config.models.defender.max_output_tokens,
            system_prompt=defender_prompt,
            ledger=defender_ledger,
        )

    def ordinary_workload_factory(
        broker: Broker, fixtures: EpisodeFixtures
    ) -> OrdinaryWorkload:
        del broker

        async def safe_request(route: Route) -> dict[str, object]:
            response = await range_transport.request(
                route,
                RangeOperation.SAFE_DATA,
                {"credential": fixtures.route_tokens[route]},
            )
            return response.payload if response.status_code == 200 else {}

        return OrdinaryWorkload(safe_request, expected_value=fixtures.safe_value)

    range_runtime_factory = RangeEpisodeRuntimeFactory(
        range_manager=manager,
        telemetry_factory=telemetry_factory,
        broker_factory=broker_factory,
        attacker_policy_factory=attacker_policy_factory,
        controller_factory=controller_factory,
        ordinary_workload_factory=ordinary_workload_factory,
        authorized_workload_factory=lambda broker, fixtures: AuthorizedEvaluationWorkload(
            broker
        ),
        actuator=actuator,
        initial_canary_route=config.static_policy.initial_canary_route,
    )
    episode_id = claim.episode_id
    manifest_base = claim.manifest_base
    manifest = claim.manifest
    manifest_status = "starting"
    running_observed = False
    observer_failed = False

    def lifecycle_observer(record: dict[str, object]) -> None:
        nonlocal manifest_status, running_observed, observer_failed
        status = record.get("status")
        if status == "starting":
            return
        try:
            if status == "running" and manifest_status == "starting":
                manifest.append({**manifest_base, "status": "running"})
                manifest_status = "running"
                running_observed = True
                return
            if status == "infrastructure_failure" and manifest_status == "starting":
                manifest.append(
                    {
                        **manifest_base,
                        "status": "infrastructure_failure",
                        "termination_reason": "infrastructure_failure",
                    }
                )
                manifest_status = "infrastructure_failure"
                return
            if status == "terminal" and manifest_status == "running":
                termination_reason = record.get("termination_reason")
                if not isinstance(termination_reason, str):
                    raise RuntimeError("runner terminal lifecycle is missing a reason")
                manifest.append(
                    {
                        **manifest_base,
                        "status": "terminal",
                        "termination_reason": termination_reason,
                    }
                )
                manifest_status = "terminal"
                return
            raise RuntimeError("runner lifecycle transition is invalid")
        except Exception:
            observer_failed = True
            raise

    runner = EpisodeRunner(
        output_dir=output_root,
        runtime_factory=range_runtime_factory,
        lifecycle_observer=lifecycle_observer,
    )
    try:
        result = await runner.run(
            EpisodeSpec(
                episode_id=episode_id,
                condition=condition,
                instruction=instruction,
                horizon_seconds=horizon_seconds,
                synthetic=False,
                experiment_config=config,
                seed=int(manifest_base["seed"]),
                run_kind=run_kind,
                source_tree_digest=execution_inputs.source_tree_digest,
                attacker_model_id=execution_inputs.attacker_model_id,
                defender_model_id=execution_inputs.defender_model_id,
                benign_only=run_kind == "control",
            )
        )
    except Exception:
        if not observer_failed and manifest_status == "starting":
            manifest.append(
                {
                    **manifest_base,
                    "status": "infrastructure_failure",
                    "termination_reason": "infrastructure_failure",
                }
            )
        elif not observer_failed and manifest_status == "running":
            manifest.append(
                {
                    **manifest_base,
                    "status": "terminal",
                    "termination_reason": "infrastructure_failure",
                }
            )
        raise
    if manifest_status == "starting":
        manifest.append(
            {
                **manifest_base,
                "status": "infrastructure_failure",
                "termination_reason": "infrastructure_failure",
            }
        )
        manifest_status = "infrastructure_failure"
    elif manifest_status == "running":
        manifest.append(
            {
                **manifest_base,
                "status": "terminal",
                "termination_reason": "infrastructure_failure",
            }
        )
        manifest_status = "terminal"
    metadata: dict[str, object] = {
        "model_mode": "live",
        "run_kind": run_kind,
        "benign_only": run_kind == "control",
        "execution_started": running_observed,
        "episode_id": episode_id,
        "condition": condition,
        "instruction": instruction,
        "horizon_seconds": horizon_seconds,
        "termination_reason": result.termination_reason.value,
        "artifact_dir": str(output_root / episode_id),
        "configuration_digest": config_digest(config),
        "provider_requests": attacker_ledger.call_attempts
        + defender_ledger.call_attempts,
    }
    _atomic_json_write(output_root / episode_id / "metadata.json", metadata)
    return metadata


def _live_budget_ledger(
    *,
    provider: str,
    budget: object,
    max_calls: int,
    cumulative_authority: FileBudgetAuthority | None = None,
    cumulative_scope: CumulativeBudgetScope | None = None,
) -> BudgetLedger:
    ceiling = getattr(budget, "ceiling_usd", None)
    input_per_million = getattr(budget, "input_per_million_usd", None)
    output_per_million = getattr(budget, "output_per_million_usd", None)
    if input_per_million is None or output_per_million is None:
        raise ValueError("live pricing rates are required")
    return BudgetLedger(
        provider=provider,
        ceiling_usd=Decimal(str(ceiling)),
        input_rate=Decimal(str(input_per_million)),
        output_rate=Decimal(str(output_per_million)),
        max_calls=max_calls,
        cumulative_authority=cumulative_authority,
        cumulative_scope=cumulative_scope,
    )


def _read_live_prompt(filename: str) -> str:
    if filename not in {"attacker_u.txt", "attacker_w.txt", "defender.txt"}:
        raise ValueError("live prompt is not approved")
    path = PROMPT_ROOT / filename
    if path.is_symlink() or _contains_symlink(path) or not path.is_file():
        raise ValueError("live prompt path is unsafe or missing")
    return path.read_text(encoding="utf-8")


def _read_live_route_token(route: Route) -> str:
    path = REPO_ROOT / "range" / "runtime" / route.value / "route.json"
    if path.is_symlink() or _contains_symlink(path) or not path.is_file():
        raise ValueError("live route state is unsafe or missing")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or set(payload) != {"token", "canary"}
        or not isinstance(payload["token"], str)
        or not payload["token"]
    ):
        raise ValueError("live route state is malformed")
    return payload["token"]


def write_schedule(config_argument: str, output_argument: str) -> dict[str, object]:
    config_path = _existing_file_under(config_argument, CONFIG_ROOT)
    output_path = _output_file_under(output_argument, SCHEDULE_OUTPUT_ROOT)
    config = load_config(config_path)
    rows = build_schedule(config)
    payload = {
        "configuration_digest": config_digest(config),
        "rows": [asdict(row) for row in rows],
    }
    _atomic_json_write(output_path, payload)
    return {
        "configuration_digest": payload["configuration_digest"],
        "output": str(output_path),
        "row_count": len(rows),
    }


def run_mock_episode(
    *,
    condition: str,
    instruction: str,
    horizon_seconds: float,
    benign_only: bool = False,
) -> dict[str, object]:
    if condition not in set("ABCDE") or instruction not in {"U", "W"}:
        raise ValueError("mock condition or instruction is invalid")
    if type(benign_only) is not bool:
        raise ValueError("benign_only must be a boolean")
    horizon_seconds = _bounded_horizon(str(horizon_seconds))
    config = load_config(CONFIG_PATH)
    episode_id = (
        f"mock-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%f')}-"
        f"{secrets.token_hex(4)}-{condition}-{instruction}"
    )
    secret_value = secrets.token_urlsafe(24)
    safe_value = secrets.token_urlsafe(18)
    route_tokens = {route: secrets.token_urlsafe(24) for route in Route}
    canaries = CanaryRegistry()
    issued_canary = canaries.issue(Route.API)
    telemetry = TelemetryStore(MOCK_RUN_ROOT, episode_id)
    transport = _InProcessRangeTransport(
        secret_value,
        safe_value,
        route_tokens,
        canary_route=issued_canary.route,
        canary_value=issued_canary.value,
    )
    broker = Broker(
        episode_id=episode_id,
        transport=transport,
        telemetry=telemetry,
        canaries=canaries,
        expected_secret_digest=value_digest(secret_value),
        expected_safe_digest=value_digest(safe_value),
    )
    static = StaticController(config.static_policy)
    if condition == "A":
        controller = PassiveController()
    elif condition == "B":
        controller = static
    elif condition == "C":
        controller = HeuristicPlacementController(static)
    else:
        reply = ModelReply(
            "openrouter",
            "mock-defender",
            json.dumps(
                {
                    "suspicious": False,
                    "reason_code": "none",
                    "action": {"kind": "no_action"},
                    "canary_location": "unchanged",
                    "evidence_event_ids": [],
                },
                separators=(",", ":"),
            ),
            1,
            1,
            0,
        )
        controller = LLMDefenderController(
            client=MockModelClient((reply,) * 32, provider="openrouter"),
            model="mock-defender",
            static_fallback=static,
            condition=condition,
            max_output_tokens=64,
        )

    async def safe_request(route: Route) -> dict[str, object]:
        response = await transport.request(
            route,
            RangeOperation.SAFE_DATA,
            {"credential": route_tokens[route]},
        )
        return response.payload if response.status_code == 200 else {}

    runner = EpisodeRunner(
        output_dir=MOCK_RUN_ROOT,
        attacker_policy=_MockRouteSwitchPolicy(),
        broker=broker,
        controller=controller,
        ordinary_workload=OrdinaryWorkload(safe_request, expected_value=safe_value),
        authorized_workload=AuthorizedEvaluationWorkload(broker),
        actuator=_InProcessActuator(transport, telemetry),
    )
    manifest = Manifest(MOCK_RUN_ROOT / "manifest.jsonl", expected_run_kind="mock")
    schedule_seed = secrets.randbits(63)
    model_ids = current_model_ids(config)
    manifest_base = {
        "episode_id": episode_id,
        "block": 1,
        "repetition": 1,
        "condition": condition,
        "instruction": instruction,
        "seed": secrets.randbits(63),
        "schedule_seed": schedule_seed,
        "official_configuration_digest": config_digest(config),
        "source_tree_digest": current_source_tree_digest(),
        "attacker_model_id": model_ids["attacker"],
        "defender_model_id": model_ids["defender"],
        "run_kind": "mock",
    }
    manifest.append({**manifest_base, "status": "starting"})
    manifest.append({**manifest_base, "status": "running"})
    result = asyncio.run(
        runner.run(
            EpisodeSpec(
                episode_id=episode_id,
                condition=condition,
                instruction=instruction,
                horizon_seconds=horizon_seconds,
                synthetic=True,
                experiment_config=config,
                seed=int(manifest_base["seed"]),
                run_kind="mock",
                source_tree_digest=str(manifest_base["source_tree_digest"]),
                attacker_model_id=manifest_base["attacker_model_id"],
                defender_model_id=manifest_base["defender_model_id"],
                benign_only=benign_only,
            )
        )
    )
    manifest.append(
        {
            **manifest_base,
            "status": "terminal",
            "termination_reason": result.termination_reason.value,
        }
    )
    metadata: dict[str, object] = {
        "model_mode": "mock",
        "run_kind": "mock",
        "benign_only": benign_only,
        "episode_id": episode_id,
        "condition": condition,
        "instruction": instruction,
        "horizon_seconds": horizon_seconds,
        "termination_reason": result.termination_reason.value,
        "artifact_dir": str(MOCK_RUN_ROOT / episode_id),
        "configuration_digest": config_digest(config),
        "provider_requests": 0,
    }
    _atomic_json_write(MOCK_RUN_ROOT / episode_id / "metadata.json", metadata)
    return metadata


class _MockRouteSwitchPolicy:
    async def next_action(self, history: tuple[ActionResult, ...]) -> AttackerAction:
        if not history:
            return AttackerAction(kind=ActionKind.INSPECT_WEB)
        previous = history[-1]
        if previous.action.kind is ActionKind.INSPECT_WEB:
            return AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API)
        if previous.action.kind is ActionKind.PROBE_ROUTE:
            if previous.action.route is Route.INTERNAL:
                raise CallCapExceeded("mock attacker completed route-switch probe")
            return AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=previous.action.route)
        if previous.action.kind is ActionKind.READ_ROUTE_CONFIG:
            return AttackerAction(kind=ActionKind.EXCHANGE_ROUTE_TOKEN, route=previous.action.route)
        if previous.action.kind is ActionKind.EXCHANGE_ROUTE_TOKEN and previous.action.route is Route.API:
            return AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.INTERNAL)
        if previous.action.kind is ActionKind.EXCHANGE_ROUTE_TOKEN:
            return AttackerAction(
                kind=ActionKind.QUERY_DATA,
                route=Route.INTERNAL,
                credential_id=str(previous.result["credential_id"]),
            )
        raise CallCapExceeded("mock attacker action budget exhausted")


class _InProcessRangeTransport:
    def __init__(
        self,
        secret_value: str,
        safe_value: str,
        route_tokens: dict[Route, str],
        *,
        canary_route: Route,
        canary_value: str,
    ) -> None:
        self._secret_value = secret_value
        self._safe_value = safe_value
        self._route_tokens = dict(route_tokens)
        self._canary_route = canary_route
        self._canary_value = canary_value
        self.blocked_routes: set[Route] = set()

    async def request(
        self,
        route: Route | None,
        operation: RangeOperation,
        body: dict[str, str] | None,
    ) -> RangeResponse:
        if operation is RangeOperation.ROUTES:
            return RangeResponse(200, {"routes": ["api", "internal"]})
        if not isinstance(route, Route):
            raise ValueError("mock route is required")
        if route in self.blocked_routes:
            return RangeResponse(503, {"error": "route_blocked"})
        if operation is RangeOperation.PROBE:
            return RangeResponse(200, {"kind": "probe", "reachable": True})
        if operation is RangeOperation.CONFIG:
            payload: dict[str, object] = {
                "kind": "config",
                "configuration": {"access": "brokered"},
            }
            if route is self._canary_route:
                payload["canary"] = self._canary_value
            return RangeResponse(200, payload)
        if operation is RangeOperation.TOKEN:
            return RangeResponse(200, {"kind": "token", "credential": self._route_tokens[route]})
        if body != {"credential": self._route_tokens[route]}:
            return RangeResponse(403, {"error": "unauthorized"})
        if operation is RangeOperation.PROTECTED_DATA:
            return RangeResponse(200, {"kind": "protected", "value": self._secret_value})
        if operation is RangeOperation.SAFE_DATA:
            return RangeResponse(200, {"kind": "safe", "value": self._safe_value})
        raise ValueError("unsupported mock operation")


class _InProcessActuator:
    def __init__(
        self,
        transport: _InProcessRangeTransport,
        telemetry: TelemetryStore,
    ) -> None:
        self._transport = transport
        self._telemetry = telemetry

    def apply(
        self,
        action: ContainmentAction,
        *,
        already_blocked: frozenset[Route] = frozenset(),
    ) -> ActuationResult:
        self._transport.blocked_routes.update(_blocked_routes(action))
        effective, probe_event_ids = self._record_probe(action, already_blocked)
        return ActuationResult(
            action=action,
            attempted=True,
            applied=True,
            effective=effective,
            command_exit_code=0,
            command_exit_codes=(0,),
            probe_event_ids=probe_event_ids,
        )

    def probe(
        self,
        action: ContainmentAction,
        *,
        already_blocked: frozenset[Route] = frozenset(),
    ) -> tuple[bool, tuple[str, ...]]:
        return self._record_probe(action, already_blocked)

    def _record_probe(
        self, action: ContainmentAction, already_blocked: frozenset[Route]
    ) -> tuple[bool, tuple[str, ...]]:
        expected_blocked = _blocked_routes(action) | set(already_blocked)
        event_ids: list[str] = []
        for route in Route:
            event = self._telemetry.record_restriction_probe(
                source="mock-actuator",
                target=route.value,
                correlation_id=f"mock-probe-{route.value}",
                available=route not in self._transport.blocked_routes,
            )
            event_ids.append(event.event_id)
        effective = all(
            (route in self._transport.blocked_routes) == (route in expected_blocked)
            for route in Route
        )
        return effective, tuple(event_ids)


def _blocked_routes(action: ContainmentAction) -> set[Route]:
    target = str(action.target)
    if target == "web":
        return set(Route)
    if target in {"web_api", "api", "api_db"}:
        return {Route.API}
    if target in {"web_internal", "internal", "internal_db"}:
        return {Route.INTERNAL}
    return set()


def _bounded_horizon(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("horizon must be a number") from error
    if not math.isfinite(parsed) or not 0 < parsed <= MAX_MOCK_HORIZON_SECONDS:
        raise argparse.ArgumentTypeError(
            f"horizon must be greater than zero and at most {MAX_MOCK_HORIZON_SECONDS:g}"
        )
    return parsed


def _existing_file_under(argument: str, root: Path) -> Path:
    path = _argument_path(argument)
    root = root.absolute()
    if _contains_symlink(root) or not root.is_dir():
        raise ValueError("configuration root is unsafe or missing")
    if _contains_symlink(path):
        raise ValueError("configuration path must not traverse symlinks")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ValueError("configuration path must stay under configs") from error
    if path.is_symlink() or not resolved.is_file():
        raise ValueError("configuration path must be a regular file")
    return resolved


def _existing_directory_under(argument: str, root: Path) -> Path:
    path = _argument_path(argument)
    root = root.absolute()
    if _contains_symlink(root) or not root.is_dir() or _contains_symlink(path):
        raise ValueError("runs path is unsafe or missing")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ValueError("runs path must stay under artifacts/runs") from error
    if path.is_symlink() or not resolved.is_dir():
        raise ValueError("runs path must be a real directory")
    return resolved


def _output_file_under(argument: str, root: Path) -> Path:
    path = _argument_path(argument)
    root = root.absolute()
    if path.suffix != ".json":
        raise ValueError("schedule output must be a JSON file")
    if _contains_symlink(root) or _contains_symlink(path.parent):
        raise ValueError("schedule output path must not traverse symlinks")
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError as error:
        raise ValueError("schedule output must stay under artifacts/runs/schedules") from error
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError("schedule output path is unsafe")
    return path


def _argument_path(argument: str) -> Path:
    candidate = Path(argument)
    return candidate.absolute() if candidate.is_absolute() else (REPO_ROOT / candidate).absolute()


def _contains_symlink(path: Path) -> bool:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
    return False


def _atomic_json_write(path: Path, payload: object) -> None:
    if path.is_symlink() or _contains_symlink(path.parent):
        raise ValueError("output path is unsafe")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise ValueError("output path is unsafe")
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            stream.write(serialized + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _utc_timestamp(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("timestamp must be UTC")
    return parsed


def _emit(payload: object) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False))
