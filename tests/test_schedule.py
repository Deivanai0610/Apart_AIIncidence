from __future__ import annotations

import json
import random
import re
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path

import pytest

from chimera.config import ExperimentConfig, config_digest, load_config
from chimera.schedule import (
    Manifest,
    ManifestError,
    ScheduleLoadError,
    build_schedule,
    load_schedule_item,
)


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


def _record(item: object, status: str, **updates: object) -> dict[str, object]:
    record = {**asdict(item), "run_kind": "measured", "status": status}
    record.update(updates)
    return record


def test_schedule_has_four_complete_randomized_blocks(
    frozen_config: ExperimentConfig,
) -> None:
    schedule = build_schedule(frozen_config)

    assert len(schedule) == 40
    for block in range(1, 5):
        cells = {
            (item.condition, item.instruction)
            for item in schedule
            if item.block == block
        }
        assert cells == {(condition, instruction) for condition in "ABCDE" for instruction in "UW"}
    assert schedule == build_schedule(frozen_config)


def test_fourth_block_extends_the_three_block_schedule_without_changing_it(
    frozen_config: ExperimentConfig,
) -> None:
    """Blocks 1-3 ran under the three-block configuration. Adding block 4 must
    reproduce their rows exactly (IDs, seeds, order); only the configuration
    digest may differ, because the block count is part of the digest."""
    three_block = ExperimentConfig.model_validate(
        {**frozen_config.model_dump(mode="json"), "schedule": {**frozen_config.schedule.model_dump(mode="json"), "blocks": 3}}
    )
    four_block = ExperimentConfig.model_validate(
        {**frozen_config.model_dump(mode="json"), "schedule": {**frozen_config.schedule.model_dump(mode="json"), "blocks": 4}}
    )

    original = build_schedule(three_block)
    extended = build_schedule(four_block)

    assert len(original) == 30 and len(extended) == 40
    stable_fields = (
        "episode_id",
        "block",
        "repetition",
        "condition",
        "instruction",
        "seed",
        "schedule_seed",
        "source_tree_digest",
        "attacker_model_id",
        "defender_model_id",
    )
    for before, after in zip(original, extended[:30], strict=True):
        assert all(getattr(before, f) == getattr(after, f) for f in stable_fields)
        assert before.official_configuration_digest != after.official_configuration_digest
    assert {item.block for item in extended[30:]} == {4}
    assert len({item.episode_id for item in extended}) == 40


def test_schedule_order_is_not_grouped_by_condition(
    frozen_config: ExperimentConfig,
) -> None:
    first_block = [
        item.condition for item in build_schedule(frozen_config) if item.block == 1
    ]

    assert first_block != sorted(first_block)


def test_schedule_rows_are_immutable_unique_and_bound_to_frozen_config(
    frozen_config: ExperimentConfig,
) -> None:
    schedule = build_schedule(frozen_config)
    ids = [item.episode_id for item in schedule]

    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"b0[1-4]-r0[1-4]-[A-E]-[UW]-[0-9a-f]{12}", episode_id) for episode_id in ids)
    assert all(item.seed >= 0 for item in schedule)
    assert all(item.schedule_seed == frozen_config.schedule.seed for item in schedule)
    assert all(item.official_configuration_digest == config_digest(frozen_config) for item in schedule)
    assert all(item.source_tree_digest == schedule[0].source_tree_digest for item in schedule)
    assert all(item.attacker_model_id == "attacker-model" for item in schedule)
    assert all(item.defender_model_id == "defender-model" for item in schedule)
    first = schedule[0]
    with pytest.raises(FrozenInstanceError):
        first.condition = "E"  # type: ignore[misc]


def test_schedule_loader_rejects_resolved_model_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    frozen_config: ExperimentConfig,
) -> None:
    rows = build_schedule(frozen_config)
    path = tmp_path / "schedule.json"
    path.write_text(
        json.dumps(
            {
                "configuration_digest": config_digest(frozen_config),
                "rows": [asdict(row) for row in rows],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "changed-attacker-model")

    with pytest.raises(ScheduleLoadError, match="deterministic"):
        load_schedule_item(
            path,
            episode_id=rows[0].episode_id,
            config=frozen_config,
            allowed_root=tmp_path,
        )


def test_schedule_loader_rejects_source_tree_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    frozen_config: ExperimentConfig,
) -> None:
    from chimera import schedule as schedule_module

    rows = build_schedule(frozen_config)
    path = tmp_path / "schedule.json"
    path.write_text(
        json.dumps(
            {
                "configuration_digest": config_digest(frozen_config),
                "rows": [asdict(row) for row in rows],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        schedule_module,
        "current_source_tree_digest",
        lambda: "f" * 64,
        raising=False,
    )

    with pytest.raises(ScheduleLoadError, match="deterministic"):
        load_schedule_item(
            path,
            episode_id=rows[0].episode_id,
            config=frozen_config,
            allowed_root=tmp_path,
        )


def test_schedule_rejects_candidate_or_incomplete_live_config() -> None:
    candidate = load_config(Path("configs/experiment.yaml")).model_copy(
        update={"status": "candidate"}
    )
    with pytest.raises(ValueError, match="frozen"):
        build_schedule(candidate)

    payload = candidate.model_dump(mode="json")
    payload["status"] = "frozen"
    for role in ("attacker", "defender"):
        payload["models"][role].update(
            {
                "pinned_provider_slug": f"verified-{role}",
                "expected_provider_name": f"Verified {role.title()}",
                "expected_endpoint_model": f"provider/{role}-v1",
            }
        )
    payload["budgets"]["openrouter"]["defender"][
        "input_per_million_usd"
    ] = None
    incomplete = ExperimentConfig.model_validate(payload)
    with pytest.raises(ValueError, match="pricing"):
        build_schedule(incomplete)


def test_schedule_does_not_mutate_global_random_state(
    frozen_config: ExperimentConfig,
) -> None:
    random.seed(90210)
    expected = random.random()
    random.seed(90210)

    build_schedule(frozen_config)

    assert random.random() == expected


def test_schedule_revalidates_model_copy_bypasses(
    frozen_config: ExperimentConfig,
) -> None:
    invalid_values = (
        frozen_config.model_copy(
            update={
                "schedule": frozen_config.schedule.model_copy(update={"blocks": 1})
            }
        ),
        frozen_config.model_copy(
            update={
                "schedule": frozen_config.schedule.model_copy(update={"seed": -1})
            }
        ),
        frozen_config.model_copy(
            update={
                "budgets": frozen_config.budgets.model_copy(
                    update={
                        "openrouter": frozen_config.budgets.openrouter.model_copy(
                            update={
                                "attacker": frozen_config.budgets.openrouter.attacker.model_copy(
                                    update={"input_per_million_usd": float("inf")}
                                )
                            }
                        )
                    }
                )
            }
        ),
    )

    for invalid in invalid_values:
        with pytest.raises(ValueError, match="configuration"):
            build_schedule(invalid)


def test_schedule_loader_returns_only_the_exact_deterministic_row(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    rows = build_schedule(frozen_config)
    path = tmp_path / "schedule.json"
    path.write_text(
        json.dumps(
            {
                "configuration_digest": config_digest(frozen_config),
                "rows": [asdict(row) for row in rows],
            }
        ),
        encoding="utf-8",
    )

    loaded = load_schedule_item(
        path,
        episode_id=rows[7].episode_id,
        config=frozen_config,
        allowed_root=tmp_path,
    )

    assert loaded == rows[7]


def test_schedule_loader_rejects_modified_or_missing_rows(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    rows = build_schedule(frozen_config)
    payload = {
        "configuration_digest": config_digest(frozen_config),
        "rows": [asdict(row) for row in rows],
    }
    payload["rows"][0]["seed"] += 1
    path = tmp_path / "schedule.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ScheduleLoadError, match="deterministic"):
        load_schedule_item(
            path,
            episode_id=rows[0].episode_id,
            config=frozen_config,
            allowed_root=tmp_path,
        )

    payload["rows"] = [asdict(row) for row in rows]
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ScheduleLoadError, match="episode ID"):
        load_schedule_item(
            path,
            episode_id="missing-episode",
            config=frozen_config,
            allowed_root=tmp_path,
        )


def test_schedule_loader_rejects_candidate_digest_and_symlink_escape(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    rows = build_schedule(frozen_config)
    outside = tmp_path / "outside"
    outside.mkdir()
    path = outside / "schedule.json"
    path.write_text(
        json.dumps(
            {
                "configuration_digest": config_digest(frozen_config),
                "rows": [asdict(row) for row in rows],
            }
        ),
        encoding="utf-8",
    )
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ScheduleLoadError, match="unsafe"):
        load_schedule_item(
            linked / "schedule.json",
            episode_id=rows[0].episode_id,
            config=frozen_config,
            allowed_root=tmp_path,
        )

    candidate = load_config(Path("configs/experiment.yaml")).model_copy(
        update={"status": "candidate"}
    )
    with pytest.raises(ScheduleLoadError, match="frozen"):
        load_schedule_item(
            path,
            episode_id=rows[0].episode_id,
            config=candidate,
            allowed_root=outside,
        )


def test_manifest_persists_valid_append_only_lifecycle(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    item = build_schedule(frozen_config)[0]
    manifest = Manifest(tmp_path / "manifest.jsonl")

    manifest.append(_record(item, "starting"))
    manifest.append(_record(item, "running"))
    manifest.append(
        _record(item, "terminal", termination_reason="fixed_horizon")
    )

    records = [
        json.loads(line)
        for line in (tmp_path / "manifest.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [record["status"] for record in records] == [
        "starting",
        "running",
        "terminal",
    ]
    assert records[0]["episode_id"] == item.episode_id


def test_manifest_requires_run_kind_on_new_and_existing_records(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    item = build_schedule(frozen_config)[0]
    missing_kind = _record(item, "starting")
    missing_kind.pop("run_kind")

    with pytest.raises(ManifestError, match="run_kind"):
        Manifest(tmp_path / "new.jsonl").append(missing_kind)

    existing_path = tmp_path / "existing.jsonl"
    existing_path.write_text(json.dumps(missing_kind) + "\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="run_kind"):
        Manifest(existing_path).records()


@pytest.mark.parametrize("run_kind", ["mock", "pilot", "measured"])
def test_manifest_enforces_expected_run_kind(
    tmp_path: Path,
    frozen_config: ExperimentConfig,
    run_kind: str,
) -> None:
    item = build_schedule(frozen_config)[0]
    manifest = Manifest(
        tmp_path / run_kind / "manifest.jsonl",
        expected_run_kind=run_kind,
    )

    manifest.append(_record(item, "starting", run_kind=run_kind))

    wrong_kind = "pilot" if run_kind != "pilot" else "measured"
    with pytest.raises(ManifestError, match="run_kind"):
        Manifest(
            tmp_path / run_kind / "manifest.jsonl",
            expected_run_kind=wrong_kind,
        ).records()


def test_manifest_allows_only_startup_failure_before_running(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    first, second = build_schedule(frozen_config)[:2]
    manifest = Manifest(tmp_path / "manifest.jsonl")

    manifest.append(_record(first, "starting"))
    manifest.append(
        _record(first, "infrastructure_failure", termination_reason="infrastructure_failure")
    )
    manifest.append(_record(second, "starting"))
    manifest.append(_record(second, "running"))

    with pytest.raises(ManifestError, match="transition"):
        manifest.append(
            _record(second, "infrastructure_failure", termination_reason="infrastructure_failure")
        )


def test_manifest_rejects_duplicates_regressions_and_metadata_changes(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    item = build_schedule(frozen_config)[0]
    manifest = Manifest(tmp_path / "manifest.jsonl")
    manifest.append(_record(item, "starting"))

    with pytest.raises(ManifestError, match="duplicate"):
        manifest.append(_record(item, "starting"))

    changed = _record(item, "running")
    changed["condition"] = "E" if item.condition != "E" else "A"
    with pytest.raises(ManifestError, match="immutable"):
        manifest.append(changed)

    manifest.append(_record(item, "running"))
    manifest.append(_record(item, "terminal", termination_reason="terminal_refusal"))
    with pytest.raises(ManifestError, match="transition"):
        manifest.append(_record(item, "running"))


def test_manifest_requires_valid_rerun_linkage_and_new_episode_id(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    original = build_schedule(frozen_config)[0]
    rerun = replace(
        original,
        episode_id=f"{original.episode_id}-rerun",
        seed=original.seed + 1,
    )
    manifest = Manifest(tmp_path / "manifest.jsonl")

    missing = _record(rerun, "starting", rerun_of="missing-episode")
    with pytest.raises(ManifestError, match="rerun_of"):
        manifest.append(missing)

    manifest.append(_record(original, "starting"))
    manifest.append(_record(original, "running"))
    manifest.append(
        _record(original, "terminal", termination_reason="infrastructure_failure")
    )
    manifest.append(_record(rerun, "starting", rerun_of=original.episode_id))

    same_id = _record(original, "starting", rerun_of=original.episode_id)
    with pytest.raises(ManifestError, match="duplicate"):
        manifest.append(same_id)

    wrong_treatment = _record(
        replace(
            rerun,
            episode_id=f"{original.episode_id}-wrong",
            condition="E" if original.condition != "E" else "A",
        ),
        "starting",
        rerun_of=original.episode_id,
    )
    with pytest.raises(ManifestError, match="rerun"):
        manifest.append(wrong_treatment)


def test_manifest_requires_rerun_link_for_repeated_schedule_cell(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    original = build_schedule(frozen_config)[0]
    duplicate = replace(
        original,
        episode_id=f"{original.episode_id}-duplicate",
        seed=original.seed + 1,
    )
    manifest = Manifest(tmp_path / "manifest.jsonl")
    manifest.append(_record(original, "starting"))
    manifest.append(_record(original, "running"))
    manifest.append(_record(original, "terminal", termination_reason="fixed_horizon"))

    with pytest.raises(ManifestError, match="rerun"):
        manifest.append(_record(duplicate, "starting"))


def test_manifest_rejects_unsafe_ids_and_invalid_existing_data(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    item = build_schedule(frozen_config)[0]
    manifest_path = tmp_path / "manifest.jsonl"
    manifest = Manifest(manifest_path)
    unsafe = _record(item, "starting")
    unsafe["episode_id"] = "../escape"

    with pytest.raises(ManifestError, match="episode_id"):
        manifest.append(unsafe)

    manifest_path.write_text('{"episode_id":', encoding="utf-8")
    with pytest.raises(ManifestError, match="malformed"):
        manifest.append(_record(item, "starting"))
    assert manifest_path.read_text(encoding="utf-8") == '{"episode_id":'


def test_manifest_serializes_concurrent_appends_within_process(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    schedule = build_schedule(frozen_config)
    manifest_path = tmp_path / "manifest.jsonl"
    manifest = Manifest(manifest_path)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda item: manifest.append(_record(item, "starting")), schedule))

    records = [json.loads(line) for line in manifest_path.read_text().splitlines()]
    assert len(records) == 40
    assert {record["episode_id"] for record in records} == {
        item.episode_id for item in schedule
    }


def test_manifest_claim_is_atomic_across_independent_processes(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    item = build_schedule(frozen_config)[0]
    manifest_path = tmp_path / "manifest.jsonl"
    gate_path = tmp_path / "start"
    record = json.dumps(
        {**_record(item, "starting"), "run_kind": "measured"},
        separators=(",", ":"),
    )
    script = """
import json
import sys
import time
from pathlib import Path
from chimera.schedule import Manifest, ManifestError

manifest_path = Path(sys.argv[1])
record = json.loads(sys.argv[2])
gate_path = Path(sys.argv[3])
while not gate_path.exists():
    time.sleep(0.001)
try:
    Manifest(manifest_path).append(record)
except ManifestError:
    print("rejected")
else:
    print("claimed")
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(manifest_path), record, str(gate_path)],
            cwd=Path.cwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(8)
    ]
    gate_path.write_text("start", encoding="utf-8")
    results = [process.communicate(timeout=10) for process in processes]

    assert all(process.returncode == 0 for process in processes), results
    assert [stdout.strip() for stdout, _ in results].count("claimed") == 1
    assert [stdout.strip() for stdout, _ in results].count("rejected") == 7
    records = Manifest(manifest_path).records()
    assert len(records) == 1
    assert records[0]["status"] == "starting"
    lock_path = tmp_path / ".manifest.jsonl.lock"
    assert lock_path.is_file()
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600


def test_manifest_rejects_substituted_fixed_lock_file(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    outside = tmp_path / "outside"
    outside.write_text("unchanged", encoding="utf-8")
    lock_path = tmp_path / ".manifest.jsonl.lock"
    lock_path.symlink_to(outside)

    with pytest.raises(ManifestError, match="lock"):
        Manifest(tmp_path / "manifest.jsonl").append(
            _record(build_schedule(frozen_config)[0], "starting")
        )

    assert outside.read_text(encoding="utf-8") == "unchanged"
    assert not (tmp_path / "manifest.jsonl").exists()


def test_manifest_rejects_obsolete_termination_and_duplicate_json_keys(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    item = build_schedule(frozen_config)[0]
    manifest = Manifest(tmp_path / "manifest.jsonl")
    manifest.append(_record(item, "starting"))
    manifest.append(_record(item, "running"))

    with pytest.raises(ManifestError, match="termination_reason"):
        manifest.append(
            _record(item, "terminal", termination_reason="route_blocked")
        )

    duplicate = json.dumps(_record(item, "starting"), separators=(",", ":"))
    duplicate = duplicate[:-1] + ',"status":"terminal"}\n'
    path = tmp_path / "duplicate.jsonl"
    path.write_text(duplicate, encoding="utf-8")
    with pytest.raises(ManifestError, match="malformed"):
        Manifest(path).records()


def test_manifest_rejects_symlinked_parent(
    tmp_path: Path, frozen_config: ExperimentConfig
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ManifestError, match="symlink"):
        Manifest(linked / "manifest.jsonl").append(
            _record(build_schedule(frozen_config)[0], "starting")
        )
    assert list(outside.iterdir()) == []

    outside_manifest = outside / "manifest.jsonl"
    safe_manifest = Manifest(outside_manifest)
    safe_manifest.append(_record(build_schedule(frozen_config)[0], "starting"))
    with pytest.raises(ManifestError, match="symlink"):
        Manifest(linked / "manifest.jsonl").records()


def test_manifest_rejects_excessively_nested_json_without_crashing(
    tmp_path: Path,
) -> None:
    nested = "[" * 1_500 + "0" + "]" * 1_500
    path = tmp_path / "manifest.jsonl"
    path.write_text('{"nested":' + nested + '}\n', encoding="utf-8")

    with pytest.raises(ManifestError, match="malformed"):
        Manifest(path).records()
