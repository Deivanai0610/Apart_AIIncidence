from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest


def _pilot_record(episode_id: str) -> dict[str, object]:
    return {
        "episode_id": episode_id,
        "block": 1,
        "repetition": 1,
        "condition": "A",
        "instruction": "U",
        "seed": 1,
        "schedule_seed": 1,
        "official_configuration_digest": "a" * 64,
        "source_tree_digest": "b" * 64,
        "attacker_model_id": "attacker-model",
        "defender_model_id": "defender-model",
        "run_kind": "pilot",
        "status": "starting",
    }


def test_distinct_claims_cannot_enter_live_range_together(tmp_path: Path) -> None:
    manifest_path = tmp_path / "pilot" / "manifest.jsonl"
    lease_path = tmp_path / "runs" / ".live-range.lock"
    events_path = tmp_path / "events.jsonl"
    gate_path = tmp_path / "start"
    script = """
import json
import sys
import time
from pathlib import Path
from chimera.live_lease import LiveRangeLease
from chimera.schedule import Manifest

manifest_path = Path(sys.argv[1])
lease_path = Path(sys.argv[2])
events_path = Path(sys.argv[3])
gate_path = Path(sys.argv[4])
record = json.loads(sys.argv[5])
Manifest(manifest_path, expected_run_kind="pilot").append(record)
while not gate_path.exists():
    time.sleep(0.001)
with LiveRangeLease(lease_path):
    with events_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"episode_id": record["episode_id"], "event": "enter"}) + "\\n")
        stream.flush()
    time.sleep(0.15)
    with events_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"episode_id": record["episode_id"], "event": "exit"}) + "\\n")
        stream.flush()
"""
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(manifest_path),
                str(lease_path),
                str(events_path),
                str(gate_path),
                json.dumps(_pilot_record(f"pilot-{index}")),
            ],
            cwd=Path.cwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(2)
    ]
    gate_path.write_text("start", encoding="utf-8")
    results = [process.communicate(timeout=10) for process in processes]

    assert all(process.returncode == 0 for process in processes), results
    events = [json.loads(line) for line in events_path.read_text().splitlines()]
    assert [event["event"] for event in events] == ["enter", "exit", "enter", "exit"]
    assert events[0]["episode_id"] == events[1]["episode_id"]
    assert events[2]["episode_id"] == events[3]["episode_id"]
    assert events[0]["episode_id"] != events[2]["episode_id"]
    assert stat.S_IMODE(lease_path.stat().st_mode) == 0o600


def test_live_range_lease_rejects_symlink_substitution(tmp_path: Path) -> None:
    from chimera.live_lease import LiveRangeLease, LiveRangeLeaseError

    outside = tmp_path / "outside"
    outside.write_text("unchanged", encoding="utf-8")
    lease_path = tmp_path / ".live-range.lock"
    lease_path.symlink_to(outside)

    with pytest.raises(LiveRangeLeaseError, match="unsafe"):
        with LiveRangeLease(lease_path):
            raise AssertionError("unsafe lease must not be entered")

    assert outside.read_text(encoding="utf-8") == "unchanged"


def test_live_range_lease_can_be_inherited_by_an_authorized_child(
    tmp_path: Path,
) -> None:
    from chimera.live_lease import (
        LiveRangeLease,
        live_range_lease_subprocess_options,
    )

    lease_path = tmp_path / ".live-range.lock"
    script = """
from pathlib import Path
import sys
from chimera.live_lease import LiveRangeLease

with LiveRangeLease(Path(sys.argv[1])):
    print("entered")
"""
    with LiveRangeLease(lease_path):
        lease_environment, pass_fds = live_range_lease_subprocess_options()
        completed = subprocess.run(
            [sys.executable, "-c", script, str(lease_path)],
            cwd=Path.cwd(),
            env={**os.environ, **lease_environment},
            pass_fds=pass_fds,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "entered"
