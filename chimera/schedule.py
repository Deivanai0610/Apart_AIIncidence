from __future__ import annotations

import fcntl
import json
import math
import os
import random
import re
import stat
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Iterator, Literal, Mapping

from chimera.config import ExperimentConfig, config_digest
from chimera.provenance import current_model_ids, current_source_tree_digest
from chimera.telemetry import validate_episode_id


_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_RECORD_BYTES = 64 * 1024
_MAX_SCHEDULE_BYTES = 2 * 1024 * 1024
_LOCK_REGISTRY_GUARD = Lock()
_LOCKS: dict[str, Lock] = {}


class ManifestError(ValueError):
    pass


class ScheduleLoadError(ValueError):
    pass


@dataclass(frozen=True)
class ScheduleItem:
    episode_id: str
    block: int
    repetition: int
    condition: Literal["A", "B", "C", "D", "E"]
    instruction: Literal["U", "W"]
    seed: int
    schedule_seed: int
    official_configuration_digest: str
    source_tree_digest: str
    attacker_model_id: str
    defender_model_id: str


_IMMUTABLE_FIELDS = (
    "block",
    "repetition",
    "condition",
    "instruction",
    "seed",
    "schedule_seed",
    "official_configuration_digest",
    "source_tree_digest",
    "attacker_model_id",
    "defender_model_id",
)
_STATUSES = frozenset({"starting", "running", "terminal", "infrastructure_failure"})
_TERMINATIONS = frozenset(
    {
        "secret_retrieved",
        "canary_quarantine",
        "terminal_refusal",
        "invalid_output",
        "attacker_call_cap",
        "fixed_horizon",
        "infrastructure_failure",
    }
)


def build_schedule(config: ExperimentConfig) -> tuple[ScheduleItem, ...]:
    if not isinstance(config, ExperimentConfig):
        raise TypeError("config must be an ExperimentConfig")
    try:
        config = ExperimentConfig.model_validate(config.model_dump(mode="json"))
    except ValueError as error:
        raise ValueError("configuration must pass strict validation") from error
    if config.status != "frozen":
        raise ValueError("configuration must be frozen before scheduling")
    config.validate_frozen_provider_controls()
    for provider in (
        config.budgets.openrouter.attacker,
        config.budgets.openrouter.defender,
    ):
        if (
            provider.input_per_million_usd is None
            or provider.output_per_million_usd is None
        ):
            raise ValueError("provider pricing must be complete before scheduling")

    official_digest = config_digest(config)
    source_tree_digest = current_source_tree_digest()
    model_ids = current_model_ids(config)
    attacker_model_id = model_ids["attacker"]
    defender_model_id = model_ids["defender"]
    if not isinstance(attacker_model_id, str) or not isinstance(defender_model_id, str):
        raise ValueError("resolved attacker and defender model IDs are required")
    rows: list[ScheduleItem] = []
    for block in range(1, config.schedule.blocks + 1):
        rng = random.Random(config.schedule.seed + block)
        cells = [
            (condition, instruction)
            for condition in config.schedule.conditions
            for instruction in config.schedule.instructions
        ]
        rng.shuffle(cells)
        for condition, instruction in cells:
            episode_seed = rng.getrandbits(63)
            suffix = f"{rng.getrandbits(48):012x}"
            episode_id = (
                f"b{block:02d}-r{block:02d}-{condition}-{instruction}-{suffix}"
            )
            rows.append(
                ScheduleItem(
                    episode_id=episode_id,
                    block=block,
                    repetition=block,
                    condition=condition,
                    instruction=instruction,
                    seed=episode_seed,
                    schedule_seed=config.schedule.seed,
                    official_configuration_digest=official_digest,
                    source_tree_digest=source_tree_digest,
                    attacker_model_id=attacker_model_id,
                    defender_model_id=defender_model_id,
                )
            )
    if len(rows) != config.schedule.attack_episode_count or len(
        {row.episode_id for row in rows}
    ) != len(rows):
        raise RuntimeError("deterministic schedule generation failed")
    return tuple(rows)


def load_schedule_item(
    path: Path,
    *,
    episode_id: str,
    config: ExperimentConfig,
    allowed_root: Path,
) -> ScheduleItem:
    if config.status != "frozen":
        raise ScheduleLoadError("configuration must be frozen before loading a schedule")
    try:
        validate_episode_id(episode_id)
    except (TypeError, ValueError) as error:
        raise ScheduleLoadError("schedule episode ID is invalid") from error
    candidate = Path(path).absolute()
    root = Path(allowed_root).absolute()
    try:
        _reject_symlink_components(root)
        _reject_symlink_components(candidate)
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
        if resolved != candidate or not resolved.is_file():
            raise ScheduleLoadError("schedule path is unsafe")
        raw = resolved.read_bytes()
    except ScheduleLoadError:
        raise
    except (OSError, ValueError) as error:
        raise ScheduleLoadError("schedule path is unsafe or missing") from error
    if len(raw) > _MAX_SCHEDULE_BYTES:
        raise ScheduleLoadError("schedule payload exceeds size limit")
    try:
        payload = _strict_json_loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        raise ScheduleLoadError("schedule payload is malformed") from error
    if not isinstance(payload, dict) or set(payload) != {
        "configuration_digest",
        "rows",
    }:
        raise ScheduleLoadError("schedule payload shape is invalid")
    expected_digest = config_digest(config)
    if payload["configuration_digest"] != expected_digest:
        raise ScheduleLoadError("schedule configuration digest differs")
    expected_rows = build_schedule(config)
    expected_payload = [asdict(row) for row in expected_rows]
    if payload["rows"] != expected_payload:
        raise ScheduleLoadError("schedule rows differ from deterministic schedule")
    matches = [row for row in expected_rows if row.episode_id == episode_id]
    if len(matches) != 1:
        raise ScheduleLoadError("schedule episode ID was not found exactly once")
    return matches[0]


class Manifest:
    def __init__(
        self,
        path: Path,
        *,
        expected_run_kind: Literal["mock", "pilot", "measured", "control"] | None = None,
    ) -> None:
        self.path = Path(path).absolute()
        if expected_run_kind not in {None, "mock", "pilot", "measured", "control"}:
            raise ValueError("expected manifest run_kind is invalid")
        self.expected_run_kind = expected_run_kind
        self.lock_path = self.path.with_name(f".{self.path.name}.lock")
        lock_key = str(self.path)
        with _LOCK_REGISTRY_GUARD:
            self._lock = _LOCKS.setdefault(lock_key, Lock())

    def append(self, record: Mapping[str, object]) -> None:
        normalized = _validate_manifest_record(record)
        self._validate_expected_run_kind(normalized)
        with self._exclusive_lock():
            records = self._read_existing()
            self._append_locked(records, normalized)

    def finalize_infrastructure_failure(self, episode_id: str) -> None:
        try:
            validate_episode_id(episode_id)
        except (TypeError, ValueError) as error:
            raise ManifestError("manifest episode_id is unsafe") from error
        with self._exclusive_lock():
            records = self._read_existing()
            history = [
                record for record in records if record["episode_id"] == episode_id
            ]
            if not history:
                raise ManifestError("manifest episode has not been claimed")
            previous = history[-1]
            if previous["status"] in {"terminal", "infrastructure_failure"}:
                return
            base = {
                key: value
                for key, value in history[0].items()
                if key not in {"status", "termination_reason"}
            }
            status = (
                "infrastructure_failure"
                if previous["status"] == "starting"
                else "terminal"
            )
            normalized = _validate_manifest_record(
                {
                    **base,
                    "status": status,
                    "termination_reason": "infrastructure_failure",
                }
            )
            self._validate_expected_run_kind(normalized)
            self._append_locked(records, normalized)

    def records(self) -> tuple[dict[str, object], ...]:
        with self._exclusive_lock():
            return tuple(dict(record) for record in self._read_existing())

    def read(self) -> tuple[dict[str, object], ...]:
        with self._exclusive_lock():
            return tuple(self._read_existing())

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        with self._lock:
            _prepare_manifest_parent(self.path.parent)
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor: int | None = None
            try:
                descriptor = os.open(self.lock_path, flags, 0o600)
                lock_stat = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(lock_stat.st_mode)
                    or stat.S_IMODE(lock_stat.st_mode) != 0o600
                ):
                    raise ManifestError("manifest lock file is unsafe")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            except ManifestError:
                raise
            except OSError as error:
                raise ManifestError("manifest lock could not be acquired") from error
            finally:
                if descriptor is not None:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    finally:
                        os.close(descriptor)

    def _append_locked(
        self,
        records: list[dict[str, object]],
        normalized: dict[str, object],
    ) -> None:
        _validate_transition(records, normalized)
        serialized = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        encoded = serialized.encode("utf-8")
        if len(encoded) > _MAX_RECORD_BYTES:
            raise ManifestError("manifest record exceeds size limit")
        if self.path.is_symlink():
            raise ManifestError("manifest path must not be a symlink")
        existing_size = self.path.stat().st_size if self.path.exists() else 0
        if existing_size + len(encoded) + 1 > _MAX_MANIFEST_BYTES:
            raise ManifestError("manifest exceeds size limit")
        try:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(serialized + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as error:
            raise ManifestError("manifest append failed") from error

    def _read_existing(self) -> list[dict[str, object]]:
        _reject_symlink_components(self.path.parent)
        if self.path.is_symlink():
            raise ManifestError("manifest path must be a regular file")
        if not self.path.exists():
            return []
        if not self.path.is_file():
            raise ManifestError("manifest path must be a regular file")
        try:
            raw = self.path.read_bytes()
        except OSError as error:
            raise ManifestError("manifest could not be read") from error
        if len(raw) > _MAX_MANIFEST_BYTES:
            raise ManifestError("manifest exceeds size limit")
        if raw and not raw.endswith(b"\n"):
            raise ManifestError("manifest is malformed: missing trailing newline")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ManifestError("manifest is malformed: invalid UTF-8") from error
        records: list[dict[str, object]] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if len(line.encode("utf-8")) > _MAX_RECORD_BYTES:
                raise ManifestError(f"manifest record {line_number} exceeds size limit")
            try:
                value = _strict_json_loads(line)
                normalized = _validate_manifest_record(value)
                self._validate_expected_run_kind(normalized)
            except ManifestError:
                raise
            except (ValueError, TypeError, json.JSONDecodeError, RecursionError) as error:
                raise ManifestError(
                    f"manifest is malformed at record {line_number}"
                ) from error
            _validate_transition(records, normalized)
            records.append(normalized)
        return records

    def _validate_expected_run_kind(self, record: Mapping[str, object]) -> None:
        if (
            self.expected_run_kind is not None
            and record.get("run_kind") != self.expected_run_kind
        ):
            raise ManifestError("manifest run_kind does not match the expected root kind")


def _validate_manifest_record(record: object) -> dict[str, object]:
    if not isinstance(record, Mapping):
        raise ManifestError("manifest record must be a mapping")
    normalized = dict(record)
    allowed = {
        "episode_id",
        "status",
        *_IMMUTABLE_FIELDS,
        "run_kind",
        "rerun_of",
        "termination_reason",
    }
    if set(normalized) - allowed:
        raise ManifestError("manifest record contains unknown fields")
    required = {"episode_id", "status", *_IMMUTABLE_FIELDS, "run_kind"}
    if required - set(normalized):
        if "run_kind" not in normalized:
            raise ManifestError("manifest record is missing run_kind")
        raise ManifestError("manifest record is missing immutable metadata")
    try:
        validate_episode_id(normalized["episode_id"])  # type: ignore[arg-type]
    except (TypeError, ValueError) as error:
        raise ManifestError("manifest episode_id is unsafe") from error
    status = normalized["status"]
    if type(status) is not str or status not in _STATUSES:
        raise ManifestError("manifest status is invalid")
    for field in ("block", "repetition"):
        value = normalized[field]
        if type(value) is not int or not 1 <= value <= 9999:
            raise ManifestError(f"manifest {field} is invalid")
    for field in ("seed", "schedule_seed"):
        value = normalized[field]
        if type(value) is not int or value < 0 or value > 2**63 - 1:
            raise ManifestError(f"manifest {field} is invalid")
    if normalized["condition"] not in {"A", "B", "C", "D", "E"}:
        raise ManifestError("manifest condition is invalid")
    if normalized["instruction"] not in {"U", "W"}:
        raise ManifestError("manifest instruction is invalid")
    run_kind = normalized["run_kind"]
    if run_kind not in {"mock", "pilot", "measured", "control"}:
        raise ManifestError("manifest run_kind is invalid")
    digest = normalized["official_configuration_digest"]
    if type(digest) is not str or _DIGEST_PATTERN.fullmatch(digest) is None:
        raise ManifestError("manifest official configuration digest is invalid")
    source_digest = normalized["source_tree_digest"]
    if type(source_digest) is not str or _DIGEST_PATTERN.fullmatch(source_digest) is None:
        raise ManifestError("manifest source tree digest is invalid")
    for field in ("attacker_model_id", "defender_model_id"):
        value = normalized[field]
        if run_kind == "mock" and value is None:
            continue
        if type(value) is not str or not value.strip() or len(value) > 512:
            raise ManifestError(f"manifest {field} is invalid")
    rerun_of = normalized.get("rerun_of")
    if rerun_of is not None:
        try:
            validate_episode_id(rerun_of)  # type: ignore[arg-type]
        except (TypeError, ValueError) as error:
            raise ManifestError("manifest rerun_of is unsafe") from error
    termination = normalized.get("termination_reason")
    if status in {"terminal", "infrastructure_failure"}:
        if type(termination) is not str or termination not in _TERMINATIONS:
            raise ManifestError("terminal manifest record requires a termination_reason")
        if status == "infrastructure_failure" and termination != "infrastructure_failure":
            raise ManifestError("startup failure must use infrastructure_failure")
    elif termination is not None:
        raise ManifestError("nonterminal manifest record cannot have termination_reason")
    return normalized


def _validate_transition(
    records: list[dict[str, object]], incoming: dict[str, object]
) -> None:
    episode_id = incoming["episode_id"]
    history = [record for record in records if record["episode_id"] == episode_id]
    status = incoming["status"]
    if not history:
        if status != "starting":
            raise ManifestError("manifest transition must begin with starting")
        rerun_of = incoming.get("rerun_of")
        treatment_fields = (
            "block",
            "repetition",
            "condition",
            "instruction",
            "schedule_seed",
            "official_configuration_digest",
            "source_tree_digest",
            "attacker_model_id",
            "defender_model_id",
        )
        repeated_treatment = any(
            all(incoming[field] == record[field] for field in treatment_fields)
            for record in records
            if record["status"] == "starting"
        )
        if (
            repeated_treatment
            and rerun_of is None
            and incoming.get("run_kind") not in {"pilot", "control"}
        ):
            raise ManifestError("repeated schedule row requires rerun_of")
        if rerun_of is not None:
            if rerun_of == episode_id:
                raise ManifestError("rerun requires a new episode_id")
            original = [record for record in records if record["episode_id"] == rerun_of]
            if not original or original[-1]["status"] not in {
                "terminal",
                "infrastructure_failure",
            }:
                raise ManifestError("rerun_of must reference an existing completed attempt")
            original_metadata = original[0]
            if any(
                incoming[field] != original_metadata[field]
                for field in treatment_fields
            ):
                raise ManifestError("rerun metadata must match the original treatment")
        return
    if status == "starting":
        raise ManifestError("duplicate starting transition for episode_id")
    first = history[0]
    if any(incoming[field] != first[field] for field in _IMMUTABLE_FIELDS):
        raise ManifestError("manifest immutable metadata changed")
    if incoming.get("rerun_of") != first.get("rerun_of"):
        raise ManifestError("manifest immutable rerun metadata changed")
    if incoming.get("run_kind") != first.get("run_kind"):
        raise ManifestError("manifest immutable run_kind changed")
    previous = history[-1]["status"]
    allowed_next = {
        "starting": {"running", "infrastructure_failure"},
        "running": {"terminal"},
        "terminal": set(),
        "infrastructure_failure": set(),
    }[previous]
    if status not in allowed_next:
        raise ManifestError(f"invalid manifest transition {previous} -> {status}")


def _prepare_manifest_parent(parent: Path) -> None:
    absolute = parent.absolute()
    _reject_symlink_components(absolute)
    try:
        absolute.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ManifestError("manifest parent could not be created") from error
    _reject_symlink_components(absolute)
    if absolute.is_symlink() or absolute.resolve(strict=True) != absolute:
        raise ManifestError("manifest parent must not traverse symlinks")


def _reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            raise ManifestError("manifest parent must not traverse symlinks")


def _strict_json_loads(text: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    value = json.loads(
        text,
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite value {token}")
        ),
    )
    _require_finite_json(value)
    return value


def _require_finite_json(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > 64:
            raise ValueError("JSON nesting exceeds depth limit")
        if type(current) is float and not math.isfinite(current):
            raise ValueError("non-finite JSON number")
        if isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
        elif isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
