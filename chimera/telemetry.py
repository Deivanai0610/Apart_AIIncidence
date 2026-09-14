from __future__ import annotations

import json
import os
import re
import stat
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

from chimera.schemas import EventType, GroundTruthEvent, ObservationEvent


_SENSITIVE_RESULT_KEYS = frozenset(
    {"credential", "token", "secret", "api_key", "prompt", "authorization"}
)
_IDENTIFIER_RESULT_KEYS = frozenset(
    {"credential_id", "token_id", "secret_id", "api_key_id", "authorization_id"}
)
_REQUIRED_EVENT_TYPES = frozenset(
    {
        EventType.CANARY_USE,
        EventType.AUTHORIZATION_FAILURE,
        EventType.DATA_REQUEST,
        EventType.RESTRICTION_RESULT,
    }
)
_EPISODE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")


def validate_episode_id(episode_id: str) -> str:
    if type(episode_id) is not str or not _EPISODE_ID_PATTERN.fullmatch(episode_id):
        raise ValueError("episode_id must be a bounded safe identifier")
    return episode_id


class EpisodeClock:
    def __init__(self) -> None:
        self._started_ns = time.monotonic_ns()

    def capture(self) -> tuple[int, datetime]:
        return time.monotonic_ns() - self._started_ns, datetime.now(UTC)

    def elapsed_ns(self) -> int:
        return time.monotonic_ns() - self._started_ns


class EventSequencer:
    def __init__(self, stream: str) -> None:
        if stream not in {"obs", "gt"}:
            raise ValueError("event stream must be 'obs' or 'gt'")
        self._stream = stream
        self._count = 0

    def next_id(self) -> str:
        self._count += 1
        if self._count > 999_999:
            raise ValueError("event stream exhausted six-digit identifiers")
        return f"{self._stream}-{self._count:06d}"


def _normalized_key(key: str) -> str:
    return key.lower().replace("-", "_")


def _is_sensitive_key(key: str) -> bool:
    normalized = _normalized_key(key)
    if normalized in _IDENTIFIER_RESULT_KEYS:
        return False
    return normalized in _SENSITIVE_RESULT_KEYS or any(
        normalized.endswith(f"_{sensitive_key}")
        for sensitive_key in _SENSITIVE_RESULT_KEYS
    )


def _redact(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _is_sensitive_key(key) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


class TelemetryStore:
    def __init__(
        self,
        output_dir: Path,
        episode_id: str,
        *,
        clock: EpisodeClock | None = None,
        observation_sink: Callable[[ObservationEvent], None] | None = None,
    ) -> None:
        validated_episode_id = validate_episode_id(episode_id)
        self._output_root = output_dir.absolute()
        self.episode_dir = self._output_root / validated_episode_id
        if self.episode_dir.parent.resolve(strict=False) != self._output_root.resolve(
            strict=False
        ):
            raise ValueError("telemetry episode directory escapes output root")
        self._reject_symlinked_output_root()
        self._created_episode_identity = self._create_episode_directory()
        self._episode_id = validated_episode_id
        self._clock = clock or EpisodeClock()
        self._observation_ids = EventSequencer("obs")
        self._ground_truth_ids = EventSequencer("gt")
        self._defender_events_path = self.episode_dir / "defender_events.jsonl"
        self._evaluator_events_path = self.episode_dir / "evaluator_events.jsonl"
        self._observation_sink = observation_sink
        self._ground_truth_event_ids: set[str] = set()
        self._ground_truth_events: list[GroundTruthEvent] = []
        # Actuation runs off the event loop; its verification probes record
        # ground-truth events from a worker thread while the loop keeps
        # recording observations. One lock keeps ID allocation, file append,
        # and the in-memory ground-truth index consistent across threads.
        self._lock = Lock()

    def _create_episode_directory(self) -> tuple[int, int] | None:
        try:
            self.episode_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        except FileExistsError:
            if self.episode_dir.is_symlink() or not self.episode_dir.is_dir():
                raise ValueError("telemetry episode directory must be a real directory")
            return None
        self.episode_dir.chmod(0o700)
        directory_stat = self.episode_dir.lstat()
        if stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(directory_stat.st_mode):
            raise ValueError("telemetry episode directory must be a real directory")
        return directory_stat.st_dev, directory_stat.st_ino

    def _reject_symlinked_output_root(self) -> None:
        current = Path(self._output_root.anchor)
        for component in self._output_root.parts[1:]:
            current /= component
            if current.is_symlink():
                raise ValueError("telemetry output root must not traverse symlinks")

    @property
    def clock(self) -> EpisodeClock:
        return self._clock

    def has_ground_truth_event_id(self, event_id: str) -> bool:
        return event_id in self._ground_truth_event_ids

    def ground_truth_checkpoint(self) -> int:
        return len(self._ground_truth_events)

    def has_fresh_restriction_probe_evidence(
        self,
        event_ids: object,
        *,
        checkpoint: int,
        expected_availability: dict[str, bool],
    ) -> bool:
        if (
            type(checkpoint) is not int
            or checkpoint < 0
            or checkpoint > len(self._ground_truth_events)
            or not isinstance(event_ids, (tuple, list))
            or len(event_ids) != len(expected_availability)
            or any(type(event_id) is not str for event_id in event_ids)
            or len(set(event_ids)) != len(event_ids)
        ):
            return False
        fresh_events = {
            event.event_id: event for event in self._ground_truth_events[checkpoint:]
        }
        observed_targets: set[str] = set()
        for event_id in event_ids:
            event = fresh_events.get(event_id)
            if (
                event is None
                or event.event_type is not EventType.RESTRICTION_RESULT
                or event.target not in expected_availability
                or event.result != {"route_available": expected_availability[event.target]}
            ):
                return False
            observed_targets.add(event.target)
        return observed_targets == set(expected_availability)

    def owns_empty_episode_directory(self) -> bool:
        if self._created_episode_identity is None:
            return False
        try:
            directory_stat = self.episode_dir.lstat()
            if (
                stat.S_ISLNK(directory_stat.st_mode)
                or not stat.S_ISDIR(directory_stat.st_mode)
                or (directory_stat.st_dev, directory_stat.st_ino)
                != self._created_episode_identity
                or stat.S_IMODE(directory_stat.st_mode) != 0o700
            ):
                return False
            return not any(self.episode_dir.iterdir())
        except OSError:
            return False

    def set_observation_sink(
        self, sink: Callable[[ObservationEvent], None] | None
    ) -> None:
        """Install the synchronous post-persistence observation consumer."""
        self._observation_sink = sink

    def record_observation(
        self,
        event_type: EventType,
        source: str,
        target: str,
        correlation_id: str,
        result: dict[str, object],
    ) -> ObservationEvent:
        if not isinstance(event_type, EventType):
            raise TypeError("event_type must be an EventType")
        with self._lock:
            elapsed_ns, occurred_at = self._clock.capture()
            event = ObservationEvent(
                episode_id=self._episode_id,
                event_id=self._observation_ids.next_id(),
                elapsed_ns=elapsed_ns,
                occurred_at=occurred_at,
                event_type=event_type,
                source=source,
                target=target,
                correlation_id=correlation_id,
                result=_redact(result),
            )
            self._append(self._defender_events_path, event, durable=False)
            if self._observation_sink is not None:
                self._observation_sink(event)
            return event

    def record_ground_truth(
        self,
        actor_class: str,
        secret_delivered: bool,
        capabilities: tuple[str, ...] = (),
        expected_benign_result: bool | None = None,
    ) -> GroundTruthEvent:
        with self._lock:
            elapsed_ns, occurred_at = self._clock.capture()
            event = GroundTruthEvent(
                episode_id=self._episode_id,
                event_id=self._ground_truth_ids.next_id(),
                elapsed_ns=elapsed_ns,
                occurred_at=occurred_at,
                event_type=EventType.DATA_REQUEST,
                source="evaluator",
                target="outcome",
                correlation_id="evaluator-outcome",
                result={},
                actor_class=actor_class,
                capabilities=capabilities,
                secret_delivered=secret_delivered,
                expected_benign_result=expected_benign_result,
            )
            self._append(self._evaluator_events_path, event, durable=True)
            self._record_persisted_ground_truth(event)
            return event

    def record_restriction_probe(
        self, *, source: str, target: str, correlation_id: str, available: bool
    ) -> GroundTruthEvent:
        if not isinstance(available, bool):
            raise TypeError("available must be a bool")
        with self._lock:
            elapsed_ns, occurred_at = self._clock.capture()
            event = GroundTruthEvent(
                episode_id=self._episode_id,
                event_id=self._ground_truth_ids.next_id(),
                elapsed_ns=elapsed_ns,
                occurred_at=occurred_at,
                event_type=EventType.RESTRICTION_RESULT,
                source=source,
                target=target,
                correlation_id=correlation_id,
                result={"route_available": available},
                actor_class="evaluator",
                secret_delivered=False,
                expected_benign_result=None,
            )
            self._append(self._evaluator_events_path, event, durable=True)
            self._record_persisted_ground_truth(event)
            return event

    def _record_persisted_ground_truth(self, event: GroundTruthEvent) -> None:
        self._ground_truth_event_ids.add(event.event_id)
        self._ground_truth_events.append(event)

    @staticmethod
    def _append(
        path: Path,
        event: ObservationEvent | GroundTruthEvent,
        *,
        durable: bool,
    ) -> None:
        serialized = json.dumps(event.model_dump(mode="json"), sort_keys=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(f"{serialized}\n")
            stream.flush()
            if durable:
                os.fsync(stream.fileno())


class DefenderBatcher:
    def __init__(self, *, observation_window: int = 64) -> None:
        if observation_window < 1:
            raise ValueError("observation_window must be positive")
        self._observation_window = observation_window
        self._pending: list[ObservationEvent] = []
        self._delivered: deque[ObservationEvent] = deque()
        self._health_fingerprints: set[str] = set()
        self._observed_routes: set[tuple[str, str]] = set()
        self._lock = Lock()

    def add(self, event: ObservationEvent) -> None:
        if not isinstance(event, ObservationEvent):
            raise TypeError("DefenderBatcher accepts ObservationEvent instances only")
        with self._lock:
            route = (event.source, event.target)
            is_new_route = route not in self._observed_routes
            self._observed_routes.add(route)
            if self._should_filter(event, is_new_route):
                return
            self._pending.append(event)

    def drain(self) -> tuple[ObservationEvent, ...]:
        with self._lock:
            batch = tuple(self._pending)
            self._pending.clear()
            self._health_fingerprints.clear()
            for event in batch:
                self._delivered.append(event)
                if len(self._delivered) > self._observation_window:
                    self._delivered.popleft()
            return batch

    def eligible_ids(self) -> frozenset[str]:
        with self._lock:
            return frozenset(event.event_id for event in self._delivered)

    def _should_filter(self, event: ObservationEvent, is_new_route: bool) -> bool:
        if event.event_type in _REQUIRED_EVENT_TYPES:
            return False
        if event.result.get("health_only") is not True:
            return False
        fingerprint = json.dumps(
            {
                "event_type": event.event_type.value,
                "source": event.source,
                "target": event.target,
                "result": event.result,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if is_new_route:
            self._health_fingerprints.add(fingerprint)
            return False
        if fingerprint in self._health_fingerprints:
            return True
        self._health_fingerprints.add(fingerprint)
        return False
