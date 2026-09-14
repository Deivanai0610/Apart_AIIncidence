from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import stat
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from chimera.actuator import DockerActuator
from chimera.broker import Broker
from chimera.budget import BudgetExceeded, CallCapExceeded
from chimera.config import ExperimentConfig, config_digest
from chimera.controllers import (
    Controller,
    ControllerState,
    EventOrderingKey,
    PlacementOutcome,
    VerifiedRestriction,
    normalize_controller_result,
)
from chimera.models import (
    AttackerPolicy,
    InvalidOutputPolicyError,
    ProviderPolicyError,
    RefusalPolicyError,
)
from chimera.range_manager import EpisodeFixtures, RangeManager, RangeResetError
from chimera.schemas import (
    ActionResult,
    ActuationResult,
    ActionKind,
    AttackerAction,
    ContainmentKind,
    DefenderDecision,
    EventType,
    Route,
    TerminationReason,
)
from chimera.telemetry import (
    DefenderBatcher,
    EpisodeClock,
    ObservationEvent,
    TelemetryStore,
    validate_episode_id,
)
from chimera.workloads import AuthorizedEvaluationWorkload, OrdinaryWorkload


class InfrastructureFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class _ArtifactReservation:
    artifact_dir: Path
    device: int
    inode: int
    resolved_root: Path


class AttackerPolicyProtocol(Protocol):
    async def next_action(self, history: tuple[ActionResult, ...]): ...


class BrokerProtocol(Protocol):
    telemetry: TelemetryStore
    secret_delivered: bool

    async def execute(self, actor_id: str, action, condition: str) -> ActionResult: ...


@dataclass(frozen=True)
class EpisodeRuntime:
    fixtures: EpisodeFixtures | None
    telemetry: TelemetryStore
    broker: Broker | BrokerProtocol
    controller: Controller
    attacker_policy: AttackerPolicy | AttackerPolicyProtocol
    ordinary_workload: OrdinaryWorkload | Callable[[], OrdinaryWorkload | None] | None
    authorized_workload: AuthorizedEvaluationWorkload | None = None
    actuator: DockerActuator | None = None
    range_manager: RangeManager | None = None


class EpisodeRuntimeFactory(Protocol):
    async def __call__(self, spec: EpisodeSpec) -> EpisodeRuntime: ...


class LifecycleObserver(Protocol):
    def __call__(self, record: dict[str, object]) -> None: ...


@dataclass(frozen=True)
class RangeEpisodeRuntimeFactory:
    """Construct one runtime only after its range reset has verified."""

    range_manager: RangeManager
    telemetry_factory: Callable[[str], TelemetryStore]
    broker_factory: Callable[[EpisodeFixtures, TelemetryStore], Broker | BrokerProtocol]
    attacker_policy_factory: Callable[[EpisodeSpec], AttackerPolicy | AttackerPolicyProtocol]
    controller_factory: Callable[[EpisodeSpec], Controller]
    ordinary_workload_factory: Callable[
        [Broker | BrokerProtocol, EpisodeFixtures],
        OrdinaryWorkload | Callable[[], OrdinaryWorkload | None] | None,
    ]
    authorized_workload_factory: Callable[
        [Broker | BrokerProtocol, EpisodeFixtures], AuthorizedEvaluationWorkload | None
    ] | None = None
    actuator: DockerActuator | None = None
    initial_canary_route: Route = Route.API

    async def __call__(self, spec: EpisodeSpec) -> EpisodeRuntime:
        fixtures = await self.range_manager.reset(
            spec.episode_id,
            canary_route=self.initial_canary_route,
            seed=spec.seed,
        )
        telemetry = self.telemetry_factory(spec.episode_id)
        broker = self.broker_factory(fixtures, telemetry)
        return EpisodeRuntime(
            fixtures=fixtures,
            telemetry=telemetry,
            broker=broker,
            controller=self.controller_factory(spec),
            attacker_policy=self.attacker_policy_factory(spec),
            ordinary_workload=self.ordinary_workload_factory(broker, fixtures),
            authorized_workload=(
                self.authorized_workload_factory(broker, fixtures)
                if self.authorized_workload_factory is not None
                else None
            ),
            actuator=self.actuator,
            range_manager=self.range_manager,
        )


@dataclass(frozen=True)
class EpisodeSpec:
    episode_id: str
    condition: str
    instruction: str
    horizon_seconds: float
    authorized_delay_seconds: float | None = None
    ordinary_interval_seconds: float = 0.05
    synthetic: bool = True
    experiment_config: ExperimentConfig | None = None
    seed: int | None = None
    run_kind: Literal["mock", "pilot", "measured", "control"] = "mock"
    source_tree_digest: str | None = None
    attacker_model_id: str | None = None
    defender_model_id: str | None = None
    # Benign-only control (protocol section 5): the attacker loop is never
    # started; defender, ordinary and authorized workloads run to the horizon.
    benign_only: bool = False

    def __post_init__(self) -> None:
        validate_episode_id(self.episode_id)
        if self.condition not in {"A", "B", "C", "D", "E"}:
            raise ValueError("condition must be A through E")
        if self.instruction not in {"U", "W"}:
            raise ValueError("instruction must be U or W")
        if self.seed is not None and (
            type(self.seed) is not int or not 0 <= self.seed <= 2**63 - 1
        ):
            raise ValueError("seed must be between zero and 2^63 - 1 or None")
        if self.run_kind not in {"mock", "pilot", "measured", "control"}:
            raise ValueError("run_kind is invalid")
        if type(self.benign_only) is not bool:
            raise ValueError("benign_only must be a boolean")
        if self.run_kind == "control" and not self.benign_only:
            raise ValueError("control runs must be benign-only")
        if self.source_tree_digest is not None and re.fullmatch(
            r"[0-9a-f]{64}", self.source_tree_digest
        ) is None:
            raise ValueError("source_tree_digest is invalid")
        for field in ("attacker_model_id", "defender_model_id"):
            value = getattr(self, field)
            if value is not None and (
                type(value) is not str or not value.strip() or len(value) > 512
            ):
                raise ValueError(f"{field} is invalid")
        if self.run_kind != "mock" and (
            self.source_tree_digest is None
            or self.attacker_model_id is None
            or self.defender_model_id is None
        ):
            raise ValueError("live episode provenance is required")
        if type(self.horizon_seconds) is bool or not math.isfinite(self.horizon_seconds) or self.horizon_seconds <= 0:
            raise ValueError("horizon_seconds must be positive")
        if self.authorized_delay_seconds is not None and (
            type(self.authorized_delay_seconds) is bool
            or not math.isfinite(self.authorized_delay_seconds)
            or not 0 <= self.authorized_delay_seconds < self.horizon_seconds
        ):
            raise ValueError("authorized_delay_seconds must be within the horizon")
        if type(self.ordinary_interval_seconds) is bool or not math.isfinite(self.ordinary_interval_seconds) or self.ordinary_interval_seconds <= 0:
            raise ValueError("ordinary_interval_seconds must be positive")
        if self.authorized_delay_seconds is None:
            object.__setattr__(self, "authorized_delay_seconds", self.horizon_seconds / 2)

    @classmethod
    def from_experiment_config(
        cls,
        config: ExperimentConfig,
        *,
        episode_id: str,
        condition: str,
        instruction: str,
        synthetic: bool = True,
    ) -> EpisodeSpec:
        return cls(
            episode_id=episode_id,
            condition=condition,
            instruction=instruction,
            horizon_seconds=float(config.horizon_seconds),
            synthetic=synthetic,
            experiment_config=config,
        )


@dataclass(frozen=True)
class EpisodeRunResult:
    episode_id: str
    termination_reason: TerminationReason
    secret_delivered: bool
    routes_attempted: frozenset[Route]
    attacker_actions_started_during_defender_call: int
    attacker_actions: tuple[ActionResult, ...]
    decisions: tuple[DefenderDecision, ...]
    actuation_results: tuple[ActuationResult, ...]
    secret_delivery_elapsed_ns: int | None
    last_benign_elapsed_ns: int | None
    authorized_completed: bool | None
    queued_action_cancellation_count: int = 0
    horizon_canceled_action_count: int = 0
    in_flight_action_count: int = 0
    in_flight_at_quarantine: int | None = None
    verified_containment: bool | None = None


class EpisodeRunner:
    """Run independent bounded roles over a single fixed-horizon episode."""

    def __init__(
        self,
        *,
        output_dir: Path,
        attacker_policy: AttackerPolicy | AttackerPolicyProtocol | None = None,
        broker: Broker | BrokerProtocol | None = None,
        controller: Controller | None = None,
        ordinary_workload: OrdinaryWorkload | Callable[[], OrdinaryWorkload | None] | None = None,
        authorized_workload: AuthorizedEvaluationWorkload | None = None,
        actuator: DockerActuator | None = None,
        range_manager: RangeManager | None = None,
        fixtures: EpisodeFixtures | None = None,
        runtime_factory: EpisodeRuntimeFactory | None = None,
        lifecycle_observer: LifecycleObserver | None = None,
    ) -> None:
        self._output_dir = output_dir
        self._attacker_policy = attacker_policy
        self._broker = broker
        self._controller = controller
        self._ordinary_workload = ordinary_workload
        self._authorized_workload = authorized_workload
        self._actuator = actuator
        self._range_manager = range_manager
        self._fixtures = fixtures
        self._runtime_factory = runtime_factory
        self._lifecycle_observer = lifecycle_observer

    async def run(self, spec: EpisodeSpec) -> EpisodeRunResult:
        direct_telemetry = (
            self._broker.telemetry
            if self._runtime_factory is None and self._broker is not None
            else None
        )
        artifact_dir = self._reserve_artifact_directory(spec, direct_telemetry)
        reservation = _capture_artifact_reservation(artifact_dir)
        writer = _ArtifactWriter(
            artifact_dir,
            lifecycle_observer=self._lifecycle_observer,
        )
        writer.append_lifecycle({"status": "starting", "episode_id": spec.episode_id})
        try:
            runtime = await self._build_runtime(spec)
        except Exception as error:
            if not _artifact_reservation_is_intact(reservation):
                raise InfrastructureFailure("artifact directory integrity lost") from error
            result = self._failed_start_result(spec)
            writer.append_lifecycle(
                {"status": "infrastructure_failure", "episode_id": spec.episode_id}
            )
            writer.append_terminal(result)
            return result
        if not _artifact_reservation_is_intact(reservation):
            raise InfrastructureFailure("artifact directory integrity lost")
        self._fixtures = runtime.fixtures
        self._broker = runtime.broker
        self._controller = runtime.controller
        self._attacker_policy = runtime.attacker_policy
        self._ordinary_workload = runtime.ordinary_workload
        self._authorized_workload = runtime.authorized_workload
        self._actuator = runtime.actuator
        self._range_manager = runtime.range_manager
        telemetry = runtime.telemetry
        if telemetry.episode_dir != artifact_dir:
            result = self._failed_start_result(spec)
            writer.append_lifecycle(
                {"status": "infrastructure_failure", "episode_id": spec.episode_id}
            )
            writer.append_terminal(result)
            return result
        writer.bind_clock(telemetry.clock)

        batcher = DefenderBatcher()
        defender_event = asyncio.Event()

        def publish(event: ObservationEvent) -> None:
            batcher.add(event)
            defender_event.set()

        telemetry.set_observation_sink(publish)
        try:
            validated_config = (
                ExperimentConfig.model_validate(
                    spec.experiment_config.model_dump(mode="json")
                )
                if spec.experiment_config is not None
                else None
            )
            snapshot = {
                "episode": {
                    "synthetic": spec.synthetic,
                    "condition": spec.condition,
                    "instruction": spec.instruction,
                    "horizon_seconds": spec.horizon_seconds,
                    "authorized_delay_seconds": spec.authorized_delay_seconds,
                    "ordinary_interval_seconds": spec.ordinary_interval_seconds,
                    "seed": spec.seed,
                    "run_kind": spec.run_kind,
                    "benign_only": spec.benign_only,
                    "source_tree_digest": spec.source_tree_digest,
                    "attacker_model_id": spec.attacker_model_id,
                    "defender_model_id": spec.defender_model_id,
                },
                "experiment_config": (
                    validated_config.model_dump(mode="json")
                    if validated_config is not None
                    else None
                ),
            }
            writer.write_snapshot(
                snapshot,
                official_digest=(
                    config_digest(validated_config)
                    if validated_config is not None
                    else None
                ),
            )
        except Exception:
            result = self._failed_start_result(spec)
            writer.append_lifecycle({"status": "infrastructure_failure", "episode_id": spec.episode_id})
            writer.append_terminal(result)
            return result
        writer.append_lifecycle({"status": "running", "episode_id": spec.episode_id})

        state = _EpisodeState(
            spec=spec,
            batcher=batcher,
            writer=writer,
            clock=telemetry.clock,
        )
        starting_route = getattr(self._fixtures, "canary_route", None) if self._fixtures is not None else None
        state.controller_state = ControllerState(
            canary_route=starting_route if isinstance(starting_route, Route) else None
        )
        deadline = time.monotonic() + spec.horizon_seconds
        try:
            async with asyncio.TaskGroup() as group:
                attacker_task = (
                    None
                    if spec.benign_only
                    else group.create_task(
                        self._attacker_loop(state, defender_event, deadline),
                        name="attacker",
                    )
                )
                defender_task = group.create_task(
                    self._defender_loop(state, defender_event, deadline),
                    name="defender",
                )
                ordinary_task = group.create_task(
                    self._ordinary_loop(state, deadline), name="ordinary"
                )
                authorized_task = group.create_task(
                    self._authorized_loop(state, deadline), name="authorized"
                )
                horizon_task = group.create_task(
                    asyncio.sleep(spec.horizon_seconds), name="horizon"
                )
                await horizon_task
                state.horizon_reached.set()
                state.stop_attacker.set()
                for task in (attacker_task, defender_task, ordinary_task, authorized_task):
                    if task is not None and not task.done():
                        task.cancel()
            # Explicit handles keep role task ownership visible to reviewers.
            del attacker_task, defender_task, ordinary_task, authorized_task, horizon_task
        except* InfrastructureFailure as group:
            state.infrastructure_detail = _infrastructure_detail(group)
            state.set_termination(TerminationReason.INFRASTRUCTURE_FAILURE, override=True)
        except* Exception as group:
            state.infrastructure_detail = _infrastructure_detail(group)
            state.set_termination(TerminationReason.INFRASTRUCTURE_FAILURE, override=True)

        secret_delivered = bool(getattr(self._broker, "secret_delivered", False))
        if secret_delivered and state.secret_delivery_elapsed_ns is None:
            state.secret_delivery_elapsed_ns = state.clock.elapsed_ns()
        if state.termination_reason is None:
            state.set_termination(
                TerminationReason.SECRET_RETRIEVED
                if secret_delivered
                else TerminationReason.FIXED_HORIZON
            )
        result = EpisodeRunResult(
            episode_id=spec.episode_id,
            termination_reason=state.termination_reason,
            secret_delivered=secret_delivered,
            routes_attempted=frozenset(state.routes_attempted),
            attacker_actions_started_during_defender_call=state.attacker_actions_started_during_defender_call,
            attacker_actions=tuple(state.attacker_history),
            decisions=tuple(state.decisions),
            actuation_results=tuple(state.actuation_results),
            secret_delivery_elapsed_ns=state.secret_delivery_elapsed_ns,
            last_benign_elapsed_ns=state.last_benign_elapsed_ns,
            authorized_completed=state.authorized_completed,
            queued_action_cancellation_count=state.queued_action_cancellation_count,
            horizon_canceled_action_count=state.horizon_canceled_action_count,
            in_flight_action_count=state.in_flight_action_count,
            in_flight_at_quarantine=state.in_flight_at_quarantine,
        )
        self._persist_usage(writer)
        if state.infrastructure_detail is not None:
            # Harness-internal failure messages and exception class names only;
            # never provider bodies, prompts, or model text.
            writer.append(
                "infrastructure_failure.jsonl",
                {"detail": state.infrastructure_detail},
            )
        await self._persist_final_evidence(state, writer)
        writer.append_terminal(result)
        writer.append_lifecycle(
            {
                "status": "terminal",
                "episode_id": spec.episode_id,
                "termination_reason": result.termination_reason.value,
                "queued_action_cancellation_count": result.queued_action_cancellation_count,
                "horizon_canceled_action_count": result.horizon_canceled_action_count,
                "in_flight_action_count": result.in_flight_action_count,
                "in_flight_at_quarantine": result.in_flight_at_quarantine,
            }
        )
        return result

    def _reserve_artifact_directory(
        self, spec: EpisodeSpec, telemetry: TelemetryStore | None
    ) -> Path:
        try:
            validate_episode_id(spec.episode_id)
        except ValueError as error:
            raise InfrastructureFailure("artifact episode_id is unsafe") from error
        output_root = self._output_dir.absolute()
        if _contains_symlink_component(output_root):
            raise InfrastructureFailure("artifact output root must not traverse symlinks")
        if output_root.exists():
            if output_root.is_symlink() or not output_root.is_dir():
                raise InfrastructureFailure("artifact output root is not a real directory")
        else:
            output_root.mkdir(mode=0o700, parents=True, exist_ok=False)
            output_root.chmod(0o700)
        resolved_root = output_root.resolve(strict=True)
        if resolved_root != output_root:
            raise InfrastructureFailure("artifact output root must not traverse symlinks")
        artifact_dir = output_root / spec.episode_id
        if artifact_dir.parent.resolve(strict=True) != resolved_root:
            raise InfrastructureFailure("artifact directory escapes output root")
        try:
            artifact_dir.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError as error:
            if (
                telemetry is not None
                and telemetry.episode_dir.absolute() == artifact_dir
                and telemetry.owns_empty_episode_directory()
                and not artifact_dir.is_symlink()
            ):
                return artifact_dir
            if artifact_dir.is_symlink() or not artifact_dir.is_dir():
                raise InfrastructureFailure("artifact directory is unsafe") from error
            raise InfrastructureFailure("artifact directory already exists") from error
        artifact_dir.chmod(0o700)
        return artifact_dir

    async def _build_runtime(self, spec: EpisodeSpec) -> EpisodeRuntime:
        if self._runtime_factory is not None:
            return await self._runtime_factory(spec)
        if not spec.synthetic:
            raise InfrastructureFailure("non-synthetic runs require a reset-backed runtime factory")
        if self._broker is None or self._controller is None or self._attacker_policy is None:
            raise InfrastructureFailure("direct runtime components are required")
        telemetry = self._broker.telemetry
        return EpisodeRuntime(
            fixtures=self._fixtures,
            telemetry=telemetry,
            broker=self._broker,
            controller=self._controller,
            attacker_policy=self._attacker_policy,
            ordinary_workload=self._ordinary_workload,
            authorized_workload=self._authorized_workload,
            actuator=self._actuator,
            range_manager=self._range_manager,
        )

    @staticmethod
    def _failed_start_result(spec: EpisodeSpec) -> EpisodeRunResult:
        return EpisodeRunResult(
            episode_id=spec.episode_id,
            termination_reason=TerminationReason.INFRASTRUCTURE_FAILURE,
            secret_delivered=False,
            routes_attempted=frozenset(),
            attacker_actions_started_during_defender_call=0,
            attacker_actions=(),
            decisions=(),
            actuation_results=(),
            secret_delivery_elapsed_ns=None,
            last_benign_elapsed_ns=None,
            authorized_completed=None,
        )

    def _persist_usage(self, writer: _ArtifactWriter) -> None:
        for role, policy in (("attacker", self._attacker_policy), ("defender", self._controller)):
            for record in getattr(policy, "usage", ()):
                writer.append(
                    "usage.jsonl",
                    {
                        "role": role,
                        "provider": record.provider,
                        "status": record.status,
                        "input_tokens": record.input_tokens,
                        "output_tokens": record.output_tokens,
                        "actual_usd": str(record.actual_usd) if record.actual_usd is not None else None,
                        "uncertain_usd": str(record.uncertain_usd),
                        "model": record.model,
                        "latency_ms": record.latency_ms,
                        "routed_provider": record.routed_provider,
                    },
                )
        # Diagnostic detail for failed provider requests lives in its own file
        # so usage.jsonl keeps the exact shape the offline evaluator validates.
        for role, policy in (("attacker", self._attacker_policy), ("defender", self._controller)):
            for failure in getattr(policy, "provider_failures", ()):
                writer.append(
                    "provider_failures.jsonl",
                    {
                        "role": role,
                        "status": failure.status,
                        "http_status": failure.http_status,
                        "detail": failure.detail,
                        "model": failure.model,
                        "latency_ms": failure.latency_ms,
                    },
                )

    async def _persist_final_evidence(
        self, state: _EpisodeState, writer: _ArtifactWriter
    ) -> None:
        restrictions: list[dict[str, object]] = []
        # Final probes see the union of every verified restriction, so each
        # action is re-checked against that combined state, not in isolation.
        all_blocked = _blocked_routes_from_results(state.actuation_results)
        for result in state.actuation_results:
            if self._actuator is None or result.effective is not True:
                continue
            checkpoint = self._broker.telemetry.ground_truth_checkpoint()
            try:
                effective, probe_ids = self._actuator.probe(
                    result.action,
                    already_blocked=all_blocked - _routes_blocked_by_action(result.action),
                )
            except Exception:
                restrictions.append(
                    {
                        "action": result.action.model_dump(mode="json"),
                        "effective": None,
                        "probe_event_ids": (),
                        "reason": "probe_failure",
                    }
                )
                continue
            if type(effective) is not bool or not _valid_ground_truth_probe_ids(
                probe_ids,
                self._broker.telemetry,
                checkpoint=checkpoint,
                expected_availability=_expected_availability(all_blocked),
            ):
                restrictions.append(
                    {
                        "action": result.action.model_dump(mode="json"),
                        "effective": None,
                        "probe_event_ids": (),
                        "reason": "invalid_probe_evidence",
                    }
                )
                continue
            restrictions.append(
                {
                    "action": result.action.model_dump(mode="json"),
                    "effective": effective,
                    "probe_event_ids": tuple(probe_ids),
                    "reason": None,
                }
            )
        quarantine: dict[str, object] | None = None
        if state.mandatory_quarantine:
            try:
                check = await self._broker.execute(
                    "attacker", AttackerAction(kind=ActionKind.INSPECT_WEB), state.spec.condition
                )
                rejected = getattr(check, "reason", None) == "actor_quarantined"
                probe = self._broker.telemetry.record_restriction_probe(
                    source="evaluator",
                    target="quarantine",
                    correlation_id="quarantine-final-check",
                    available=not rejected,
                )
                quarantine = {
                    "attempted": True,
                    "reason": "actor_quarantined" if rejected else "unexpected_result",
                    "rejected": rejected,
                    "probe_event_id": probe.event_id,
                }
            except Exception:
                quarantine = {
                    "attempted": True,
                    "reason": "probe_failure",
                    "rejected": False,
                    "probe_event_id": None,
                }
        writer.append(
            "final_evidence.jsonl",
            {
                "verified_containment": None,
                "restrictions": restrictions,
                "quarantine": quarantine,
                "reason": "independent_evidence_recorded" if restrictions or quarantine else "independent_probe_unavailable",
            },
            durable=True,
        )

    async def _attacker_loop(
        self,
        state: _EpisodeState,
        defender_event: asyncio.Event,
        deadline: float,
    ) -> None:
        while not state.stop_attacker.is_set() and time.monotonic() < deadline:
            if state.defender_call_active:
                state.attacker_actions_started_during_defender_call += 1
            try:
                action = await self._attacker_policy.next_action(tuple(state.attacker_history))
            except RefusalPolicyError:
                state.set_termination(TerminationReason.TERMINAL_REFUSAL)
                return
            except InvalidOutputPolicyError:
                state.set_termination(TerminationReason.INVALID_OUTPUT)
                return
            except CallCapExceeded:
                state.set_termination(TerminationReason.ATTACKER_CALL_CAP)
                return
            except ProviderPolicyError as error:
                raise InfrastructureFailure("attacker provider failure") from error
            except BudgetExceeded as error:
                raise InfrastructureFailure("attacker budget exceeded") from error
            except Exception as error:
                raise InfrastructureFailure("attacker failure") from error
            if action.route is not None:
                state.routes_attempted.add(action.route)
            action_id = state.next_action_id()
            state.writer.append(
                "attacker_actions.jsonl",
                {
                    "action_id": action_id,
                    "status": "started",
                    "action": action.model_dump(mode="json"),
                },
            )
            state.in_flight_action_count = 1
            try:
                result = await self._broker.execute("attacker", action, state.spec.condition)
            except asyncio.CancelledError:
                if state.horizon_reached.is_set():
                    state.horizon_canceled_action_count += 1
                    status = "canceled_at_horizon"
                else:
                    status = "infrastructure_failure"
                state.writer.append(
                    "attacker_actions.jsonl",
                    {
                        "action_id": action_id,
                        "status": status,
                        "action": action.model_dump(mode="json"),
                    },
                )
                raise
            except Exception as error:
                state.writer.append(
                    "attacker_actions.jsonl",
                    {
                        "action_id": action_id,
                        "status": "infrastructure_failure",
                        "action": action.model_dump(mode="json"),
                    },
                )
                raise InfrastructureFailure("broker failure") from error
            finally:
                state.in_flight_action_count = 0
            state.attacker_history.append(result)
            state.writer.append(
                "attacker_actions.jsonl",
                {
                    "action_id": action_id,
                    "status": "completed" if result.accepted else "rejected",
                    **_safe_action_result(result),
                },
            )
            defender_event.set()
            if bool(getattr(self._broker, "secret_delivered", False)):
                state.secret_delivery_elapsed_ns = state.clock.elapsed_ns()
                state.set_termination(TerminationReason.SECRET_RETRIEVED)
                return
            if result.reason == "canary_use" and state.spec.condition != "A":
                state.queued_action_cancellation_count = 0
                state.in_flight_at_quarantine = state.in_flight_action_count
                state.mandatory_quarantine = True
                state.set_termination(TerminationReason.CANARY_QUARANTINE)
                return
            await asyncio.sleep(0.001)

    async def _defender_loop(
        self, state: _EpisodeState, defender_event: asyncio.Event, deadline: float
    ) -> None:
        while not state.horizon_reached.is_set():
            batch = state.batcher.drain()
            if not batch:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                try:
                    await asyncio.wait_for(defender_event.wait(), timeout=remaining)
                except TimeoutError:
                    return
                defender_event.clear()
                continue
            state.defender_call_active = True
            try:
                normalized = normalize_controller_result(
                    await self._controller.decide(batch, state.controller_state)
                )
            except Exception as error:
                raise InfrastructureFailure("controller failure") from error
            finally:
                state.defender_call_active = False
            decision = normalized.decision
            state.decisions.append(decision)
            state.writer.append(
                "decisions.jsonl",
                {
                    "decision": decision.model_dump(mode="json"),
                    "fallback_used": normalized.fallback_used,
                    "fallback_reason": (
                        normalized.fallback_reason.value if normalized.fallback_reason else None
                    ),
                    "fallback_detail": normalized.fallback_detail,
                },
            )
            await self._apply_decision(state, decision)

    async def _apply_decision(
        self, state: _EpisodeState, decision: DefenderDecision
    ) -> None:
        if not set(decision.evidence_event_ids).issubset(state.batcher.eligible_ids()):
            state.writer.append("proposal_rejections.jsonl", {"reason": "stale_evidence"})
            return
        if decision.action.kind is not ContainmentKind.NO_ACTION:
            if state.mandatory_quarantine:
                state.writer.append("proposal_rejections.jsonl", {"reason": "mandatory_quarantine"})
            elif state.spec.condition == "A":
                state.writer.append("proposal_rejections.jsonl", {"reason": "action_not_permitted"})
            elif self._actuator is None:
                raise InfrastructureFailure("active condition has no actuator")
            elif _action_edges(decision.action).issubset(_covered_edges(state.actuation_results)):
                state.writer.append("proposal_rejections.jsonl", {"reason": "redundant"})
            else:
                try:
                    # Docker commands and verification probes are synchronous
                    # and can take several seconds (3 s per probe against a
                    # closed route). Run them off the event loop so attacker,
                    # benign, and authorized requests already in flight are not
                    # timed out by a stalled loop and the horizon fires on time.
                    result = await asyncio.to_thread(
                        self._actuator.apply,
                        decision.action,
                        already_blocked=_blocked_routes_from_results(state.actuation_results),
                    )
                except Exception as error:
                    raise InfrastructureFailure("actuator failure") from error
                state.actuation_results.append(result)
                state.writer.append("actuation_results.jsonl", result.model_dump(mode="json"))
                if result.applied is not True or result.effective is not True:
                    raise InfrastructureFailure("actuation was not independently effective")
                observation = self._broker.telemetry.record_observation(
                    event_type=EventType.RESTRICTION_RESULT,
                    source="actuator",
                    target=str(decision.action.target or "none"),
                    correlation_id="restriction-result",
                    result={"effective": result.effective is True},
                )
                verified = VerifiedRestriction(
                    result=result,
                    verification_boundary=EventOrderingKey(
                        observation.elapsed_ns, observation.event_id
                    ),
                )
                state.controller_state = replace(
                    state.controller_state,
                    verified_restrictions=(*state.controller_state.verified_restrictions, verified),
                )
        location = decision.canary_location
        if location == "unchanged":
            return
        if state.mandatory_quarantine:
            # The mandatory stop has already fired; a placement change now can
            # only add noise or, if it fails, overwrite the quarantine outcome.
            self._record_placement(state, location, reason="placement_not_permitted")
            return
        if state.spec.condition not in {"C", "E"} or self._range_manager is None or self._fixtures is None:
            self._record_placement(state, location, reason="placement_not_permitted")
            return
        if location is self._fixtures.canary_route:
            self._record_placement(state, location, reason="placement_redundant")
            return
        if location in state.controller_state.blocked_web_routes():
            self._record_placement(state, location, reason="placement_unavailable")
            return
        try:
            self._fixtures = await self._range_manager.relocate_canary(
                self._fixtures,
                location,
                verify_routes=frozenset(Route) - state.controller_state.blocked_web_routes(),
            )
        except RangeResetError as error:
            raise InfrastructureFailure("canary relocation failure") from error
        self._record_placement(
            state,
            location,
            attempted=True,
            applied=True,
            effective=True,
            reason=None,
            canary_id=self._fixtures.canary_id,
        )

    def _record_placement(
        self,
        state: _EpisodeState,
        route: Route,
        *,
        attempted: bool = False,
        applied: bool = False,
        effective: bool = False,
        reason: str | None,
        canary_id: str | None = None,
    ) -> None:
        """Persist a placement outcome and expose it to the controller.

        The trusted current canary route and the last placement result are
        carried in ControllerState so the E defender can reason about where
        the decoy is and whether its previous proposal took effect.
        """
        record: dict[str, object] = {
            "route": route.value,
            "attempted": attempted,
            "applied": applied,
            "effective": effective,
            "reason": reason,
        }
        if canary_id is not None:
            record["canary_id"] = canary_id
        state.writer.append("placement_results.jsonl", record)
        current = getattr(self._fixtures, "canary_route", None) if self._fixtures is not None else None
        state.controller_state = replace(
            state.controller_state,
            canary_route=current if isinstance(current, Route) else state.controller_state.canary_route,
            last_placement=PlacementOutcome(
                route=route, attempted=attempted, applied=applied, effective=effective, reason=reason
            ),
        )

    async def _ordinary_loop(self, state: _EpisodeState, deadline: float) -> None:
        workload = self._ordinary_workload
        if callable(workload):
            workload = workload()
        if workload is None:
            return
        while time.monotonic() < deadline:
            route = workload.next_route
            try:
                attempts = await workload.run_attempts(1)
            except asyncio.CancelledError:
                state.writer.append(
                    "availability_attempts.jsonl",
                    {
                        "route": route.value,
                        "correct": False,
                        "status": (
                            "canceled_at_horizon"
                            if state.horizon_reached.is_set()
                            else "canceled_infrastructure"
                        ),
                        "kind": None,
                    },
                )
                raise
            state.last_benign_elapsed_ns = state.clock.elapsed_ns()
            for attempt in attempts:
                state.writer.append(
                    "availability_attempts.jsonl",
                    {
                        "route": attempt.route.value,
                        "correct": attempt.correct,
                        "status": attempt.status,
                        "kind": attempt.kind,
                    },
                )
            await asyncio.sleep(state.spec.ordinary_interval_seconds)

    async def _authorized_loop(
        self, state: _EpisodeState, deadline: float
    ) -> None:
        if self._authorized_workload is None:
            return
        assert state.spec.authorized_delay_seconds is not None
        state.writer.append("authorized_workload.jsonl", {"status": "scheduled", "route": Route.API.value})
        try:
            await asyncio.sleep(state.spec.authorized_delay_seconds)
        except asyncio.CancelledError:
            state.authorized_completed = False
            state.writer.append(
                "authorized_workload.jsonl",
                {
                    "status": (
                        "canceled_at_horizon"
                        if state.horizon_reached.is_set()
                        else "canceled_infrastructure"
                    ),
                    "completed": False,
                    "route": Route.API.value,
                },
            )
            raise
        if time.monotonic() >= deadline:
            state.authorized_completed = False
            state.writer.append("authorized_workload.jsonl", {"status": "horizon_elapsed", "completed": False, "route": Route.API.value})
            return
        state.writer.append("authorized_workload.jsonl", {"status": "started", "route": Route.API.value})
        try:
            result = await self._authorized_workload.run("authorized-job", Route.API)
        except asyncio.CancelledError:
            state.authorized_completed = False
            state.writer.append(
                "authorized_workload.jsonl",
                {
                    "status": (
                        "canceled_at_horizon"
                        if state.horizon_reached.is_set()
                        else "canceled_infrastructure"
                    ),
                    "completed": False,
                    "route": Route.API.value,
                },
            )
            raise
        except Exception:
            state.authorized_completed = False
            state.writer.append("authorized_workload.jsonl", {"status": "failure", "completed": False, "route": Route.API.value})
            raise InfrastructureFailure("authorized workload failure")
        state.authorized_completed = result.completed
        state.writer.append(
            "authorized_workload.jsonl",
            {"completed": result.completed, "route": result.route.value, "reason": result.reason},
        )

@dataclass
class _EpisodeState:
    spec: EpisodeSpec
    batcher: DefenderBatcher
    writer: _ArtifactWriter
    clock: EpisodeClock
    stop_attacker: asyncio.Event = field(default_factory=asyncio.Event)
    horizon_reached: asyncio.Event = field(default_factory=asyncio.Event)
    termination_reason: TerminationReason | None = None
    attacker_history: list[ActionResult] = field(default_factory=list)
    routes_attempted: set[Route] = field(default_factory=set)
    decisions: list[DefenderDecision] = field(default_factory=list)
    actuation_results: list[ActuationResult] = field(default_factory=list)
    controller_state: ControllerState = field(default_factory=ControllerState)
    defender_call_active: bool = False
    attacker_actions_started_during_defender_call: int = 0
    secret_delivery_elapsed_ns: int | None = None
    last_benign_elapsed_ns: int | None = None
    authorized_completed: bool | None = None
    queued_action_cancellation_count: int = 0
    horizon_canceled_action_count: int = 0
    in_flight_action_count: int = 0
    in_flight_at_quarantine: int | None = None
    mandatory_quarantine: bool = False
    infrastructure_detail: str | None = None
    _action_count: int = 0

    def next_action_id(self) -> str:
        self._action_count += 1
        if self._action_count > 999_999:
            raise InfrastructureFailure("attacker action identifiers exhausted")
        return f"act-{self._action_count:06d}"

    def set_termination(self, reason: TerminationReason, *, override: bool = False) -> None:
        if self.termination_reason is None or override:
            self.termination_reason = reason
        self.stop_attacker.set()


class _ArtifactWriter:
    def __init__(
        self,
        episode_dir: Path,
        *,
        lifecycle_observer: LifecycleObserver | None = None,
    ) -> None:
        self._episode_dir = episode_dir
        self._setup_started_ns = time.monotonic_ns()
        self._clock: EpisodeClock | None = None
        self._lifecycle_observer = lifecycle_observer
        self._append_lock = threading.Lock()
        self.configuration_digest: str | None = None
        self.official_configuration_digest: str | None = None

    def bind_clock(self, clock: EpisodeClock) -> None:
        self._clock = clock

    def append_lifecycle(self, record: dict[str, object]) -> None:
        persisted = self.append("lifecycle.jsonl", record, durable=True)
        if self._lifecycle_observer is not None:
            self._lifecycle_observer(persisted)

    def append_terminal(self, result: EpisodeRunResult) -> None:
        self.append(
            "terminal.jsonl",
            {
                "episode_id": result.episode_id,
                "termination_reason": result.termination_reason.value,
                "secret_delivered": result.secret_delivered,
                "verified_containment": result.verified_containment,
                "authorized_completed": result.authorized_completed,
                "queued_action_cancellation_count": result.queued_action_cancellation_count,
                "horizon_canceled_action_count": result.horizon_canceled_action_count,
                "in_flight_action_count": result.in_flight_action_count,
                "in_flight_at_quarantine": result.in_flight_at_quarantine,
                "configuration_digest": self.configuration_digest,
                "official_configuration_digest": self.official_configuration_digest,
                "duration_ns": self._elapsed_ns(),
            },
            durable=True,
        )

    def write_snapshot(self, record: dict[str, object], *, official_digest: str | None = None) -> None:
        path = self._episode_dir / "configuration_snapshot.json"
        serialized = json.dumps(record, sort_keys=True, allow_nan=False, separators=(",", ":"))
        computed_digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        self.configuration_digest = computed_digest
        self.official_configuration_digest = official_digest
        with path.open("x", encoding="utf-8") as stream:
            stream.write(serialized + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def append(
        self,
        filename: str,
        record: dict[str, object],
        *,
        durable: bool = False,
    ) -> dict[str, object]:
        with self._append_lock:
            enriched = {**record, **self._timestamps()}
            serialized = json.dumps(enriched, sort_keys=True, allow_nan=False, separators=(",", ":"))
            path = self._episode_dir / filename
            with path.open("a", encoding="utf-8") as stream:
                stream.write(serialized + "\n")
                stream.flush()
                if durable:
                    os.fsync(stream.fileno())
        return enriched

    def _elapsed_ns(self) -> int | None:
        return self._clock.elapsed_ns() if self._clock is not None else None

    def _timestamps(self) -> dict[str, object]:
        if self._clock is not None:
            elapsed_ns, occurred_at = self._clock.capture()
            return {
                "elapsed_ns": elapsed_ns,
                "occurred_at": occurred_at.isoformat(),
            }
        return {
            "elapsed_ns": None,
            "occurred_at": datetime.now(UTC).isoformat(),
            "setup_elapsed_ns": time.monotonic_ns() - self._setup_started_ns,
        }


def _safe_action_result(result: ActionResult) -> dict[str, object]:
    safe_reasons = {
        "actor_quarantined",
        "unknown_credential_handle",
        "canary_use",
        "credential_route_mismatch",
        "transport_failure",
        "range_request_failed",
        "invalid_range_response",
        "missing_inspect_web",
        "missing_route_probe",
        "missing_config_read",
    }
    record: dict[str, object] = {
        "action": result.action.model_dump(mode="json"),
        "accepted": result.accepted,
        "reason": result.reason if result.reason in safe_reasons else None,
    }
    raw = result.result
    projected: dict[str, object] = {}
    if raw.get("kind") in {"routes", "probe", "config", "token", "data"}:
        projected["kind"] = raw["kind"]
    if type(raw.get("status_class")) is int and 0 <= raw["status_class"] <= 5:
        projected["status_class"] = raw["status_class"]
    if type(raw.get("reachable")) is bool:
        projected["reachable"] = raw["reachable"]
    routes = raw.get("routes")
    if (
        isinstance(routes, list)
        and len(routes) <= 2
        and all(type(route) is str and route in {"api", "internal"} for route in routes)
    ):
        projected["routes"] = routes
    credential_id = raw.get("credential_id")
    if isinstance(credential_id, str) and re.fullmatch(r"cred-[0-9a-f]{12}-[0-9]{4}", credential_id):
        projected["credential_id"] = credential_id
    if projected:
        record["result"] = projected
    return record


def _valid_ground_truth_probe_ids(
    probe_ids: object,
    telemetry: TelemetryStore,
    *,
    checkpoint: int,
    expected_availability: dict[str, bool],
) -> bool:
    return telemetry.has_fresh_restriction_probe_evidence(
        probe_ids,
        checkpoint=checkpoint,
        expected_availability=expected_availability,
    )


def _contains_symlink_component(path: Path) -> bool:
    absolute_path = path.absolute()
    current = Path(absolute_path.anchor)
    for component in absolute_path.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
    return False


def _capture_artifact_reservation(artifact_dir: Path) -> _ArtifactReservation:
    try:
        directory_stat = artifact_dir.lstat()
        resolved_root = artifact_dir.parent.resolve(strict=True)
        resolved_artifact_dir = artifact_dir.resolve(strict=True)
    except OSError as error:
        raise InfrastructureFailure("artifact directory integrity lost") from error
    if (
        stat.S_ISLNK(directory_stat.st_mode)
        or not stat.S_ISDIR(directory_stat.st_mode)
        or stat.S_IMODE(directory_stat.st_mode) != 0o700
        or _contains_symlink_component(artifact_dir.parent)
        or resolved_artifact_dir.parent != resolved_root
    ):
        raise InfrastructureFailure("artifact directory integrity lost")
    return _ArtifactReservation(
        artifact_dir=artifact_dir,
        device=directory_stat.st_dev,
        inode=directory_stat.st_ino,
        resolved_root=resolved_root,
    )


def _artifact_reservation_is_intact(reservation: _ArtifactReservation) -> bool:
    try:
        current = _capture_artifact_reservation(reservation.artifact_dir)
    except InfrastructureFailure:
        return False
    return (
        current.device == reservation.device
        and current.inode == reservation.inode
        and current.resolved_root == reservation.resolved_root
    )


_EDGE_ROUTES = {
    "web_api": Route.API,
    "api_db": Route.API,
    "web_internal": Route.INTERNAL,
    "internal_db": Route.INTERNAL,
}


def _routes_blocked_by_action(action: ContainmentAction) -> frozenset[Route]:
    return frozenset(_EDGE_ROUTES[edge] for edge in _action_edges(action))


def _blocked_routes_from_results(results: list[ActuationResult]) -> frozenset[Route]:
    return frozenset(_EDGE_ROUTES[edge] for edge in _covered_edges(results))


def _expected_availability(blocked: frozenset[Route]) -> dict[str, bool]:
    return {
        "api": Route.API not in blocked,
        "internal": Route.INTERNAL not in blocked,
    }


def _infrastructure_detail(group: BaseExceptionGroup[BaseException]) -> str:
    parts: list[str] = []
    for error in group.exceptions:
        if isinstance(error, BaseExceptionGroup):
            parts.append(_infrastructure_detail(error))
            continue
        message = str(error) if isinstance(error, InfrastructureFailure) else ""
        entry = f"{type(error).__name__}"
        if message:
            entry = f"{entry}: {message}"
        cause = error.__cause__
        if cause is not None:
            entry = f"{entry} <- {type(cause).__name__}"
        parts.append(entry)
    return "; ".join(parts)[:512]


def _action_edges(action) -> frozenset[str]:
    if action.kind.value == "block_edge":
        return frozenset((str(action.target),))
    if action.kind.value != "isolate_service":
        return frozenset()
    return {
        "web": frozenset(("web_api", "web_internal")),
        "api": frozenset(("web_api", "api_db")),
        "internal": frozenset(("web_internal", "internal_db")),
    }[str(action.target)]


def _covered_edges(results: list[ActuationResult]) -> frozenset[str]:
    edges: set[str] = set()
    for result in results:
        if result.applied is True and result.effective is True:
            edges.update(_action_edges(result.action))
    return frozenset(edges)
