from __future__ import annotations

import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from chimera.actuator import CommandResult, DockerActuator, ProbeResult
from chimera.broker import Broker
from chimera.range_client import RangeOperation, RangeResponse
from chimera.range_manager import RangeManager, RangeResetError
from chimera.schemas import ActionKind, AttackerAction, ContainmentAction, Route
from chimera.telemetry import TelemetryStore


@dataclass
class RecordingCommandRunner:
    calls: list[list[str]] = field(default_factory=list)
    inputs: list[str | None] = field(default_factory=list)
    results: list[CommandResult | BaseException] = field(default_factory=list)

    def run(self, argv: list[str], *, input_text: str | None = None) -> CommandResult:
        self.calls.append(argv)
        self.inputs.append(input_text)
        if self.results:
            result = self.results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        return CommandResult(0, "CHIMERA_FIXTURES_COMMITTED\n")


class RecordingActuator(DockerActuator):
    def __init__(self, runner: RecordingCommandRunner, lifecycle: list[str]) -> None:
        super().__init__(runner, membership_inspector=lambda network, service: True)
        self._lifecycle = lifecycle

    def restore(self) -> tuple[CommandResult, ...]:
        self._lifecycle.append("restore")
        return ()


def _manager(
    tmp_path: Path,
    *,
    runner: RecordingCommandRunner | None = None,
    actuator: DockerActuator | None = None,
    stop_new_work=lambda: True,
    clear_host_state=lambda: True,
) -> RangeManager:
    command_runner = runner or RecordingCommandRunner()
    return RangeManager(
        runtime_dir=tmp_path / "runtime",
        actuator=actuator
        or DockerActuator(
            command_runner,
            membership_inspector=lambda network, service: True,
        ),
        command_runner=command_runner,
        stop_new_work=stop_new_work,
        clear_host_state=clear_host_state,
        health_check=lambda: True,
        route_verifier=lambda route, token, safe, secret: True,
        canary_verifier=lambda route, digest: True,
    )


def test_actuator_uses_enumerated_argv() -> None:
    runner = RecordingCommandRunner()
    actuator = DockerActuator(runner, membership_inspector=lambda network, service: True)

    result = actuator.apply(ContainmentAction.block_edge("web_api"))

    assert runner.calls == [["docker", "network", "disconnect", "chimera_web_api", "chimera-web-1"]]
    assert result.applied is True
    assert result.effective is None


def test_actuator_does_not_treat_command_exit_as_effectiveness() -> None:
    actuator = DockerActuator(RecordingCommandRunner())

    result = actuator.apply(ContainmentAction.block_edge("api_db"))

    assert result.command_exit_code == 0
    assert result.command_exit_codes == (0,)
    assert result.effective is None
    assert result.reason == "probe_unavailable"


def test_actuator_reason_retains_command_and_verification_failures() -> None:
    runner = RecordingCommandRunner(results=[CommandResult(7)])

    result = DockerActuator(
        runner, membership_inspector=lambda network, service: True
    ).apply(ContainmentAction.block_edge("api_db"))

    assert result.command_exit_code == 7
    assert result.effective is None
    assert result.reason == "docker_disconnect_failed;probe_unavailable"


def test_probe_result_accepts_only_persisted_ground_truth_ids() -> None:
    with pytest.raises(ValueError, match="ground-truth"):
        ProbeResult(True, "obs-000001")
    with pytest.raises(ValueError, match="ground-truth"):
        ProbeResult(True, "gt-1")

    assert ProbeResult(True, "gt-000001").event_id == "gt-000001"


def test_isolation_records_partial_and_exception_exit_codes_and_continues() -> None:
    runner = RecordingCommandRunner(
        results=[CommandResult(0), TimeoutError("disconnect timed out")]
    )
    probes: list[Route] = []

    def probe(route: Route) -> ProbeResult:
        probes.append(route)
        return ProbeResult(route is Route.INTERNAL, f"gt-{len(probes):06d}")

    result = DockerActuator(
        runner, route_probe=probe, membership_inspector=lambda network, service: True
    ).apply(ContainmentAction.isolate_service("api"))

    assert len(runner.calls) == 2
    assert result.command_exit_codes == (0, -1)
    assert result.command_exit_code == -1
    assert result.applied is False
    assert result.effective is True
    assert result.reason == "docker_command_exception"
    assert result.probe_event_ids == ("gt-000001", "gt-000002")


@pytest.mark.parametrize("failed_route", [Route.API, Route.INTERNAL])
def test_actuator_probes_routes_independently_and_retains_available_ids(
    failed_route: Route,
) -> None:
    runner = RecordingCommandRunner()
    calls: list[Route] = []

    def probe(route: Route) -> ProbeResult:
        calls.append(route)
        if route is failed_route:
            raise TimeoutError("probe timed out")
        return ProbeResult(True, "gt-000009")

    result = DockerActuator(runner, route_probe=probe).apply(
        ContainmentAction.block_edge("web_api")
    )

    assert calls == [Route.API, Route.INTERNAL]
    assert result.effective is None
    assert result.reason == "probe_exception"
    assert result.probe_event_ids == ("gt-000009",)


def test_web_isolation_requires_both_routes_to_be_unavailable() -> None:
    availability = {Route.API: False, Route.INTERNAL: False}
    result = DockerActuator(
        RecordingCommandRunner(),
        route_probe=lambda route: ProbeResult(
            availability[route],
            "gt-000001" if route is Route.API else "gt-000002",
        ),
    ).apply(ContainmentAction.isolate_service("web"))

    assert result.applied is True
    assert result.effective is True
    assert result.probe_event_ids == ("gt-000001", "gt-000002")


@pytest.mark.asyncio
async def test_reset_rotates_and_invalidates_episode_state(tmp_path: Path) -> None:
    manager = _manager(tmp_path)

    first = await manager.reset("ep-1")
    second = await manager.reset("ep-2")

    assert first.secret_digest != second.secret_digest
    assert first.canary_digest != second.canary_digest
    assert first.safe_value != second.safe_value
    assert first.route_tokens != second.route_tokens
    with pytest.raises(TypeError):
        second.route_tokens[Route.API] = "replacement"  # type: ignore[index]
    assert stat.S_IMODE((tmp_path / "runtime").stat().st_mode) == 0o700
    assert second.api_state_path == tmp_path / "runtime" / "api" / "route.json"
    assert second.internal_state_path == (
        tmp_path / "runtime" / "internal" / "route.json"
    )
    assert stat.S_IMODE(second.api_state_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(second.internal_state_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(second.api_state_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(second.internal_state_path.stat().st_mode) == 0o600
    api_state = __import__("json").loads(second.api_state_path.read_text())
    internal_state = __import__("json").loads(second.internal_state_path.read_text())
    assert api_state == {
        "token": second.route_tokens[Route.API],
        "canary": api_state["canary"],
    }
    assert internal_state == {
        "token": second.route_tokens[Route.INTERNAL],
        "canary": None,
    }
    mounted_canary = second.canaries.match(api_state["canary"])
    assert mounted_canary is not None
    assert mounted_canary.canary_id == second.canary_id
    assert mounted_canary.digest == second.canary_digest
    assert mounted_canary.current is True


@pytest.mark.asyncio
async def test_reset_uses_episode_seed_for_deterministic_dummy_fixtures(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)

    first = await manager.reset("ep-1", seed=8675309)
    second = await manager.reset("ep-2", seed=8675309)

    assert first.secret_digest == second.secret_digest
    assert first.canary_digest == second.canary_digest
    assert first.safe_value == second.safe_value
    assert first.route_tokens == second.route_tokens


@pytest.mark.asyncio
async def test_relocate_canary_preserves_history_and_verifies_both_route_states(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    fixtures = await manager.reset("ep-1", canary_route=Route.API)
    old_canary = __import__("json").loads(fixtures.api_state_path.read_text())["canary"]

    relocated = await manager.relocate_canary(fixtures, Route.INTERNAL)

    api_state = __import__("json").loads(relocated.api_state_path.read_text())
    internal_state = __import__("json").loads(relocated.internal_state_path.read_text())
    assert api_state["canary"] is None
    assert isinstance(internal_state["canary"], str)
    assert relocated.canary_route is Route.INTERNAL
    historical = relocated.canaries.match(old_canary)
    assert historical is not None
    assert historical.current is False


@pytest.mark.asyncio
async def test_reset_stops_clears_state_then_restores_exactly(tmp_path: Path) -> None:
    lifecycle: list[str] = []
    controller_state: dict[str, Any] = {"route": "api"}
    queued_events = ["obs-000001"]
    runner = RecordingCommandRunner()

    def stop() -> bool:
        lifecycle.append("stop")
        return True

    def clear() -> bool:
        lifecycle.append("clear")
        controller_state.clear()
        queued_events.clear()
        return True

    manager = _manager(
        tmp_path,
        runner=runner,
        actuator=RecordingActuator(runner, lifecycle),
        stop_new_work=stop,
        clear_host_state=clear,
    )

    await manager.reset("ep-1")

    assert lifecycle == ["stop", "clear", "restore"]
    assert controller_state == {}
    assert queued_events == []


@pytest.mark.asyncio
async def test_reset_sends_fixture_values_only_on_psql_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = iter(
        ["known-secret", "known-safe", "api-token", "internal-token", "canary-value"]
    )
    monkeypatch.setattr("chimera.range_manager.secrets.token_urlsafe", lambda size: next(values))
    runner = RecordingCommandRunner()

    await _manager(tmp_path, runner=runner).reset("ep-1")

    argv = runner.calls[-1]
    script = runner.inputs[-1]
    assert argv == [
        "docker",
        "compose",
        "-f",
        "range/compose.yaml",
        "-p",
        "chimera",
        "exec",
        "-T",
        "postgres",
        "psql",
        "-X",
        "-q",
        "-t",
        "-A",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        "chimera_owner",
        "-d",
        "chimera",
    ]
    assert all(value not in " ".join(argv) for value in ("known-secret", "known-safe"))
    assert script is not None
    assert "a25vd24tc2VjcmV0" in script
    assert "a25vd24tc2FmZQ==" in script
    protected_validation = script.index("AS protected_valid")
    safe_validation = script.index("AS safe_valid")
    commit = script.index("COMMIT;")
    assert protected_validation < commit
    assert safe_validation < commit
    assert "ROLLBACK;" in script
    assert "\\quit 3" in script
    assert script.endswith("COMMIT;\n\\echo CHIMERA_FIXTURES_COMMITTED\n")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command_result",
    [
        CommandResult(3, ""),
        CommandResult(0, ""),
        CommandResult(0, "CHIMERA_FIXTURES_COMMITTED\nextra\n"),
    ],
)
async def test_reset_rejects_psql_failure_or_nonexact_commit_marker(
    tmp_path: Path, command_result: CommandResult
) -> None:
    runner = RecordingCommandRunner(results=[command_result])

    with pytest.raises(RangeResetError, match="Postgres fixture reset failed"):
        await _manager(tmp_path, runner=runner).reset("ep-1")


@pytest.mark.asyncio
async def test_new_episode_broker_rejects_stale_handle_before_transport(
    tmp_path: Path,
) -> None:
    class TokenTransport:
        def __init__(self, token: str) -> None:
            self.token = token
            self.calls: list[RangeOperation] = []

        async def request(self, route, operation, body):
            self.calls.append(operation)
            responses = {
                RangeOperation.ROUTES: RangeResponse(
                    200, {"routes": ["api", "internal"]}
                ),
                RangeOperation.PROBE: RangeResponse(
                    200, {"kind": "probe", "reachable": True}
                ),
                RangeOperation.CONFIG: RangeResponse(
                    200,
                    {"kind": "config", "configuration": {"access": "brokered"}},
                ),
                RangeOperation.TOKEN: RangeResponse(
                    200, {"kind": "token", "credential": self.token}
                ),
            }
            return responses[operation]

    manager = _manager(tmp_path)
    first = await manager.reset("ep-1")
    old_transport = TokenTransport(first.route_tokens[Route.API])
    old_broker = Broker(
        episode_id=first.episode_id,
        transport=old_transport,
        telemetry=TelemetryStore(tmp_path, "old-events"),
        canaries=first.canaries,
        expected_secret_digest=first.secret_digest,
    )
    actor = "evaluation-job"
    await old_broker.execute(actor, AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    await old_broker.execute(
        actor, AttackerAction(kind=ActionKind.PROBE_ROUTE, route=Route.API), "A"
    )
    await old_broker.execute(
        actor,
        AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=Route.API),
        "A",
    )
    token_result = await old_broker.execute(
        actor,
        AttackerAction(kind=ActionKind.EXCHANGE_ROUTE_TOKEN, route=Route.API),
        "A",
    )
    stale_handle = str(token_result.result["credential_id"])
    old_broker.quarantine.quarantine(actor)

    second = await manager.reset("ep-2")
    new_transport = TokenTransport(second.route_tokens[Route.API])
    new_broker = Broker(
        episode_id=second.episode_id,
        transport=new_transport,
        telemetry=TelemetryStore(tmp_path, "new-events"),
        canaries=second.canaries,
        expected_secret_digest=second.secret_digest,
    )
    rejected = await new_broker.execute(
        actor,
        AttackerAction(
            kind=ActionKind.QUERY_DATA,
            route=Route.API,
            credential_id=stale_handle,
        ),
        "B",
    )

    assert old_broker.quarantine.is_quarantined(actor) is True
    assert new_broker.quarantine.is_quarantined(actor) is False
    assert rejected.reason == "unknown_credential_handle"
    assert new_transport.calls == []


def test_second_edge_block_is_effective_when_other_route_was_already_blocked() -> None:
    availability = {Route.API: False, Route.INTERNAL: False}
    actuator = DockerActuator(
        RecordingCommandRunner(),
        route_probe=lambda route: ProbeResult(
            availability[route],
            "gt-000001" if route is Route.API else "gt-000002",
        ),
    )

    naive = actuator.apply(ContainmentAction.block_edge("web_api"))
    aware = actuator.apply(
        ContainmentAction.block_edge("web_api"),
        already_blocked=frozenset({Route.INTERNAL}),
    )

    assert naive.effective is False
    assert aware.effective is True
    assert aware.probe_event_ids == ("gt-000001", "gt-000002")


def test_already_blocked_does_not_excuse_an_ineffective_block() -> None:
    availability = {Route.API: True, Route.INTERNAL: False}
    result = DockerActuator(
        RecordingCommandRunner(),
        route_probe=lambda route: ProbeResult(
            availability[route],
            "gt-000001" if route is Route.API else "gt-000002",
        ),
    ).apply(
        ContainmentAction.block_edge("web_api"),
        already_blocked=frozenset({Route.INTERNAL}),
    )

    assert result.effective is False


def test_already_blocked_requires_unaffected_route_to_stay_unavailable() -> None:
    availability = {Route.API: False, Route.INTERNAL: True}
    result = DockerActuator(
        RecordingCommandRunner(),
        route_probe=lambda route: ProbeResult(
            availability[route],
            "gt-000001" if route is Route.API else "gt-000002",
        ),
    ).apply(
        ContainmentAction.block_edge("web_api"),
        already_blocked=frozenset({Route.INTERNAL}),
    )

    # A supposedly blocked internal route that probes as available is evidence
    # the earlier restriction lapsed, so the actuator must not report success.
    assert result.effective is False


def _retry_manager(tmp_path: Path, canary_verifier, *, attempts: int) -> RangeManager:
    command_runner = RecordingCommandRunner()
    return RangeManager(
        runtime_dir=tmp_path / "runtime",
        actuator=DockerActuator(command_runner, membership_inspector=lambda network, service: True),
        command_runner=command_runner,
        stop_new_work=lambda: True,
        clear_host_state=lambda: True,
        health_check=lambda: True,
        route_verifier=lambda route, token, safe, secret: True,
        canary_verifier=canary_verifier,
        verification_attempts=attempts,
        verification_delay_seconds=0,
    )


@pytest.mark.asyncio
async def test_relocation_tolerates_transient_verification_failures(tmp_path: Path) -> None:
    calls: dict[Route, int] = {Route.API: 0, Route.INTERNAL: 0}

    def verifier(route: Route, digest: str | None) -> bool:
        calls[route] += 1
        # Simulate the container briefly failing to read the replaced file.
        return calls[route] > 2

    manager = _retry_manager(tmp_path, verifier, attempts=5)
    fixtures = await manager.reset("ep-1", canary_route=Route.API)
    calls[Route.API] = calls[Route.INTERNAL] = 0

    relocated = await manager.relocate_canary(fixtures, Route.INTERNAL)

    assert relocated.canary_route is Route.INTERNAL
    assert calls == {Route.API: 3, Route.INTERNAL: 3}


@pytest.mark.asyncio
async def test_relocation_still_fails_when_verification_never_succeeds(tmp_path: Path) -> None:
    calls: dict[Route, int] = {Route.API: 0, Route.INTERNAL: 0}

    def verifier(route: Route, digest: str | None) -> bool:
        calls[route] += 1
        return calls[route] <= 1  # reset verifies once per route; relocation never does

    manager = _retry_manager(tmp_path, verifier, attempts=3)
    fixtures = await manager.reset("ep-1", canary_route=Route.API)
    assert calls == {Route.API: 1, Route.INTERNAL: 1}

    with pytest.raises(RangeResetError, match="relocation verification failed"):
        await manager.relocate_canary(fixtures, Route.INTERNAL)

    assert calls[Route.API] == 1 + 3


def test_range_manager_rejects_invalid_retry_settings(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="verification_attempts"):
        _retry_manager(tmp_path, lambda route, digest: True, attempts=0)


def test_isolation_skips_memberships_already_removed_by_an_earlier_block() -> None:
    runner = RecordingCommandRunner()
    availability = {Route.API: False, Route.INTERNAL: False}
    present = {("chimera_web_internal", "chimera-web-1"): False}
    actuator = DockerActuator(
        runner,
        route_probe=lambda route: ProbeResult(
            availability[route], "gt-000001" if route is Route.API else "gt-000002"
        ),
        membership_inspector=lambda network, service: present.get((network, service), True),
    )

    result = actuator.apply(ContainmentAction.isolate_service("web"))

    assert result.applied is True
    assert result.effective is True
    assert result.command_exit_codes == (0, 0, 0)
    assert result.reason is None
    assert runner.calls == [
        ["docker", "network", "disconnect", "chimera_gateway_web", "chimera-web-1"],
        ["docker", "network", "disconnect", "chimera_web_api", "chimera-web-1"],
    ]


def test_membership_inspection_failure_still_attempts_the_disconnect() -> None:
    runner = RecordingCommandRunner()

    def broken_inspector(network: str, service: str) -> bool:
        raise RuntimeError("inspect failed")

    result = DockerActuator(runner, membership_inspector=broken_inspector).apply(
        ContainmentAction.block_edge("web_api")
    )

    assert runner.calls == [["docker", "network", "disconnect", "chimera_web_api", "chimera-web-1"]]
    assert result.applied is True


@pytest.mark.asyncio
async def test_relocation_verifies_only_reachable_routes(tmp_path: Path) -> None:
    verified: list[tuple[Route, str | None]] = []

    def verifier(route: Route, digest: str | None) -> bool:
        verified.append((route, digest))
        return True

    manager = _retry_manager(tmp_path, verifier, attempts=1)
    fixtures = await manager.reset("ep-1", canary_route=Route.INTERNAL)
    verified.clear()

    relocated = await manager.relocate_canary(
        fixtures, Route.API, verify_routes=frozenset({Route.API})
    )

    assert relocated.canary_route is Route.API
    assert [route for route, _ in verified] == [Route.API]
    assert verified[0][1] == relocated.canary_digest
    internal_state = __import__("json").loads(relocated.internal_state_path.read_text())
    assert internal_state["canary"] is None


@pytest.mark.asyncio
async def test_relocation_destination_must_be_verifiable(tmp_path: Path) -> None:
    manager = _retry_manager(tmp_path, lambda route, digest: True, attempts=1)
    fixtures = await manager.reset("ep-1", canary_route=Route.API)

    with pytest.raises(ValueError, match="verifiable"):
        await manager.relocate_canary(
            fixtures, Route.INTERNAL, verify_routes=frozenset({Route.API})
        )
