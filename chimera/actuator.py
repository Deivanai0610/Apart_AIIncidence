from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from chimera.live_lease import live_range_lease_subprocess_options
from chimera.schemas import ActuationResult, ContainmentAction, ContainmentKind, Route


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class ProbeResult:
    available: bool
    event_id: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"gt-\d{6}", self.event_id):
            raise ValueError("probe event_id must be a persisted ground-truth ID")


class DockerCommandRunner(Protocol):
    def run(
        self, argv: list[str], *, input_text: str | None = None
    ) -> CommandResult | int: ...


class SubprocessDockerCommandRunner:
    def __init__(self, *, timeout_seconds: float = 15.0) -> None:
        self._timeout_seconds = timeout_seconds

    def run(self, argv: list[str], *, input_text: str | None = None) -> CommandResult:
        # Docker subprocesses inherit the live-range lease descriptor so an
        # orphaned command cannot outlive the lease if this process is killed.
        lease_environment, pass_fds = live_range_lease_subprocess_options()
        completed = subprocess.run(
            argv,
            check=False,
            shell=False,
            env={"PATH": os.environ.get("PATH", ""), **lease_environment},
            pass_fds=pass_fds,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=self._timeout_seconds,
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


_EDGE_MEMBERSHIP = MappingProxyType(
    {
        "web_api": ("chimera_web_api", "chimera-web-1", Route.API, Route.INTERNAL),
        "web_internal": (
            "chimera_web_internal",
            "chimera-web-1",
            Route.INTERNAL,
            Route.API,
        ),
        "api_db": ("chimera_api_db", "chimera-api-1", Route.API, Route.INTERNAL),
        "internal_db": (
            "chimera_internal_db",
            "chimera-internal-1",
            Route.INTERNAL,
            Route.API,
        ),
    }
)
_SERVICE_MEMBERSHIPS = MappingProxyType(
    {
        "web": (
            ("chimera_gateway_web", "chimera-web-1"),
            ("chimera_web_api", "chimera-web-1"),
            ("chimera_web_internal", "chimera-web-1"),
        ),
        "api": (
            ("chimera_web_api", "chimera-api-1"),
            ("chimera_api_db", "chimera-api-1"),
        ),
        "internal": (
            ("chimera_web_internal", "chimera-internal-1"),
            ("chimera_internal_db", "chimera-internal-1"),
        ),
    }
)
_DECLARED_MEMBERSHIPS = tuple(
    dict.fromkeys(
        (
            *[pair for pairs in _SERVICE_MEMBERSHIPS.values() for pair in pairs],
            ("chimera_gateway_ingress", "chimera-gateway-1"),
            ("chimera_gateway_web", "chimera-gateway-1"),
            ("chimera_api_db", "chimera-postgres-1"),
            ("chimera_internal_db", "chimera-postgres-1"),
        )
    )
)


class DockerActuator:
    def __init__(
        self,
        command_runner: DockerCommandRunner,
        *,
        route_probe: Callable[[Route], ProbeResult] | None = None,
        membership_inspector: Callable[[str, str], bool] | None = None,
    ) -> None:
        self._runner = command_runner
        self._route_probe = route_probe
        self._membership_inspector = membership_inspector

    def apply(
        self,
        action: ContainmentAction,
        *,
        already_blocked: frozenset[Route] = frozenset(),
    ) -> ActuationResult:
        """Apply one enumerated restriction and verify its effect by probing.

        ``already_blocked`` names routes that earlier verified restrictions have
        already made unavailable. The unaffected route of this action is then
        expected to stay unavailable rather than available; without this, a
        second block on the other edge is always judged ineffective.
        """
        if action.kind is ContainmentKind.NO_ACTION:
            return ActuationResult(
                action=action,
                attempted=False,
                applied=False,
                effective=None,
            )
        pairs, blocked_route, unaffected_route = self._pairs_for(action)
        results: list[CommandResult] = []
        failure_reason: str | None = None
        for network, service in pairs:
            # An earlier verified restriction may already have removed this
            # membership (isolate web after block_edge web_internal). Docker
            # reports that as a failed disconnect, which is not a failure of
            # this action, so skip pairs that are already disconnected.
            try:
                already_disconnected = not self._member_present(network, service)
            except RuntimeError:
                already_disconnected = False
            if already_disconnected:
                results.append(CommandResult(0, stdout="already_disconnected"))
                continue
            try:
                results.append(
                    self._command(
                        ["docker", "network", "disconnect", network, service]
                    )
                )
            except Exception:
                results.append(CommandResult(-1))
                failure_reason = "docker_command_exception"
                continue
        applied = all(result.exit_code == 0 for result in results)
        if any(result.exit_code != 0 for result in results):
            applied = False
            failure_reason = failure_reason or "docker_disconnect_failed"
        effective, probe_ids, probe_reason = self._probe_routes(
            action, blocked_route, unaffected_route, already_blocked=already_blocked
        )
        nonzero = next((result.exit_code for result in results if result.exit_code != 0), 0)
        reasons = tuple(
            reason for reason in (failure_reason, probe_reason) if reason is not None
        )
        return ActuationResult(
            action=action,
            attempted=True,
            applied=applied,
            effective=effective,
            command_exit_code=nonzero,
            command_exit_codes=tuple(result.exit_code for result in results),
            probe_event_ids=probe_ids,
            reason=";".join(reasons) or None,
        )

    def probe(
        self,
        action: ContainmentAction,
        blocked_route: Route | None = None,
        unaffected_route: Route | None = None,
        *,
        already_blocked: frozenset[Route] = frozenset(),
    ) -> tuple[bool | None, tuple[str, ...]]:
        effective, event_ids, _ = self._probe_routes(
            action, blocked_route, unaffected_route, already_blocked=already_blocked
        )
        return effective, event_ids

    def _probe_routes(
        self,
        action: ContainmentAction,
        blocked_route: Route | None = None,
        unaffected_route: Route | None = None,
        *,
        already_blocked: frozenset[Route] = frozenset(),
    ) -> tuple[bool | None, tuple[str, ...], str | None]:
        if self._route_probe is None:
            return None, (), "probe_unavailable"
        if blocked_route is None or unaffected_route is None:
            _, blocked_route, unaffected_route = self._pairs_for(action)
        results: dict[Route, ProbeResult] = {}
        event_ids: list[str] = []
        probe_failed = False
        for route in (blocked_route, unaffected_route):
            try:
                result = self._route_probe(route)
            except Exception:
                probe_failed = True
                continue
            results[route] = result
            event_ids.append(result.event_id)
        if probe_failed or set(results) != {blocked_route, unaffected_route}:
            return None, tuple(event_ids), "probe_exception"
        blocked = results[blocked_route]
        unaffected = results[unaffected_route]
        if action.kind is ContainmentKind.ISOLATE_SERVICE and action.target == "web":
            effective = not blocked.available and not unaffected.available
        else:
            expected_unaffected_available = unaffected_route not in already_blocked
            effective = (
                not blocked.available
                and unaffected.available == expected_unaffected_available
            )
        return effective, tuple(event_ids), None

    def restore(self) -> tuple[CommandResult, ...]:
        restored: list[CommandResult] = []
        for network, service in _DECLARED_MEMBERSHIPS:
            if not self._member_present(network, service):
                restored.append(
                    self._command(["docker", "network", "connect", network, service])
                )
        if any(result.exit_code != 0 for result in restored):
            raise RuntimeError("declared network restoration failed")
        return tuple(restored)

    def _pairs_for(
        self, action: ContainmentAction
    ) -> tuple[tuple[tuple[str, str], ...], Route, Route]:
        if action.kind is ContainmentKind.BLOCK_EDGE:
            assert isinstance(action.target, str)
            network, service, blocked, unaffected = _EDGE_MEMBERSHIP[action.target]
            return ((network, service),), blocked, unaffected
        assert action.kind is ContainmentKind.ISOLATE_SERVICE
        assert isinstance(action.target, str)
        pairs = _SERVICE_MEMBERSHIPS[action.target]
        if action.target == "web":
            return pairs, Route.API, Route.INTERNAL
        blocked = Route.API if action.target == "api" else Route.INTERNAL
        unaffected = Route.INTERNAL if blocked is Route.API else Route.API
        return pairs, blocked, unaffected

    def _command(self, argv: list[str]) -> CommandResult:
        result = self._runner.run(argv)
        return result if isinstance(result, CommandResult) else CommandResult(result)

    def _member_present(self, network: str, service: str) -> bool:
        if self._membership_inspector is not None:
            return self._membership_inspector(network, service)
        result = self._command(
            [
                "docker",
                "network",
                "inspect",
                network,
                "--format",
                "{{json .Containers}}",
            ]
        )
        if result.exit_code != 0:
            raise RuntimeError("declared network membership inspection failed")
        try:
            containers = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("declared network membership is invalid") from error
        if not isinstance(containers, dict):
            raise RuntimeError("declared network membership is invalid")
        return any(
            isinstance(container, dict) and container.get("Name") == service
            for container in containers.values()
        )
