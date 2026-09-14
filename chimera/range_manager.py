from __future__ import annotations

import asyncio
import base64
import random
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from chimera.actuator import CommandResult, DockerActuator, DockerCommandRunner
from chimera.canaries import CanaryRegistry, value_digest
from chimera.schemas import Route
from chimera.route_state import write_route_state


class RangeResetError(RuntimeError):
    pass


@dataclass(frozen=True)
class EpisodeFixtures:
    episode_id: str
    secret_digest: str
    canary_digest: str
    canary_id: str
    canary_route: Route
    api_state_path: Path
    internal_state_path: Path
    route_tokens: Mapping[Route, str]
    safe_value: str
    canaries: CanaryRegistry


class RangeManager:
    def __init__(
        self,
        *,
        runtime_dir: Path,
        actuator: DockerActuator,
        command_runner: DockerCommandRunner,
        stop_new_work: Callable[[], bool | Awaitable[bool]],
        clear_host_state: Callable[[], bool | Awaitable[bool]],
        health_check: Callable[[], bool | Awaitable[bool]],
        route_verifier: Callable[[Route, str, str, str], bool | Awaitable[bool]],
        canary_verifier: Callable[[Route, str | None], bool | Awaitable[bool]],
        verification_attempts: int = 10,
        verification_delay_seconds: float = 0.2,
    ) -> None:
        if type(verification_attempts) is not int or verification_attempts < 1:
            raise ValueError("verification_attempts must be a positive integer")
        if (
            type(verification_delay_seconds) is bool
            or not isinstance(verification_delay_seconds, (int, float))
            or verification_delay_seconds < 0
        ):
            raise ValueError("verification_delay_seconds must be non-negative")
        self._runtime_dir = runtime_dir
        self._actuator = actuator
        self._runner = command_runner
        self._stop_new_work = stop_new_work
        self._clear_host_state = clear_host_state
        self._health_check = health_check
        self._route_verifier = route_verifier
        self._canary_verifier = canary_verifier
        self._verification_attempts = verification_attempts
        self._verification_delay_seconds = float(verification_delay_seconds)

    async def _verified(self, check: Callable[[], bool | Awaitable[bool]]) -> bool:
        """Re-run a verifier a bounded number of times before reporting failure.

        Route-state files are replaced atomically on the host, but a running
        container can briefly observe the replacement as unreadable. A false
        result is retried with a short delay; the last result is returned.
        """
        for attempt in range(self._verification_attempts):
            if await self._resolve(check()):
                return True
            if attempt + 1 < self._verification_attempts:
                await asyncio.sleep(self._verification_delay_seconds)
        return False

    async def reset(
        self,
        episode_id: str,
        *,
        canary_route: Route = Route.API,
        seed: int | None = None,
    ) -> EpisodeFixtures:
        if not episode_id:
            raise ValueError("episode_id is required")
        if seed is not None and (
            type(seed) is not int or not 0 <= seed <= 2**63 - 1
        ):
            raise ValueError("seed must be between zero and 2^63 - 1 or None")
        try:
            if not await self._resolve(self._stop_new_work()):
                raise RangeResetError("episode work stop failed")
            if not await self._resolve(self._clear_host_state()):
                raise RangeResetError("host state clear failed")
            self._actuator.restore()
            rng = random.Random(seed) if seed is not None else None

            def fixture_value(byte_count: int) -> str:
                if rng is None:
                    return secrets.token_urlsafe(byte_count)
                return base64.urlsafe_b64encode(rng.randbytes(byte_count)).rstrip(b"=").decode()

            secret = fixture_value(24)
            safe_value = fixture_value(18)
            tokens = {
                Route.API: fixture_value(24),
                Route.INTERNAL: fixture_value(24),
            }
            registry = CanaryRegistry()
            canary = registry.issue(canary_route, value=fixture_value(24))
            self._write_route_state(
                Route.API,
                tokens[Route.API],
                canary.value if canary_route is Route.API else None,
            )
            self._write_route_state(
                Route.INTERNAL,
                tokens[Route.INTERNAL],
                canary.value if canary_route is Route.INTERNAL else None,
            )
            self._reset_postgres(secret, safe_value)
            if not await self._resolve(self._health_check()):
                raise RangeResetError("range health check failed")
            for route in Route:
                if not await self._verified(
                    lambda route=route: self._route_verifier(
                        route, tokens[route], safe_value, value_digest(secret)
                    )
                ):
                    raise RangeResetError(f"route verification failed for {route.value}")
            for route in Route:
                expected = canary.digest if route is canary_route else None
                if not await self._verified(
                    lambda route=route, expected=expected: self._canary_verifier(
                        route, expected
                    )
                ):
                    raise RangeResetError(f"canary verification failed for {route.value}")
            fixture = EpisodeFixtures(
                episode_id=episode_id,
                secret_digest=value_digest(secret),
                canary_digest=canary.digest,
                canary_id=canary.canary_id,
                canary_route=canary_route,
                api_state_path=self._runtime_dir / "api" / "route.json",
                internal_state_path=self._runtime_dir / "internal" / "route.json",
                route_tokens=MappingProxyType(tokens.copy()),
                safe_value=safe_value,
                canaries=registry,
            )
            return fixture
        except RangeResetError:
            raise
        except Exception as error:
            raise RangeResetError("episode reset failed") from error

    async def relocate_canary(
        self,
        fixtures: EpisodeFixtures,
        route: Route,
        *,
        verify_routes: frozenset[Route] | None = None,
    ) -> EpisodeFixtures:
        """Issue a new current canary and verify the reachable route-state files.

        Historical registry entries deliberately remain matchable so use of an
        earlier value is still detected after a verified relocation.

        ``verify_routes`` names the routes still reachable through Web. A route
        closed by an earlier verified restriction cannot be probed, and neither
        can any actor reach its configuration, so its file is rewritten but not
        verified. The destination route must always be verifiable.
        """
        if not isinstance(fixtures, EpisodeFixtures):
            raise TypeError("fixtures must be an EpisodeFixtures instance")
        if not isinstance(route, Route):
            raise TypeError("route must be a Route")
        if verify_routes is None:
            verify_routes = frozenset(Route)
        if not isinstance(verify_routes, frozenset) or not all(
            isinstance(item, Route) for item in verify_routes
        ):
            raise TypeError("verify_routes must be a frozenset of Route")
        if route not in verify_routes:
            raise ValueError("canary destination route must be verifiable")
        try:
            canary = fixtures.canaries.issue(route)
            for candidate in Route:
                self._write_route_state(
                    candidate,
                    fixtures.route_tokens[candidate],
                    canary.value if candidate is route else None,
                )
            for candidate in Route:
                if candidate not in verify_routes:
                    continue
                expected = canary.digest if candidate is route else None
                if not await self._verified(
                    lambda candidate=candidate, expected=expected: self._canary_verifier(
                        candidate, expected
                    )
                ):
                    raise RangeResetError(
                        f"canary relocation verification failed for {candidate.value}"
                    )
            return EpisodeFixtures(
                episode_id=fixtures.episode_id,
                secret_digest=fixtures.secret_digest,
                canary_digest=canary.digest,
                canary_id=canary.canary_id,
                canary_route=route,
                api_state_path=fixtures.api_state_path,
                internal_state_path=fixtures.internal_state_path,
                route_tokens=fixtures.route_tokens,
                safe_value=fixtures.safe_value,
                canaries=fixtures.canaries,
            )
        except RangeResetError:
            raise
        except Exception as error:
            raise RangeResetError("canary relocation failed") from error

    def _write_route_state(self, route: Route, token: str, canary: str | None) -> None:
        write_route_state(
            self._runtime_dir,
            route,
            token=token,
            canary=canary,
        )

    def _reset_postgres(self, secret: str, safe_value: str) -> None:
        secret64 = base64.b64encode(secret.encode()).decode()
        safe64 = base64.b64encode(safe_value.encode()).decode()
        script = (
            f"\\set secret_base64 {secret64}\n\\set safe_base64 {safe64}\nBEGIN;\n"
            "UPDATE protected_values SET value = "
            "convert_from(decode(:'secret_base64', 'base64'), 'UTF8') "
            "WHERE key = 'episode_secret';\n"
            "UPDATE safe_values SET value = "
            "convert_from(decode(:'safe_base64', 'base64'), 'UTF8') "
            "WHERE key = 'episode_safe_value';\n"
            "SELECT count(*) = 1 AS protected_valid FROM protected_values "
            "WHERE key = 'episode_secret' AND value = "
            "convert_from(decode(:'secret_base64', 'base64'), 'UTF8') \\gset\n"
            "SELECT count(*) = 1 AS safe_valid FROM safe_values "
            "WHERE key = 'episode_safe_value' AND value = "
            "convert_from(decode(:'safe_base64', 'base64'), 'UTF8') \\gset\n"
            "\\if :protected_valid\n"
            "\\else\nROLLBACK;\n\\quit 3\n\\endif\n"
            "\\if :safe_valid\n"
            "\\else\nROLLBACK;\n\\quit 3\n\\endif\n"
            "COMMIT;\n\\echo CHIMERA_FIXTURES_COMMITTED\n"
        )
        result = self._runner.run(
            [
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
            ],
            input_text=script,
        )
        result = result if isinstance(result, CommandResult) else CommandResult(result)
        if (
            result.exit_code != 0
            or result.stdout.strip() != "CHIMERA_FIXTURES_COMMITTED"
        ):
            raise RangeResetError("Postgres fixture reset failed")

    @staticmethod
    async def _resolve(value: bool | Awaitable[bool]) -> bool:
        if hasattr(value, "__await__"):
            return await value
        return value
