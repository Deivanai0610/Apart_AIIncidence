from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

from chimera.broker import AuthorizedWorkflowResult, Broker
from chimera.schemas import Route


@dataclass(frozen=True)
class OrdinaryAttempt:
    route: Route
    elapsed_ns: int
    correct: bool
    kind: Literal["safe"] | None
    status: Literal["success", "invalid_response", "transport_failure"]


class OrdinaryWorkload:
    def __init__(
        self,
        safe_request: Callable[[Route], Awaitable[dict[str, object]]],
        *,
        expected_value: str,
    ) -> None:
        self._safe_request = safe_request
        self._expected_value = expected_value
        self.records: list[OrdinaryAttempt] = []
        self._next_route = Route.API

    @property
    def next_route(self) -> Route:
        return self._next_route

    async def run_attempts(
        self, count: int, *, interval_seconds: float = 0.0
    ) -> tuple[OrdinaryAttempt, ...]:
        if count < 0:
            raise ValueError("count must not be negative")
        started = time.monotonic_ns()
        records: list[OrdinaryAttempt] = []
        for index in range(count):
            route = self._next_route
            self._next_route = Route.INTERNAL if route is Route.API else Route.API
            try:
                response = await self._safe_request(route)
            except Exception:
                response = None
            correct = response == {"kind": "safe", "value": self._expected_value}
            kind: Literal["safe"] | None = (
                "safe"
                if isinstance(response, dict) and response.get("kind") == "safe"
                else None
            )
            if response is None:
                status: Literal[
                    "success", "invalid_response", "transport_failure"
                ] = "transport_failure"
            else:
                status = "success" if correct else "invalid_response"
            attempt = OrdinaryAttempt(
                route=route,
                elapsed_ns=time.monotonic_ns() - started,
                correct=correct,
                kind=kind,
                status=status,
            )
            self.records.append(attempt)
            records.append(attempt)
            if interval_seconds and index + 1 < count:
                await asyncio.sleep(interval_seconds)
        return tuple(records)


class AuthorizedEvaluationWorkload:
    def __init__(self, broker: Broker) -> None:
        self._broker = broker
        self.records: list[AuthorizedWorkflowResult] = []

    async def run(self, actor_id: str, route: Route) -> AuthorizedWorkflowResult:
        try:
            result = await self._broker.execute_authorized_workflow(actor_id, route)
        except Exception:
            self.records.append(AuthorizedWorkflowResult(False, route, "transport_failure"))
            raise
        self.records.append(result)
        return result
