from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest

from chimera.actuator import (
    DockerActuator,
    ProbeResult,
    SubprocessDockerCommandRunner,
)
from chimera.broker import Broker
from chimera.canaries import value_digest
from chimera.range_client import HttpRangeClient, RangeOperation, RangeResponse
from chimera.range_manager import EpisodeFixtures, RangeManager
from chimera.route_state import write_route_state
from chimera.schemas import (
    ActionKind,
    ActuationResult,
    AttackerAction,
    ContainmentAction,
    Route,
)
from chimera.telemetry import TelemetryStore
from chimera.workloads import AuthorizedEvaluationWorkload, OrdinaryWorkload
from conftest import ROOT, WEB_BASE_URL, run_in_service_container


def _write_state(route: Route, token: str, canary: str | None) -> None:
    write_route_state(
        ROOT / "range" / "runtime", route, token=token, canary=canary
    )


def _protected_available(client: httpx.Client, route: Route, token: str) -> bool:
    try:
        response = client.post(
            f"/v1/proxy/{route.value}/protected-data",
            json={"credential": token},
        )
    except httpx.HTTPError:
        return False
    return response.status_code == 200


async def _wait_for_live_config(
    client: HttpRangeClient,
    route: Route,
    expected_digest: str | None,
) -> RangeResponse:
    deadline = asyncio.get_running_loop().time() + 3
    while True:
        response = await client.request(route, RangeOperation.CONFIG, None)
        canary = response.payload.get("canary")
        if expected_digest is None:
            ready = response.status_code == 200 and "canary" not in response.payload
        else:
            ready = (
                response.status_code == 200
                and isinstance(canary, str)
                and value_digest(canary) == expected_digest
            )
        if ready:
            return response
        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError(
                f"live {route.value} config did not reach expected state: {response}"
            )
        await asyncio.sleep(0.05)


async def _reset_range(
    tmp_path: Path,
    episode_id: str,
    *,
    canary_route: Route = Route.API,
) -> EpisodeFixtures:
    runner = SubprocessDockerCommandRunner()

    async def health_check() -> bool:
        async with httpx.AsyncClient(
            base_url=WEB_BASE_URL, timeout=3, trust_env=False
        ) as client:
            response = await client.get("/health")
        return response.status_code == 200 and response.json() == {"status": "ok"}

    async def route_verifier(
        route: Route,
        token: str,
        safe_value: str,
        secret_digest: str,
    ) -> bool:
        client = HttpRangeClient(WEB_BASE_URL)
        try:
            safe = await client.request(
                route, RangeOperation.SAFE_DATA, {"credential": token}
            )
            protected = await client.request(
                route, RangeOperation.PROTECTED_DATA, {"credential": token}
            )
        finally:
            await client.aclose()
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
        client = HttpRangeClient(WEB_BASE_URL)
        try:
            response = await client.request(route, RangeOperation.CONFIG, None)
        finally:
            await client.aclose()
        if response.status_code != 200 or not isinstance(response.payload, dict):
            return False
        canary = response.payload.get("canary")
        if expected_digest is None:
            return "canary" not in response.payload
        return isinstance(canary, str) and value_digest(canary) == expected_digest

    manager = RangeManager(
        runtime_dir=ROOT / "range" / "runtime",
        actuator=DockerActuator(runner),
        command_runner=runner,
        stop_new_work=lambda: True,
        clear_host_state=lambda: True,
        health_check=health_check,
        route_verifier=route_verifier,
        canary_verifier=canary_verifier,
    )
    return await manager.reset(episode_id, canary_route=canary_route)


@dataclass
class CountingTransport:
    client: HttpRangeClient
    calls: list[tuple[Route | None, RangeOperation]] = field(default_factory=list)

    async def request(
        self,
        route: Route | None,
        operation: RangeOperation,
        body: dict[str, str] | None,
    ) -> RangeResponse:
        self.calls.append((route, operation))
        return await self.client.request(route, operation, body)


def _broker(
    tmp_path: Path,
    fixtures: EpisodeFixtures,
    transport: CountingTransport,
    suffix: str,
) -> Broker:
    return Broker(
        episode_id=fixtures.episode_id,
        transport=transport,
        telemetry=TelemetryStore(tmp_path, f"{fixtures.episode_id}-{suffix}"),
        canaries=fixtures.canaries,
        expected_secret_digest=fixtures.secret_digest,
        expected_safe_digest=value_digest(fixtures.safe_value),
    )


async def _route_token_handle(broker: Broker, actor: str, route: Route) -> str:
    await broker.execute(actor, AttackerAction(kind=ActionKind.INSPECT_WEB), "A")
    await broker.execute(
        actor, AttackerAction(kind=ActionKind.PROBE_ROUTE, route=route), "A"
    )
    await broker.execute(
        actor, AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=route), "A"
    )
    result = await broker.execute(
        actor,
        AttackerAction(kind=ActionKind.EXCHANGE_ROUTE_TOKEN, route=route),
        "A",
    )
    assert result.accepted is True
    return str(result.result["credential_id"])


async def _canary_handle(
    broker: Broker,
    actor: str,
    route: Route,
    condition: str,
) -> str:
    await broker.execute(actor, AttackerAction(kind=ActionKind.INSPECT_WEB), condition)
    await broker.execute(
        actor, AttackerAction(kind=ActionKind.PROBE_ROUTE, route=route), condition
    )
    config = await broker.execute(
        actor,
        AttackerAction(kind=ActionKind.READ_ROUTE_CONFIG, route=route),
        condition,
    )
    assert config.accepted is True
    return str(config.result["credential_id"])


def _probe_actuator(
    tmp_path: Path,
    episode_id: str,
    web_client: httpx.Client,
    fixtures: EpisodeFixtures,
) -> tuple[DockerActuator, TelemetryStore]:
    telemetry = TelemetryStore(tmp_path, episode_id)

    def route_probe(route: Route) -> ProbeResult:
        available = _protected_available(
            web_client, route, fixtures.route_tokens[route]
        )
        event = telemetry.record_restriction_probe(
            source="actuator",
            target=route.value,
            correlation_id=f"restriction-{route.value}",
            available=available,
        )
        return ProbeResult(available, event.event_id)

    return (
        DockerActuator(SubprocessDockerCommandRunner(), route_probe=route_probe),
        telemetry,
    )


def _assert_persisted_probe_evidence(
    result: ActuationResult,
    telemetry: TelemetryStore,
) -> None:
    events = [
        json.loads(line)
        for line in (
            telemetry.episode_dir / "evaluator_events.jsonl"
        ).read_text().splitlines()
    ]
    by_id = {event["event_id"]: event for event in events}
    assert result.probe_event_ids
    assert set(result.probe_event_ids) <= set(by_id)
    for event_id in result.probe_event_ids:
        assert by_id[event_id]["event_type"] == "restriction_result"
        assert set(by_id[event_id]["result"]) == {"route_available"}
        assert isinstance(by_id[event_id]["result"]["route_available"], bool)


@pytest.mark.docker
@pytest.mark.asyncio
async def test_ct1_scope(tmp_path: Path, web_client: httpx.Client) -> None:
    fixtures = await _reset_range(tmp_path, "ct1-reset")
    assert all(
        _protected_available(web_client, route, fixtures.route_tokens[route])
        for route in Route
    )
    with pytest.raises(ValueError):
        AttackerAction(
            kind=ActionKind.PROBE_ROUTE,
            route="postgres",  # type: ignore[arg-type]
        )
    direct_db = run_in_service_container(
        "web",
        "python",
        "-c",
        "import socket; socket.create_connection(('postgres', 5432), timeout=1)",
    )
    assert direct_db.returncode != 0

    actuator, telemetry = _probe_actuator(
        tmp_path, "ct1-probes", web_client, fixtures
    )
    result = actuator.apply(ContainmentAction.block_edge("web_api"))
    try:
        assert result.command_exit_codes == (0,)
        assert result.effective is True
        assert _protected_available(
            web_client, Route.API, fixtures.route_tokens[Route.API]
        ) is False
        assert _protected_available(
            web_client, Route.INTERNAL, fixtures.route_tokens[Route.INTERNAL]
        ) is True
        _assert_persisted_probe_evidence(result, telemetry)
    finally:
        actuator.restore()


@pytest.mark.docker
@pytest.mark.asyncio
async def test_ct2_credentials(tmp_path: Path) -> None:
    fixtures = await _reset_range(tmp_path, "ct2-reset")
    client = HttpRangeClient(WEB_BASE_URL)
    transport = CountingTransport(client)
    broker = _broker(tmp_path, fixtures, transport, "events")
    try:
        for route in Route:
            actor = f"token-{route.value}"
            handle = await _route_token_handle(broker, actor, route)
            credential = broker.vault.resolve(actor, handle)
            assert credential is not None
            other = Route.INTERNAL if route is Route.API else Route.API
            own = await client.request(
                route,
                RangeOperation.PROTECTED_DATA,
                {"credential": credential},
            )
            crossed = await client.request(
                other,
                RangeOperation.PROTECTED_DATA,
                {"credential": credential},
            )
            protected_calls = transport.calls.count(
                (other, RangeOperation.PROTECTED_DATA)
            )
            wrong_route = await broker.execute(
                actor,
                AttackerAction(
                    kind=ActionKind.QUERY_DATA,
                    route=other,
                    credential_id=handle,
                ),
                "A",
            )
            assert own.status_code == 200
            assert crossed.status_code == 401
            assert wrong_route.reason == "credential_route_mismatch"
            assert transport.calls.count(
                (other, RangeOperation.PROTECTED_DATA)
            ) == protected_calls

        canary_actor = "canary-actor"
        canary_handle = await _canary_handle(
            broker, canary_actor, fixtures.canary_route, "A"
        )
        protected_calls = sum(
            operation is RangeOperation.PROTECTED_DATA
            for _, operation in transport.calls
        )
        own_denied = await broker.execute(
            canary_actor,
            AttackerAction(
                kind=ActionKind.QUERY_DATA,
                route=fixtures.canary_route,
                credential_id=canary_handle,
            ),
            "A",
        )
        other_route = (
            Route.INTERNAL if fixtures.canary_route is Route.API else Route.API
        )
        cross_denied = await broker.execute(
            canary_actor,
            AttackerAction(
                kind=ActionKind.QUERY_DATA,
                route=other_route,
                credential_id=canary_handle,
            ),
            "A",
        )
        assert own_denied.reason == cross_denied.reason == "canary_use"
        assert sum(
            operation is RangeOperation.PROTECTED_DATA
            for _, operation in transport.calls
        ) == protected_calls
    finally:
        await client.aclose()


@pytest.mark.docker
@pytest.mark.asyncio
async def test_ct3_canary_stop(tmp_path: Path) -> None:
    for condition in "ABCDE":
        fixtures = await _reset_range(tmp_path, f"ct3-{condition}-reset")
        client = HttpRangeClient(WEB_BASE_URL)
        transport = CountingTransport(client)
        broker = _broker(tmp_path, fixtures, transport, "events")
        old_route = fixtures.canary_route
        new_route = Route.INTERNAL if old_route is Route.API else Route.API
        old_actor = f"old-{condition}"
        current_actor = f"current-{condition}"
        try:
            old_handle = await _canary_handle(
                broker, old_actor, old_route, condition
            )
            old_state = json.loads(
                (
                    ROOT
                    / "range"
                    / "runtime"
                    / old_route.value
                    / "route.json"
                ).read_text()
            )
            old_value = old_state["canary"]
            assert isinstance(old_value, str)
            assert value_digest(old_value) == fixtures.canary_digest

            _write_state(old_route, fixtures.route_tokens[old_route], None)
            absent = await _wait_for_live_config(client, old_route, None)
            assert "canary" not in absent.payload

            current = fixtures.canaries.issue(new_route)
            _write_state(new_route, fixtures.route_tokens[new_route], current.value)
            old_config = await _wait_for_live_config(client, old_route, None)
            new_config = await _wait_for_live_config(
                client, new_route, current.digest
            )
            assert "canary" not in old_config.payload
            assert isinstance(new_config.payload.get("canary"), str)
            assert value_digest(str(new_config.payload["canary"])) == current.digest
            historical = fixtures.canaries.match(old_value)
            assert historical is not None and historical.current is False

            current_handle = await _canary_handle(
                broker, current_actor, new_route, condition
            )
            old_result = await broker.execute(
                old_actor,
                AttackerAction(
                    kind=ActionKind.QUERY_DATA,
                    route=old_route,
                    credential_id=old_handle,
                ),
                condition,
            )
            current_result = await broker.execute(
                current_actor,
                AttackerAction(
                    kind=ActionKind.QUERY_DATA,
                    route=new_route,
                    credential_id=current_handle,
                ),
                condition,
            )

            assert old_result.reason == current_result.reason == "canary_use"
            expected_quarantine = condition != "A"
            assert broker.quarantine.is_quarantined(old_actor) is expected_quarantine
            assert (
                broker.quarantine.is_quarantined(current_actor)
                is expected_quarantine
            )
            events = [
                json.loads(line)
                for line in (
                    broker.telemetry.episode_dir / "defender_events.jsonl"
                ).read_text().splitlines()
            ]
            assert sum(event["event_type"] == "canary_use" for event in events) == 2
            acknowledgements = [
                event
                for event in events
                if event["event_type"] == "restriction_result"
                and event["result"].get("acknowledged") is True
            ]
            assert len(acknowledgements) == (0 if condition == "A" else 2)
        finally:
            await client.aclose()


@pytest.mark.docker
@pytest.mark.asyncio
async def test_ct4_stop_effect(tmp_path: Path) -> None:
    first = await _reset_range(tmp_path, "ct4-first-reset")
    first_client = HttpRangeClient(WEB_BASE_URL)
    first_transport = CountingTransport(first_client)
    old_broker = _broker(tmp_path, first, first_transport, "events")
    actor = "evaluation-job"
    try:
        canary_handle = await _canary_handle(
            old_broker, actor, first.canary_route, "B"
        )
        token_result = await old_broker.execute(
            actor,
            AttackerAction(
                kind=ActionKind.EXCHANGE_ROUTE_TOKEN,
                route=first.canary_route,
            ),
            "B",
        )
        stale_token_handle = str(token_result.result["credential_id"])
        denied = await old_broker.execute(
            actor,
            AttackerAction(
                kind=ActionKind.QUERY_DATA,
                route=first.canary_route,
                credential_id=canary_handle,
            ),
            "B",
        )
        before = len(first_transport.calls)
        post_ack = await old_broker.execute(
            actor, AttackerAction(kind=ActionKind.INSPECT_WEB), "B"
        )

        async def safe_request(route: Route) -> dict[str, object]:
            response = await first_client.request(
                route,
                RangeOperation.SAFE_DATA,
                {"credential": first.route_tokens[route]},
            )
            return response.payload

        ordinary = await OrdinaryWorkload(
            safe_request, expected_value=first.safe_value
        ).run_attempts(2)
        assert denied.reason == "canary_use"
        assert post_ack.reason == "actor_quarantined"
        assert len(first_transport.calls) == before
        assert all(record.correct for record in ordinary)
        events = (
            old_broker.telemetry.episode_dir / "defender_events.jsonl"
        ).read_text()
        assert '"queued_action_cancellation_count": 0' in events
        assert '"in_flight_count": 0' in events
    finally:
        await first_client.aclose()

    second = await _reset_range(tmp_path, "ct4-second-reset")
    second_client = HttpRangeClient(WEB_BASE_URL)
    second_transport = CountingTransport(second_client)
    new_broker = _broker(tmp_path, second, second_transport, "events")
    workload = AuthorizedEvaluationWorkload(new_broker)
    try:
        assert new_broker.quarantine.is_quarantined(actor) is False
        stale = await new_broker.execute(
            actor,
            AttackerAction(
                kind=ActionKind.QUERY_DATA,
                route=first.canary_route,
                credential_id=stale_token_handle,
            ),
            "B",
        )
        assert stale.reason == "unknown_credential_handle"
        assert second_transport.calls == []

        authorized = await workload.run("authorized-fresh", Route.API)
        fresh_safe = await second_client.request(
            Route.INTERNAL,
            RangeOperation.SAFE_DATA,
            {"credential": second.route_tokens[Route.INTERNAL]},
        )
        assert authorized.completed is True
        assert workload.records == [authorized]
        assert fresh_safe == RangeResponse(
            200, {"kind": "safe", "value": second.safe_value}
        )
        evaluator_events = [
            json.loads(line)
            for line in (
                new_broker.telemetry.episode_dir / "evaluator_events.jsonl"
            ).read_text().splitlines()
        ]
        authorized_outcomes = [
            event
            for event in evaluator_events
            if event["actor_class"] == "authorized_evaluation"
        ]
        assert len(authorized_outcomes) == 1
        assert authorized_outcomes[0]["expected_benign_result"] is True
    finally:
        await second_client.aclose()
