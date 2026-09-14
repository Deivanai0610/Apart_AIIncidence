from __future__ import annotations

import json
import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from chimera.config import StaticPolicyConfig
from chimera.controllers import (
    ControllerState,
    EventOrderingKey,
    HeuristicPlacementController,
    PassiveController,
    StaticController,
    VerifiedRestriction,
    build_controller,
    LLMDefenderController,
    DEFAULT_DEFENDER_PROMPT,
    DefenderDecisionResult,
    FallbackCategory,
    normalize_controller_result,
)
from chimera.models import ModelProviderFailure, ModelReply, ModelRequest, ProviderFailureDetail
from chimera.schemas import (
    ActuationResult,
    ContainmentAction,
    ContainmentKind,
    DefenderDecision,
    EventType,
    ObservationEvent,
    Route,
)


BASE_TIME = datetime(2026, 9, 13, tzinfo=UTC)


@pytest.fixture
def static_config() -> StaticPolicyConfig:
    return StaticPolicyConfig(
        initial_canary_route=Route.API,
        tie_break_route=Route.API,
        first_route_pattern=[
            "route_probe",
            "config_read",
            "token_exchange",
        ],
        alternate_route_pattern=[
            "route_probe",
            "config_read",
            "token_exchange",
        ],
    )


def event(
    number: int,
    event_type: EventType,
    *,
    route: str = "api",
    correlation_id: str = "corr-1",
    elapsed_ns: int | None = None,
    result: dict[str, object] | None = None,
) -> ObservationEvent:
    return ObservationEvent(
        episode_id="episode-1",
        event_id=f"obs-{number:06d}",
        elapsed_ns=number if elapsed_ns is None else elapsed_ns,
        occurred_at=BASE_TIME + timedelta(microseconds=number),
        event_type=event_type,
        source="broker",
        target=route,
        correlation_id=correlation_id,
        result={} if result is None else result,
    )


def test_default_defender_prompt_is_the_approved_prompt_contract() -> None:
    from pathlib import Path

    assert DEFAULT_DEFENDER_PROMPT == Path("prompts/defender.txt").read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_plain_controller_decision_normalizes_to_non_fallback_result(
    static_config: StaticPolicyConfig,
) -> None:
    result = normalize_controller_result(
        await PassiveController().decide((), ControllerState())
    )

    assert result.fallback_used is False


def test_correlation_id_is_always_opaque_digest() -> None:
    projected = LLMDefenderController._safe_correlation_id("corr-secret")

    assert projected.startswith("corr-")
    assert projected != "corr-secret"


def route_pattern(
    start: int,
    route: str,
    correlation_id: str = "corr-1",
) -> tuple[ObservationEvent, ...]:
    return (
        event(start, EventType.ROUTE_PROBE, route=route, correlation_id=correlation_id),
        event(start + 1, EventType.CONFIG_READ, route=route, correlation_id=correlation_id),
        event(start + 2, EventType.TOKEN_EXCHANGE, route=route, correlation_id=correlation_id),
    )


def verified_block(
    edge: str,
    *,
    effective: bool | None = True,
    boundary: EventOrderingKey | None = None,
) -> VerifiedRestriction:
    return VerifiedRestriction(
        result=ActuationResult(
            action=ContainmentAction.block_edge(edge),
            attempted=True,
            applied=True,
            effective=effective,
            command_exit_code=0,
            command_exit_codes=(0,),
        ),
        verification_boundary=boundary,
    )


def verified_isolation(
    target: str,
    *,
    boundary: EventOrderingKey | None = None,
) -> VerifiedRestriction:
    return VerifiedRestriction(
        result=ActuationResult(
            action=ContainmentAction.isolate_service(target),
            attempted=True,
            applied=True,
            effective=True,
            command_exit_code=0,
            command_exit_codes=(0,),
        ),
        verification_boundary=boundary,
    )


def test_effective_web_blocks_maps_service_isolation_to_affected_routes() -> None:
    api_boundary = EventOrderingKey(10, "obs-000010")
    internal_boundary = EventOrderingKey(20, "obs-000020")
    web_boundary = EventOrderingKey(30, "obs-000030")

    assert ControllerState(
        verified_restrictions=(verified_isolation("api", boundary=api_boundary),)
    ).effective_web_blocks() == {Route.API: api_boundary}
    assert ControllerState(
        verified_restrictions=(verified_isolation("internal", boundary=internal_boundary),)
    ).effective_web_blocks() == {Route.INTERNAL: internal_boundary}
    assert ControllerState(
        verified_restrictions=(verified_isolation("web", boundary=web_boundary),)
    ).effective_web_blocks() == {
        Route.API: web_boundary,
        Route.INTERNAL: web_boundary,
    }


@pytest.mark.asyncio
async def test_a_stays_non_suspicious_on_canary_and_complete_route_pattern() -> None:
    decision = await PassiveController().decide(
        route_pattern(1, "api")
        + (event(4, EventType.CANARY_USE, route="api"),),
        ControllerState(),
    )

    assert decision.suspicious is False
    assert decision.reason_code == "none"
    assert decision.action.kind is ContainmentKind.NO_ACTION
    assert decision.canary_location == "unchanged"
    assert decision.evidence_event_ids == ()


@pytest.mark.asyncio
async def test_b_matches_a_split_pattern_once_and_rejects_replayed_evidence(
    static_config: StaticPolicyConfig,
) -> None:
    controller = StaticController(static_config)
    probe, config, token = route_pattern(1, "api")

    assert (await controller.decide((probe,), ControllerState())).action.kind is ContainmentKind.NO_ACTION
    assert (await controller.decide((config,), ControllerState())).action.kind is ContainmentKind.NO_ACTION
    decision = await controller.decide((config, token), ControllerState())
    replay = await controller.decide((token,), ControllerState())

    assert decision.action == ContainmentAction.block_edge("web_api")
    assert decision.reason_code == "route_pattern"
    assert decision.evidence_event_ids == (probe.event_id, config.event_id, token.event_id)
    assert replay.action.kind is ContainmentKind.NO_ACTION
    assert replay.evidence_event_ids == ()


@pytest.mark.asyncio
async def test_b_requires_order_and_one_correlation_route_for_each_pattern(
    static_config: StaticPolicyConfig,
) -> None:
    controller = StaticController(static_config)
    out_of_order = (
        event(1, EventType.ROUTE_PROBE, route="api", correlation_id="corr-a"),
        event(2, EventType.TOKEN_EXCHANGE, route="api", correlation_id="corr-a"),
        event(3, EventType.CONFIG_READ, route="api", correlation_id="corr-a"),
    )
    mixed = (
        event(4, EventType.ROUTE_PROBE, route="api", correlation_id="corr-b"),
        event(5, EventType.CONFIG_READ, route="internal", correlation_id="corr-b"),
        event(6, EventType.TOKEN_EXCHANGE, route="api", correlation_id="corr-c"),
    )

    decision = await controller.decide(out_of_order + mixed, ControllerState())

    assert decision.action.kind is ContainmentKind.NO_ACTION
    assert decision.suspicious is False
    assert decision.evidence_event_ids == ()


@pytest.mark.asyncio
async def test_b_canonicalizes_reversed_timestamps_before_matching(
    static_config: StaticPolicyConfig,
) -> None:
    controller = StaticController(static_config)

    decision = await controller.decide(
        (
            event(1, EventType.ROUTE_PROBE, elapsed_ns=30),
            event(2, EventType.CONFIG_READ, elapsed_ns=10),
            event(3, EventType.TOKEN_EXCHANGE, elapsed_ns=20),
        ),
        ControllerState(),
    )

    assert decision.action.kind is ContainmentKind.NO_ACTION


@pytest.mark.asyncio
async def test_b_ignores_stale_events_without_resetting_or_advancing_progress(
    static_config: StaticPolicyConfig,
) -> None:
    controller = StaticController(static_config)

    await controller.decide((event(1, EventType.ROUTE_PROBE, elapsed_ns=10),), ControllerState())
    await controller.decide((event(2, EventType.TOKEN_EXCHANGE, elapsed_ns=5),), ControllerState())
    decision = await controller.decide(
        (
            event(3, EventType.CONFIG_READ, elapsed_ns=11),
            event(4, EventType.TOKEN_EXCHANGE, elapsed_ns=12),
        ),
        ControllerState(),
    )
    stale_config = await StaticController(static_config).decide(
        (
            event(5, EventType.ROUTE_PROBE, elapsed_ns=20),
            event(6, EventType.CONFIG_READ, elapsed_ns=10),
            event(7, EventType.TOKEN_EXCHANGE, elapsed_ns=21),
        ),
        ControllerState(),
    )

    assert decision.action == ContainmentAction.block_edge("web_api")
    assert stale_config.action.kind is ContainmentKind.NO_ACTION


@pytest.mark.asyncio
async def test_b_does_not_escalate_an_unverified_proposal_or_successful_command(
    static_config: StaticPolicyConfig,
) -> None:
    controller = StaticController(static_config)
    first = await controller.decide(route_pattern(1, "api"), ControllerState())
    restriction_event = event(
        4,
        EventType.RESTRICTION_RESULT,
        route="api",
        result={"effective": True, "command_exit_code": 0},
    )
    second = await controller.decide(
        (restriction_event,) + route_pattern(5, "internal"),
        ControllerState(verified_restrictions=(verified_block("web_api", effective=False),)),
    )

    assert first.action == ContainmentAction.block_edge("web_api")
    assert second.action == ContainmentAction.block_edge("web_internal")
    assert second.reason_code == "route_pattern"


@pytest.mark.asyncio
async def test_b_fails_closed_without_an_effective_restriction_boundary(
    static_config: StaticPolicyConfig,
) -> None:
    boundary = EventOrderingKey(10, "obs-000010")
    proposal = await StaticController(static_config).decide(
        route_pattern(20, "internal"), ControllerState()
    )
    ineffective = await StaticController(static_config).decide(
        route_pattern(20, "internal"),
        ControllerState(
            verified_restrictions=(
                verified_block("web_api", effective=False, boundary=boundary),
            )
        ),
    )
    no_boundary = await StaticController(static_config).decide(
        route_pattern(20, "internal"),
        ControllerState(
            verified_restrictions=(verified_block("web_api", boundary=None),)
        ),
    )

    assert proposal.action == ContainmentAction.block_edge("web_internal")
    assert ineffective.action == ContainmentAction.block_edge("web_internal")
    assert no_boundary.action.kind is ContainmentKind.NO_ACTION


@pytest.mark.asyncio
async def test_b_isolates_web_only_after_caller_supplies_effective_alternate_block(
    static_config: StaticPolicyConfig,
) -> None:
    controller = StaticController(static_config)
    state = ControllerState(
        verified_restrictions=(
            verified_block("web_api", boundary=EventOrderingKey(0, "obs-000000")),
        )
    )

    decision = await controller.decide(route_pattern(1, "internal"), state)
    replay = await controller.decide(route_pattern(1, "internal"), state)

    assert decision.action == ContainmentAction.isolate_service("web")
    assert decision.reason_code == "alternate_route_pattern"
    assert decision.evidence_event_ids == ("obs-000001", "obs-000002", "obs-000003")
    assert replay.action.kind is ContainmentKind.NO_ACTION


@pytest.mark.asyncio
async def test_b_rejects_alternate_patterns_started_before_or_at_verification_boundary(
    static_config: StaticPolicyConfig,
) -> None:
    partial_controller = StaticController(static_config)
    await partial_controller.decide(route_pattern(1, "internal")[:2], ControllerState())
    partial = await partial_controller.decide(
        route_pattern(1, "internal")[2:],
        ControllerState(
            verified_restrictions=(
                verified_block("web_api", boundary=EventOrderingKey(2, "obs-000002")),
            )
        ),
    )
    queued = await StaticController(static_config).decide(
        route_pattern(10, "internal"),
        ControllerState(
            verified_restrictions=(
                verified_block("web_api", boundary=EventOrderingKey(20, "obs-000020")),
            )
        ),
    )
    equal = await StaticController(static_config).decide(
        route_pattern(30, "internal"),
        ControllerState(
            verified_restrictions=(
                verified_block("web_api", boundary=EventOrderingKey(30, "obs-000030")),
            )
        ),
    )

    assert partial.action.kind is ContainmentKind.NO_ACTION
    assert queued.action.kind is ContainmentKind.NO_ACTION
    assert equal.action.kind is ContainmentKind.NO_ACTION


@pytest.mark.asyncio
async def test_b_isolates_only_for_a_complete_pattern_strictly_after_boundary(
    static_config: StaticPolicyConfig,
) -> None:
    state = ControllerState(
        verified_restrictions=(
            verified_block("web_api", boundary=EventOrderingKey(10, "obs-000010")),
        )
    )

    decision = await StaticController(static_config).decide(route_pattern(11, "internal"), state)

    assert decision.action == ContainmentAction.isolate_service("web")


@pytest.mark.asyncio
async def test_b_selects_a_post_boundary_alternate_completion_from_a_mixed_batch(
    static_config: StaticPolicyConfig,
) -> None:
    state = ControllerState(
        verified_restrictions=(
            verified_block("web_api", boundary=EventOrderingKey(10, "obs-000010")),
        )
    )
    pre_boundary = route_pattern(1, "internal", correlation_id="corr-pre")
    post_boundary = route_pattern(11, "internal", correlation_id="corr-post")

    decision = await StaticController(static_config).decide(pre_boundary + post_boundary, state)

    assert decision.action == ContainmentAction.isolate_service("web")
    assert decision.evidence_event_ids == ("obs-000011", "obs-000012", "obs-000013")


@pytest.mark.asyncio
async def test_b_reports_canary_use_without_a_discretionary_action(
    static_config: StaticPolicyConfig,
) -> None:
    canary_use = event(1, EventType.CANARY_USE, route="internal")

    decision = await StaticController(static_config).decide((canary_use,), ControllerState())

    assert decision.suspicious is True
    assert decision.reason_code == "mandatory_canary"
    assert decision.action.kind is ContainmentKind.NO_ACTION
    assert decision.evidence_event_ids == (canary_use.event_id,)


@pytest.mark.asyncio
async def test_c_moves_to_most_recent_reachable_unblocked_route(
    static_config: StaticPolicyConfig,
) -> None:
    controller = HeuristicPlacementController(StaticController(static_config))
    api_probe = event(
        1,
        EventType.ROUTE_PROBE,
        route="api",
        elapsed_ns=10,
        result={"reachable": True},
    )
    internal_probe = event(
        2,
        EventType.ROUTE_PROBE,
        route="internal",
        elapsed_ns=20,
        result={"reachable": True},
    )

    decision = await controller.decide((api_probe, internal_probe), ControllerState())

    assert decision.canary_location == Route.INTERNAL
    assert decision.action.kind is ContainmentKind.NO_ACTION


@pytest.mark.asyncio
async def test_c_ignores_invalid_or_blocked_probes_and_retains_location_without_evidence(
    static_config: StaticPolicyConfig,
) -> None:
    controller = HeuristicPlacementController(StaticController(static_config))
    blocked_internal = ControllerState(
        verified_restrictions=(verified_block("web_internal"),)
    )
    first = await controller.decide(
        (
            event(1, EventType.ROUTE_PROBE, route="web", elapsed_ns=30, result={"reachable": True}),
            event(2, EventType.ROUTE_PROBE, route="internal", elapsed_ns=20, result={"reachable": True}),
            event(3, EventType.ROUTE_PROBE, route="api", elapsed_ns=10, result={"reachable": True}),
            event(4, EventType.ROUTE_PROBE, route="api", elapsed_ns=40, result={"reachable": False}),
        ),
        blocked_internal,
    )
    retained = await controller.decide(
        (event(5, EventType.CONFIG_READ, route="api"),),
        blocked_internal,
    )

    assert first.canary_location == Route.API
    assert retained.canary_location == Route.API


@pytest.mark.asyncio
async def test_c_uses_configured_tie_break_unless_that_web_edge_is_blocked(
    static_config: StaticPolicyConfig,
) -> None:
    api_probe = event(1, EventType.ROUTE_PROBE, route="api", elapsed_ns=10, result={"reachable": True})
    internal_probe = event(2, EventType.ROUTE_PROBE, route="internal", elapsed_ns=10, result={"reachable": True})

    tied = await HeuristicPlacementController(StaticController(static_config)).decide(
        (api_probe, internal_probe), ControllerState()
    )
    api_blocked = await HeuristicPlacementController(StaticController(static_config)).decide(
        (api_probe, internal_probe),
        ControllerState(verified_restrictions=(verified_block("web_api"),)),
    )

    assert tied.canary_location == Route.API
    assert api_blocked.canary_location == Route.INTERNAL


@pytest.mark.asyncio
async def test_c_does_not_move_backward_for_stale_cross_batch_probes(
    static_config: StaticPolicyConfig,
) -> None:
    controller = HeuristicPlacementController(StaticController(static_config))

    current = await controller.decide(
        (event(3, EventType.ROUTE_PROBE, route="internal", elapsed_ns=30, result={"reachable": True}),),
        ControllerState(),
    )
    stale = await controller.decide(
        (event(4, EventType.ROUTE_PROBE, route="api", elapsed_ns=20, result={"reachable": True}),),
        ControllerState(),
    )
    newer = await controller.decide(
        (event(5, EventType.ROUTE_PROBE, route="api", elapsed_ns=31, result={"reachable": True}),),
        ControllerState(),
    )

    assert current.canary_location == Route.INTERNAL
    assert stale.canary_location == Route.INTERNAL
    assert newer.canary_location == Route.API


@pytest.mark.asyncio
async def test_c_applies_the_tie_break_to_equal_time_probes_across_batches(
    static_config: StaticPolicyConfig,
) -> None:
    controller = HeuristicPlacementController(StaticController(static_config))

    first = await controller.decide(
        (event(10, EventType.ROUTE_PROBE, route="api", elapsed_ns=40, result={"reachable": True}),),
        ControllerState(),
    )
    tied = await controller.decide(
        (event(11, EventType.ROUTE_PROBE, route="internal", elapsed_ns=40, result={"reachable": True}),),
        ControllerState(),
    )

    assert first.canary_location == Route.API
    assert tied.canary_location == Route.API


@pytest.mark.asyncio
async def test_c_applies_equal_time_ties_across_batches_despite_reverse_event_ids(
    static_config: StaticPolicyConfig,
) -> None:
    first_internal = HeuristicPlacementController(StaticController(static_config))
    await first_internal.decide(
        (event(30, EventType.ROUTE_PROBE, route="internal", elapsed_ns=60, result={"reachable": True}),),
        ControllerState(),
    )
    internal_then_api = await first_internal.decide(
        (event(29, EventType.ROUTE_PROBE, route="api", elapsed_ns=60, result={"reachable": True}),),
        ControllerState(),
    )

    first_api = HeuristicPlacementController(StaticController(static_config))
    await first_api.decide(
        (event(40, EventType.ROUTE_PROBE, route="api", elapsed_ns=70, result={"reachable": True}),),
        ControllerState(),
    )
    api_then_internal = await first_api.decide(
        (event(39, EventType.ROUTE_PROBE, route="internal", elapsed_ns=70, result={"reachable": True}),),
        ControllerState(),
    )

    assert internal_then_api.canary_location == Route.API
    assert api_then_internal.canary_location == Route.API


@pytest.mark.asyncio
async def test_c_removes_newly_blocked_routes_from_stored_equal_time_ties(
    static_config: StaticPolicyConfig,
) -> None:
    controller = HeuristicPlacementController(StaticController(static_config))
    await controller.decide(
        (event(50, EventType.ROUTE_PROBE, route="api", elapsed_ns=50, result={"reachable": True}),),
        ControllerState(),
    )
    state = ControllerState(
        verified_restrictions=(verified_block("web_api", boundary=EventOrderingKey(49, "obs-000049")),)
    )

    decision = await controller.decide(
        (event(51, EventType.ROUTE_PROBE, route="internal", elapsed_ns=50, result={"reachable": True}),),
        state,
    )

    assert decision.canary_location == Route.INTERNAL


@pytest.mark.asyncio
async def test_b_ignores_unrelated_first_pattern_completions_when_escalating(
    static_config: StaticPolicyConfig,
) -> None:
    distinct_patterns = StaticPolicyConfig(
        initial_canary_route=static_config.initial_canary_route,
        tie_break_route=static_config.tie_break_route,
        first_route_pattern=["route_probe"],
        alternate_route_pattern=["config_read", "token_exchange"],
    )
    state = ControllerState(
        verified_restrictions=(
            verified_block("web_api", boundary=EventOrderingKey(10, "obs-000010")),
        )
    )

    decision = await StaticController(distinct_patterns).decide(
        (
            event(9, EventType.ROUTE_PROBE, route="internal", elapsed_ns=9),
            event(11, EventType.CONFIG_READ, route="internal", elapsed_ns=11),
            event(12, EventType.TOKEN_EXCHANGE, route="internal", elapsed_ns=12),
        ),
        state,
    )

    assert decision.action == ContainmentAction.isolate_service("web")
    assert decision.evidence_event_ids == ("obs-000011", "obs-000012")


def test_controller_factory_supports_only_a_through_c(
    static_config: StaticPolicyConfig,
) -> None:
    assert isinstance(build_controller("A", static_config), PassiveController)
    assert isinstance(build_controller("B", static_config), StaticController)
    assert isinstance(build_controller("C", static_config), HeuristicPlacementController)
    with pytest.raises(ValueError, match="A through C"):
        build_controller("D", static_config)
    with pytest.raises(ValueError, match="A through C"):
        build_controller("E", static_config)


class ScriptedDefenderClient:
    provider = "anthropic"
    def __init__(self, replies: list[ModelReply | Exception]) -> None:
        self.replies = replies
        self.requests: list[ModelRequest] = []

    async def complete(self, request: ModelRequest) -> ModelReply:
        self.requests.append(request)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class SpyStaticController(StaticController):
    def __init__(self, static_config: StaticPolicyConfig) -> None:
        super().__init__(static_config)
        self.fallback_calls: list[tuple[tuple[ObservationEvent, ...], ControllerState]] = []
        self.observe_calls: list[tuple[ObservationEvent, ...]] = []

    async def observe(self, events: tuple[ObservationEvent, ...], state: ControllerState) -> None:
        self.observe_calls.append(events)
        await super().observe(events, state)

    async def decide(self, events: tuple[ObservationEvent, ...], state: ControllerState) -> DefenderDecision:
        self.fallback_calls.append((events, state))
        return await super().decide(events, state)


def defender_reply(text: str) -> ModelReply:
    return ModelReply(
        provider="anthropic",
        model="defender-model",
        text=text,
        input_tokens=1,
        output_tokens=1,
        latency_ms=1,
    )


@pytest.mark.asyncio
async def test_defender_accepts_openrouter_client_and_reply(
    static_config: StaticPolicyConfig,
) -> None:
    from chimera.models import MockModelClient

    reply = ModelReply(
        provider="openrouter",
        model="google/gemini-3.7-flash",
        text='{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}',
        input_tokens=10,
        output_tokens=4,
        latency_ms=20,
        routed_provider="Google AI Studio",
    )
    controller = LLMDefenderController(
        client=MockModelClient((reply,), provider="openrouter"),
        model="google/gemini-3.7-flash",
        static_fallback=StaticController(static_config),
        condition="E",
        max_output_tokens=512,
    )

    result = await controller.decide((), ControllerState())

    assert result.fallback_used is False


def test_defender_rejects_ledger_provider_different_from_client(
    static_config: StaticPolicyConfig,
) -> None:
    from decimal import Decimal

    from chimera.budget import BudgetLedger
    from chimera.models import MockModelClient

    ledger = BudgetLedger(
        provider="anthropic",
        ceiling_usd=Decimal("1"),
        input_rate=Decimal("1"),
        output_rate=Decimal("1"),
        max_calls=1,
    )

    with pytest.raises(ValueError, match="match client provider"):
        LLMDefenderController(
            client=MockModelClient(provider="openrouter"),
            model="google/gemini-3.7-flash",
            static_fallback=StaticController(static_config),
            condition="D",
            max_output_tokens=512,
            ledger=ledger,
        )


@pytest.mark.asyncio
async def test_defender_records_reply_provider_mismatch_before_fallback(
    static_config: StaticPolicyConfig,
) -> None:
    from decimal import Decimal

    from chimera.budget import BudgetLedger
    from chimera.models import MockModelClient

    reply = ModelReply(
        provider="anthropic",
        model="google/gemini-3.7-flash",
        text="{}",
        input_tokens=1,
        output_tokens=1,
        latency_ms=1,
    )
    ledger = BudgetLedger(
        provider="openrouter",
        ceiling_usd=Decimal("1"),
        input_rate=Decimal("1"),
        output_rate=Decimal("1"),
        max_calls=1,
    )
    controller = LLMDefenderController(
        client=MockModelClient((reply,), provider="openrouter"),
        model="google/gemini-3.7-flash",
        static_fallback=StaticController(static_config),
        condition="D",
        max_input_tokens=4_000,
        max_output_tokens=64,
        ledger=ledger,
    )

    result = await controller.decide((), ControllerState())

    assert result.fallback_reason == FallbackCategory.PROVIDER_FAILURE
    assert result.fallback_detail == "provider_mismatch"
    assert [record.status for record in controller.usage] == ["provider_mismatch"]
    assert ledger.actual_usd == Decimal("0.000002")


@pytest.mark.asyncio
async def test_ct5_provider_failure_fallback_uses_same_batch_once(
    static_config: StaticPolicyConfig,
) -> None:
    client = ScriptedDefenderClient([ModelProviderFailure("anthropic", "timeout")])
    static = SpyStaticController(static_config)
    controller = LLMDefenderController(
        client=client,
        model="defender-model",
        static_fallback=static,
        condition="D",
        max_output_tokens=64,
    )
    batch = route_pattern(1, "api")

    result = await controller.decide(batch, ControllerState())

    assert result.fallback_used is True
    assert result.fallback_reason == "provider_failure"
    assert result.decision == await StaticController(static_config).decide(batch, ControllerState())
    assert len(client.requests) == 1
    assert static.fallback_calls == [(batch, ControllerState())]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text",
    [
        "```json\n{}\n```",
        '{"suspicious":true,"reason_code":"x","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":["obs-999999"]}',
        '{"suspicious":true,"reason_code":"x","action":{"kind":"block_edge","target":"public-internet"},"canary_location":"unchanged","evidence_event_ids":["obs-000001"]}',
        '{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"api","evidence_event_ids":[]}',
    ],
)
async def test_llm_defender_rejects_invalid_decisions_and_falls_back(
    static_config: StaticPolicyConfig,
    text: str,
) -> None:
    client = ScriptedDefenderClient([defender_reply(text)])
    controller = LLMDefenderController(
        client=client,
        model="defender-model",
        static_fallback=StaticController(static_config),
        condition="D",
        max_output_tokens=64,
    )

    result = await controller.decide(route_pattern(1, "api"), ControllerState())

    assert result.fallback_used is True
    assert result.fallback_reason == "validation_failure"
    assert result.decision.action == ContainmentAction.block_edge("web_api")


@pytest.mark.asyncio
async def test_llm_defender_retains_only_explicit_bounded_prior_evidence_ids(
    static_config: StaticPolicyConfig,
) -> None:
    client = ScriptedDefenderClient(
        [
            defender_reply(
                '{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}'
            ),
            defender_reply(
                '{"suspicious":true,"reason_code":"suspicious_activity","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":["obs-000001"]}'
            ),
            defender_reply(
                '{"suspicious":true,"reason_code":"suspicious_activity","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":["obs-000001"]}'
            ),
        ]
    )
    controller = LLMDefenderController(
        client=client,
        model="defender-model",
        static_fallback=StaticController(static_config),
        condition="E",
        max_output_tokens=64,
        retained_id_limit=1,
    )

    first = await controller.decide((event(1, EventType.ROUTE_PROBE),), ControllerState())
    retained = await controller.decide((event(2, EventType.CONFIG_READ),), ControllerState())
    expired = await controller.decide((event(3, EventType.TOKEN_EXCHANGE),), ControllerState())

    assert first.fallback_used is False
    assert retained.fallback_used is False
    assert expired.fallback_used is True


@pytest.mark.asyncio
async def test_llm_shadow_playbook_keeps_split_pattern_for_a_later_failure(
    static_config: StaticPolicyConfig,
) -> None:
    static = SpyStaticController(static_config)
    client = ScriptedDefenderClient(
        [
            defender_reply('{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}'),
            defender_reply('{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}'),
            ModelProviderFailure("anthropic", "timeout"),
        ]
    )
    controller = LLMDefenderController(
        client=client,
        model="defender-model",
        static_fallback=static,
        condition="D",
        max_output_tokens=64,
    )
    state = ControllerState()
    probe, config, token = route_pattern(1, "api")

    await controller.decide((probe,), state)
    await controller.decide((config,), state)
    result = await controller.decide((token,), state)

    assert result.fallback_used is True
    assert result.decision.action == ContainmentAction.block_edge("web_api")
    assert static.observe_calls == [(probe,), (config,)]
    assert static.fallback_calls == [((token,), state)]


@pytest.mark.asyncio
async def test_llm_prompt_contains_bounded_prior_events_decisions_and_effects(
    static_config: StaticPolicyConfig,
) -> None:
    client = ScriptedDefenderClient(
        [
            defender_reply('{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}'),
            defender_reply('{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}'),
        ]
    )
    controller = LLMDefenderController(
        client=client,
        model="defender-model",
        static_fallback=StaticController(static_config),
        condition="E",
        max_output_tokens=64,
        retained_id_limit=1,
    )
    state = ControllerState(verified_restrictions=(verified_block("web_api"),))

    await controller.decide((event(1, EventType.ROUTE_PROBE, result={"reachable": True}),), state)
    await controller.decide((event(2, EventType.CONFIG_READ),), state)

    prompt = json.loads(client.requests[1].messages[-1].content)
    assert prompt["condition"] == "E"
    assert prompt["allowed_canary_locations"] == ["api", "internal", "unchanged"]
    assert prompt["retained_events"][0]["event_id"] == "obs-000001"
    assert prompt["prior_decisions"][0]["reason_code"] == "none"
    assert prompt["verified_effects"][0]["action"] == {"kind": "block_edge", "target": "web_api"}


@pytest.mark.asyncio
async def test_llm_preflight_limits_batch_sanitizes_event_text_and_skips_call(
    static_config: StaticPolicyConfig,
) -> None:
    client = ScriptedDefenderClient([])
    controller = LLMDefenderController(
        client=client, model="defender-model", static_fallback=StaticController(static_config),
        condition="D", max_output_tokens=1, max_input_tokens=1, max_batch_events=2,
    )
    events = tuple(
        event(number, EventType.ROUTE_PROBE, route="secret-target", correlation_id="credential-secret")
        for number in range(1, 4)
    )

    result = await controller.decide(events, ControllerState())

    assert result.fallback_used is True
    assert result.fallback_reason == "input_limit"
    assert client.requests == []


@pytest.mark.asyncio
async def test_shadow_completed_pattern_survives_to_empty_failure_batch(
    static_config: StaticPolicyConfig,
) -> None:
    static = SpyStaticController(static_config)
    client = ScriptedDefenderClient([
        defender_reply('{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}'),
        ModelProviderFailure("anthropic", "timeout"),
    ])
    controller = LLMDefenderController(
        client=client, model="defender-model", static_fallback=static,
        condition="D", max_output_tokens=64,
    )

    await controller.decide(route_pattern(1, "api"), ControllerState())
    result = await controller.decide((), ControllerState())

    assert result.decision.action == ContainmentAction.block_edge("web_api")
    assert result.decision.evidence_event_ids == ("obs-000001", "obs-000002", "obs-000003")


@pytest.mark.asyncio
async def test_defender_cancellation_finalizes_reservation_as_uncertain(
    static_config: StaticPolicyConfig,
) -> None:
    class CancelledClient:
        provider = "anthropic"

        async def complete(self, request: ModelRequest) -> ModelReply:
            raise asyncio.CancelledError

    from chimera.budget import BudgetLedger
    from decimal import Decimal

    ledger = BudgetLedger(
        provider="anthropic", ceiling_usd=Decimal("1"), input_rate=Decimal("1"), output_rate=Decimal("1"), max_calls=1
    )
    controller = LLMDefenderController(
        client=CancelledClient(), model="defender", static_fallback=StaticController(static_config),
        condition="D", max_output_tokens=1, max_input_tokens=4_000, ledger=ledger,
    )

    with pytest.raises(asyncio.CancelledError):
        await controller.decide((), ControllerState())

    assert ledger.reserved_usd == Decimal("0")
    assert controller.usage[-1].status == "cancelled"


@pytest.mark.asyncio
async def test_valid_e_placement_and_d_unchanged_are_accepted(
    static_config: StaticPolicyConfig,
) -> None:
    e_client = ScriptedDefenderClient([defender_reply(
        '{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"api","evidence_event_ids":[]}'
    )])
    d_client = ScriptedDefenderClient([defender_reply(
        '{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}'
    )])
    e_result = await LLMDefenderController(
        client=e_client, model="defender", static_fallback=StaticController(static_config), condition="E", max_output_tokens=64
    ).decide((), ControllerState())
    d_result = await LLMDefenderController(
        client=d_client, model="defender", static_fallback=StaticController(static_config), condition="D", max_output_tokens=64
    ).decide((), ControllerState())

    assert e_result.fallback_used is False
    assert d_result.fallback_used is False


@pytest.mark.asyncio
async def test_known_anthropic_over_cap_usage_is_recorded_before_fallback(
    static_config: StaticPolicyConfig,
) -> None:
    class KnownUsageFailureClient:
        provider = "anthropic"

        async def complete(self, request: ModelRequest) -> ModelReply:
            raise ModelProviderFailure(
                "anthropic", "invalid_usage", input_tokens=2, output_tokens=2,
                model="defender", latency_ms=3,
            )

    from chimera.budget import BudgetLedger
    from decimal import Decimal

    ledger = BudgetLedger(
        provider="anthropic", ceiling_usd=Decimal("1"), input_rate=Decimal("1"), output_rate=Decimal("1"), max_calls=2
    )
    controller = LLMDefenderController(
        client=KnownUsageFailureClient(), model="defender", static_fallback=StaticController(static_config),
        condition="D", max_output_tokens=1, max_input_tokens=4_000, ledger=ledger,
    )

    result = await controller.decide((), ControllerState())

    assert result.fallback_reason == "accounting_failure"
    assert controller.usage[-1].status == "over_reservation"
    assert ledger.actual_usd == Decimal("0.000004")


@pytest.mark.asyncio
async def test_adapter_malformed_content_with_known_usage_settles_defender_ledger(
    static_config: StaticPolicyConfig,
) -> None:
    async def handler(request):
        import httpx
        return httpx.Response(200, json={"model": "defender", "content": [], "usage": {"input_tokens": 2, "output_tokens": 1}})

    import httpx
    from chimera.models import AnthropicClient
    from chimera.budget import BudgetLedger
    from decimal import Decimal

    ledger = BudgetLedger(provider="anthropic", ceiling_usd=Decimal("1"), input_rate=Decimal("1"), output_rate=Decimal("1"), max_calls=1)
    client = AnthropicClient(api_key="key", transport=httpx.MockTransport(handler))
    controller = LLMDefenderController(client=client, model="defender", static_fallback=StaticController(static_config), condition="D", max_input_tokens=4_000, max_output_tokens=2, ledger=ledger)
    result = await controller.decide((), ControllerState())
    await client.aclose()

    assert result.fallback_reason == "provider_failure"
    assert ledger.actual_usd == Decimal("0.000003")
    assert ledger.reserved_usd == ledger.uncertain_usd == Decimal("0")


def test_normalize_controller_result_preserves_envelope_identity_and_metadata() -> None:
    envelope = DefenderDecisionResult(
        decision=DefenderDecision(
            suspicious=False,
            reason_code="none",
            action=ContainmentAction.no_action(),
            canary_location="unchanged",
        ),
        fallback_used=True,
        fallback_reason=FallbackCategory.PROVIDER_FAILURE,
        fallback_detail="timeout",
    )

    assert normalize_controller_result(envelope) is envelope


@pytest.mark.asyncio
async def test_delayed_defender_provider_failure_uses_measured_latency_when_missing(
    static_config: StaticPolicyConfig,
) -> None:
    class DelayedFailureClient:
        provider = "anthropic"

        async def complete(self, request: ModelRequest) -> ModelReply:
            await asyncio.sleep(0.01)
            raise ModelProviderFailure("anthropic", "timeout", latency_ms=-1)

    from chimera.budget import BudgetLedger
    from decimal import Decimal

    ledger = BudgetLedger(provider="anthropic", ceiling_usd=Decimal("1"), input_rate=Decimal("1"), output_rate=Decimal("1"), max_calls=1)
    controller = LLMDefenderController(
        client=DelayedFailureClient(), model="defender", static_fallback=StaticController(static_config),
        condition="D", max_input_tokens=4_000, max_output_tokens=1, ledger=ledger,
    )

    result = await controller.decide((), ControllerState())

    assert result.fallback_reason == "provider_failure"
    assert len(controller.usage) == 1
    assert controller.usage[0].latency_ms is not None and controller.usage[0].latency_ms >= 1
    assert ledger.reserved_usd == Decimal("0")


@pytest.mark.asyncio
async def test_invalid_anthropic_returned_model_with_valid_usage_settles_defender_ledger(
    static_config: StaticPolicyConfig,
) -> None:
    import httpx
    from chimera.budget import BudgetLedger
    from chimera.models import AnthropicClient
    from decimal import Decimal

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "model": None,
            "content": [{"type": "text", "text": "{}"}],
            "usage": {"input_tokens": 2, "output_tokens": 1},
        })

    ledger = BudgetLedger(provider="anthropic", ceiling_usd=Decimal("1"), input_rate=Decimal("1"), output_rate=Decimal("1"), max_calls=1)
    client = AnthropicClient(api_key="key", transport=httpx.MockTransport(handler))
    controller = LLMDefenderController(
        client=client, model="defender", static_fallback=StaticController(static_config),
        condition="D", max_input_tokens=4_000, max_output_tokens=2, ledger=ledger,
    )

    result = await controller.decide((), ControllerState())
    await client.aclose()

    assert result.fallback_reason == "provider_failure"
    assert len(controller.usage) == 1
    assert controller.usage[0].status == "malformed_response"
    assert ledger.actual_usd == Decimal("0.000003")
    assert ledger.reserved_usd == ledger.uncertain_usd == Decimal("0")


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["", None, [], {}, "cred-0123abcdefab-0001"])
async def test_untrusted_defender_provider_status_closes_one_reservation(
    static_config: StaticPolicyConfig,
    status: object,
) -> None:
    class FailureClient:
        provider = "anthropic"

        async def complete(self, request: ModelRequest) -> ModelReply:
            raise ModelProviderFailure("anthropic", status)  # type: ignore[arg-type]

    from chimera.budget import BudgetLedger
    from decimal import Decimal

    ledger = BudgetLedger(provider="anthropic", ceiling_usd=Decimal("1"), input_rate=Decimal("1"), output_rate=Decimal("1"), max_calls=1)
    controller = LLMDefenderController(
        client=FailureClient(), model="defender", static_fallback=StaticController(static_config),
        condition="D", max_input_tokens=4_000, max_output_tokens=1, ledger=ledger,
    )

    result = await controller.decide((), ControllerState())

    assert result.fallback_detail == "provider_response"
    assert [record.status for record in controller.usage] == ["provider_response"]
    assert ledger.reserved_usd == Decimal("0")


@pytest.mark.asyncio
async def test_shadow_multiple_pending_route_completions_survive_sequential_fallbacks(
    static_config: StaticPolicyConfig,
) -> None:
    valid = defender_reply('{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}')
    controller = LLMDefenderController(
        client=ScriptedDefenderClient([valid, ModelProviderFailure("anthropic", "timeout"), ModelProviderFailure("anthropic", "timeout")]),
        model="defender-model", static_fallback=StaticController(static_config), condition="D", max_output_tokens=64,
    )

    await controller.decide(route_pattern(1, "api") + route_pattern(4, "internal"), ControllerState())
    first = await controller.decide((), ControllerState())
    second = await controller.decide((), ControllerState())

    assert first.decision.action == ContainmentAction.block_edge("web_api")
    assert second.decision.action == ContainmentAction.block_edge("web_internal")


@pytest.mark.asyncio
async def test_shadow_pending_completion_is_suppressed_after_verified_restriction(
    static_config: StaticPolicyConfig,
) -> None:
    valid = defender_reply('{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}')
    controller = LLMDefenderController(
        client=ScriptedDefenderClient([valid, ModelProviderFailure("anthropic", "timeout")]),
        model="defender-model", static_fallback=StaticController(static_config), condition="D", max_output_tokens=64,
    )

    await controller.decide(route_pattern(1, "api"), ControllerState())
    result = await controller.decide((), ControllerState(verified_restrictions=(verified_block("web_api"),)))

    assert result.decision.action.kind is ContainmentKind.NO_ACTION


@pytest.mark.asyncio
async def test_shadow_canary_priority_retains_pending_route_completion(
    static_config: StaticPolicyConfig,
) -> None:
    valid = defender_reply('{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}')
    controller = LLMDefenderController(
        client=ScriptedDefenderClient([
            valid,
            ModelProviderFailure("anthropic", "timeout"),
            ModelProviderFailure("anthropic", "timeout"),
        ]),
        model="defender-model", static_fallback=StaticController(static_config), condition="D", max_output_tokens=64,
    )

    await controller.decide(route_pattern(1, "api") + (event(4, EventType.CANARY_USE),), ControllerState())
    canary = await controller.decide((), ControllerState())
    route = await controller.decide((), ControllerState())

    assert canary.decision.reason_code == "mandatory_canary"
    assert route.decision.action == ContainmentAction.block_edge("web_api")


@pytest.mark.asyncio
async def test_fallback_preserves_existing_hard_restrictions(
    static_config: StaticPolicyConfig,
) -> None:
    state = ControllerState(verified_restrictions=(verified_block("web_api"),))
    controller = LLMDefenderController(
        client=ScriptedDefenderClient([ModelProviderFailure("anthropic", "timeout")]),
        model="defender-model", static_fallback=StaticController(static_config), condition="D", max_output_tokens=64,
    )

    result = await controller.decide((), state)

    assert result.fallback_used is True
    assert state.verified_restrictions == (verified_block("web_api"),)


@pytest.mark.asyncio
async def test_canary_deferred_completion_is_suppressed_by_verified_web_isolation(
    static_config: StaticPolicyConfig,
) -> None:
    valid = defender_reply('{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}')
    controller = LLMDefenderController(
        client=ScriptedDefenderClient([
            valid,
            ModelProviderFailure("anthropic", "timeout"),
            ModelProviderFailure("anthropic", "timeout"),
        ]),
        model="defender-model", static_fallback=StaticController(static_config), condition="D", max_output_tokens=64,
    )
    isolated = ControllerState(verified_restrictions=(
        verified_isolation("web", boundary=EventOrderingKey(10, "obs-000010")),
    ))

    await controller.decide(route_pattern(1, "api") + (event(4, EventType.CANARY_USE),), ControllerState())
    canary = await controller.decide((), isolated)
    deferred = await controller.decide((), isolated)

    assert canary.decision.reason_code == "mandatory_canary"
    assert deferred.decision.action.kind is ContainmentKind.NO_ACTION


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("isolated_service", "suppressed_route", "other_route"),
    [
        ("api", "api", "internal"),
        ("internal", "internal", "api"),
    ],
)
async def test_route_local_isolation_suppresses_only_its_own_route(
    static_config: StaticPolicyConfig,
    isolated_service: str,
    suppressed_route: str,
    other_route: str,
) -> None:
    state = ControllerState(verified_restrictions=(
        verified_isolation(isolated_service, boundary=EventOrderingKey(10, "obs-000010")),
    ))

    suppressed = await StaticController(static_config).decide(
        route_pattern(11, suppressed_route), state
    )
    other = await StaticController(static_config).decide(
        route_pattern(11, other_route), state
    )

    assert suppressed.action.kind is ContainmentKind.NO_ACTION
    assert other.action.kind is not ContainmentKind.NO_ACTION


@pytest.mark.asyncio
async def test_service_isolation_prevents_alternate_escalation_from_obsolete_shadow_match(
    static_config: StaticPolicyConfig,
) -> None:
    valid = defender_reply('{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}')
    controller = LLMDefenderController(
        client=ScriptedDefenderClient([valid, ModelProviderFailure("anthropic", "timeout")]),
        model="defender-model", static_fallback=StaticController(static_config), condition="D", max_output_tokens=64,
    )
    state = ControllerState(verified_restrictions=(
        verified_isolation("api", boundary=EventOrderingKey(10, "obs-000010")),
    ))

    await controller.decide(route_pattern(1, "internal"), ControllerState())
    result = await controller.decide((), state)

    assert result.decision.action.kind is ContainmentKind.NO_ACTION


@pytest.mark.asyncio
async def test_defender_records_provider_failure_detail_alongside_fallback(
    static_config: StaticPolicyConfig,
) -> None:
    client = ScriptedDefenderClient(
        [
            ModelProviderFailure(
                "anthropic",
                "http_404",
                model="defender-model",
                latency_ms=301,
                http_status=404,
                detail="No endpoints found [failed_routing_step=Filter by Parameters]",
            )
        ]
    )
    controller = LLMDefenderController(
        client=client,
        model="defender-model",
        static_fallback=SpyStaticController(static_config),
        condition="D",
        max_output_tokens=64,
    )

    result = await controller.decide(route_pattern(1, "api"), ControllerState())

    assert result.fallback_used is True
    assert result.fallback_reason == "provider_failure"
    assert controller.provider_failures == [
        ProviderFailureDetail(
            status="http_error",
            http_status=404,
            detail="No endpoints found [failed_routing_step=Filter by Parameters]",
            model="defender-model",
            latency_ms=301,
        )
    ]


@pytest.mark.asyncio
async def test_defender_records_invalid_output_summary_before_fallback(
    static_config: StaticPolicyConfig,
) -> None:
    client = ScriptedDefenderClient(
        [ModelReply("anthropic", "defender-model", "```json\n{\"suspicious\": true}\n```", 394, 138, 5255, "Anthropic")]
    )
    controller = LLMDefenderController(
        client=client,
        model="defender-model",
        static_fallback=SpyStaticController(static_config),
        condition="D",
        max_output_tokens=64,
    )

    result = await controller.decide(route_pattern(1, "api"), ControllerState())

    assert result.fallback_used is True
    assert result.fallback_reason == "validation_failure"
    assert controller.provider_failures == [
        ProviderFailureDetail(
            status="invalid_output",
            http_status=None,
            detail="length=32 fenced=true json=object known_keys=suspicious unknown_keys=0 reason=invalid_json",
            model="defender-model",
            latency_ms=5255,
        )
    ]


@pytest.mark.asyncio
async def test_defender_invalid_decision_summary_names_failed_rule_without_values(
    static_config: StaticPolicyConfig,
) -> None:
    text = (
        '{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},'
        '"canary_location":"unchanged","evidence_event_ids":["obs-000001"]}'
    )
    client = ScriptedDefenderClient(
        [ModelReply("anthropic", "defender-model", text, 540, 101, 5609, "Anthropic")]
    )
    controller = LLMDefenderController(
        client=client,
        model="defender-model",
        static_fallback=SpyStaticController(static_config),
        condition="D",
        max_output_tokens=64,
    )

    result = await controller.decide(route_pattern(1, "api"), ControllerState())

    assert result.fallback_used is True
    assert result.fallback_detail == "invalid_decision"
    assert len(controller.provider_failures) == 1
    detail = controller.provider_failures[0].detail
    assert detail == (
        f"length={len(text)} json=object "
        "known_keys=action,canary_location,evidence_event_ids,reason_code,suspicious unknown_keys=0 "
        "reason=invalid_decision validation=_:value_error"
    )
    assert "obs-000001" not in detail


@pytest.mark.asyncio
async def test_defender_sees_current_canary_route_and_last_placement_result(
    static_config: StaticPolicyConfig,
) -> None:
    from chimera.controllers import PlacementOutcome

    client = ScriptedDefenderClient(
        [
            defender_reply('{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}'),
            defender_reply('{"suspicious":false,"reason_code":"none","action":{"kind":"no_action"},"canary_location":"unchanged","evidence_event_ids":[]}'),
        ]
    )
    controller = LLMDefenderController(
        client=client,
        model="defender-model",
        static_fallback=StaticController(static_config),
        condition="E",
        max_output_tokens=64,
    )

    await controller.decide((event(1, EventType.ROUTE_PROBE, result={"reachable": True}),), ControllerState())
    informed = ControllerState(
        canary_route=Route.INTERNAL,
        last_placement=PlacementOutcome(route=Route.INTERNAL, attempted=True, applied=True, effective=True, reason=None),
    )
    await controller.decide((event(2, EventType.CONFIG_READ),), informed)

    first = json.loads(client.requests[0].messages[-1].content)
    second = json.loads(client.requests[1].messages[-1].content)
    assert first["canary_placement"] == {"current_route": None, "last_result": None}
    assert second["canary_placement"] == {
        "current_route": "internal",
        "last_result": {"route": "internal", "attempted": True, "applied": True, "effective": True, "reason": None},
    }
