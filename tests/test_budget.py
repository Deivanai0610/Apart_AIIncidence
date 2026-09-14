from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import json
from pathlib import Path
import subprocess
import sys

import pytest

from chimera.budget import (
    AccountingError,
    BudgetExceeded,
    BudgetLedger,
    CallCapExceeded,
    CumulativeBudgetScope,
    FileBudgetAuthority,
    BudgetAuthorityError,
    ReservationStateError,
)


def test_reservation_prevents_crossing_provider_ceiling() -> None:
    ledger = BudgetLedger(
        provider="anthropic",
        ceiling_usd=Decimal("1.00"),
        input_rate=Decimal("2.00"),
        output_rate=Decimal("10.00"),
        max_calls=2,
    )
    first = ledger.reserve(max_input_tokens=100_000, max_output_tokens=50_000)

    with pytest.raises(BudgetExceeded):
        ledger.reserve(max_input_tokens=100_000, max_output_tokens=50_000)

    first.settle(actual_input_tokens=10_000, actual_output_tokens=1_000)

    assert ledger.actual_usd == Decimal("0.03000")
    assert ledger.reserved_usd == Decimal("0")


def test_failed_api_attempt_consumes_call_cap() -> None:
    ledger = BudgetLedger(
        provider="anthropic",
        ceiling_usd=Decimal("1.00"),
        input_rate=Decimal("2.00"),
        output_rate=Decimal("10.00"),
        max_calls=1,
    )
    reservation = ledger.reserve(max_input_tokens=100, max_output_tokens=100)
    record = reservation.fail(status="timeout")

    assert record.status == "timeout"
    assert record.uncertain_usd == Decimal("0.0012")
    assert ledger.uncertain_usd == Decimal("0.0012")
    assert ledger.failure_counts == {"timeout": 1}
    with pytest.raises(CallCapExceeded):
        ledger.reserve(max_input_tokens=100, max_output_tokens=100)


def test_reservation_can_settle_or_fail_only_once() -> None:
    ledger = BudgetLedger(
        provider="openrouter",
        ceiling_usd=Decimal("1.00"),
        input_rate=Decimal("1"),
        output_rate=Decimal("1"),
        max_calls=2,
    )
    reservation = ledger.reserve(max_input_tokens=10, max_output_tokens=10)
    reservation.settle(actual_input_tokens=1, actual_output_tokens=1)

    with pytest.raises(ReservationStateError):
        reservation.settle(actual_input_tokens=1, actual_output_tokens=1)
    with pytest.raises(ReservationStateError):
        reservation.fail(status="timeout")


def test_over_reservation_is_finalized_then_blocks_future_calls() -> None:
    ledger = BudgetLedger(
        provider="openrouter",
        ceiling_usd=Decimal("1.00"),
        input_rate=Decimal("1"),
        output_rate=Decimal("1"),
        max_calls=2,
    )
    reservation = ledger.reserve(max_input_tokens=10, max_output_tokens=10)

    with pytest.raises(AccountingError) as error:
        reservation.settle(actual_input_tokens=11, actual_output_tokens=10)

    assert error.value.record.status == "over_reservation"
    assert ledger.reserved_usd == Decimal("0")
    assert ledger.actual_usd == Decimal("0.000021")
    with pytest.raises(BudgetExceeded):
        ledger.reserve(max_input_tokens=1, max_output_tokens=1)


def test_uncertain_provider_failure_remains_in_the_ceiling_gate() -> None:
    ledger = BudgetLedger(
        provider="anthropic",
        ceiling_usd=Decimal("0.0002"),
        input_rate=Decimal("1"),
        output_rate=Decimal("1"),
        max_calls=2,
    )
    reservation = ledger.reserve(max_input_tokens=100, max_output_tokens=100)
    reservation.fail(status="transport_error")

    assert ledger.accounted_usd == Decimal("0.0002")
    with pytest.raises(BudgetExceeded):
        ledger.reserve(max_input_tokens=1, max_output_tokens=1)


def test_invalid_reported_usage_finalizes_as_uncertain_without_stranding() -> None:
    ledger = BudgetLedger(
        provider="anthropic",
        ceiling_usd=Decimal("1"),
        input_rate=Decimal("1"),
        output_rate=Decimal("1"),
        max_calls=2,
    )
    reservation = ledger.reserve(max_input_tokens=10, max_output_tokens=10)

    with pytest.raises(AccountingError) as error:
        reservation.settle(actual_input_tokens=True, actual_output_tokens=1)

    assert error.value.record.status == "invalid_usage"
    assert ledger.reserved_usd == Decimal("0")
    assert ledger.uncertain_usd == Decimal("0.00002")
    with pytest.raises(ReservationStateError):
        reservation.fail("timeout")


def _shared_ledger(
    root: Path,
    *,
    ceiling: str = "0.0003",
    input_rate: str = "1",
    output_rate: str = "1",
    account: str = "openrouter",
    authorization_id: str = "auth-1",
    profile: str = "attacker",
    project_ceiling: str | None = None,
    authorization_ceiling: str | None = None,
) -> BudgetLedger:
    authority = FileBudgetAuthority(root)
    return BudgetLedger(
        provider="openrouter",
        ceiling_usd=Decimal(ceiling),
        input_rate=Decimal(input_rate),
        output_rate=Decimal(output_rate),
        max_calls=3,
        cumulative_authority=authority,
        cumulative_scope=CumulativeBudgetScope(
            account=account,
            authorization_id=authorization_id,
            profile=profile,
            project_ceiling_usd=Decimal(project_ceiling or ceiling),
            authorization_ceiling_usd=Decimal(
                authorization_ceiling or ceiling
            ),
        ),
    )


def test_one_authority_accepts_two_profiles_with_different_rates(
    tmp_path: Path,
) -> None:
    root = tmp_path / "budget"
    attacker = _shared_ledger(
        root,
        ceiling="0.20",
        input_rate="0.936",
        output_rate="3.168",
        profile="attacker",
        project_ceiling="20",
        authorization_ceiling="0.25",
    )
    defender = _shared_ledger(
        root,
        ceiling="0.05",
        input_rate="0.375",
        output_rate="1.875",
        profile="defender",
        project_ceiling="20",
        authorization_ceiling="0.25",
    )

    attacker.reserve(max_input_tokens=8_000, max_output_tokens=2_048)
    defender.reserve(max_input_tokens=8_000, max_output_tokens=512)

    assert attacker.cumulative_accounted_usd == Decimal("0.013976064")
    assert defender.cumulative_accounted_usd == Decimal("0.003960")


def test_profiles_share_one_authorization_ceiling(tmp_path: Path) -> None:
    root = tmp_path / "budget"
    attacker = _shared_ledger(
        root,
        ceiling="0.0003",
        profile="attacker",
        project_ceiling="1",
        authorization_ceiling="0.0003",
    )
    defender = _shared_ledger(
        root,
        ceiling="0.0003",
        profile="defender",
        project_ceiling="1",
        authorization_ceiling="0.0003",
    )
    attacker.reserve(max_input_tokens=100, max_output_tokens=100)

    with pytest.raises(BudgetExceeded, match="authorization"):
        defender.reserve(max_input_tokens=100, max_output_tokens=100)


def test_authorizations_share_one_project_ceiling(tmp_path: Path) -> None:
    root = tmp_path / "budget"
    first = _shared_ledger(
        root,
        authorization_id="auth-1",
        project_ceiling="0.0003",
        authorization_ceiling="0.0003",
    )
    second = _shared_ledger(
        root,
        authorization_id="auth-2",
        project_ceiling="0.0003",
        authorization_ceiling="0.0003",
    )
    first.reserve(max_input_tokens=100, max_output_tokens=100)

    with pytest.raises(BudgetExceeded, match="project"):
        second.reserve(max_input_tokens=100, max_output_tokens=100)


def test_file_authority_accumulates_across_separately_constructed_ledgers(
    tmp_path: Path,
) -> None:
    first = _shared_ledger(tmp_path / "budget")
    second = _shared_ledger(tmp_path / "budget")

    first.reserve(max_input_tokens=100, max_output_tokens=100)

    with pytest.raises(BudgetExceeded):
        second.reserve(max_input_tokens=100, max_output_tokens=100)


def test_file_authority_serializes_concurrent_reservations(tmp_path: Path) -> None:
    root = tmp_path / "budget"

    def reserve_once(_: int) -> bool:
        try:
            _shared_ledger(root).reserve(max_input_tokens=100, max_output_tokens=100)
        except BudgetExceeded:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as executor:
        accepted = list(executor.map(reserve_once, range(8)))

    assert accepted.count(True) == 1


def test_file_authority_serializes_cross_profile_reservations(
    tmp_path: Path,
) -> None:
    root = tmp_path / "budget"

    def reserve_once(profile: str) -> bool:
        try:
            _shared_ledger(
                root,
                profile=profile,
                ceiling="0.0003",
                project_ceiling="1",
                authorization_ceiling="0.0003",
            ).reserve(max_input_tokens=100, max_output_tokens=100)
        except BudgetExceeded:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        accepted = list(executor.map(reserve_once, ("attacker", "defender")))

    assert accepted.count(True) == 1


def test_file_authority_serializes_reservations_across_processes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "budget"
    _shared_ledger(root)
    script = """
from decimal import Decimal
from pathlib import Path
import sys
from chimera.budget import (
    BudgetExceeded,
    BudgetLedger,
    CumulativeBudgetScope,
    FileBudgetAuthority,
)

ledger = BudgetLedger(
    provider="openrouter",
    ceiling_usd=Decimal("0.0003"),
    input_rate=Decimal("1"),
    output_rate=Decimal("1"),
    max_calls=3,
    cumulative_authority=FileBudgetAuthority(Path(sys.argv[1])),
    cumulative_scope=CumulativeBudgetScope(
        account="openrouter",
        authorization_id="auth-1",
        profile="attacker",
        project_ceiling_usd=Decimal("0.0003"),
        authorization_ceiling_usd=Decimal("0.0003"),
    ),
)
try:
    ledger.reserve(max_input_tokens=100, max_output_tokens=100)
except BudgetExceeded:
    print("rejected")
else:
    print("accepted")
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(4)
    ]
    results = [process.communicate(timeout=10) for process in processes]

    assert all(process.returncode == 0 for process in processes), results
    assert [stdout.strip() for stdout, _ in results].count("accepted") == 1


def test_crashed_request_reservation_remains_outstanding(tmp_path: Path) -> None:
    root = tmp_path / "budget"
    _shared_ledger(root).reserve(max_input_tokens=100, max_output_tokens=100)

    restarted = _shared_ledger(root)

    assert restarted.cumulative_accounted_usd == Decimal("0.0002")
    with pytest.raises(BudgetExceeded):
        restarted.reserve(max_input_tokens=100, max_output_tokens=100)


def test_file_authority_persists_known_and_uncertain_settlement(tmp_path: Path) -> None:
    root = tmp_path / "budget"
    known = _shared_ledger(root, ceiling="0.001")
    known.reserve(max_input_tokens=100, max_output_tokens=100).settle(50, 25)
    uncertain = _shared_ledger(root, ceiling="0.001")
    uncertain.reserve(max_input_tokens=100, max_output_tokens=100).fail("timeout")

    restarted = _shared_ledger(root, ceiling="0.001")

    assert restarted.cumulative_accounted_usd == Decimal("0.000275")


def test_uncertain_cost_counts_against_authorization_and_project(
    tmp_path: Path,
) -> None:
    root = tmp_path / "budget"
    _shared_ledger(
        root,
        project_ceiling="0.0003",
        authorization_ceiling="0.0003",
    ).reserve(max_input_tokens=100, max_output_tokens=100).fail("timeout")

    with pytest.raises(BudgetExceeded, match="authorization"):
        _shared_ledger(
            root,
            profile="defender",
            project_ceiling="0.0003",
            authorization_ceiling="0.0003",
        ).reserve(max_input_tokens=100, max_output_tokens=100)
    with pytest.raises(BudgetExceeded, match="project"):
        _shared_ledger(
            root,
            authorization_id="auth-2",
            project_ceiling="0.0003",
            authorization_ceiling="0.0003",
        ).reserve(max_input_tokens=100, max_output_tokens=100)

    state = json.loads((root / "provider-budget.json").read_text(encoding="utf-8"))
    profile = state["accounts"]["openrouter"]["authorizations"]["auth-1"][
        "profiles"
    ]["attacker"]
    assert profile["uncertain_usd"] == "0.0002"
    assert profile["outstanding"] == {}


def test_over_reservation_marks_every_budget_scope_fail_safe(tmp_path: Path) -> None:
    root = tmp_path / "budget"
    reservation = _shared_ledger(
        root,
        project_ceiling="1",
        authorization_ceiling="0.0003",
    ).reserve(max_input_tokens=10, max_output_tokens=10)

    with pytest.raises(AccountingError):
        reservation.settle(actual_input_tokens=11, actual_output_tokens=10)

    state = json.loads((root / "provider-budget.json").read_text(encoding="utf-8"))
    account = state["accounts"]["openrouter"]
    authorization = account["authorizations"]["auth-1"]
    profile = authorization["profiles"]["attacker"]
    assert account["breached"] is True
    assert authorization["breached"] is True
    assert profile["breached"] is True
    with pytest.raises(BudgetExceeded, match="project budget is fail-safe"):
        _shared_ledger(
            root,
            authorization_id="auth-2",
            project_ceiling="1",
            authorization_ceiling="0.0003",
        ).reserve(max_input_tokens=1, max_output_tokens=1)


def test_file_authority_rejects_legacy_state(tmp_path: Path) -> None:
    root = tmp_path / "budget"
    _shared_ledger(root)
    state_path = root / "provider-budget.json"
    state_path.write_text(
        json.dumps({"schema_version": 1, "providers": {}}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(BudgetAuthorityError, match="corrupt"):
        _shared_ledger(root)


def test_file_authority_rejects_corrupt_state_and_ceiling_changes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "budget"
    ledger = _shared_ledger(root)
    ledger.reserve(max_input_tokens=10, max_output_tokens=10).settle(1, 1)
    state_path = root / "provider-budget.json"
    state_path.write_text("not json\n", encoding="utf-8")

    with pytest.raises(BudgetAuthorityError):
        _shared_ledger(root).reserve(max_input_tokens=1, max_output_tokens=1)

    state_path.unlink()
    _shared_ledger(root)
    with pytest.raises(BudgetAuthorityError, match="configuration"):
        _shared_ledger(root, ceiling="0.0004").reserve(
            max_input_tokens=1, max_output_tokens=1
        )


def test_file_authority_rejects_symlinked_state_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "budget"
    linked.symlink_to(outside, target_is_directory=True)

    with pytest.raises(BudgetAuthorityError, match="unsafe"):
        _shared_ledger(linked).reserve(max_input_tokens=1, max_output_tokens=1)

    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("filename", ["provider-budget.json", ".provider-budget.lock"])
def test_file_authority_rejects_symlinked_state_or_lock(
    tmp_path: Path, filename: str
) -> None:
    root = tmp_path / "budget"
    _shared_ledger(root)
    target = root / filename
    target.unlink()
    target.symlink_to(tmp_path / "missing-target")

    with pytest.raises(BudgetAuthorityError):
        _shared_ledger(root)


def test_per_role_ceiling_is_episode_local_not_cumulative(tmp_path: Path) -> None:
    root = tmp_path / "budget"
    # Two episodes' attacker ledgers share one authorization; each ledger's
    # own ceiling covers one episode, so the second episode must not be
    # refused because the first one spent against the same profile.
    first = _shared_ledger(root, ceiling="0.0003", profile="attacker", project_ceiling="1", authorization_ceiling="1")
    second = _shared_ledger(root, ceiling="0.0003", profile="attacker", project_ceiling="1", authorization_ceiling="1")

    first.reserve(max_input_tokens=100, max_output_tokens=100).settle(
        actual_input_tokens=100, actual_output_tokens=100
    )
    second.reserve(max_input_tokens=100, max_output_tokens=100).settle(
        actual_input_tokens=100, actual_output_tokens=100
    )

    # Within one episode the local ceiling still applies.
    with pytest.raises(BudgetExceeded, match="ceiling"):
        second.reserve(max_input_tokens=100, max_output_tokens=100)
