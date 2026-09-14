from __future__ import annotations

import fcntl
import json
import os
import secrets
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from threading import Lock
from typing import Iterator, Protocol


class BudgetExceeded(RuntimeError):
    pass


class CallCapExceeded(RuntimeError):
    pass


class ReservationStateError(RuntimeError):
    pass


class BudgetAuthorityError(RuntimeError):
    pass


@dataclass(frozen=True)
class CumulativeBudgetScope:
    account: str
    authorization_id: str
    profile: str
    project_ceiling_usd: Decimal
    authorization_ceiling_usd: Decimal


class CumulativeBudgetAuthority(Protocol):
    def bind(
        self,
        *,
        scope: CumulativeBudgetScope,
        ceiling_usd: Decimal,
        input_rate: Decimal,
        output_rate: Decimal,
    ) -> Decimal: ...

    def reserve(
        self,
        *,
        scope: CumulativeBudgetScope,
        reservation_id: str,
        amount: Decimal,
        ceiling_usd: Decimal,
        input_rate: Decimal,
        output_rate: Decimal,
    ) -> Decimal: ...

    def settle(
        self,
        *,
        scope: CumulativeBudgetScope,
        reservation_id: str,
        actual_usd: Decimal,
        over_reservation: bool,
        ceiling_usd: Decimal,
        input_rate: Decimal,
        output_rate: Decimal,
    ) -> Decimal: ...

    def fail(
        self,
        *,
        scope: CumulativeBudgetScope,
        reservation_id: str,
        ceiling_usd: Decimal,
        input_rate: Decimal,
        output_rate: Decimal,
    ) -> Decimal: ...


_AUTHORITY_LOCKS_GUARD = Lock()
_AUTHORITY_LOCKS: dict[str, Lock] = {}
_AUTHORITY_FILENAME = "provider-budget.json"
_AUTHORITY_LOCK_FILENAME = ".provider-budget.lock"
_MAX_AUTHORITY_BYTES = 256 * 1024


class FileBudgetAuthority:
    def __init__(self, root: Path) -> None:
        self.root = Path(root).absolute()
        self.path = self.root / _AUTHORITY_FILENAME
        self.lock_path = self.root / _AUTHORITY_LOCK_FILENAME
        with _AUTHORITY_LOCKS_GUARD:
            self._thread_lock = _AUTHORITY_LOCKS.setdefault(str(self.path), Lock())

    def bind(
        self,
        *,
        scope: CumulativeBudgetScope,
        ceiling_usd: Decimal,
        input_rate: Decimal,
        output_rate: Decimal,
    ) -> Decimal:
        with self._locked_state() as state:
            _, _, profile_state = self._budget_states(
                state,
                scope=scope,
                ceiling_usd=ceiling_usd,
                input_rate=input_rate,
                output_rate=output_rate,
                create=True,
            )
            self._write_state(state)
            return _profile_accounted(profile_state)

    def reserve(
        self,
        *,
        scope: CumulativeBudgetScope,
        reservation_id: str,
        amount: Decimal,
        ceiling_usd: Decimal,
        input_rate: Decimal,
        output_rate: Decimal,
    ) -> Decimal:
        _validate_decimal(amount, "reservation amount")
        with self._locked_state() as state:
            account_state, authorization_state, profile_state = self._budget_states(
                state,
                scope=scope,
                ceiling_usd=ceiling_usd,
                input_rate=input_rate,
                output_rate=output_rate,
            )
            if account_state["breached"] is True:
                raise BudgetExceeded(f"{scope.account} project budget is fail-safe")
            if authorization_state["breached"] is True:
                raise BudgetExceeded("authorization budget is fail-safe")
            if profile_state["breached"] is True:
                raise BudgetExceeded(f"{scope.profile} profile budget is fail-safe")
            outstanding = profile_state["outstanding"]
            assert isinstance(outstanding, dict)
            if _reservation_exists(state, reservation_id):
                raise BudgetAuthorityError("duplicate cumulative reservation identifier")
            # The per-role ceiling is an episode-local limit enforced by the
            # BudgetLedger that owns this reservation. The shared authority
            # enforces only the authorization and project ceilings across every
            # episode that shares the configuration digest; the profile state is
            # kept for accounting, not as a third cumulative cap.
            if (
                _authorization_accounted(authorization_state) + amount
                > scope.authorization_ceiling_usd
            ):
                raise BudgetExceeded("authorization budget ceiling would be exceeded")
            if (
                _project_accounted(account_state) + amount
                > scope.project_ceiling_usd
            ):
                raise BudgetExceeded(
                    f"{scope.account} project budget ceiling would be exceeded"
                )
            outstanding[reservation_id] = str(amount)
            self._write_state(state)
            return _profile_accounted(profile_state)

    def settle(
        self,
        *,
        scope: CumulativeBudgetScope,
        reservation_id: str,
        actual_usd: Decimal,
        over_reservation: bool,
        ceiling_usd: Decimal,
        input_rate: Decimal,
        output_rate: Decimal,
    ) -> Decimal:
        _validate_decimal(actual_usd, "actual cost")
        if type(over_reservation) is not bool:
            raise TypeError("over_reservation must be a boolean")
        with self._locked_state() as state:
            account_state, authorization_state, profile_state = self._budget_states(
                state,
                scope=scope,
                ceiling_usd=ceiling_usd,
                input_rate=input_rate,
                output_rate=output_rate,
            )
            self._pop_reservation(profile_state, reservation_id)
            profile_state["actual_usd"] = str(
                Decimal(str(profile_state["actual_usd"])) + actual_usd
            )
            profile_state["breached"] = (
                profile_state["breached"] is True or over_reservation
            )
            authorization_state["breached"] = (
                authorization_state["breached"] is True
                or over_reservation
                or _authorization_accounted(authorization_state)
                > scope.authorization_ceiling_usd
            )
            account_state["breached"] = (
                account_state["breached"] is True
                or over_reservation
                or _project_accounted(account_state) > scope.project_ceiling_usd
            )
            self._write_state(state)
            return _profile_accounted(profile_state)

    def fail(
        self,
        *,
        scope: CumulativeBudgetScope,
        reservation_id: str,
        ceiling_usd: Decimal,
        input_rate: Decimal,
        output_rate: Decimal,
    ) -> Decimal:
        with self._locked_state() as state:
            _, _, profile_state = self._budget_states(
                state,
                scope=scope,
                ceiling_usd=ceiling_usd,
                input_rate=input_rate,
                output_rate=output_rate,
            )
            amount = self._pop_reservation(profile_state, reservation_id)
            profile_state["uncertain_usd"] = str(
                Decimal(str(profile_state["uncertain_usd"])) + amount
            )
            self._write_state(state)
            return _profile_accounted(profile_state)

    @contextmanager
    def _locked_state(self) -> Iterator[dict[str, object]]:
        with self._thread_lock:
            self._prepare_root()
            descriptor: int | None = None
            try:
                flags = os.O_RDWR | os.O_CREAT
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(self.lock_path, flags, 0o600)
                mode = os.fstat(descriptor).st_mode
                if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o600:
                    raise BudgetAuthorityError("cumulative budget lock path is unsafe")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield self._read_state()
            except BudgetAuthorityError:
                raise
            except OSError as error:
                raise BudgetAuthorityError("cumulative budget lock failed") from error
            finally:
                if descriptor is not None:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    finally:
                        os.close(descriptor)

    def _prepare_root(self) -> None:
        _reject_symlink_components(self.root)
        if self.root.exists():
            try:
                root_stat = self.root.lstat()
            except OSError as error:
                raise BudgetAuthorityError("cumulative budget path is unsafe") from error
            if (
                not stat.S_ISDIR(root_stat.st_mode)
                or stat.S_IMODE(root_stat.st_mode) != 0o700
            ):
                raise BudgetAuthorityError("cumulative budget path is unsafe")
            return
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        except OSError as error:
            raise BudgetAuthorityError("cumulative budget path could not be created") from error
        _reject_symlink_components(self.root)
        self.root.chmod(0o700)

    def _read_state(self) -> dict[str, object]:
        if self.path.is_symlink():
            raise BudgetAuthorityError("cumulative budget state path is unsafe")
        if not self.path.exists():
            return {"schema_version": 2, "accounts": {}}
        try:
            file_stat = self.path.lstat()
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or stat.S_IMODE(file_stat.st_mode) != 0o600
                or file_stat.st_size > _MAX_AUTHORITY_BYTES
            ):
                raise BudgetAuthorityError("cumulative budget state path is unsafe")
            raw = self.path.read_text(encoding="utf-8")
            state = json.loads(
                raw,
                object_pairs_hook=_no_duplicate_keys,
                parse_constant=lambda token: (_ for _ in ()).throw(
                    ValueError(f"non-finite constant {token}")
                ),
            )
            return _validate_state(state)
        except BudgetAuthorityError:
            raise
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
            raise BudgetAuthorityError("cumulative budget state is corrupt") from error

    def _write_state(self, state: dict[str, object]) -> None:
        _validate_state(state)
        serialized = json.dumps(
            state, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        temporary = self.root / f".{_AUTHORITY_FILENAME}.{secrets.token_hex(8)}.tmp"
        descriptor: int | None = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = None
                stream.write(serialized + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory_descriptor = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError as error:
            raise BudgetAuthorityError("cumulative budget state write failed") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _budget_states(
        state: dict[str, object],
        *,
        scope: CumulativeBudgetScope,
        ceiling_usd: Decimal,
        input_rate: Decimal,
        output_rate: Decimal,
        create: bool = False,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        _validate_scope(scope)
        for value, label in (
            (ceiling_usd, "ceiling"),
            (input_rate, "input rate"),
            (output_rate, "output rate"),
        ):
            _validate_decimal(value, label)
        accounts = state["accounts"]
        assert isinstance(accounts, dict)
        account_state = accounts.get(scope.account)
        if account_state is None:
            if not create:
                raise BudgetAuthorityError("cumulative budget account state is missing")
            account_state = {
                "project_ceiling_usd": str(scope.project_ceiling_usd),
                "breached": False,
                "authorizations": {},
            }
            accounts[scope.account] = account_state
        if not isinstance(account_state, dict):
            raise BudgetAuthorityError("cumulative budget account state is corrupt")
        if account_state.get("project_ceiling_usd") != str(scope.project_ceiling_usd):
            raise BudgetAuthorityError(
                "cumulative budget project configuration differs from established state"
            )

        authorizations = account_state.get("authorizations")
        if not isinstance(authorizations, dict):
            raise BudgetAuthorityError("cumulative budget account state is corrupt")
        authorization_state = authorizations.get(scope.authorization_id)
        if authorization_state is None:
            if not create:
                raise BudgetAuthorityError(
                    "cumulative budget authorization state is missing"
                )
            authorization_state = {
                "ceiling_usd": str(scope.authorization_ceiling_usd),
                "breached": False,
                "profiles": {},
            }
            authorizations[scope.authorization_id] = authorization_state
        if not isinstance(authorization_state, dict):
            raise BudgetAuthorityError(
                "cumulative budget authorization state is corrupt"
            )
        if authorization_state.get("ceiling_usd") != str(
            scope.authorization_ceiling_usd
        ):
            raise BudgetAuthorityError(
                "cumulative budget authorization configuration differs from established state"
            )

        profiles = authorization_state.get("profiles")
        if not isinstance(profiles, dict):
            raise BudgetAuthorityError(
                "cumulative budget authorization state is corrupt"
            )
        profile_state = profiles.get(scope.profile)
        expected_profile = {
            "ceiling_usd": str(ceiling_usd),
            "input_rate": str(input_rate),
            "output_rate": str(output_rate),
        }
        if profile_state is None:
            if not create:
                raise BudgetAuthorityError("cumulative budget profile state is missing")
            profile_state = {
                **expected_profile,
                "actual_usd": "0",
                "uncertain_usd": "0",
                "outstanding": {},
                "breached": False,
            }
            profiles[scope.profile] = profile_state
        if not isinstance(profile_state, dict):
            raise BudgetAuthorityError("cumulative budget profile state is corrupt")
        if any(
            profile_state.get(key) != value
            for key, value in expected_profile.items()
        ):
            raise BudgetAuthorityError(
                "cumulative budget configuration differs from established state"
            )
        return account_state, authorization_state, profile_state

    @staticmethod
    def _pop_reservation(
        provider_state: dict[str, object], reservation_id: str
    ) -> Decimal:
        outstanding = provider_state["outstanding"]
        assert isinstance(outstanding, dict)
        try:
            value = outstanding.pop(reservation_id)
        except KeyError as error:
            raise BudgetAuthorityError("cumulative reservation is missing") from error
        return Decimal(str(value))


@dataclass(frozen=True)
class UsageRecord:
    provider: str
    status: str
    input_tokens: int | None
    output_tokens: int | None
    actual_usd: Decimal | None
    uncertain_usd: Decimal
    model: str | None = None
    latency_ms: int | None = None
    routed_provider: str | None = None


class AccountingError(RuntimeError):
    def __init__(self, record: UsageRecord) -> None:
        self.record = record
        super().__init__(f"{record.provider} accounting failure: {record.status}")


class Reservation:
    def __init__(
        self,
        ledger: BudgetLedger,
        *,
        max_input_tokens: int,
        max_output_tokens: int,
        reserved_usd: Decimal,
        cumulative_reservation_id: str | None,
    ) -> None:
        self._ledger = ledger
        self.max_input_tokens = max_input_tokens
        self.max_output_tokens = max_output_tokens
        self.reserved_usd = reserved_usd
        self.cumulative_reservation_id = cumulative_reservation_id
        self._closed = False

    def settle(
        self,
        actual_input_tokens: int,
        actual_output_tokens: int,
        *,
        status: str = "success",
        model: str | None = None,
        latency_ms: int | None = None,
        routed_provider: str | None = None,
    ) -> UsageRecord:
        self._require_open()
        return self._ledger._settle(
            self,
            actual_input_tokens,
            actual_output_tokens,
            status=status,
            model=model,
            latency_ms=latency_ms,
            routed_provider=routed_provider,
        )

    def fail(
        self,
        status: str,
        *,
        model: str | None = None,
        latency_ms: int | None = None,
        routed_provider: str | None = None,
    ) -> UsageRecord:
        self._require_open()
        return self._ledger._fail(
            self,
            status,
            model=model,
            latency_ms=latency_ms,
            routed_provider=routed_provider,
        )

    def _require_open(self) -> None:
        if self._closed:
            raise ReservationStateError("reservation has already been finalized")


class BudgetLedger:
    def __init__(
        self,
        *,
        provider: str,
        ceiling_usd: Decimal,
        input_rate: Decimal,
        output_rate: Decimal,
        max_calls: int,
        cumulative_authority: CumulativeBudgetAuthority | None = None,
        cumulative_scope: CumulativeBudgetScope | None = None,
    ) -> None:
        if not provider:
            raise ValueError("provider is required")
        if not all(isinstance(value, Decimal) for value in (ceiling_usd, input_rate, output_rate)):
            raise TypeError("budget amounts must be Decimal values")
        if ceiling_usd < 0 or input_rate < 0 or output_rate < 0:
            raise ValueError("budget amounts must be non-negative")
        if max_calls < 1:
            raise ValueError("max_calls must be positive")
        if (cumulative_authority is None) != (cumulative_scope is None):
            raise ValueError(
                "cumulative authority and scope must be configured together"
            )
        self.provider = provider
        self.ceiling_usd = ceiling_usd
        self.input_rate = input_rate
        self.output_rate = output_rate
        self.max_calls = max_calls
        self.actual_usd = Decimal("0")
        self.uncertain_usd = Decimal("0")
        self.reserved_usd = Decimal("0")
        self.call_attempts = 0
        self.failure_counts: dict[str, int] = {}
        self._breached = False
        self._cumulative_authority = cumulative_authority
        self._cumulative_scope = cumulative_scope
        self._cumulative_accounted_usd = (
            cumulative_authority.bind(
                scope=cumulative_scope,
                ceiling_usd=ceiling_usd,
                input_rate=input_rate,
                output_rate=output_rate,
            )
            if cumulative_authority is not None
            else None
        )

    @property
    def accounted_usd(self) -> Decimal:
        return self.actual_usd + self.uncertain_usd + self.reserved_usd

    @property
    def cumulative_accounted_usd(self) -> Decimal:
        return (
            self.accounted_usd
            if self._cumulative_accounted_usd is None
            else self._cumulative_accounted_usd
        )

    def reserve(self, *, max_input_tokens: int, max_output_tokens: int) -> Reservation:
        self._validate_tokens(max_input_tokens, max_output_tokens)
        if self._breached:
            raise BudgetExceeded(f"{self.provider} ledger is fail-safe after an accounting breach")
        if self.call_attempts >= self.max_calls:
            raise CallCapExceeded(f"{self.provider} call cap exhausted")
        amount = self._cost(max_input_tokens, max_output_tokens)
        if self.accounted_usd + amount > self.ceiling_usd:
            raise BudgetExceeded(f"{self.provider} budget ceiling would be exceeded")
        cumulative_reservation_id = (
            secrets.token_hex(16) if self._cumulative_authority is not None else None
        )
        if self._cumulative_authority is not None:
            assert cumulative_reservation_id is not None
            assert self._cumulative_scope is not None
            self._cumulative_accounted_usd = self._cumulative_authority.reserve(
                scope=self._cumulative_scope,
                reservation_id=cumulative_reservation_id,
                amount=amount,
                ceiling_usd=self.ceiling_usd,
                input_rate=self.input_rate,
                output_rate=self.output_rate,
            )
        self.call_attempts += 1
        self.reserved_usd += amount
        return Reservation(
            self,
            max_input_tokens=max_input_tokens,
            max_output_tokens=max_output_tokens,
            reserved_usd=amount,
            cumulative_reservation_id=cumulative_reservation_id,
        )

    def _settle(
        self,
        reservation: Reservation,
        actual_input_tokens: int,
        actual_output_tokens: int,
        *,
        status: str,
        model: str | None,
        latency_ms: int | None,
        routed_provider: str | None,
    ) -> UsageRecord:
        try:
            self._validate_tokens(actual_input_tokens, actual_output_tokens)
            self._validate_latency(latency_ms)
        except (TypeError, ValueError) as error:
            self._fail_cumulative(reservation)
            self._close_reservation(reservation)
            self.uncertain_usd += reservation.reserved_usd
            self.failure_counts["invalid_usage"] = self.failure_counts.get("invalid_usage", 0) + 1
            record = UsageRecord(
                provider=self.provider,
                status="invalid_usage",
                input_tokens=None,
                output_tokens=None,
                actual_usd=None,
                uncertain_usd=reservation.reserved_usd,
                model=model,
                latency_ms=None,
                routed_provider=routed_provider,
            )
            raise AccountingError(record) from error
        actual_cost = self._cost(actual_input_tokens, actual_output_tokens)
        over_reservation = (
            actual_input_tokens > reservation.max_input_tokens
            or actual_output_tokens > reservation.max_output_tokens
        )
        self._settle_cumulative(
            reservation, actual_usd=actual_cost, over_reservation=over_reservation
        )
        self._close_reservation(reservation)
        final_status = "over_reservation" if over_reservation else status
        record = UsageRecord(
            provider=self.provider,
            status=final_status,
            input_tokens=actual_input_tokens,
            output_tokens=actual_output_tokens,
            actual_usd=actual_cost,
            uncertain_usd=Decimal("0"),
            model=model,
            latency_ms=latency_ms,
            routed_provider=routed_provider,
        )
        self.actual_usd += actual_cost
        if final_status != "success":
            self.failure_counts[final_status] = self.failure_counts.get(final_status, 0) + 1
        if over_reservation:
            self._breached = True
            raise AccountingError(record)
        return record

    def _fail(
        self,
        reservation: Reservation,
        status: str,
        *,
        model: str | None,
        latency_ms: int | None,
        routed_provider: str | None,
    ) -> UsageRecord:
        if not status:
            raise ValueError("failure status is required")
        self._validate_latency(latency_ms)
        self._fail_cumulative(reservation)
        self._close_reservation(reservation)
        self.uncertain_usd += reservation.reserved_usd
        self.failure_counts[status] = self.failure_counts.get(status, 0) + 1
        return UsageRecord(
            provider=self.provider,
            status=status,
            input_tokens=None,
            output_tokens=None,
            actual_usd=None,
            uncertain_usd=reservation.reserved_usd,
            model=model,
            latency_ms=latency_ms,
            routed_provider=routed_provider,
        )

    def _close_reservation(self, reservation: Reservation) -> None:
        self.reserved_usd -= reservation.reserved_usd
        reservation._closed = True

    def _settle_cumulative(
        self,
        reservation: Reservation,
        *,
        actual_usd: Decimal,
        over_reservation: bool,
    ) -> None:
        if self._cumulative_authority is None:
            return
        reservation_id = reservation.cumulative_reservation_id
        if reservation_id is None:
            raise BudgetAuthorityError("cumulative reservation identifier is missing")
        if self._cumulative_scope is None:
            raise BudgetAuthorityError("cumulative budget scope is missing")
        self._cumulative_accounted_usd = self._cumulative_authority.settle(
            scope=self._cumulative_scope,
            reservation_id=reservation_id,
            actual_usd=actual_usd,
            over_reservation=over_reservation,
            ceiling_usd=self.ceiling_usd,
            input_rate=self.input_rate,
            output_rate=self.output_rate,
        )

    def _fail_cumulative(self, reservation: Reservation) -> None:
        if self._cumulative_authority is None:
            return
        reservation_id = reservation.cumulative_reservation_id
        if reservation_id is None:
            raise BudgetAuthorityError("cumulative reservation identifier is missing")
        if self._cumulative_scope is None:
            raise BudgetAuthorityError("cumulative budget scope is missing")
        self._cumulative_accounted_usd = self._cumulative_authority.fail(
            scope=self._cumulative_scope,
            reservation_id=reservation_id,
            ceiling_usd=self.ceiling_usd,
            input_rate=self.input_rate,
            output_rate=self.output_rate,
        )

    def _cost(self, input_tokens: int, output_tokens: int) -> Decimal:
        return (
            Decimal(input_tokens) * self.input_rate
            + Decimal(output_tokens) * self.output_rate
        ) / Decimal(1_000_000)

    @staticmethod
    def _validate_tokens(input_tokens: int, output_tokens: int) -> None:
        if type(input_tokens) is not int or type(output_tokens) is not int:
            raise TypeError("token counts must be integers")
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("token counts must be non-negative")

    @staticmethod
    def _validate_latency(latency_ms: int | None) -> None:
        if latency_ms is not None and (type(latency_ms) is not int or latency_ms < 0):
            raise ValueError("latency_ms must be a non-negative integer or None")


def _validate_decimal(value: Decimal, label: str) -> None:
    if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
        raise BudgetAuthorityError(f"cumulative budget {label} is invalid")


def _profile_accounted(profile_state: dict[str, object]) -> Decimal:
    outstanding = profile_state["outstanding"]
    assert isinstance(outstanding, dict)
    return (
        Decimal(str(profile_state["actual_usd"]))
        + Decimal(str(profile_state["uncertain_usd"]))
        + sum((Decimal(str(value)) for value in outstanding.values()), Decimal("0"))
    )


def _authorization_accounted(authorization_state: dict[str, object]) -> Decimal:
    profiles = authorization_state["profiles"]
    assert isinstance(profiles, dict)
    total = Decimal("0")
    for profile_state in profiles.values():
        assert isinstance(profile_state, dict)
        total += _profile_accounted(profile_state)
    return total


def _project_accounted(account_state: dict[str, object]) -> Decimal:
    authorizations = account_state["authorizations"]
    assert isinstance(authorizations, dict)
    total = Decimal("0")
    for authorization_state in authorizations.values():
        assert isinstance(authorization_state, dict)
        total += _authorization_accounted(authorization_state)
    return total


def _reservation_exists(state: dict[str, object], reservation_id: str) -> bool:
    accounts = state["accounts"]
    assert isinstance(accounts, dict)
    for account_state in accounts.values():
        assert isinstance(account_state, dict)
        authorizations = account_state["authorizations"]
        assert isinstance(authorizations, dict)
        for authorization_state in authorizations.values():
            assert isinstance(authorization_state, dict)
            profiles = authorization_state["profiles"]
            assert isinstance(profiles, dict)
            for profile_state in profiles.values():
                assert isinstance(profile_state, dict)
                outstanding = profile_state["outstanding"]
                assert isinstance(outstanding, dict)
                if reservation_id in outstanding:
                    return True
    return False


def _validate_scope(scope: CumulativeBudgetScope) -> None:
    if not isinstance(scope, CumulativeBudgetScope):
        raise BudgetAuthorityError("cumulative budget scope is invalid")
    for value in (scope.account, scope.authorization_id, scope.profile):
        if not _valid_scope_name(value):
            raise BudgetAuthorityError("cumulative budget scope is invalid")
    _validate_decimal(scope.project_ceiling_usd, "project ceiling")
    _validate_decimal(scope.authorization_ceiling_usd, "authorization ceiling")
    if (
        scope.project_ceiling_usd <= 0
        or scope.authorization_ceiling_usd <= 0
        or scope.authorization_ceiling_usd > scope.project_ceiling_usd
    ):
        raise BudgetAuthorityError("cumulative budget scope is invalid")


def _valid_scope_name(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and all(
            character.isascii()
            and (character.isalnum() or character in "._:-")
            for character in value
        )
    )


def _stored_decimal(value: object, label: str, *, positive: bool = False) -> Decimal:
    if type(value) is not str:
        raise BudgetAuthorityError("cumulative budget state is corrupt")
    try:
        amount = Decimal(value)
    except Exception as error:
        raise BudgetAuthorityError("cumulative budget state is corrupt") from error
    _validate_decimal(amount, label)
    if positive and amount <= 0:
        raise BudgetAuthorityError("cumulative budget state is corrupt")
    return amount


def _validate_state(value: object) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "accounts"}
        or value["schema_version"] != 2
        or type(value["schema_version"]) is not int
        or not isinstance(value["accounts"], dict)
    ):
        raise BudgetAuthorityError("cumulative budget state is corrupt")
    for account_name, account_state in value["accounts"].items():
        if not _valid_scope_name(account_name) or not isinstance(account_state, dict):
            raise BudgetAuthorityError("cumulative budget state is corrupt")
        if set(account_state) != {
            "project_ceiling_usd",
            "breached",
            "authorizations",
        }:
            raise BudgetAuthorityError("cumulative budget state is corrupt")
        project_ceiling = _stored_decimal(
            account_state["project_ceiling_usd"], "project ceiling", positive=True
        )
        if type(account_state["breached"]) is not bool:
            raise BudgetAuthorityError("cumulative budget state is corrupt")
        authorizations = account_state["authorizations"]
        if not isinstance(authorizations, dict):
            raise BudgetAuthorityError("cumulative budget state is corrupt")
        for authorization_name, authorization_state in authorizations.items():
            if not _valid_scope_name(authorization_name) or not isinstance(
                authorization_state, dict
            ):
                raise BudgetAuthorityError("cumulative budget state is corrupt")
            if set(authorization_state) != {"ceiling_usd", "breached", "profiles"}:
                raise BudgetAuthorityError("cumulative budget state is corrupt")
            authorization_ceiling = _stored_decimal(
                authorization_state["ceiling_usd"],
                "authorization ceiling",
                positive=True,
            )
            if authorization_ceiling > project_ceiling:
                raise BudgetAuthorityError("cumulative budget state is corrupt")
            if type(authorization_state["breached"]) is not bool:
                raise BudgetAuthorityError("cumulative budget state is corrupt")
            profiles = authorization_state["profiles"]
            if not isinstance(profiles, dict):
                raise BudgetAuthorityError("cumulative budget state is corrupt")
            for profile_name, profile_state in profiles.items():
                _validate_profile_state(profile_name, profile_state)
                assert isinstance(profile_state, dict)
                if profile_state["breached"] is True and (
                    authorization_state["breached"] is not True
                    or account_state["breached"] is not True
                ):
                    raise BudgetAuthorityError(
                        "cumulative budget breach state is inconsistent"
                    )
            if (
                _authorization_accounted(authorization_state)
                > authorization_ceiling
                and authorization_state["breached"] is not True
            ):
                raise BudgetAuthorityError(
                    "cumulative budget authorization state is inconsistent"
                )
            if (
                authorization_state["breached"] is True
                and account_state["breached"] is not True
            ):
                raise BudgetAuthorityError(
                    "cumulative budget breach state is inconsistent"
                )
        if (
            _project_accounted(account_state) > project_ceiling
            and account_state["breached"] is not True
        ):
            raise BudgetAuthorityError("cumulative budget project state is inconsistent")
    return value


def _validate_profile_state(profile_name: object, profile_state: object) -> None:
    if not _valid_scope_name(profile_name) or not isinstance(profile_state, dict):
        raise BudgetAuthorityError("cumulative budget state is corrupt")
    if set(profile_state) != {
        "ceiling_usd",
        "input_rate",
        "output_rate",
        "actual_usd",
        "uncertain_usd",
        "outstanding",
        "breached",
    }:
        raise BudgetAuthorityError("cumulative budget state is corrupt")
    ceiling = _stored_decimal(profile_state["ceiling_usd"], "profile ceiling")
    for key in ("input_rate", "output_rate", "actual_usd", "uncertain_usd"):
        _stored_decimal(profile_state[key], key)
    outstanding = profile_state["outstanding"]
    if not isinstance(outstanding, dict):
        raise BudgetAuthorityError("cumulative budget state is corrupt")
    for reservation_id, amount_value in outstanding.items():
        if type(reservation_id) is not str or not re_fullmatch_hex(reservation_id):
            raise BudgetAuthorityError("cumulative budget state is corrupt")
        _stored_decimal(amount_value, "outstanding reservation")
    if type(profile_state["breached"]) is not bool:
        raise BudgetAuthorityError("cumulative budget state is corrupt")
    del ceiling  # per-role ceilings are episode-local; the stored value only pins the ledger's declaration


def re_fullmatch_hex(value: str) -> bool:
    return len(value) == 32 and all(character in "0123456789abcdef" for character in value)


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            if current.is_symlink():
                raise BudgetAuthorityError("cumulative budget path is unsafe")
        except OSError as error:
            raise BudgetAuthorityError("cumulative budget path is unsafe") from error
