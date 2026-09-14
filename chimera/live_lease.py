from __future__ import annotations

import fcntl
import os
import stat
from pathlib import Path
from threading import Lock, local


class LiveRangeLeaseError(RuntimeError):
    pass


_LEASE_LOCKS_GUARD = Lock()
_LEASE_LOCKS: dict[str, Lock] = {}
_ACTIVE_LEASE = local()
_LEASE_FD_ENV = "CHIMERA_LIVE_RANGE_LEASE_FD"


def live_range_lease_subprocess_options() -> tuple[dict[str, str], tuple[int, ...]]:
    descriptor = getattr(_ACTIVE_LEASE, "descriptor", None)
    if descriptor is None:
        descriptor = _inherited_descriptor()
    if descriptor is None:
        return {}, ()
    _validate_descriptor(descriptor)
    return {_LEASE_FD_ENV: str(descriptor)}, (descriptor,)


class LiveRangeLease:
    def __init__(self, path: Path) -> None:
        self.path = Path(path).absolute()
        if self.path.name != ".live-range.lock":
            raise LiveRangeLeaseError("live range lease path is unsafe")
        with _LEASE_LOCKS_GUARD:
            self._thread_lock = _LEASE_LOCKS.setdefault(str(self.path), Lock())
        self._descriptor: int | None = None
        self._previous_active_descriptor: int | None = None

    def __enter__(self) -> LiveRangeLease:
        if self._descriptor is not None:
            raise LiveRangeLeaseError("live range lease is already held")
        self._thread_lock.acquire()
        descriptor: int | None = None
        try:
            _prepare_parent(self.path.parent)
            if self.path.is_symlink():
                raise LiveRangeLeaseError("live range lease path is unsafe")
            inherited_descriptor = _inherited_descriptor()
            if inherited_descriptor is None:
                flags = os.O_RDWR | os.O_CREAT
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(self.path, flags, 0o600)
            else:
                _validate_descriptor_matches_path(inherited_descriptor, self.path)
                descriptor = os.dup(inherited_descriptor)
            _validate_descriptor_matches_path(descriptor, self.path)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self._descriptor = descriptor
            self._previous_active_descriptor = getattr(
                _ACTIVE_LEASE, "descriptor", None
            )
            _ACTIVE_LEASE.descriptor = descriptor
            return self
        except LiveRangeLeaseError:
            if descriptor is not None:
                os.close(descriptor)
            self._thread_lock.release()
            raise
        except OSError as error:
            if descriptor is not None:
                os.close(descriptor)
            self._thread_lock.release()
            raise LiveRangeLeaseError("live range lease could not be acquired") from error

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            raise LiveRangeLeaseError("live range lease is not held")
        self._descriptor = None
        try:
            os.close(descriptor)
        except OSError as error:
            raise LiveRangeLeaseError("live range lease could not be released") from error
        finally:
            if self._previous_active_descriptor is None:
                try:
                    del _ACTIVE_LEASE.descriptor
                except AttributeError:
                    pass
            else:
                _ACTIVE_LEASE.descriptor = self._previous_active_descriptor
            self._previous_active_descriptor = None
            self._thread_lock.release()


def _prepare_parent(parent: Path) -> None:
    _reject_symlink_components(parent)
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        raise LiveRangeLeaseError("live range lease parent is unsafe") from error
    _reject_symlink_components(parent)
    try:
        parent_stat = parent.lstat()
    except OSError as error:
        raise LiveRangeLeaseError("live range lease parent is unsafe") from error
    if not stat.S_ISDIR(parent_stat.st_mode) or parent.resolve(strict=True) != parent:
        raise LiveRangeLeaseError("live range lease parent is unsafe")


def _reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            raise LiveRangeLeaseError("live range lease path is unsafe")


def _inherited_descriptor() -> int | None:
    raw = os.getenv(_LEASE_FD_ENV)
    if raw is None:
        return None
    try:
        descriptor = int(raw)
    except ValueError as error:
        raise LiveRangeLeaseError("inherited live range lease is invalid") from error
    if descriptor < 0:
        raise LiveRangeLeaseError("inherited live range lease is invalid")
    _validate_descriptor(descriptor)
    return descriptor


def _validate_descriptor(descriptor: int) -> os.stat_result:
    try:
        file_stat = os.fstat(descriptor)
    except OSError as error:
        raise LiveRangeLeaseError("inherited live range lease is invalid") from error
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or stat.S_IMODE(file_stat.st_mode) != 0o600
    ):
        raise LiveRangeLeaseError("live range lease path is unsafe")
    return file_stat


def _validate_descriptor_matches_path(descriptor: int, path: Path) -> None:
    descriptor_stat = _validate_descriptor(descriptor)
    try:
        path_stat = path.lstat()
    except OSError as error:
        raise LiveRangeLeaseError("live range lease path is unsafe") from error
    if (
        not stat.S_ISREG(path_stat.st_mode)
        or descriptor_stat.st_dev != path_stat.st_dev
        or descriptor_stat.st_ino != path_stat.st_ino
    ):
        raise LiveRangeLeaseError("live range lease path is unsafe")
