from __future__ import annotations

import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from chimera.schemas import Route


class RouteStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class RouteState:
    token: str
    canary: str | None


def initialize_route_states(runtime_dir: Path) -> None:
    runtime_dir = _prepare_runtime_dir(runtime_dir)
    _reject_legacy_route_states(runtime_dir)
    for route in Route:
        route_dir = _prepare_route_dir(runtime_dir, route)
        path = route_dir / "route.json"
        if path.exists() or path.is_symlink():
            try:
                read_route_state(path)
            except RouteStateError as error:
                raise RouteStateError("existing route state is malformed or unsafe") from error
    for route in Route:
        write_route_state(
            runtime_dir,
            route,
            token=secrets.token_urlsafe(24),
            canary=None,
        )


def write_route_state(
    runtime_dir: Path,
    route: Route,
    *,
    token: str,
    canary: str | None,
) -> Path:
    if not isinstance(route, Route):
        raise TypeError("route must be a Route")
    state = _validate_payload({"token": token, "canary": canary})
    runtime_dir = _prepare_runtime_dir(runtime_dir)
    _reject_legacy_route_states(runtime_dir)
    route_dir = _prepare_route_dir(runtime_dir, route)
    path = route_dir / "route.json"
    if path.exists() or path.is_symlink():
        try:
            path_stat = path.lstat()
        except OSError as error:
            raise RouteStateError("route state path is unsafe") from error
        if not stat.S_ISREG(path_stat.st_mode):
            raise RouteStateError("route state path must be a regular file")
        if stat.S_IMODE(path_stat.st_mode) != 0o600:
            raise RouteStateError("route state file mode is unsafe")
        read_route_state(path)
    serialized = json.dumps(
        {"token": state.token, "canary": state.canary},
        sort_keys=True,
        separators=(",", ":"),
    )
    temporary = route_dir / f".route.{secrets.token_hex(8)}.tmp"
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
        os.replace(temporary, path)
        directory_descriptor = os.open(route_dir, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except RouteStateError:
        raise
    except OSError as error:
        raise RouteStateError("route state write failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return path


def read_route_state(path: Path) -> RouteState:
    path = Path(path).absolute()
    _reject_symlink_components(path)
    try:
        path_stat = path.lstat()
        if (
            not stat.S_ISREG(path_stat.st_mode)
            or stat.S_IMODE(path_stat.st_mode) != 0o600
            or path_stat.st_size > 16 * 1024
        ):
            raise RouteStateError("route state path is unsafe")
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant {token}")
            ),
        )
        return _validate_payload(payload)
    except RouteStateError:
        raise
    except FileNotFoundError as error:
        raise RouteStateError("route state is unavailable") from error
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RouteStateError("route state is malformed") from error


def _prepare_runtime_dir(runtime_dir: Path) -> Path:
    runtime_dir = Path(runtime_dir).absolute()
    _reject_symlink_components(runtime_dir)
    if runtime_dir.exists():
        try:
            directory_stat = runtime_dir.lstat()
        except OSError as error:
            raise RouteStateError("route state directory is unsafe") from error
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise RouteStateError("route state directory is unsafe")
        runtime_dir.chmod(0o700)
    else:
        try:
            runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        except OSError as error:
            raise RouteStateError("route state directory creation failed") from error
        _reject_symlink_components(runtime_dir)
        runtime_dir.chmod(0o700)
    if stat.S_IMODE(runtime_dir.stat().st_mode) != 0o700:
        raise RouteStateError("route state directory mode is unsafe")
    return runtime_dir


def _prepare_route_dir(runtime_dir: Path, route: Route) -> Path:
    route_dir = runtime_dir / route.value
    if route_dir.exists() or route_dir.is_symlink():
        try:
            directory_stat = route_dir.lstat()
        except OSError as error:
            raise RouteStateError("route state directory is unsafe") from error
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise RouteStateError("route state directory is unsafe")
        try:
            route_dir.chmod(0o700)
        except OSError as error:
            raise RouteStateError("route state directory mode is unsafe") from error
    else:
        try:
            route_dir.mkdir(mode=0o700, exist_ok=False)
        except OSError as error:
            raise RouteStateError("route state directory creation failed") from error
    _reject_symlink_components(route_dir)
    try:
        directory_stat = route_dir.lstat()
    except OSError as error:
        raise RouteStateError("route state directory is unsafe") from error
    if (
        not stat.S_ISDIR(directory_stat.st_mode)
        or stat.S_IMODE(directory_stat.st_mode) != 0o700
    ):
        raise RouteStateError("route state directory mode is unsafe")
    return route_dir


def _reject_legacy_route_states(runtime_dir: Path) -> None:
    for route in Route:
        legacy = runtime_dir / f"{route.value}.json"
        if legacy.exists() or legacy.is_symlink():
            raise RouteStateError("legacy route state path is unsafe")


def _validate_payload(value: object) -> RouteState:
    if not isinstance(value, dict) or set(value) != {"token", "canary"}:
        raise RouteStateError("route state is malformed")
    token = value["token"]
    canary = value["canary"]
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 4096
        or (canary is not None and (not isinstance(canary, str) or not canary or len(canary) > 4096))
    ):
        raise RouteStateError("route state is malformed")
    return RouteState(token=token, canary=canary)


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            raise RouteStateError("route state path is unsafe")


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result
