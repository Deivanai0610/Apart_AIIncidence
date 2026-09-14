import json
import stat
from pathlib import Path

import pytest
import yaml

from chimera.route_state import (
    RouteStateError,
    initialize_route_states,
    read_route_state,
    write_route_state,
)
from chimera.schemas import Route


def test_initialize_route_states_creates_private_valid_files(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"

    initialize_route_states(runtime)

    assert stat.S_IMODE(runtime.stat().st_mode) == 0o700
    for route in Route:
        route_dir = runtime / route.value
        path = route_dir / "route.json"
        assert stat.S_IMODE(route_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        state = read_route_state(path)
        assert state.token
        assert state.canary is None


def test_compose_mounts_only_each_private_route_directory() -> None:
    compose = yaml.safe_load(Path("range/compose.yaml").read_text(encoding="utf-8"))

    assert compose["services"]["api"]["volumes"] == [
        "./runtime/api:/run/chimera:ro"
    ]
    assert compose["services"]["internal"]["volumes"] == [
        "./runtime/internal:/run/chimera:ro"
    ]


def test_route_state_writer_rejects_symlinks_and_file_substitutions(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "runtime"
    linked.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RouteStateError, match="unsafe"):
        write_route_state(linked, Route.API, token="dummy-token", canary=None)

    linked.unlink()
    linked.mkdir(mode=0o700)
    (linked / "api").write_text("not a directory", encoding="utf-8")
    with pytest.raises(RouteStateError, match="directory"):
        write_route_state(linked, Route.API, token="dummy-token", canary=None)

    (linked / "api").unlink()
    (linked / "api").symlink_to(outside, target_is_directory=True)
    with pytest.raises(RouteStateError, match="directory"):
        write_route_state(linked, Route.API, token="dummy-token", canary=None)

    (linked / "api").unlink()
    (linked / "api").mkdir(mode=0o700)
    (linked / "api" / "route.json").symlink_to(tmp_path / "missing-state")
    with pytest.raises(RouteStateError, match="regular file"):
        write_route_state(linked, Route.API, token="dummy-token", canary=None)


def test_initializer_rejects_malformed_existing_state_without_replacing_it(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    route_dir = runtime / "api"
    route_dir.mkdir(mode=0o700)
    path = route_dir / "route.json"
    path.write_text(json.dumps({"token": "", "canary": None}), encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(RouteStateError, match="malformed"):
        initialize_route_states(runtime)

    assert json.loads(path.read_text(encoding="utf-8"))["token"] == ""


def test_route_state_replacement_changes_inode_inside_stable_route_directory(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    initialize_route_states(runtime)
    route_dir = runtime / "api"
    path = route_dir / "route.json"
    directory_inode = route_dir.stat().st_ino
    first_inode = path.stat().st_ino

    write_route_state(runtime, Route.API, token="replacement-token", canary=None)

    assert route_dir.stat().st_ino == directory_inode
    assert path.stat().st_ino != first_inode
    assert read_route_state(path).token == "replacement-token"


@pytest.mark.parametrize("legacy_kind", ["file", "directory"])
def test_initializer_rejects_legacy_flat_route_state(
    tmp_path: Path, legacy_kind: str
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    legacy = runtime / "api.json"
    if legacy_kind == "file":
        legacy.write_text('{"token":"legacy","canary":null}', encoding="utf-8")
    else:
        legacy.mkdir()

    with pytest.raises(RouteStateError, match="legacy"):
        initialize_route_states(runtime)
