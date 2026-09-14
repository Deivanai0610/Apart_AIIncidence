from http import HTTPStatus
from pathlib import Path

import pytest

from range.service import handlers


def test_web_health_does_not_require_route_state() -> None:
    assert handlers.Application("web").get("/health") == (
        HTTPStatus.OK,
        {"status": "ok"},
    )


def test_route_health_fails_when_route_state_is_missing_or_malformed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "route.json"
    monkeypatch.setattr(handlers, "ROUTE_STATE_PATH", path)
    application = handlers.Application("api")

    with pytest.raises(RuntimeError, match="unavailable"):
        application.get("/health")

    path.write_text('{"token":"","canary":null}', encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid"):
        application.get("/health")


def test_route_state_read_retries_transient_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    from range.service import handlers

    reads: list[int] = []

    def flaky_read() -> str:
        reads.append(1)
        if len(reads) == 1:
            raise OSError("not yet visible")
        if len(reads) == 2:
            return ""  # incomplete file
        return '{"token": "tok", "canary": null}'

    monkeypatch.setattr(handlers, "_read_route_state_text", flaky_read)
    monkeypatch.setattr(handlers, "ROUTE_STATE_READ_DELAY_SECONDS", 0)

    assert handlers.load_route_state() == {"token": "tok", "canary": None}
    assert len(reads) == 3


def test_route_state_read_gives_up_after_bounded_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    from range.service import handlers

    reads: list[int] = []

    def broken_read() -> str:
        reads.append(1)
        raise OSError("gone")

    monkeypatch.setattr(handlers, "_read_route_state_text", broken_read)
    monkeypatch.setattr(handlers, "ROUTE_STATE_READ_DELAY_SECONDS", 0)
    monkeypatch.setattr(handlers, "ROUTE_STATE_READ_ATTEMPTS", 4)

    with pytest.raises(RuntimeError, match="unavailable"):
        handlers.load_route_state()
    assert len(reads) == 4
