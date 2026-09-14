from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from chimera.live_lease import live_range_lease_subprocess_options


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "range" / "compose.yaml"
RUNTIME_DIR = ROOT / "range" / "runtime"
WEB_BASE_URL = "http://127.0.0.1:18080"
PROJECT_NAME = "chimera"


@dataclass(frozen=True)
class ComposeInspect:
    published_services: dict[str, list[tuple[str, int]]]


def _compose(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "-p", PROJECT_NAME, *args],
        cwd=ROOT,
        check=check,
        capture_output=True,
        text=True,
    )


def _wait_for_gateway_health() -> None:
    deadline = time.monotonic() + 30
    with httpx.Client(base_url=WEB_BASE_URL, timeout=1, trust_env=False) as client:
        while time.monotonic() < deadline:
            try:
                response = client.get("/health")
            except httpx.HTTPError:
                time.sleep(0.25)
                continue
            if response.status_code == 200:
                return
            time.sleep(0.25)
    logs = _compose("logs", check=False).stdout
    raise RuntimeError(f"web health check timed out\n{logs}")


def _remove_runtime_state() -> None:
    for route in ("api", "internal"):
        route_dir = RUNTIME_DIR / route
        state_path = route_dir / "route.json"
        if state_path.is_file() or state_path.is_symlink():
            state_path.unlink()
        if route_dir.is_dir():
            route_dir.rmdir()
        elif route_dir.is_symlink():
            route_dir.unlink()
        legacy_path = RUNTIME_DIR / f"{route}.json"
        if legacy_path.is_file() or legacy_path.is_symlink():
            legacy_path.unlink()
        elif legacy_path.is_dir():
            legacy_path.rmdir()
    if RUNTIME_DIR.exists() and not any(RUNTIME_DIR.iterdir()):
        RUNTIME_DIR.rmdir()


@pytest.fixture(scope="module")
def route_token() -> dict[str, str]:
    return {}


@pytest.fixture(scope="module", autouse=True)
def compose_range(route_token: dict[str, str]) -> Iterator[None]:
    _compose("down", "--volumes", "--remove-orphans", check=False)
    _remove_runtime_state()
    try:
        lease_environment, pass_fds = live_range_lease_subprocess_options()
        completed = subprocess.run(
            [sys.executable, "-m", "chimera", "range", "up"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, **lease_environment},
            pass_fds=pass_fds,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"CLI range startup failed\n{completed.stdout}\n{completed.stderr}"
            )
        for route in ("api", "internal"):
            payload = json.loads(
                (RUNTIME_DIR / route / "route.json").read_text(encoding="utf-8")
            )
            route_token[route] = payload["token"]
        _wait_for_gateway_health()
        yield
    finally:
        _compose("down", "--volumes", "--remove-orphans", check=False)
        _remove_runtime_state()


@pytest.fixture(scope="module")
def web_client() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=WEB_BASE_URL, timeout=5, trust_env=False) as client:
        yield client


@pytest.fixture(scope="module")
def compose_inspect() -> ComposeInspect:
    container_ids = _compose("ps", "-q").stdout.split()
    result = subprocess.run(
        ["docker", "inspect", *container_ids],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    containers = json.loads(result.stdout)
    published_services: dict[str, list[tuple[str, int]]] = {}
    for container in containers:
        ports = container["NetworkSettings"]["Ports"].values()
        bindings = [
            (binding["HostIp"], int(binding["HostPort"]))
            for port in ports
            if port
            for binding in port
        ]
        if bindings:
            service = container["Config"]["Labels"]["com.docker.compose.service"]
            published_services[service] = bindings
    return ComposeInspect(published_services=published_services)


def run_in_service_container(
    service: str, *command: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "-p",
            PROJECT_NAME,
            "exec",
            "-T",
            service,
            *command,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
