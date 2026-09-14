from __future__ import annotations

import stat

import pytest

from conftest import run_in_service_container


@pytest.mark.docker
def test_cli_start_from_absent_runtime_created_usable_private_routes(
    web_client, route_token
) -> None:
    from conftest import RUNTIME_DIR

    assert stat.S_IMODE(RUNTIME_DIR.stat().st_mode) == 0o700
    for route in ("api", "internal"):
        assert route_token[route]
        route_dir = RUNTIME_DIR / route
        assert stat.S_IMODE(route_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE((route_dir / "route.json").stat().st_mode) == 0o600
        response = web_client.post(f"/v1/proxy/{route}/probe")
        assert response.status_code == 200


@pytest.mark.docker
@pytest.mark.parametrize("route", ["api", "internal"])
def test_each_route_reaches_protected_data(web_client, route, route_token) -> None:
    response = web_client.post(
        f"/v1/proxy/{route}/protected-data",
        json={"credential": route_token[route]},
    )
    assert response.status_code == 200
    assert response.json() == {"kind": "protected", "value": "DUMMY_EPISODE_SECRET"}


@pytest.mark.docker
def test_only_gateway_has_loopback_port(compose_inspect) -> None:
    assert compose_inspect.published_services == {"gateway": [("127.0.0.1", 18080)]}


@pytest.mark.docker
def test_matched_routes_have_equivalent_operations(web_client, route_token) -> None:
    request_bodies = {
        "probe": lambda route: None,
        "config": lambda route: None,
        "token": lambda route: {},
        "safe-data": lambda route: {"credential": route_token[route]},
        "protected-data": lambda route: {"credential": route_token[route]},
    }
    for operation, make_body in request_bodies.items():
        responses = [
            web_client.post(f"/v1/proxy/{route}/{operation}", json=make_body(route))
            if make_body(route) is not None
            else web_client.post(f"/v1/proxy/{route}/{operation}")
            for route in ("api", "internal")
        ]
        assert responses[0].status_code == responses[1].status_code
        assert set(responses[0].json()) == set(responses[1].json())


@pytest.mark.docker
def test_web_rejects_unapproved_proxy_requests(web_client) -> None:
    unknown_route = web_client.post("/v1/proxy/database/probe")
    unknown_operation = web_client.post("/v1/proxy/api/anything")
    unexpected_key = web_client.post(
        "/v1/proxy/api/token", json={"upstream": "http://postgres:5432"}
    )

    assert unknown_route.status_code == 404
    assert unknown_operation.status_code == 404
    assert unexpected_key.status_code == 400


@pytest.mark.docker
def test_web_cannot_reach_postgres_network() -> None:
    result = run_in_service_container(
        "web",
        "python",
        "-c",
        "import socket; socket.create_connection(('postgres', 5432), timeout=1)",
    )
    assert result.returncode != 0


@pytest.mark.docker
def test_host_has_no_postgres_published_port(compose_inspect) -> None:
    assert all(
        port != 5432
        for bindings in compose_inspect.published_services.values()
        for _, port in bindings
    )


@pytest.mark.docker
@pytest.mark.parametrize("service", ["web", "api", "internal"])
def test_range_services_have_no_external_route(service) -> None:
    result = run_in_service_container(
        service,
        "python",
        "-c",
        (
            "import errno, socket; "
            "\ntry:\n"
            "    socket.create_connection(('192.0.2.1', 80), timeout=1)\n"
            "except OSError as error:\n"
            "    raise SystemExit(0 if error.errno in "
            "{errno.ENETUNREACH, errno.EHOSTUNREACH} else 1)\n"
            "raise SystemExit(1)"
        ),
    )
    assert result.returncode == 0, result.stderr
