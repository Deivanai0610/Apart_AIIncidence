from __future__ import annotations

import json
import os
from http import HTTPStatus
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .handlers import OPERATIONS, ROUTES, RequestError, assert_empty_body, parse_json_body


class GatewayApplication:
    def __init__(self) -> None:
        self.web_base_url = os.environ.get("WEB_BASE_URL", "")
        if not self.web_base_url:
            raise RuntimeError("missing fixed Web URL")

    def get(self, path: str) -> tuple[HTTPStatus, dict[str, Any]]:
        if path not in {"/health", "/v1/routes"}:
            raise RequestError(HTTPStatus.NOT_FOUND, "unknown endpoint")
        return self._forward("GET", path, None)

    def post(self, path: str, handler: Any) -> tuple[HTTPStatus, dict[str, Any]]:
        parts = path.split("/")
        if len(parts) != 5 or parts[:3] != ["", "v1", "proxy"]:
            raise RequestError(HTTPStatus.NOT_FOUND, "unknown endpoint")
        route, operation = parts[3:]
        if route not in ROUTES or operation not in OPERATIONS:
            raise RequestError(HTTPStatus.NOT_FOUND, "unknown route or operation")
        if operation in {"probe", "config"}:
            assert_empty_body(handler)
            body = None
        elif operation == "token":
            parse_json_body(handler, set())
            body = b"{}"
        else:
            payload = parse_json_body(handler, {"credential"})
            if not isinstance(payload["credential"], str):
                raise RequestError(HTTPStatus.BAD_REQUEST, "credential must be a string")
            body = json.dumps(payload).encode("utf-8")
        return self._forward("POST", path, body)

    def _forward(
        self, method: str, path: str, body: bytes | None
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request = Request(
            f"{self.web_base_url}{path}",
            data=body,
            method=method,
            headers={"Content-Type": "application/json"} if body is not None else {},
        )
        try:
            with urlopen(request, timeout=3) as response:
                status = HTTPStatus(response.status)
                payload = json.loads(response.read())
        except HTTPError as error:
            status = HTTPStatus(error.code)
            payload = json.loads(error.read())
        except (URLError, TimeoutError) as error:
            raise RequestError(HTTPStatus.BAD_GATEWAY, "Web service unavailable") from error
        if not isinstance(payload, dict):
            raise RuntimeError("Web service response is invalid")
        return status, payload
