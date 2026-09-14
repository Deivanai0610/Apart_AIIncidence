from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

import httpx

from chimera.config import APPROVED_WEB_BASE_URL
from chimera.schemas import Route


class RangeOperation(str, Enum):
    ROUTES = "routes"
    PROBE = "probe"
    CONFIG = "config"
    TOKEN = "token"
    SAFE_DATA = "safe-data"
    PROTECTED_DATA = "protected-data"


@dataclass(frozen=True)
class RangeResponse:
    status_code: int
    payload: dict[str, object]


class RangeTransport(Protocol):
    async def request(
        self,
        route: Route | None,
        operation: RangeOperation,
        body: dict[str, str] | None,
    ) -> RangeResponse: ...


_ROUTE_OPERATIONS = frozenset(
    {
        RangeOperation.PROBE,
        RangeOperation.CONFIG,
        RangeOperation.TOKEN,
        RangeOperation.SAFE_DATA,
        RangeOperation.PROTECTED_DATA,
    }
)


class HttpRangeClient:
    def __init__(
        self,
        web_base_url: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if web_base_url != APPROVED_WEB_BASE_URL:
            raise ValueError("web_base_url must be the approved local range URL")
        self._client = httpx.AsyncClient(
            base_url=web_base_url,
            timeout=httpx.Timeout(connect=3.0, read=3.0, write=3.0, pool=3.0),
            trust_env=False,
            headers={"Connection": "close"},
            transport=transport,
        )

    async def request(
        self,
        route: Route | None,
        operation: RangeOperation,
        body: dict[str, str] | None,
    ) -> RangeResponse:
        if not isinstance(operation, RangeOperation):
            raise TypeError("operation must be a RangeOperation")
        if operation is RangeOperation.ROUTES:
            if route is not None or body is not None:
                raise ValueError("routes accepts no route or request body")
            response = await self._client.get("/v1/routes")
        else:
            if not isinstance(route, Route):
                raise TypeError("route must be a Route")
            if operation not in _ROUTE_OPERATIONS:
                raise ValueError("unsupported range operation")
            if operation is RangeOperation.TOKEN:
                if body != {}:
                    raise ValueError("token requires an empty JSON object")
            elif operation in {RangeOperation.PROBE, RangeOperation.CONFIG}:
                if body is not None:
                    raise ValueError("probe and config do not accept a request body")
            elif (
                not isinstance(body, dict)
                or set(body) != {"credential"}
                or not isinstance(body["credential"], str)
            ):
                raise ValueError("data operations require only a credential")
            response = await self._client.post(
                f"/v1/proxy/{route.value}/{operation.value}", json=body
            )
        try:
            payload = response.json()
        except ValueError as error:
            raise RuntimeError("range response is not JSON") from error
        if not isinstance(payload, dict):
            raise RuntimeError("range response must be a JSON object")
        return RangeResponse(status_code=response.status_code, payload=payload)

    async def aclose(self) -> None:
        await self._client.aclose()
