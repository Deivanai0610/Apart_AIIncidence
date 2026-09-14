from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from chimera.schemas import Route


def value_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IssuedCanary:
    canary_id: str
    route: Route
    value: str
    digest: str


@dataclass(frozen=True)
class CanaryMatch:
    canary_id: str
    route: Route
    digest: str
    current: bool


@dataclass(frozen=True)
class _CanaryRecord:
    canary_id: str
    route: Route
    digest: str


class CanaryRegistry:
    def __init__(self) -> None:
        self._records: list[_CanaryRecord] = []
        self._current_id: str | None = None

    def issue(self, route: Route, *, value: str | None = None) -> IssuedCanary:
        if not isinstance(route, Route):
            raise TypeError("route must be a Route")
        if value is None:
            value = secrets.token_urlsafe(24)
        elif not isinstance(value, str) or not value:
            raise ValueError("canary value must be a non-empty string")
        canary_id = f"canary-{len(self._records) + 1:04d}"
        digest = value_digest(value)
        self._records.append(_CanaryRecord(canary_id, route, digest))
        self._current_id = canary_id
        return IssuedCanary(canary_id, route, value, digest)

    def match(self, value: str) -> CanaryMatch | None:
        digest = value_digest(value)
        for record in self._records:
            if secrets.compare_digest(record.digest, digest):
                return CanaryMatch(
                    canary_id=record.canary_id,
                    route=record.route,
                    digest=record.digest,
                    current=record.canary_id == self._current_id,
                )
        return None

    def snapshot(self) -> dict[str, object]:
        return {
            "current_canary_id": self._current_id,
            "canaries": [
                {
                    "canary_id": record.canary_id,
                    "route": record.route.value,
                    "digest": record.digest,
                    "current": record.canary_id == self._current_id,
                }
                for record in self._records
            ],
        }


@dataclass(frozen=True)
class _CredentialRecord:
    actor_id: str
    value: str
    route: Route | None


class CredentialVault:
    def __init__(self, episode_id: str) -> None:
        if not episode_id:
            raise ValueError("episode_id is required")
        self._episode_id = episode_id
        self._records: dict[str, _CredentialRecord] = {}

    @property
    def episode_id(self) -> str:
        return self._episode_id

    def store(self, actor_id: str, value: str, *, route: Route | None = None) -> str:
        if not actor_id:
            raise ValueError("actor_id is required")
        if not isinstance(value, str):
            raise TypeError("credential value must be a string")
        if route is not None and not isinstance(route, Route):
            raise TypeError("route must be a Route or None")
        episode_marker = value_digest(self._episode_id)[:12]
        handle = f"cred-{episode_marker}-{len(self._records) + 1:04d}"
        self._records[handle] = _CredentialRecord(
            actor_id=actor_id,
            value=value,
            route=route,
        )
        return handle

    def resolve(self, actor_id: str, handle: str) -> str | None:
        record = self._records.get(handle)
        if record is None or record.actor_id != actor_id:
            return None
        return record.value

    def route_for(self, actor_id: str, handle: str) -> Route | None:
        record = self._records.get(handle)
        if record is None or record.actor_id != actor_id:
            return None
        return record.route
