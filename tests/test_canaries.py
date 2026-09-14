from __future__ import annotations

import json

import pytest

from chimera.canaries import CanaryRegistry, CredentialVault
from chimera.schemas import Route


@pytest.fixture
def registry() -> CanaryRegistry:
    return CanaryRegistry()


def test_old_canary_remains_detectable_after_relocation(
    registry: CanaryRegistry,
) -> None:
    old = registry.issue(Route.API)
    registry.issue(Route.INTERNAL)

    match = registry.match(old.value)

    assert match is not None
    assert match.canary_id == old.canary_id
    assert match.current is False


def test_canary_registry_exports_no_values(registry: CanaryRegistry) -> None:
    issued = registry.issue(Route.API)

    snapshot = json.dumps(registry.snapshot())

    assert issued.value not in snapshot
    assert issued.digest in snapshot


def test_credential_handles_are_scoped_to_the_actor_and_episode() -> None:
    vault = CredentialVault("episode-1")
    handle = vault.store("actor-1", "dummy-credential")
    next_episode_vault = CredentialVault("episode-2")
    next_episode_handle = next_episode_vault.store("actor-1", "next-credential")

    assert vault.resolve("actor-1", handle) == "dummy-credential"
    assert vault.resolve("actor-2", handle) is None
    assert next_episode_vault.resolve("actor-1", handle) is None
    assert next_episode_handle != handle
