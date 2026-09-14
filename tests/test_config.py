import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chimera.config import ExperimentConfig, RangeConfig, config_digest, load_config


@pytest.fixture
def config() -> ExperimentConfig:
    return load_config(Path("configs/experiment.yaml"))


def _openrouter_payload(config: ExperimentConfig) -> dict[str, object]:
    payload = config.model_dump(mode="json")
    attacker = dict(payload["models"]["attacker"])
    defender = dict(payload["models"]["defender"])
    attacker.update(
        {
            "model_env": "OPENROUTER_ATTACKER_MODEL",
            "pinned_provider_slug": None,
            "expected_provider_name": None,
            "expected_endpoint_model": None,
        }
    )
    defender = {
        "provider": "openrouter",
        "model_env": "OPENROUTER_DEFENDER_MODEL",
        "api_key_env": "OPENROUTER_API_KEY",
        "max_calls": defender["max_calls"],
        "max_output_tokens": defender["max_output_tokens"],
        "pinned_provider_slug": None,
        "expected_provider_name": None,
        "expected_endpoint_model": None,
        "allow_fallbacks": False,
        "require_parameters": True,
        "provider_sort": "price",
        "reasoning_effort": "low",
    }
    payload["models"] = {"attacker": attacker, "defender": defender}
    payload["budgets"] = {
        "openrouter": {
            "project_ceiling_usd": 20.0,
            "authorization_ceiling_usd": 0.25,
            "attacker": {
                "ceiling_usd": 0.20,
                "input_per_million_usd": None,
                "output_per_million_usd": None,
            },
            "defender": {
                "ceiling_usd": 0.05,
                "input_per_million_usd": None,
                "output_per_million_usd": None,
            },
        }
    }
    return payload


def _complete_openrouter_candidate(config: ExperimentConfig) -> ExperimentConfig:
    payload = _openrouter_payload(config)
    routes = {
        "attacker": ("reka/fp8", "Reka", "z-ai/glm-5.3-20260816"),
        "defender": (
            "google-ai-studio/flex",
            "Google AI Studio",
            "google/gemini-3.7-flash-20260813",
        ),
    }
    rates = {
        "attacker": (0.936, 3.168),
        "defender": (0.375, 1.875),
    }
    for role in ("attacker", "defender"):
        slug, provider, endpoint_model = routes[role]
        payload["models"][role].update(
            {
                "pinned_provider_slug": slug,
                "expected_provider_name": provider,
                "expected_endpoint_model": endpoint_model,
            }
        )
        input_rate, output_rate = rates[role]
        payload["budgets"]["openrouter"][role].update(
            {
                "input_per_million_usd": input_rate,
                "output_per_million_usd": output_rate,
            }
        )
    return ExperimentConfig.model_validate(payload)


def test_config_has_forty_balanced_attack_episodes(config: ExperimentConfig) -> None:
    # Three pre-registered blocks plus the one further complete block the
    # protocol allows (section 5), added on 14 September 2026.
    assert config.schedule.blocks == 4
    assert config.schedule.conditions == ["A", "B", "C", "D", "E"]
    assert config.schedule.instructions == ["U", "W"]
    assert config.schedule.attack_episode_count == 40


@pytest.mark.parametrize("blocks", [3, 4])
def test_schedule_accepts_three_or_four_complete_blocks(
    config: ExperimentConfig, blocks: int
) -> None:
    payload = config.model_dump(mode="json")
    payload["schedule"]["blocks"] = blocks

    assert ExperimentConfig.model_validate(payload).schedule.blocks == blocks


@pytest.mark.parametrize("blocks", [1, 2, 5, 6])
def test_schedule_rejects_other_block_counts(config: ExperimentConfig, blocks: int) -> None:
    payload = config.model_dump(mode="json")
    payload["schedule"]["blocks"] = blocks

    with pytest.raises(ValidationError, match="three or four blocks"):
        ExperimentConfig.model_validate(payload)


def test_candidate_config_is_not_valid_for_measured_runs(
    config: ExperimentConfig,
) -> None:
    candidate = config.model_copy(update={"status": "candidate"})
    assert candidate.status == "candidate"
    with pytest.raises(ValueError, match="frozen"):
        candidate.validate_for_measured_run()


def test_checked_in_config_is_frozen_after_pilots(config: ExperimentConfig) -> None:
    assert config.status == "frozen"
    config.validate_frozen_provider_controls()


def test_candidate_config_declares_verified_fail_closed_provider_controls(
    config: ExperimentConfig,
) -> None:
    attacker = config.models.attacker
    defender = config.models.defender

    assert attacker.pinned_provider_slug == "reka/fp8"
    assert attacker.expected_provider_name == "Reka"
    assert attacker.expected_endpoint_model == "z-ai/glm-5.3-20260816"
    assert attacker.allow_fallbacks is False
    assert attacker.require_parameters is True
    assert attacker.provider_sort == "price"
    assert attacker.reasoning_effort == "low"
    assert defender.pinned_provider_slug == "google-ai-studio/flex"
    assert defender.expected_provider_name == "Google AI Studio"
    assert (
        defender.expected_endpoint_model
        == "google/gemini-3.7-flash-20260813"
    )
    assert defender.allow_fallbacks is False
    assert defender.require_parameters is True
    assert defender.provider_sort == "price"
    assert defender.reasoning_effort == "low"


def test_candidate_config_declares_verified_role_rates_and_shared_ceilings(
    config: ExperimentConfig,
) -> None:
    budget = config.budgets.openrouter

    assert budget.project_ceiling_usd == 20.0
    assert budget.authorization_ceiling_usd == 3.00
    assert budget.attacker.ceiling_usd == 0.20
    assert budget.attacker.input_per_million_usd == 0.936
    assert budget.attacker.output_per_million_usd == 3.168
    assert budget.defender.ceiling_usd == 0.05
    assert budget.defender.input_per_million_usd == 0.375
    assert budget.defender.output_per_million_usd == 1.875


def test_both_model_roles_use_one_key_and_distinct_model_environments(
    config: ExperimentConfig,
) -> None:
    assert config.models.attacker.api_key_env == "OPENROUTER_API_KEY"
    assert config.models.defender.api_key_env == "OPENROUTER_API_KEY"
    assert config.models.attacker.model_env == "OPENROUTER_ATTACKER_MODEL"
    assert config.models.defender.model_env == "OPENROUTER_DEFENDER_MODEL"


def test_openrouter_authorization_cannot_exceed_project_ceiling(
    config: ExperimentConfig,
) -> None:
    payload = _openrouter_payload(config)
    payload["budgets"]["openrouter"]["authorization_ceiling_usd"] = 21.0

    with pytest.raises(ValidationError, match="authorization ceiling"):
        ExperimentConfig.model_validate(payload)


def test_role_ceilings_cannot_exceed_authorization(
    config: ExperimentConfig,
) -> None:
    payload = _openrouter_payload(config)
    payload["budgets"]["openrouter"]["attacker"]["ceiling_usd"] = 0.24
    payload["budgets"]["openrouter"]["defender"]["ceiling_usd"] = 0.02

    with pytest.raises(ValidationError, match="role ceilings"):
        ExperimentConfig.model_validate(payload)


def test_complete_candidate_is_valid_for_pilot(
    config: ExperimentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _complete_openrouter_candidate(config)
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "z-ai/glm-5.3")
    monkeypatch.setenv(
        "OPENROUTER_DEFENDER_MODEL", "google/gemini-3.7-flash"
    )

    candidate.validate_for_pilot_run()


def test_live_config_rejects_unverified_or_placeholder_routing_values(
    config: ExperimentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = config.model_dump(mode="json")
    payload["status"] = "frozen"
    for role in ("attacker", "defender"):
        payload["models"][role].update(
            {
                "pinned_provider_slug": None,
                "expected_provider_name": None,
                "expected_endpoint_model": None,
            }
        )
        payload["budgets"]["openrouter"][role]["input_per_million_usd"] = 1.0
        payload["budgets"]["openrouter"][role]["output_per_million_usd"] = 1.0
    frozen = ExperimentConfig.model_validate(payload)
    monkeypatch.setenv("OPENROUTER_ATTACKER_MODEL", "exact-attacker-model")
    monkeypatch.setenv("OPENROUTER_DEFENDER_MODEL", "exact-defender-model")

    with pytest.raises(ValueError, match="routing"):
        frozen.validate_for_measured_run()

    payload["models"]["attacker"].update(
        {
            "pinned_provider_slug": "placeholder",
            "expected_provider_name": "verified provider",
            "expected_endpoint_model": "provider/model-v1",
        }
    )
    placeholder = ExperimentConfig.model_validate(payload)
    with pytest.raises(ValueError, match="routing"):
        placeholder.validate_for_measured_run()


@pytest.mark.parametrize(
    ("role", "field", "value"),
    [
        ("attacker", "allow_fallbacks", True),
        ("attacker", "require_parameters", False),
        ("attacker", "provider_sort", "throughput"),
        ("attacker", "reasoning_effort", "high"),
        ("defender", "allow_fallbacks", True),
        ("defender", "require_parameters", False),
        ("defender", "provider_sort", "throughput"),
        ("defender", "reasoning_effort", "high"),
    ],
)
def test_provider_control_configuration_rejects_drift(
    config: ExperimentConfig, role: str, field: str, value: object
) -> None:
    payload = config.model_dump(mode="json")
    payload["models"][role][field] = value

    with pytest.raises(ValidationError):
        ExperimentConfig.model_validate(payload)


def test_config_digest_is_stable_and_does_not_require_environment_values(
    config: ExperimentConfig,
) -> None:
    assert config_digest(config) == config_digest(config)
    assert len(config_digest(config)) == 64


@pytest.mark.parametrize(
    "web_base_url",
    [
        "https://example.com:443",
        "http://localhost:18080",
        "http://127.0.0.1:18081",
    ],
)
def test_range_config_rejects_endpoints_outside_approved_local_range(
    web_base_url: str,
) -> None:
    with pytest.raises(ValidationError, match="approved local range URL"):
        RangeConfig(
            web_base_url=web_base_url,
            compose_file="range/compose.yaml",
        )


def test_model_config_rejects_plaintext_api_key_as_environment_name(
    config: ExperimentConfig,
) -> None:
    sentinel = "sk-live-plaintext-sentinel"
    payload = config.model_dump(mode="json")
    payload["models"]["attacker"]["api_key_env"] = sentinel

    with pytest.raises(ValidationError, match="api_key_env"):
        ExperimentConfig.model_validate(payload)
    assert sentinel not in json.dumps(config.model_dump(mode="json"))


@pytest.mark.parametrize(
    ("role", "value"),
    [
        ("attacker", "PLAINTEXTCREDENTIAL123"),
        ("attacker", "sk-live-plaintext-sentinel"),
        ("attacker", "ANTHROPIC_API_KEY"),
        ("defender", "ANTHROPIC_API_KEY"),
    ],
)
def test_model_config_requires_the_provider_api_key_environment_name(
    config: ExperimentConfig, role: str, value: str
) -> None:
    payload = config.model_dump(mode="json")
    payload["models"][role]["api_key_env"] = value

    with pytest.raises(ValidationError, match="api_key_env"):
        ExperimentConfig.model_validate(payload)


@pytest.mark.parametrize(
    ("role", "value"),
    [
        ("attacker", "PLAINTEXTMODEL123"),
        ("attacker", "OPENROUTER_DEFENDER_MODEL"),
        ("defender", "OPENROUTER_ATTACKER_MODEL"),
    ],
)
def test_model_config_requires_the_provider_model_environment_name(
    config: ExperimentConfig, role: str, value: str
) -> None:
    payload = config.model_dump(mode="json")
    payload["models"][role]["model_env"] = value

    with pytest.raises(ValidationError, match="model_env"):
        ExperimentConfig.model_validate(payload)
