from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import PositiveFloat, PositiveInt, field_validator, model_validator

from chimera.schemas import ActionKind, Route, StrictModel

APPROVED_WEB_BASE_URL = "http://127.0.0.1:18080"
_ENVIRONMENT_NAME = r"[A-Z_][A-Z0-9_]{0,127}"
_OPENROUTER_API_KEY_ENV = "OPENROUTER_API_KEY"
_ROLE_MODEL_ENVS = {
    "attacker": "OPENROUTER_ATTACKER_MODEL",
    "defender": "OPENROUTER_DEFENDER_MODEL",
}


class RangeConfig(StrictModel):
    web_base_url: str
    compose_file: str

    @field_validator("web_base_url")
    @classmethod
    def validate_web_base_url(cls, value: str) -> str:
        if value != APPROVED_WEB_BASE_URL:
            raise ValueError("web_base_url must be the approved local range URL")
        return value


class ScheduleConfig(StrictModel):
    seed: int
    blocks: PositiveInt
    conditions: list[Literal["A", "B", "C", "D", "E"]]
    instructions: list[Literal["U", "W"]]

    @field_validator("seed")
    @classmethod
    def validate_seed(cls, value: int) -> int:
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise ValueError("schedule seed must be between zero and 2^63 - 1")
        return value

    @model_validator(mode="after")
    def validate_complete_block_shape(self) -> ScheduleConfig:
        # Three balanced blocks are the pre-registered sample; the protocol
        # allows one further complete block (40 episodes), never a partial one.
        if not 3 <= self.blocks <= 4:
            raise ValueError("schedule must contain three or four blocks")
        if self.conditions != ["A", "B", "C", "D", "E"]:
            raise ValueError("schedule conditions must be A through E")
        if self.instructions != ["U", "W"]:
            raise ValueError("schedule instructions must be U and W")
        return self

    @property
    def attack_episode_count(self) -> int:
        return self.blocks * len(self.conditions) * len(self.instructions)


class StaticPolicyConfig(StrictModel):
    initial_canary_route: Route
    tie_break_route: Route
    first_route_pattern: list[ActionKind]
    alternate_route_pattern: list[ActionKind]


class RoleLimitsConfig(StrictModel):
    attacker_max_in_flight: PositiveInt
    defender_max_in_flight: PositiveInt


class ModelRoleConfig(StrictModel):
    provider: Literal["openrouter"]
    model_env: str
    api_key_env: str
    max_calls: PositiveInt
    max_output_tokens: PositiveInt

    @field_validator("api_key_env", "model_env")
    @classmethod
    def validate_environment_name(cls, value: str) -> str:
        if not re.fullmatch(_ENVIRONMENT_NAME, value):
            raise ValueError("provider environment names must be variable names")
        return value


class OpenRouterModelConfig(ModelRoleConfig):
    provider: Literal["openrouter"]
    pinned_provider_slug: str | None
    expected_provider_name: str | None
    expected_endpoint_model: str | None
    allow_fallbacks: Literal[False]
    require_parameters: Literal[True]
    provider_sort: Literal["price"]
    reasoning_effort: Literal["low"]


class ModelsConfig(StrictModel):
    attacker: OpenRouterModelConfig
    defender: OpenRouterModelConfig

    @model_validator(mode="after")
    def validate_role_environment_names(self) -> ModelsConfig:
        for role, model in (
            ("attacker", self.attacker),
            ("defender", self.defender),
        ):
            if model.api_key_env != _OPENROUTER_API_KEY_ENV:
                raise ValueError(
                    f"{role} api_key_env must be {_OPENROUTER_API_KEY_ENV}"
                )
            expected_model_env = _ROLE_MODEL_ENVS[role]
            if model.model_env != expected_model_env:
                raise ValueError(
                    f"{role} model_env must be {expected_model_env}"
                )
        return self


class RoleBudget(StrictModel):
    ceiling_usd: PositiveFloat
    input_per_million_usd: PositiveFloat | None
    output_per_million_usd: PositiveFloat | None


class OpenRouterAccountBudget(StrictModel):
    project_ceiling_usd: PositiveFloat
    authorization_ceiling_usd: PositiveFloat
    attacker: RoleBudget
    defender: RoleBudget

    @model_validator(mode="after")
    def validate_nested_ceilings(self) -> OpenRouterAccountBudget:
        if self.authorization_ceiling_usd > self.project_ceiling_usd:
            raise ValueError("authorization ceiling cannot exceed project ceiling")
        if (
            self.attacker.ceiling_usd + self.defender.ceiling_usd
            > self.authorization_ceiling_usd
        ):
            raise ValueError("role ceilings cannot exceed authorization ceiling")
        return self


class BudgetConfig(StrictModel):
    openrouter: OpenRouterAccountBudget


class ExperimentConfig(StrictModel):
    status: Literal["candidate", "frozen"]
    horizon_seconds: PositiveInt
    range: RangeConfig
    schedule: ScheduleConfig
    static_policy: StaticPolicyConfig
    role_limits: RoleLimitsConfig
    models: ModelsConfig
    budgets: BudgetConfig

    def validate_frozen_provider_controls(self) -> None:
        for role in (self.models.attacker, self.models.defender):
            routing_values = (
                role.pinned_provider_slug,
                role.expected_provider_name,
                role.expected_endpoint_model,
            )
            if not all(
                _is_verified_provider_value(value) for value in routing_values
            ):
                raise ValueError(
                    "OpenRouter routing values must be pilot verified"
                )

    def _validate_complete_provider_controls(self) -> None:
        self.validate_frozen_provider_controls()
        for role in (self.models.attacker, self.models.defender):
            model_id = os.environ.get(role.model_env, "").strip()
            if not model_id:
                raise ValueError(f"missing model ID in {role.model_env}")
        for role_name, budget in (
            ("attacker", self.budgets.openrouter.attacker),
            ("defender", self.budgets.openrouter.defender),
        ):
            if budget.ceiling_usd <= 0:
                raise ValueError(f"{role_name} ceiling must be positive")
            if (
                budget.input_per_million_usd is None
                or budget.output_per_million_usd is None
            ):
                raise ValueError(
                    f"{role_name} pricing rates are required for a live run"
                )

    def validate_for_pilot_run(self) -> None:
        self._validate_complete_provider_controls()

    def validate_for_measured_run(self) -> None:
        if self.status != "frozen":
            raise ValueError("configuration must be frozen before a measured run")
        self._validate_complete_provider_controls()


def load_config(path: Path) -> ExperimentConfig:
    contents = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(contents, dict):
        raise ValueError("experiment configuration must be a YAML mapping")
    return ExperimentConfig.model_validate(contents)


def config_digest(config: ExperimentConfig) -> str:
    serialized = json.dumps(
        config.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _is_verified_provider_value(value: str | None) -> bool:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        return False
    normalized = value.strip().lower()
    return normalized not in {
        "unknown",
        "unverified",
        "placeholder",
        "tbd",
        "todo",
        "none",
        "null",
    }
