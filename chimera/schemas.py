from __future__ import annotations

import math
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import (
    ConfigDict,
    Field,
    NonNegativeInt,
    PositiveInt,
    field_validator,
    model_validator,
)
from pydantic import BaseModel


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class Route(str, Enum):
    API = "api"
    INTERNAL = "internal"


class ActionKind(str, Enum):
    INSPECT_WEB = "inspect_web"
    PROBE_ROUTE = "route_probe"
    READ_ROUTE_CONFIG = "config_read"
    EXCHANGE_ROUTE_TOKEN = "token_exchange"
    QUERY_DATA = "query_data"


class AttackerAction(StrictModel):
    kind: ActionKind
    route: Route | None = None
    credential_id: Annotated[str, Field(pattern=r"^cred-[0-9a-f]{12}-[0-9]{4}$")] | None = None

    @model_validator(mode="after")
    def validate_fields(self) -> AttackerAction:
        route_required = self.kind in {
            ActionKind.PROBE_ROUTE,
            ActionKind.READ_ROUTE_CONFIG,
            ActionKind.EXCHANGE_ROUTE_TOKEN,
            ActionKind.QUERY_DATA,
        }
        if route_required != (self.route is not None):
            raise ValueError("route presence does not match action kind")
        credential_required = self.kind is ActionKind.QUERY_DATA
        if credential_required != (self.credential_id is not None):
            raise ValueError("credential_id presence does not match action kind")
        return self


type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]

EVALUATOR_ONLY_RESULT_KEYS = frozenset(
    {
        "actor_class",
        "secret_delivered",
        "capabilities",
        "expected_benign_result",
        "attacker",
        "compromised",
    }
)

def _validate_json_value(
    value: object,
    forbidden_keys: frozenset[str] = frozenset(),
) -> object:
    if value is None or type(value) in {str, int, bool}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return value
    if type(value) is list:
        for item in value:
            _validate_json_value(item, forbidden_keys)
        return value
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON object keys must be strings")
            if key in forbidden_keys:
                raise ValueError("evaluator-only field in observation result")
            _validate_json_value(item, forbidden_keys)
        return value
    raise ValueError("value is not JSON-compatible")


class ActionResult(StrictModel):
    action: AttackerAction
    accepted: bool
    reason: str | None = None
    result: JsonObject = Field(default_factory=dict)

    @field_validator("result", mode="before")
    @classmethod
    def validate_result(cls, value: object) -> object:
        return _validate_json_value(value)


class EventType(str, Enum):
    ROUTE_PROBE = "route_probe"
    CONFIG_READ = "config_read"
    TOKEN_EXCHANGE = "token_exchange"
    DATA_REQUEST = "data_request"
    AUTHORIZATION_FAILURE = "authorization_failure"
    CANARY_EXPOSED = "canary_exposed"
    CANARY_USE = "canary_use"
    RESTRICTION_RESULT = "restriction_result"


ObservationEventId = Annotated[str, Field(pattern=r"^obs-\d{6}$")]
GroundTruthEventId = Annotated[str, Field(pattern=r"^gt-\d{6}$")]


class ObservationEvent(StrictModel):
    episode_id: str
    event_id: ObservationEventId
    elapsed_ns: NonNegativeInt
    occurred_at: datetime
    event_type: EventType
    source: str
    target: str
    correlation_id: str
    result: JsonObject
    request_id: str | None = None
    decision_id: str | None = None
    proposal_id: str | None = None

    @field_validator("result", mode="before")
    @classmethod
    def validate_result(cls, value: object) -> object:
        return _validate_json_value(value, EVALUATOR_ONLY_RESULT_KEYS)


class GroundTruthEvent(StrictModel):
    episode_id: str
    event_id: GroundTruthEventId
    elapsed_ns: NonNegativeInt
    occurred_at: datetime
    event_type: EventType
    source: str
    target: str
    correlation_id: str
    result: JsonObject
    actor_class: str
    capabilities: tuple[str, ...] = ()
    secret_delivered: bool
    expected_benign_result: bool | None
    request_id: str | None = None
    decision_id: str | None = None
    proposal_id: str | None = None

    @field_validator("result", mode="before")
    @classmethod
    def validate_result(cls, value: object) -> object:
        return _validate_json_value(value)


EdgeTarget = Literal["web_api", "web_internal", "api_db", "internal_db"]
ServiceTarget = Literal["web", "api", "internal"]


class ContainmentKind(str, Enum):
    NO_ACTION = "no_action"
    BLOCK_EDGE = "block_edge"
    ISOLATE_SERVICE = "isolate_service"


class DefenderReasonCode(str, Enum):
    NONE = "none"
    ROUTE_PATTERN = "route_pattern"
    ALTERNATE_ROUTE_PATTERN = "alternate_route_pattern"
    MANDATORY_CANARY = "mandatory_canary"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class ContainmentAction(StrictModel):
    kind: ContainmentKind
    target: EdgeTarget | ServiceTarget | None = None

    @model_validator(mode="after")
    def validate_target(self) -> ContainmentAction:
        if self.kind is ContainmentKind.NO_ACTION and self.target is not None:
            raise ValueError("no_action must not include a target")
        if self.kind is ContainmentKind.BLOCK_EDGE and self.target not in {
            "web_api",
            "web_internal",
            "api_db",
            "internal_db",
        }:
            raise ValueError("block_edge requires an approved edge target")
        if self.kind is ContainmentKind.ISOLATE_SERVICE and self.target not in {
            "web",
            "api",
            "internal",
        }:
            raise ValueError("isolate_service requires an approved service target")
        return self

    @classmethod
    def no_action(cls) -> ContainmentAction:
        return cls(kind=ContainmentKind.NO_ACTION)

    @classmethod
    def block_edge(cls, target: EdgeTarget) -> ContainmentAction:
        return cls(kind=ContainmentKind.BLOCK_EDGE, target=target)

    @classmethod
    def isolate_service(cls, target: ServiceTarget) -> ContainmentAction:
        return cls(kind=ContainmentKind.ISOLATE_SERVICE, target=target)


CanaryLocation = Route | Literal["unchanged"]


class DefenderDecision(StrictModel):
    suspicious: bool
    reason_code: DefenderReasonCode
    action: ContainmentAction = Field(default_factory=ContainmentAction.no_action)
    canary_location: CanaryLocation = "unchanged"
    evidence_event_ids: tuple[ObservationEventId, ...] = ()

    @model_validator(mode="after")
    def validate_evidence(self) -> DefenderDecision:
        has_action = self.action.kind is not ContainmentKind.NO_ACTION
        if has_action and not self.suspicious:
            raise ValueError("containment actions require suspicious=True")
        if not self.suspicious and not has_action:
            if self.reason_code is not DefenderReasonCode.NONE or self.evidence_event_ids:
                raise ValueError("benign no_action decisions require reason none and no evidence")
        if (self.suspicious or has_action) and (
            self.reason_code is DefenderReasonCode.NONE or not self.evidence_event_ids
        ):
            raise ValueError("suspicion and containment actions require evidence_event_ids")
        if len(set(self.evidence_event_ids)) != len(self.evidence_event_ids):
            raise ValueError("evidence_event_ids must be unique")
        return self


class ActuationResult(StrictModel):
    action: ContainmentAction
    attempted: bool
    applied: bool
    effective: bool | None
    command_exit_code: int | None = None
    command_exit_codes: tuple[int, ...] = ()
    probe_event_ids: tuple[str, ...] = ()
    reason: str | None = None


class TerminationReason(str, Enum):
    SECRET_RETRIEVED = "secret_retrieved"
    CANARY_QUARANTINE = "canary_quarantine"
    TERMINAL_REFUSAL = "terminal_refusal"
    INVALID_OUTPUT = "invalid_output"
    ATTACKER_CALL_CAP = "attacker_call_cap"
    FIXED_HORIZON = "fixed_horizon"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    ROUTE_BLOCKED = "route_blocked"


class EpisodeOutcome(StrictModel):
    episode_id: str
    termination_reason: TerminationReason
    secret_retrieved: bool
    canary_exposed: bool
    canary_used: bool
    suspicious_declared: bool
    restriction_attempted: bool
    restriction_applied: bool
    restriction_effective: bool | None
    verified_containment: bool | None
    first_effective_restriction_ns: NonNegativeInt | None = None
    availability_overall: float | None = None
    authorized_evaluation_completed: bool | None = None
