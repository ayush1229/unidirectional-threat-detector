"""Agent 1 owned versioned contracts; no imports from other agents."""
from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue, model_validator


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False, validate_assignment=True)


class Measurement(Contract):
    value: JsonValue = None
    available: bool = False
    applicable: bool = True
    reason: str = "NOT_OBSERVED"

    @model_validator(mode="after")
    def consistent(self):
        if self.available != (self.value is not None):
            raise ValueError("value and availability disagree")
        if not self.applicable and self.available:
            raise ValueError("inapplicable value cannot be available")
        if not self.reason or (self.available and self.reason != "OBSERVED"):
            raise ValueError("measurement requires a consistent reason")
        if not self.available and self.reason == "OBSERVED":
            raise ValueError("missing measurement cannot be observed")
        return self


def measured(value: JsonValue, reason: str = "NOT_OBSERVED", *, applicable: bool = True) -> Measurement:
    return Measurement(value=value, available=value is not None, applicable=applicable,
                       reason="OBSERVED" if value is not None else reason)


class EntityKeys(Contract):
    flow_id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    destination: str = Field(min_length=1)


class Features(Contract):
    flow: dict[str, Measurement] = Field(default_factory=dict)
    window: dict[str, Measurement] = Field(default_factory=dict)
    dns: dict[str, Measurement] = Field(default_factory=dict)
    tls: dict[str, Measurement] = Field(default_factory=dict)


class Visibility(Contract):
    direction_reconstructable: bool = False
    dns_response_visible: bool = False
    nxdomain_ratio_available: bool = False
    tls_handshake_visible: bool = False
    ja4_available: bool = False
    ja4s_available: bool = False
    sni_available: bool = False
    flow_completion_visible: bool = False
    feature_availability_ratio: float = Field(default=0, ge=0, le=1)
    reason_codes: dict[str, str] = Field(default_factory=dict)


class History(Contract):
    event_count: int = Field(ge=0)
    duration_ms: float = Field(ge=0)
    window_complete: bool


class RouteHints(Contract):
    dns: bool = False
    tls: bool = False
    flow: bool = True


class ObservationEnvelope(Contract):
    schema_version: Literal["2.0.0"] = "2.0.0"
    event_id: str = Field(min_length=1)
    sensor_id: str = Field(min_length=1)
    event_time: AwareDatetime
    entity_keys: EntityKeys
    protocol: Literal["TCP", "UDP", "DNS", "TLS", "QUIC", "OTHER"]
    features: Features
    visibility: Visibility
    history: History
    route_hints: RouteHints
    feature_schema_version: Literal["2.0.0"] = "2.0.0"
    snapshot_kind: Literal["partial", "final"] = "partial"
    reason_codes: list[str] = Field(default_factory=list)


class SpecialistScore(Contract):
    schema_version: Literal["2.0.0"] = "2.0.0"
    event_id: str = Field(min_length=1)
    specialist: str = Field(min_length=1)
    probability: float | None = Field(default=None, ge=0, le=1)
    score_present: bool = False
    applicable: bool = True
    uncertainty: float | None = Field(default=None, ge=0, le=1)
    inference_ms: float = Field(default=0, ge=0)
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    reason_codes: list[str] = Field(min_length=1)
    model_version: str = Field(min_length=1)

    @model_validator(mode="after")
    def consistent(self):
        if self.score_present != (self.probability is not None):
            raise ValueError("missing scores must be null")
        if not self.applicable and self.score_present:
            raise ValueError("inapplicable specialist cannot score")
        if not self.score_present and self.uncertainty is not None:
            raise ValueError("unavailable score has unavailable uncertainty")
        return self


Family = Literal["BENIGN", "DDOS", "PORT_SCAN", "DGA", "DNS_TUNNEL", "C2", "BOTNET", "ENCRYPTED_MALWARE", "EXFILTRATION"]


class ScenarioRelease(Contract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    scenario_id: str = Field(min_length=1)
    generator: str = Field(min_length=1)
    family: Family
    seed: int = Field(ge=0)
    start: AwareDatetime
    end: AwareDatetime
    source: str
    destination: str
    software_versions: dict[str, str]
    attack_parameters: dict[str, JsonValue]
    expected_labels: list[str] = Field(min_length=1)
    split_assignment: Literal["train", "validation", "test"]
    split_group: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    hard_negative_tags: list[str] = Field(default_factory=list)
    feature_snapshots: list[dict[str, JsonValue]] = Field(default_factory=list)
    synthetic: bool = True

    @model_validator(mode="after")
    def ordered(self):
        if self.end < self.start:
            raise ValueError("end precedes start")
        return self
