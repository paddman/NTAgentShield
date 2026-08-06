from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class AssetContext(BaseModel):
    id: str
    hostname: str | None = None
    ip: str | None = None
    os: str | None = None
    role: str | None = None
    criticality: int = Field(default=3, ge=1, le=5)


class ActorContext(BaseModel):
    user: str | None = None
    domain: str | None = None
    session_id: str | None = None
    integrity: str | None = None
    logon_type: str | None = None
    is_service_account: bool | None = None


class ProcessContext(BaseModel):
    name: str | None = None
    path: str | None = None
    pid: int | None = None
    parent_name: str | None = None
    parent_path: str | None = None
    parent_pid: int | None = None
    command_line: str | None = None
    sha256: str | None = None
    signer: str | None = None
    signed: bool | None = None


class NetworkContext(BaseModel):
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    direction: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    domain: str | None = None
    is_external: bool | None = None


class FileContext(BaseModel):
    path: str | None = None
    operation: str | None = None
    sha256: str | None = None
    extension: str | None = None
    count: int | None = None
    entropy: float | None = None


class ServiceContext(BaseModel):
    name: str | None = None
    binary_path: str | None = None
    start_type: str | None = None
    action: str | None = None


class RegistryContext(BaseModel):
    path: str | None = None
    value_name: str | None = None
    value_data: str | None = None
    operation: str | None = None


class WebContext(BaseModel):
    method: str | None = None
    path: str | None = None
    status: int | None = None
    user_agent: str | None = None
    request_id: str | None = None
    payload_novelty: float | None = Field(default=None, ge=0, le=1)
    route: str | None = None


class DatabaseContext(BaseModel):
    engine: str | None = None
    database: str | None = None
    statement: str | None = None
    query_shape: str | None = None
    rows: int | None = None
    sensitivity: str | None = None
    duration_ms: float | None = None


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    observed_at: datetime = Field(default_factory=utc_now)
    source_type: str
    event_type: str
    asset: AssetContext
    actor: ActorContext = Field(default_factory=ActorContext)
    process: ProcessContext = Field(default_factory=ProcessContext)
    network: NetworkContext = Field(default_factory=NetworkContext)
    file: FileContext = Field(default_factory=FileContext)
    service: ServiceContext = Field(default_factory=ServiceContext)
    registry: RegistryContext = Field(default_factory=RegistryContext)
    web: WebContext = Field(default_factory=WebContext)
    database: DatabaseContext = Field(default_factory=DatabaseContext)
    action: str | None = None
    outcome: str | None = None
    message: str | None = None
    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def ensure_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class RawEventEnvelope(BaseModel):
    tenant_id: str
    asset_id: str
    source_type: str
    data: dict[str, Any]
    observed_at: datetime | None = None
    asset_role: str | None = None
    asset_criticality: int = Field(default=3, ge=1, le=5)


class MitreMapping(BaseModel):
    tactic: str
    technique_id: str
    technique: str


class EvidenceRef(BaseModel):
    event_id: str
    observed_at: datetime
    event_type: str
    summary: str


class BehaviorFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    rule_id: str
    title: str
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    risk_score: float = Field(ge=0, le=100)
    anomaly_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    created_at: datetime = Field(default_factory=utc_now)
    first_seen: datetime
    last_seen: datetime
    asset_id: str
    entities: list[str] = Field(default_factory=list)
    mitre: list[MitreMapping] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    status: Literal["open", "investigating", "closed"] = "open"


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    risk_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    first_seen: datetime
    last_seen: datetime
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    status: Literal["open", "investigating", "contained", "closed"] = "open"
    asset_ids: list[str] = Field(default_factory=list)
    entities: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    mitre: list[MitreMapping] = Field(default_factory=list)
    analyst_report: dict[str, Any] | None = None


class BaselineObservation(BaseModel):
    score: float = Field(ge=0, le=100)
    cold_start: bool
    rare_features: list[str] = Field(default_factory=list)
    feature_scores: dict[str, float] = Field(default_factory=dict)


class IngestResult(BaseModel):
    event_id: str
    anomaly: BaselineObservation
    findings: list[BehaviorFinding] = Field(default_factory=list)
    incidents: list[Incident] = Field(default_factory=list)
