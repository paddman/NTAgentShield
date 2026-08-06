from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SecurityEvent(BaseModel):
    """Canonical event used by the hunting engine.

    The shape is intentionally OCSF-inspired while remaining small enough for an MVP.
    Source adapters should preserve the original record in ``raw`` or ``data``.
    """

    model_config = ConfigDict(extra="allow")

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str = Field(min_length=1, max_length=128)
    asset_id: str = Field(min_length=1, max_length=256)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: str = Field(min_length=1, max_length=128)
    source: str = Field(default="unknown", max_length=128)
    activity_id: int | None = None
    class_uid: int | None = None
    category_uid: int | None = None
    severity_id: int | None = Field(default=None, ge=0, le=10)
    sensor_confidence: float = Field(default=0.8, ge=0, le=1)
    asset_criticality: int = Field(default=3, ge=1, le=5)

    actor: dict[str, Any] = Field(default_factory=dict)
    host: dict[str, Any] = Field(default_factory=dict)
    process: dict[str, Any] = Field(default_factory=dict)
    parent_process: dict[str, Any] = Field(default_factory=dict)
    network: dict[str, Any] = Field(default_factory=dict)
    file: dict[str, Any] = Field(default_factory=dict)
    http: dict[str, Any] = Field(default_factory=dict)
    database: dict[str, Any] = Field(default_factory=dict)
    auth: dict[str, Any] = Field(default_factory=dict)
    service: dict[str, Any] = Field(default_factory=dict)
    registry: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    raw: str | None = None

    @field_validator("observed_at")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class AnomalyReason(BaseModel):
    feature: str
    value: str
    novelty: float = Field(ge=0, le=1)
    weight: float = Field(ge=0, le=1)
    prior_count: int = Field(ge=0)
    prior_total: int = Field(ge=0)
    explanation: str


class AnomalyResult(BaseModel):
    score: float = Field(ge=0, le=100)
    reasons: list[AnomalyReason] = Field(default_factory=list)
    baseline_mature: bool = False


class RuleMatch(BaseModel):
    rule_id: str
    title: str
    description: str = ""
    severity: Literal["informational", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    event_ids: list[str]
    step_names: list[str]
    tags: list[str] = Field(default_factory=list)
    fingerprint: str


class Incident(BaseModel):
    incident_id: str
    tenant_id: str
    asset_id: str
    title: str
    rule_id: str | None = None
    severity: Literal["informational", "low", "medium", "high", "critical"]
    risk_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    status: Literal["open", "investigating", "contained", "resolved"] = "open"
    created_at: datetime
    updated_at: datetime
    event_ids: list[str]
    anomaly_reasons: list[dict[str, Any]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    fingerprint: str
    analysis: dict[str, Any] | None = None


class HuntAnalysis(BaseModel):
    verdict: Literal["malicious", "suspicious", "benign", "insufficient_evidence"]
    confidence: float = Field(ge=0, le=1)
    summary_th: str
    behavior_chain: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_queries: list[dict[str, Any]] = Field(default_factory=list)
    recommended_actions: list[dict[str, Any]] = Field(default_factory=list)
    model: str | None = None
    tool_rounds: int = 0
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IngestResult(BaseModel):
    event_id: str
    anomaly: AnomalyResult
    incidents: list[Incident] = Field(default_factory=list)


class ActionRequest(BaseModel):
    incident_id: str
    action: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ActionDecision(BaseModel):
    action: str
    decision: Literal["allowed", "approval_required", "denied"]
    reason: str
    risk_score: float
