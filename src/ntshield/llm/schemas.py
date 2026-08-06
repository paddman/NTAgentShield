from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AnalystEvidence(BaseModel):
    event_id: str
    observation: str


class AttackStage(BaseModel):
    stage: str
    technique_id: str | None = None
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    action: str
    purpose: str
    risk: Literal["low", "medium", "high"]
    requires_approval: bool = True


class ZeroDayHypothesis(BaseModel):
    plausible: bool
    confidence: float = Field(ge=0, le=1)
    rationale: str
    signature_gap: str


class AnalystReport(BaseModel):
    verdict: Literal["malicious", "suspicious", "benign", "inconclusive"]
    confidence: float = Field(ge=0, le=1)
    executive_summary: str
    technical_summary: str
    zero_day_hypothesis: ZeroDayHypothesis
    evidence: list[AnalystEvidence]
    attack_chain: list[AttackStage] = Field(default_factory=list)
    investigation_queries: list[str] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)
