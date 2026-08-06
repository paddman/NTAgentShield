from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from ntshield.models import MitreMapping


class RuleStep(BaseModel):
    id: str
    description: str
    match: dict[str, Any]
    within_seconds: int | None = None
    bind: dict[str, str] = Field(default_factory=dict)
    where: dict[str, str] = Field(default_factory=dict)


class BehaviorRule(BaseModel):
    id: str
    title: str
    description: str
    enabled: bool = True
    family: str | None = None
    severity: str
    base_score: float = Field(ge=0, le=100)
    confidence: float = Field(default=0.8, ge=0, le=1)
    window_seconds: int = Field(default=600, gt=0)
    group_by: list[str] = Field(default_factory=lambda: ["tenant_id", "asset.id"])
    minimum_anomaly_score: float = Field(default=0, ge=0, le=100)
    mitre: list[MitreMapping] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    steps: list[RuleStep]

    @field_validator("steps")
    @classmethod
    def require_multiple_steps(cls, value: list[RuleStep]) -> list[RuleStep]:
        if len(value) < 2:
            raise ValueError("Behavioral rules must contain at least two ordered steps")
        return value


def load_rules(path: str | Path) -> list[BehaviorRule]:
    base = Path(path)
    rules: list[BehaviorRule] = []
    for file_path in sorted(base.glob("*.yaml")):
        payload = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        if not payload:
            continue
        rule = BehaviorRule.model_validate(payload)
        if rule.enabled:
            rules.append(rule)
    return rules
