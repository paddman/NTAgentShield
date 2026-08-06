from __future__ import annotations

from statistics import fmean
from typing import Any

from .models import RuleMatch

_SEVERITY_SCORE = {
    "informational": 15.0,
    "low": 35.0,
    "medium": 60.0,
    "high": 80.0,
    "critical": 95.0,
}


def risk_for_rule_match(match: RuleMatch, payloads: list[dict[str, Any]]) -> float:
    anomaly_scores = [
        float(payload.get("detection", {}).get("score", 0.0)) for payload in payloads
    ]
    criticalities = [float(payload.get("asset_criticality", 3)) * 20.0 for payload in payloads]
    sensor_confidences = [float(payload.get("sensor_confidence", 0.8)) * 100.0 for payload in payloads]
    severity = _SEVERITY_SCORE[match.severity]
    anomaly = max(anomaly_scores, default=0.0)
    criticality = max(criticalities, default=60.0)
    sensor = fmean(sensor_confidences) if sensor_confidences else 80.0
    risk = (
        0.48 * severity
        + 0.25 * anomaly
        + 0.17 * criticality
        + 0.10 * sensor
        + max(0.0, match.confidence - 0.8) * 10.0
    )
    return round(min(100.0, risk), 2)


def risk_for_anomaly(
    anomaly_score: float, *, asset_criticality: int, sensor_confidence: float
) -> float:
    risk = (
        0.65 * anomaly_score
        + 0.25 * (asset_criticality * 20.0)
        + 0.10 * (sensor_confidence * 100.0)
    )
    return round(min(100.0, risk), 2)


def severity_for_risk(risk_score: float) -> str:
    if risk_score >= 90:
        return "critical"
    if risk_score >= 75:
        return "high"
    if risk_score >= 50:
        return "medium"
    if risk_score >= 25:
        return "low"
    return "informational"
