from __future__ import annotations

from ntshield.engine.sequence import SequenceMatch
from ntshield.models import SecurityEvent


def severity_for_score(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def score_match(match: SequenceMatch, events: list[SecurityEvent]) -> float:
    asset_criticality = max((event.asset.criticality for event in events), default=3)
    event_diversity = len({event.event_type for event in events})
    source_diversity = len({event.source_type for event in events})
    anomaly_component = min(15.0, match.max_anomaly_score * 0.15)
    criticality_component = max(0.0, (asset_criticality - 1) * 2.5)
    diversity_component = min(8.0, event_diversity * 1.5 + source_diversity)
    return round(
        min(
            100.0,
            match.rule.base_score
            + anomaly_component
            + criticality_component
            + diversity_component,
        ),
        2,
    )
