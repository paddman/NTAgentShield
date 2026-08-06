from __future__ import annotations

from datetime import timedelta
from typing import Any

from .baseline import BehavioralBaseline
from .config import Settings
from .models import AnomalyResult, Incident, IngestResult, RuleMatch, SecurityEvent
from .rules import RuleEngine
from .scoring import risk_for_anomaly, risk_for_rule_match, severity_for_risk
from .store import SQLiteStore
from .utils import stable_hash


class HuntingPipeline:
    def __init__(
        self,
        settings: Settings,
        *,
        store: SQLiteStore | None = None,
        rule_engine: RuleEngine | None = None,
    ):
        self.settings = settings
        self.store = store or SQLiteStore(settings.db_path)
        self.rule_engine = rule_engine or RuleEngine.from_directory(settings.rules_dir)
        self.baseline = BehavioralBaseline(
            self.store, min_observations=settings.baseline_min_observations
        )

    def ingest(self, event: SecurityEvent) -> IngestResult:
        existing = self.store.get_event_payload(event.event_id)
        if existing is not None:
            if existing.get("tenant_id") != event.tenant_id:
                raise ValueError("event_id already belongs to another tenant")
            anomaly = AnomalyResult.model_validate(existing.get("detection", {}))
            incidents = [
                incident
                for incident in self.store.list_incidents(tenant_id=event.tenant_id, limit=500)
                if event.event_id in incident.event_ids
            ]
            return IngestResult(event_id=event.event_id, anomaly=anomaly, incidents=incidents)

        anomaly = self.baseline.score(event, learn=True)
        self.store.save_event(event, anomaly)

        since = event.observed_at - timedelta(seconds=self.rule_engine.max_window_seconds)
        recent_payloads = self.store.get_recent_event_payloads(
            event.tenant_id,
            event.asset_id,
            since,
            limit=5000,
        )
        rule_matches = self.rule_engine.evaluate(event, recent_payloads)
        incidents: list[Incident] = []

        for match in rule_matches:
            incident = self._incident_from_match(event, match)
            if incident is not None:
                incidents.append(incident)

        anomaly_incident = self._incident_from_standalone_anomaly(event, anomaly)
        if anomaly_incident is not None:
            incidents.append(anomaly_incident)

        unique = {incident.incident_id: incident for incident in incidents}
        return IngestResult(
            event_id=event.event_id,
            anomaly=anomaly,
            incidents=list(unique.values()),
        )

    def ingest_batch(self, events: list[SecurityEvent]) -> list[IngestResult]:
        return [self.ingest(event) for event in sorted(events, key=lambda item: item.observed_at)]

    def _incident_from_match(
        self, current_event: SecurityEvent, match: RuleMatch
    ) -> Incident | None:
        payloads = self.store.get_event_payloads(match.event_ids)
        risk = risk_for_rule_match(match, payloads)
        if risk < self.settings.incident_threshold and match.severity not in {"high", "critical"}:
            return None
        reasons = self._collect_anomaly_reasons(payloads)
        return self.store.create_or_update_incident(
            tenant_id=current_event.tenant_id,
            asset_id=current_event.asset_id,
            title=match.title,
            rule_id=match.rule_id,
            severity=match.severity,
            risk_score=risk,
            confidence=match.confidence,
            event_ids=match.event_ids,
            anomaly_reasons=reasons,
            tags=match.tags,
            fingerprint=match.fingerprint,
            observed_at=current_event.observed_at,
        )

    def _incident_from_standalone_anomaly(
        self, event: SecurityEvent, anomaly: AnomalyResult
    ) -> Incident | None:
        strong_reasons = [reason for reason in anomaly.reasons if reason.novelty * reason.weight >= 0.55]
        should_raise = (
            anomaly.score >= self.settings.anomaly_threshold
            and anomaly.baseline_mature
            and len(strong_reasons) >= 2
        ) or (anomaly.score >= 92 and anomaly.baseline_mature)
        if not should_raise:
            return None
        risk = risk_for_anomaly(
            anomaly.score,
            asset_criticality=event.asset_criticality,
            sensor_confidence=event.sensor_confidence,
        )
        return self.store.create_or_update_incident(
            tenant_id=event.tenant_id,
            asset_id=event.asset_id,
            title="Rare behavioral combination requires hunting",
            rule_id=None,
            severity=severity_for_risk(risk),
            risk_score=risk,
            confidence=min(0.95, 0.55 + anomaly.score / 250.0),
            event_ids=[event.event_id],
            anomaly_reasons=[reason.model_dump(mode="json") for reason in anomaly.reasons],
            tags=["behavioral-anomaly", "zero-day-hunt-candidate"],
            fingerprint=stable_hash("ANOMALY", event.event_id),
            observed_at=event.observed_at,
        )

    @staticmethod
    def _collect_anomaly_reasons(payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
        reasons: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for payload in payloads:
            for reason in payload.get("detection", {}).get("reasons", []):
                key = (str(reason.get("feature")), str(reason.get("value")))
                if key not in seen:
                    reasons.append(reason)
                    seen.add(key)
        reasons.sort(
            key=lambda item: float(item.get("novelty", 0)) * float(item.get("weight", 0)),
            reverse=True,
        )
        return reasons[:20]
