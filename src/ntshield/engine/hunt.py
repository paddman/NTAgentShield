from __future__ import annotations

from ntshield.engine.baseline import BaselineEngine
from ntshield.engine.correlator import IncidentCorrelator
from ntshield.engine.rules import BehaviorRule, load_rules
from ntshield.engine.scoring import score_match, severity_for_score
from ntshield.engine.sequence import SequenceEngine, SequenceMatch
from ntshield.models import (
    BehaviorFinding,
    EvidenceRef,
    IngestResult,
    MitreMapping,
    SecurityEvent,
)
from ntshield.settings import Settings
from ntshield.storage import SQLiteStore


def _event_summary(event: SecurityEvent) -> str:
    parts = [event.event_type, f"asset={event.asset.id}"]
    if event.actor.user:
        parts.append(f"user={event.actor.user}")
    if event.process.name:
        lineage = (
            f"{event.process.parent_name}->{event.process.name}"
            if event.process.parent_name
            else event.process.name
        )
        parts.append(f"process={lineage}")
    if event.network.destination_ip or event.network.domain:
        destination = event.network.destination_ip or event.network.domain
        parts.append(f"dst={destination}:{event.network.destination_port or 0}")
    if event.file.path:
        parts.append(f"file={event.file.path}")
    if event.service.name:
        parts.append(f"service={event.service.name}")
    if event.web.path:
        parts.append(f"web={event.web.method or ''} {event.web.path}")
    if event.database.database:
        parts.append(f"db={event.database.database} rows={event.database.rows or 0}")
    return " | ".join(parts)[:500]


def _entities(events: list[SecurityEvent]) -> list[str]:
    values: set[str] = set()
    for event in events:
        values.add(f"asset:{event.asset.id}")
        if event.actor.user:
            values.add(f"user:{event.actor.user.casefold()}")
        for value in (
            event.network.source_ip,
            event.network.destination_ip,
            event.network.domain,
        ):
            if value:
                values.add(f"network:{value.casefold()}")
        if event.process.sha256:
            values.add(f"sha256:{event.process.sha256.casefold()}")
        if event.file.sha256:
            values.add(f"sha256:{event.file.sha256.casefold()}")
        if event.web.request_id:
            values.add(f"request:{event.web.request_id}")
    return sorted(values)


class HuntEngine:
    def __init__(self, settings: Settings, store: SQLiteStore | None = None):
        self.settings = settings
        self.store = store or SQLiteStore(settings.database_path)
        self.rules: list[BehaviorRule] = load_rules(settings.rules_path)
        self.baseline = BaselineEngine(self.store, settings.baseline_warmup_events)
        self.sequences = SequenceEngine(self.rules)
        self.correlator = IncidentCorrelator(
            self.store, window_seconds=settings.incident_window_seconds
        )

    def ingest(self, event: SecurityEvent) -> IngestResult:
        anomaly = self.baseline.assess(event)
        self.store.insert_event(event)
        sequence_matches = self._suppress_subsumed(
            self.sequences.process(event, anomaly.score)
        )
        findings: list[BehaviorFinding] = []
        incidents = []

        for match in sequence_matches:
            finding = self._finding_from_match(match)
            self.store.insert_finding(finding)
            findings.append(finding)
            incidents.append(self.correlator.correlate(finding))

        if (
            anomaly.score >= self.settings.anomaly_finding_threshold
            and not anomaly.cold_start
            and anomaly.rare_features
        ):
            finding = self._finding_from_anomaly(event, anomaly.score, anomaly.rare_features)
            self.store.insert_finding(finding)
            findings.append(finding)
            incidents.append(self.correlator.correlate(finding))

        self.baseline.learn(event)
        unique_incidents = {incident.incident_id: incident for incident in incidents}
        return IngestResult(
            event_id=event.event_id,
            anomaly=anomaly,
            findings=findings,
            incidents=list(unique_incidents.values()),
        )

    @staticmethod
    def _suppress_subsumed(matches: list[SequenceMatch]) -> list[SequenceMatch]:
        """Keep the most specific match when rules in the same family overlap."""
        ordered = sorted(
            matches,
            key=lambda item: (len(item.event_ids), item.rule.base_score),
            reverse=True,
        )
        kept: list[SequenceMatch] = []
        for candidate in ordered:
            candidate_events = set(candidate.event_ids)
            subsumed = any(
                candidate.rule.family
                and candidate.rule.family == existing.rule.family
                and candidate_events.issubset(set(existing.event_ids))
                for existing in kept
            )
            if not subsumed:
                kept.append(candidate)
        return kept

    def _finding_from_match(self, match: SequenceMatch) -> BehaviorFinding:
        events = self.store.get_events(match.event_ids)
        risk_score = score_match(match, events)
        evidence = [
            EvidenceRef(
                event_id=event.event_id,
                observed_at=event.observed_at,
                event_type=event.event_type,
                summary=_event_summary(event),
            )
            for event in events
        ]
        confidence = min(0.99, match.rule.confidence + min(0.12, 0.03 * len(events)))
        return BehaviorFinding(
            tenant_id=events[0].tenant_id,
            rule_id=match.rule.id,
            title=match.rule.title,
            description=match.rule.description,
            severity=severity_for_score(risk_score),
            risk_score=risk_score,
            anomaly_score=match.max_anomaly_score,
            confidence=round(confidence, 2),
            first_seen=match.first_seen,
            last_seen=match.last_seen,
            asset_id=events[0].asset.id,
            entities=_entities(events),
            mitre=match.rule.mitre,
            evidence=evidence,
            reason_codes=match.rule.reason_codes,
        )

    @staticmethod
    def _finding_from_anomaly(
        event: SecurityEvent, anomaly_score: float, rare_features: list[str]
    ) -> BehaviorFinding:
        risk = round(min(82.0, 45.0 + anomaly_score * 0.4), 2)
        return BehaviorFinding(
            tenant_id=event.tenant_id,
            rule_id="BZH-ANOMALY-000",
            title="High-confidence behavior outside learned baseline",
            description=(
                "The event contains multiple feature combinations that are rare for this asset "
                "after baseline warm-up. It is a hunting lead, not proof of compromise."
            ),
            severity=severity_for_score(risk),
            risk_score=risk,
            anomaly_score=anomaly_score,
            confidence=0.62,
            first_seen=event.observed_at,
            last_seen=event.observed_at,
            asset_id=event.asset.id,
            entities=_entities([event]),
            mitre=[
                MitreMapping(
                    tactic="Discovery",
                    technique_id="UNMAPPED",
                    technique="Behavioral anomaly requiring investigation",
                )
            ],
            evidence=[
                EvidenceRef(
                    event_id=event.event_id,
                    observed_at=event.observed_at,
                    event_type=event.event_type,
                    summary=_event_summary(event),
                )
            ],
            reason_codes=["BASELINE_RARITY", *rare_features[:6]],
        )
