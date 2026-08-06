from __future__ import annotations

from datetime import timedelta

from ntshield.engine.scoring import severity_for_score
from ntshield.models import BehaviorFinding, Incident, MitreMapping, utc_now
from ntshield.storage import SQLiteStore


class IncidentCorrelator:
    def __init__(self, store: SQLiteStore, window_seconds: int = 1800):
        self.store = store
        self.window = timedelta(seconds=window_seconds)

    @staticmethod
    def _merge_mitre(left: list[MitreMapping], right: list[MitreMapping]) -> list[MitreMapping]:
        merged: dict[str, MitreMapping] = {item.technique_id: item for item in left}
        for item in right:
            merged[item.technique_id] = item
        return list(merged.values())

    def correlate(self, finding: BehaviorFinding) -> Incident:
        finding_entities = set(finding.entities)
        candidates = self.store.list_open_incidents(finding.tenant_id)
        selected: Incident | None = None
        for incident in candidates:
            time_close = finding.first_seen <= incident.last_seen + self.window
            entity_overlap = bool(finding_entities.intersection(incident.entities))
            same_asset = finding.asset_id in incident.asset_ids
            if time_close and (entity_overlap or same_asset):
                selected = incident
                break

        if selected is None:
            incident = Incident(
                tenant_id=finding.tenant_id,
                title=finding.title,
                severity=finding.severity,
                risk_score=finding.risk_score,
                confidence=finding.confidence,
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
                asset_ids=[finding.asset_id],
                entities=sorted(finding_entities),
                finding_ids=[finding.finding_id],
                mitre=finding.mitre,
            )
        else:
            selected.first_seen = min(selected.first_seen, finding.first_seen)
            selected.last_seen = max(selected.last_seen, finding.last_seen)
            selected.updated_at = utc_now()
            selected.finding_ids = sorted({*selected.finding_ids, finding.finding_id})
            selected.asset_ids = sorted({*selected.asset_ids, finding.asset_id})
            selected.entities = sorted({*selected.entities, *finding.entities})
            selected.mitre = self._merge_mitre(selected.mitre, finding.mitre)
            selected.risk_score = round(
                min(100.0, max(selected.risk_score, finding.risk_score) + 2.5), 2
            )
            selected.confidence = round(max(selected.confidence, finding.confidence), 2)
            selected.severity = severity_for_score(selected.risk_score)
            selected.title = (
                f"Behavioral attack chain on {', '.join(selected.asset_ids[:2])}"
                if len(selected.finding_ids) > 1
                else selected.title
            )
            incident = selected

        self.store.upsert_incident(incident)
        return incident
