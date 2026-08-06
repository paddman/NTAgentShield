from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

from ntshield.models import BehaviorFinding, Incident, SecurityEvent


class SQLiteStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        self._create_schema()

    def _create_schema(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            data_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_tenant_time
            ON events(tenant_id, observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_events_asset_time
            ON events(tenant_id, asset_id, observed_at DESC);

        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            risk_score REAL NOT NULL,
            data_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_findings_tenant_time
            ON findings(tenant_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            risk_score REAL NOT NULL,
            status TEXT NOT NULL,
            data_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_tenant_time
            ON incidents(tenant_id, updated_at DESC);

        CREATE TABLE IF NOT EXISTS baseline_counts (
            tenant_id TEXT NOT NULL,
            scope_key TEXT NOT NULL,
            feature_name TEXT NOT NULL,
            feature_value TEXT NOT NULL,
            count INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (tenant_id, scope_key, feature_name, feature_value)
        );
        CREATE TABLE IF NOT EXISTS baseline_totals (
            tenant_id TEXT NOT NULL,
            scope_key TEXT NOT NULL,
            feature_name TEXT NOT NULL,
            total INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, scope_key, feature_name)
        );
        """
        with self._lock:
            self._conn.executescript(schema)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def insert_event(self, event: SecurityEvent) -> None:
        payload = event.model_dump_json()
        with self._lock:
            self._conn.execute(
                """INSERT OR IGNORE INTO events
                (event_id, tenant_id, asset_id, observed_at, event_type, data_json)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id,
                    event.tenant_id,
                    event.asset.id,
                    event.observed_at.isoformat(),
                    event.event_type,
                    payload,
                ),
            )
            self._conn.commit()

    def get_event(self, event_id: str) -> SecurityEvent | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data_json FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        return SecurityEvent.model_validate_json(row["data_json"]) if row else None

    def get_events(self, event_ids: list[str]) -> list[SecurityEvent]:
        if not event_ids:
            return []
        placeholders = ",".join("?" for _ in event_ids)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT data_json FROM events WHERE event_id IN ({placeholders})",
                event_ids,
            ).fetchall()
        by_id = {
            event.event_id: event
            for row in rows
            if (event := SecurityEvent.model_validate_json(row["data_json"]))
        }
        return [by_id[event_id] for event_id in event_ids if event_id in by_id]

    def list_events(self, tenant_id: str, limit: int = 200) -> list[SecurityEvent]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT data_json FROM events WHERE tenant_id = ?
                ORDER BY observed_at DESC LIMIT ?""",
                (tenant_id, limit),
            ).fetchall()
        return [SecurityEvent.model_validate_json(row["data_json"]) for row in rows]

    def insert_finding(self, finding: BehaviorFinding) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO findings
                (finding_id, tenant_id, asset_id, created_at, risk_score, data_json)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding.finding_id,
                    finding.tenant_id,
                    finding.asset_id,
                    finding.created_at.isoformat(),
                    finding.risk_score,
                    finding.model_dump_json(),
                ),
            )
            self._conn.commit()

    def list_findings(self, tenant_id: str, limit: int = 100) -> list[BehaviorFinding]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT data_json FROM findings WHERE tenant_id = ?
                ORDER BY created_at DESC LIMIT ?""",
                (tenant_id, limit),
            ).fetchall()
        return [BehaviorFinding.model_validate_json(row["data_json"]) for row in rows]

    def upsert_incident(self, incident: Incident) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO incidents
                (incident_id, tenant_id, updated_at, risk_score, status, data_json)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    incident.incident_id,
                    incident.tenant_id,
                    incident.updated_at.isoformat(),
                    incident.risk_score,
                    incident.status,
                    incident.model_dump_json(),
                ),
            )
            self._conn.commit()

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data_json FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        return Incident.model_validate_json(row["data_json"]) if row else None

    def list_incidents(self, tenant_id: str, limit: int = 100) -> list[Incident]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT data_json FROM incidents WHERE tenant_id = ?
                ORDER BY updated_at DESC LIMIT ?""",
                (tenant_id, limit),
            ).fetchall()
        return [Incident.model_validate_json(row["data_json"]) for row in rows]

    def list_open_incidents(self, tenant_id: str, limit: int = 200) -> list[Incident]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT data_json FROM incidents
                WHERE tenant_id = ? AND status IN ('open', 'investigating')
                ORDER BY updated_at DESC LIMIT ?""",
                (tenant_id, limit),
            ).fetchall()
        return [Incident.model_validate_json(row["data_json"]) for row in rows]

    def get_feature_count(
        self, tenant_id: str, scope_key: str, feature_name: str, feature_value: str
    ) -> tuple[int, int]:
        with self._lock:
            row = self._conn.execute(
                """SELECT count FROM baseline_counts
                WHERE tenant_id = ? AND scope_key = ? AND feature_name = ? AND feature_value = ?""",
                (tenant_id, scope_key, feature_name, feature_value),
            ).fetchone()
            total_row = self._conn.execute(
                """SELECT total FROM baseline_totals
                WHERE tenant_id = ? AND scope_key = ? AND feature_name = ?""",
                (tenant_id, scope_key, feature_name),
            ).fetchone()
        return (int(row["count"]) if row else 0, int(total_row["total"]) if total_row else 0)

    def increment_feature(
        self,
        tenant_id: str,
        scope_key: str,
        feature_name: str,
        feature_value: str,
        observed_at: str,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO baseline_counts
                (tenant_id, scope_key, feature_name, feature_value, count, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(tenant_id, scope_key, feature_name, feature_value)
                DO UPDATE SET count = count + 1, last_seen = excluded.last_seen""",
                (
                    tenant_id,
                    scope_key,
                    feature_name,
                    feature_value,
                    observed_at,
                    observed_at,
                ),
            )
            self._conn.execute(
                """INSERT INTO baseline_totals
                (tenant_id, scope_key, feature_name, total)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(tenant_id, scope_key, feature_name)
                DO UPDATE SET total = total + 1""",
                (tenant_id, scope_key, feature_name),
            )
            self._conn.commit()

    def stats(self, tenant_id: str) -> dict[str, Any]:
        with self._lock:
            event_count = self._conn.execute(
                "SELECT COUNT(*) AS c FROM events WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()["c"]
            finding_count = self._conn.execute(
                "SELECT COUNT(*) AS c FROM findings WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()["c"]
            incident_count = self._conn.execute(
                "SELECT COUNT(*) AS c FROM incidents WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()["c"]
            critical_count = self._conn.execute(
                """SELECT COUNT(*) AS c FROM incidents
                WHERE tenant_id = ? AND risk_score >= 85 AND status != 'closed'""",
                (tenant_id,),
            ).fetchone()["c"]
        return {
            "events": int(event_count),
            "findings": int(finding_count),
            "incidents": int(incident_count),
            "critical_open": int(critical_count),
        }
