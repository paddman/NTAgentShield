from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from .models import AnomalyResult, Incident, SecurityEvent


class SQLiteStore:
    """Small durable store for the MVP.

    SQLite keeps the prototype simple and replayable. The production topology in the
    architecture document moves high-volume events to ClickHouse while retaining the
    same service interfaces.
    """

    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._initialize()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source TEXT NOT NULL,
            anomaly_score REAL NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_tenant_asset_time
            ON events(tenant_id, asset_id, observed_at);
        CREATE INDEX IF NOT EXISTS idx_events_type_time
            ON events(event_type, observed_at);

        CREATE TABLE IF NOT EXISTS categorical_baselines (
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            feature_name TEXT NOT NULL,
            feature_value TEXT NOT NULL,
            count INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY(tenant_id, asset_id, feature_name, feature_value)
        );

        CREATE TABLE IF NOT EXISTS categorical_totals (
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            feature_name TEXT NOT NULL,
            total_count INTEGER NOT NULL,
            PRIMARY KEY(tenant_id, asset_id, feature_name)
        );

        CREATE TABLE IF NOT EXISTS numeric_baselines (
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            feature_name TEXT NOT NULL,
            n INTEGER NOT NULL,
            mean REAL NOT NULL,
            m2 REAL NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(tenant_id, asset_id, feature_name)
        );

        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            title TEXT NOT NULL,
            rule_id TEXT,
            severity TEXT NOT NULL,
            risk_score REAL NOT NULL,
            confidence REAL NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            event_ids_json TEXT NOT NULL,
            anomaly_reasons_json TEXT NOT NULL,
            tags_json TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE,
            analysis_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status_time
            ON incidents(tenant_id, status, updated_at DESC);
        """
        with self._lock, self._conn:
            self._conn.executescript(schema)

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)

    def save_event(self, event: SecurityEvent, anomaly: AnomalyResult) -> None:
        payload = event.model_dump(mode="json")
        payload["detection"] = anomaly.model_dump(mode="json")
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO events(
                    event_id, tenant_id, asset_id, observed_at, event_type,
                    source, anomaly_score, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.tenant_id,
                    event.asset_id,
                    event.observed_at.isoformat(),
                    event.event_type,
                    event.source,
                    anomaly.score,
                    self._json(payload),
                ),
            )

    def get_event_payload(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload_json FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        return json.loads(row["payload_json"]) if row else None

    def get_event_payloads(self, event_ids: Iterable[str]) -> list[dict[str, Any]]:
        ids = list(dict.fromkeys(event_ids))
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT payload_json FROM events WHERE event_id IN ({placeholders})",
                ids,
            ).fetchall()
        payloads = [json.loads(row["payload_json"]) for row in rows]
        order = {event_id: index for index, event_id in enumerate(ids)}
        payloads.sort(key=lambda item: order.get(item.get("event_id", ""), len(order)))
        return payloads

    def get_recent_event_payloads(
        self,
        tenant_id: str,
        asset_id: str,
        since: datetime,
        *,
        limit: int = 2000,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 10_000))
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT payload_json
                FROM events
                WHERE tenant_id = ? AND asset_id = ? AND observed_at >= ?
                ORDER BY observed_at ASC
                LIMIT ?
                """,
                (tenant_id, asset_id, since.astimezone(UTC).isoformat(), limit),
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def search_event_payloads(
        self,
        *,
        tenant_id: str,
        asset_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        event_types: list[str] | None = None,
        process_name: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if asset_id:
            clauses.append("asset_id = ?")
            params.append(asset_id)
        if start:
            clauses.append("observed_at >= ?")
            params.append(start.astimezone(UTC).isoformat())
        if end:
            clauses.append("observed_at <= ?")
            params.append(end.astimezone(UTC).isoformat())
        if event_types:
            placeholders = ",".join("?" for _ in event_types)
            clauses.append(f"event_type IN ({placeholders})")
            params.extend(event_types)
        limit = max(1, min(limit, 500))
        params.append(limit * 5 if process_name else limit)
        query = (
            "SELECT payload_json FROM events WHERE "
            + " AND ".join(clauses)
            + " ORDER BY observed_at ASC LIMIT ?"
        )
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        payloads = [json.loads(row["payload_json"]) for row in rows]
        if process_name:
            wanted = process_name.lower()
            payloads = [
                payload
                for payload in payloads
                if str(payload.get("process", {}).get("name", "")).lower() == wanted
            ][:limit]
        return payloads

    def get_categorical_stats(
        self,
        tenant_id: str,
        asset_id: str,
        feature_name: str,
        feature_value: str,
    ) -> tuple[int, int]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT count FROM categorical_baselines
                WHERE tenant_id = ? AND asset_id = ?
                  AND feature_name = ? AND feature_value = ?
                """,
                (tenant_id, asset_id, feature_name, feature_value),
            ).fetchone()
            total_row = self._conn.execute(
                """
                SELECT total_count FROM categorical_totals
                WHERE tenant_id = ? AND asset_id = ? AND feature_name = ?
                """,
                (tenant_id, asset_id, feature_name),
            ).fetchone()
        return (int(row["count"]) if row else 0, int(total_row["total_count"]) if total_row else 0)

    def increment_categorical(
        self,
        tenant_id: str,
        asset_id: str,
        feature_name: str,
        feature_value: str,
        observed_at: datetime,
    ) -> None:
        timestamp = observed_at.astimezone(UTC).isoformat()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO categorical_baselines(
                    tenant_id, asset_id, feature_name, feature_value,
                    count, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(tenant_id, asset_id, feature_name, feature_value)
                DO UPDATE SET count = count + 1, last_seen = excluded.last_seen
                """,
                (tenant_id, asset_id, feature_name, feature_value, timestamp, timestamp),
            )
            self._conn.execute(
                """
                INSERT INTO categorical_totals(tenant_id, asset_id, feature_name, total_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(tenant_id, asset_id, feature_name)
                DO UPDATE SET total_count = total_count + 1
                """,
                (tenant_id, asset_id, feature_name),
            )

    def get_numeric_stats(
        self, tenant_id: str, asset_id: str, feature_name: str
    ) -> tuple[int, float, float]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT n, mean, m2 FROM numeric_baselines
                WHERE tenant_id = ? AND asset_id = ? AND feature_name = ?
                """,
                (tenant_id, asset_id, feature_name),
            ).fetchone()
        if not row:
            return (0, 0.0, 0.0)
        return (int(row["n"]), float(row["mean"]), float(row["m2"]))

    def update_numeric(
        self,
        tenant_id: str,
        asset_id: str,
        feature_name: str,
        value: float,
        observed_at: datetime,
    ) -> None:
        n, mean, m2 = self.get_numeric_stats(tenant_id, asset_id, feature_name)
        new_n = n + 1
        delta = value - mean
        new_mean = mean + delta / new_n
        new_m2 = m2 + delta * (value - new_mean)
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO numeric_baselines(
                    tenant_id, asset_id, feature_name, n, mean, m2, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, asset_id, feature_name)
                DO UPDATE SET n = excluded.n, mean = excluded.mean,
                              m2 = excluded.m2, updated_at = excluded.updated_at
                """,
                (
                    tenant_id,
                    asset_id,
                    feature_name,
                    new_n,
                    new_mean,
                    new_m2,
                    observed_at.astimezone(UTC).isoformat(),
                ),
            )

    def create_or_update_incident(
        self,
        *,
        tenant_id: str,
        asset_id: str,
        title: str,
        rule_id: str | None,
        severity: str,
        risk_score: float,
        confidence: float,
        event_ids: list[str],
        anomaly_reasons: list[dict[str, Any]],
        tags: list[str],
        fingerprint: str,
        observed_at: datetime,
    ) -> Incident:
        now = observed_at.astimezone(UTC)
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT * FROM incidents WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            if existing:
                old_event_ids = json.loads(existing["event_ids_json"])
                merged_event_ids = list(dict.fromkeys([*old_event_ids, *event_ids]))
                old_reasons = json.loads(existing["anomaly_reasons_json"])
                merged_reasons = [*old_reasons]
                seen_reason_keys = {
                    (reason.get("feature"), reason.get("value")) for reason in merged_reasons
                }
                for reason in anomaly_reasons:
                    key = (reason.get("feature"), reason.get("value"))
                    if key not in seen_reason_keys:
                        merged_reasons.append(reason)
                        seen_reason_keys.add(key)
                self._conn.execute(
                    """
                    UPDATE incidents
                    SET updated_at = ?, risk_score = ?, confidence = ?,
                        event_ids_json = ?, anomaly_reasons_json = ?
                    WHERE fingerprint = ?
                    """,
                    (
                        now.isoformat(),
                        max(float(existing["risk_score"]), risk_score),
                        max(float(existing["confidence"]), confidence),
                        self._json(merged_event_ids),
                        self._json(merged_reasons),
                        fingerprint,
                    ),
                )
            else:
                incident_id = str(uuid4())
                self._conn.execute(
                    """
                    INSERT INTO incidents(
                        incident_id, tenant_id, asset_id, title, rule_id,
                        severity, risk_score, confidence, status,
                        created_at, updated_at, event_ids_json,
                        anomaly_reasons_json, tags_json, fingerprint, analysis_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        incident_id,
                        tenant_id,
                        asset_id,
                        title,
                        rule_id,
                        severity,
                        risk_score,
                        confidence,
                        now.isoformat(),
                        now.isoformat(),
                        self._json(event_ids),
                        self._json(anomaly_reasons),
                        self._json(tags),
                        fingerprint,
                    ),
                )
        incident = self.get_incident_by_fingerprint(fingerprint)
        if incident is None:  # pragma: no cover - defensive database guard
            raise RuntimeError("Incident disappeared after creation")
        return incident

    @staticmethod
    def _incident_from_row(row: sqlite3.Row) -> Incident:
        return Incident(
            incident_id=row["incident_id"],
            tenant_id=row["tenant_id"],
            asset_id=row["asset_id"],
            title=row["title"],
            rule_id=row["rule_id"],
            severity=row["severity"],
            risk_score=float(row["risk_score"]),
            confidence=float(row["confidence"]),
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            event_ids=json.loads(row["event_ids_json"]),
            anomaly_reasons=json.loads(row["anomaly_reasons_json"]),
            tags=json.loads(row["tags_json"]),
            fingerprint=row["fingerprint"],
            analysis=json.loads(row["analysis_json"]) if row["analysis_json"] else None,
        )

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        return self._incident_from_row(row) if row else None

    def get_incident_by_fingerprint(self, fingerprint: str) -> Incident | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM incidents WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
        return self._incident_from_row(row) if row else None

    def list_incidents(
        self,
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[Incident]:
        clauses: list[str] = []
        params: list[Any] = []
        if tenant_id:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM incidents {where} ORDER BY updated_at DESC LIMIT ?",
                params,
            ).fetchall()
        return [self._incident_from_row(row) for row in rows]

    def save_incident_analysis(self, incident_id: str, analysis: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE incidents SET analysis_json = ?, updated_at = ?
                WHERE incident_id = ?
                """,
                (self._json(analysis), datetime.now(UTC).isoformat(), incident_id),
            )

    def count_events(self, tenant_id: str | None = None) -> int:
        with self._lock:
            if tenant_id:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM events WHERE tenant_id = ?", (tenant_id,)
                ).fetchone()
            else:
                row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])
