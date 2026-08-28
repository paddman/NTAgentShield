from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

JobKind = Literal["normalized", "raw"]
JobStatus = Literal["queued", "leased", "succeeded", "dead_letter"]


@dataclass(frozen=True, slots=True)
class IngestJob:
    job_id: str
    tenant_id: str
    kind: JobKind
    payload: dict[str, Any]
    payload_sha256: str
    idempotency_key: str | None
    status: JobStatus
    attempts: int
    max_attempts: int
    available_at: datetime
    lease_owner: str | None
    lease_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime
    last_error: str | None
    result: dict[str, Any] | None

    def as_dict(self, *, include_payload: bool = False) -> dict[str, Any]:
        value: dict[str, Any] = {
            "job_id": self.job_id,
            "tenant_id": self.tenant_id,
            "kind": self.kind,
            "payload_sha256": self.payload_sha256,
            "idempotency_key": self.idempotency_key,
            "status": self.status,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "available_at": self.available_at.isoformat(),
            "lease_owner": self.lease_owner,
            "lease_expires_at": (
                self.lease_expires_at.isoformat() if self.lease_expires_at else None
            ),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_error": self.last_error,
            "result": self.result,
        }
        if include_payload:
            value["payload"] = self.payload
        return value


class DurableIngestQueue:
    """SQLite WAL queue with idempotency, leases, retry and dead-letter state."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ingest_jobs (
                    job_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('normalized', 'raw')),
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    idempotency_key TEXT,
                    status TEXT NOT NULL CHECK(status IN
                        ('queued', 'leased', 'succeeded', 'dead_letter')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL,
                    available_at TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_error TEXT,
                    result_json TEXT,
                    UNIQUE(tenant_id, kind, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS idx_ingest_jobs_claim
                    ON ingest_jobs(status, available_at, created_at);
                CREATE INDEX IF NOT EXISTS idx_ingest_jobs_tenant_time
                    ON ingest_jobs(tenant_id, created_at DESC);
                """
            )
            self._conn.commit()

    def enqueue(
        self,
        *,
        tenant_id: str,
        kind: JobKind,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
        max_attempts: int = 8,
        now: datetime | None = None,
    ) -> tuple[IngestJob, bool]:
        tenant_id = _bounded(tenant_id, "tenant_id", 128)
        if kind not in {"normalized", "raw"}:
            raise ValueError("ingest job kind must be normalized or raw")
        if not isinstance(payload, dict):
            raise ValueError("ingest queue payload must be an object")
        if max_attempts < 1 or max_attempts > 100:
            raise ValueError("max_attempts must be between 1 and 100")
        if idempotency_key is not None:
            idempotency_key = _bounded(idempotency_key, "idempotency_key", 128)
        payload_json = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        encoded = payload_json.encode("utf-8")
        if len(encoded) > 8 * 1024 * 1024:
            raise ValueError("ingest queue payload exceeds 8 MiB")
        digest = hashlib.sha256(encoded).hexdigest()
        timestamp = (now or datetime.now(UTC)).astimezone(UTC)
        job_id = f"ing_{uuid4().hex}"
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                if idempotency_key:
                    existing = self._conn.execute(
                        """
                        SELECT * FROM ingest_jobs
                        WHERE tenant_id = ? AND kind = ? AND idempotency_key = ?
                        """,
                        (tenant_id, kind, idempotency_key),
                    ).fetchone()
                    if existing is not None:
                        if existing["payload_sha256"] != digest:
                            raise ValueError(
                                "idempotency key was already used with a different payload"
                            )
                        self._conn.commit()
                        return _row(existing), False
                self._conn.execute(
                    """
                    INSERT INTO ingest_jobs
                    (job_id, tenant_id, kind, payload_json, payload_sha256,
                     idempotency_key, status, attempts, max_attempts, available_at,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?, ?)
                    """,
                    (
                        job_id,
                        tenant_id,
                        kind,
                        payload_json,
                        digest,
                        idempotency_key,
                        max_attempts,
                        timestamp.isoformat(),
                        timestamp.isoformat(),
                        timestamp.isoformat(),
                    ),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        job = self.get(job_id)
        assert job is not None
        return job, True

    def claim(
        self,
        *,
        worker_id: str,
        limit: int = 100,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> list[IngestJob]:
        worker_id = _bounded(worker_id, "worker_id", 128)
        if limit < 1 or limit > 1000:
            raise ValueError("claim limit must be between 1 and 1000")
        if lease_seconds < 10 or lease_seconds > 3600:
            raise ValueError("lease_seconds must be between 10 and 3600")
        timestamp = (now or datetime.now(UTC)).astimezone(UTC)
        expires_at = timestamp + timedelta(seconds=lease_seconds)
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute(
                    """
                    UPDATE ingest_jobs
                    SET status = 'dead_letter', lease_owner = NULL, lease_expires_at = NULL,
                        available_at = ?, updated_at = ?,
                        last_error = COALESCE(last_error, 'worker lease expired at retry limit')
                    WHERE status = 'leased' AND lease_expires_at <= ?
                      AND attempts >= max_attempts
                    """,
                    (timestamp.isoformat(), timestamp.isoformat(), timestamp.isoformat()),
                )
                self._conn.execute(
                    """
                    UPDATE ingest_jobs
                    SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL,
                        available_at = ?, updated_at = ?,
                        last_error = COALESCE(last_error, 'worker lease expired')
                    WHERE status = 'leased' AND lease_expires_at <= ?
                      AND attempts < max_attempts
                    """,
                    (timestamp.isoformat(), timestamp.isoformat(), timestamp.isoformat()),
                )
                self._conn.execute(
                    """
                    UPDATE ingest_jobs
                    SET status = 'dead_letter', updated_at = ?,
                        last_error = COALESCE(last_error, 'retry limit exhausted')
                    WHERE status = 'queued' AND attempts >= max_attempts
                    """,
                    (timestamp.isoformat(),),
                )
                rows = self._conn.execute(
                    """
                    SELECT job_id FROM ingest_jobs
                    WHERE status = 'queued' AND available_at <= ?
                    ORDER BY created_at, job_id
                    LIMIT ?
                    """,
                    (timestamp.isoformat(), limit),
                ).fetchall()
                job_ids = [str(row["job_id"]) for row in rows]
                for job_id in job_ids:
                    self._conn.execute(
                        """
                        UPDATE ingest_jobs
                        SET status = 'leased', attempts = attempts + 1,
                            lease_owner = ?, lease_expires_at = ?, updated_at = ?
                        WHERE job_id = ? AND status = 'queued'
                        """,
                        (
                            worker_id,
                            expires_at.isoformat(),
                            timestamp.isoformat(),
                            job_id,
                        ),
                    )
                claimed = self._select_many(job_ids)
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return claimed

    def complete(
        self,
        job_id: str,
        *,
        worker_id: str,
        result: dict[str, Any],
        now: datetime | None = None,
    ) -> IngestJob:
        worker_id = _bounded(worker_id, "worker_id", 128)
        result_json = json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        if len(result_json.encode("utf-8")) > 64 * 1024:
            raise ValueError("ingest worker result exceeds 64 KiB")
        timestamp = (now or datetime.now(UTC)).astimezone(UTC)
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE ingest_jobs
                SET status = 'succeeded', result_json = ?, last_error = NULL,
                    lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
                WHERE job_id = ? AND status = 'leased' AND lease_owner = ?
                  AND lease_expires_at > ?
                """,
                (
                    result_json,
                    timestamp.isoformat(),
                    job_id,
                    worker_id,
                    timestamp.isoformat(),
                ),
            )
            if cursor.rowcount != 1:
                self._conn.rollback()
                raise ValueError("ingest job lease is missing or owned by another worker")
            self._conn.commit()
        job = self.get(job_id)
        assert job is not None
        return job

    def fail(
        self,
        job_id: str,
        *,
        worker_id: str,
        error: str,
        retry_delay_seconds: int,
        now: datetime | None = None,
    ) -> IngestJob:
        worker_id = _bounded(worker_id, "worker_id", 128)
        error = _bounded(error, "error", 4096)
        if retry_delay_seconds < 1 or retry_delay_seconds > 3600:
            raise ValueError("retry_delay_seconds must be between 1 and 3600")
        timestamp = (now or datetime.now(UTC)).astimezone(UTC)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT attempts, max_attempts FROM ingest_jobs
                WHERE job_id = ? AND status = 'leased' AND lease_owner = ?
                  AND lease_expires_at > ?
                """,
                (job_id, worker_id, timestamp.isoformat()),
            ).fetchone()
            if row is None:
                raise ValueError("ingest job lease is missing or owned by another worker")
            terminal = int(row["attempts"]) >= int(row["max_attempts"])
            status = "dead_letter" if terminal else "queued"
            available_at = timestamp if terminal else timestamp + timedelta(
                seconds=retry_delay_seconds
            )
            self._conn.execute(
                """
                UPDATE ingest_jobs
                SET status = ?, available_at = ?, lease_owner = NULL,
                    lease_expires_at = NULL, updated_at = ?, last_error = ?
                WHERE job_id = ?
                """,
                (
                    status,
                    available_at.isoformat(),
                    timestamp.isoformat(),
                    error,
                    job_id,
                ),
            )
            self._conn.commit()
        job = self.get(job_id)
        assert job is not None
        return job

    def get(self, job_id: str) -> IngestJob | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM ingest_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return _row(row) if row is not None else None

    def stats(self, tenant_id: str | None = None) -> dict[str, int]:
        where = " WHERE tenant_id = ?" if tenant_id else ""
        params = (tenant_id,) if tenant_id else ()
        with self._lock:
            rows = self._conn.execute(
                f"SELECT status, COUNT(*) AS count FROM ingest_jobs{where} GROUP BY status",
                params,
            ).fetchall()
        values = {"queued": 0, "leased": 0, "succeeded": 0, "dead_letter": 0}
        for row in rows:
            values[str(row["status"])] = int(row["count"])
        return values

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _select_many(self, job_ids: list[str]) -> list[IngestJob]:
        if not job_ids:
            return []
        placeholders = ",".join("?" for _ in job_ids)
        rows = self._conn.execute(
            f"SELECT * FROM ingest_jobs WHERE job_id IN ({placeholders})",
            job_ids,
        ).fetchall()
        by_id = {str(row["job_id"]): _row(row) for row in rows}
        return [by_id[job_id] for job_id in job_ids if job_id in by_id]


def default_queue_path(database_path: str | Path) -> Path:
    path = Path(database_path)
    return path.with_name(f"{path.stem}-ingest-queue.db")


def _row(row: sqlite3.Row) -> IngestJob:
    return IngestJob(
        job_id=row["job_id"],
        tenant_id=row["tenant_id"],
        kind=row["kind"],
        payload=json.loads(row["payload_json"]),
        payload_sha256=row["payload_sha256"],
        idempotency_key=row["idempotency_key"],
        status=row["status"],
        attempts=int(row["attempts"]),
        max_attempts=int(row["max_attempts"]),
        available_at=datetime.fromisoformat(row["available_at"]).astimezone(UTC),
        lease_owner=row["lease_owner"],
        lease_expires_at=(
            datetime.fromisoformat(row["lease_expires_at"]).astimezone(UTC)
            if row["lease_expires_at"]
            else None
        ),
        created_at=datetime.fromisoformat(row["created_at"]).astimezone(UTC),
        updated_at=datetime.fromisoformat(row["updated_at"]).astimezone(UTC),
        last_error=row["last_error"],
        result=json.loads(row["result_json"]) if row["result_json"] else None,
    )


def _bounded(value: object, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > limit:
        raise ValueError(f"{field} must be between 1 and {limit} characters")
    return normalized
