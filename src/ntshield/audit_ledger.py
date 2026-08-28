from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

GENESIS_HASH = "0" * 64
MAX_AUDIT_PAYLOAD_BYTES = 32 * 1024


class AuditLedgerError(RuntimeError):
    """Raised when the control-plane audit ledger cannot preserve its invariants."""


@dataclass(frozen=True, slots=True)
class AuditRecord:
    sequence: int
    recorded_at: datetime
    tenant_id: str | None
    actor: str
    action: str
    resource_type: str
    resource_id: str | None
    request_id: str
    outcome: str
    payload: dict[str, Any]
    previous_hash: str
    record_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "recorded_at": self.recorded_at.isoformat(),
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "request_id": self.request_id,
            "outcome": self.outcome,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
        }


@dataclass(frozen=True, slots=True)
class AuditVerification:
    valid: bool
    records_checked: int
    last_sequence: int
    last_hash: str
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "records_checked": self.records_checked,
            "last_sequence": self.last_sequence,
            "last_hash": self.last_hash,
            "error": self.error,
        }


class AuditLedger:
    """Append-only hash-chained audit ledger for operator and control-plane actions.

    A deployment should provide an independent HMAC secret. When the secret is
    unavailable the ledger still hashes records, but callers must keep the
    production plane locked until a real secret is configured.
    """

    def __init__(self, path: str | Path, hmac_secret: str | bytes = b""):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        secret = hmac_secret.encode("utf-8") if isinstance(hmac_secret, str) else bytes(hmac_secret)
        self._secret = secret
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS control_audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at TEXT NOT NULL,
                    tenant_id TEXT,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT,
                    request_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS idx_control_audit_tenant_sequence
                    ON control_audit(tenant_id, sequence DESC);
                CREATE INDEX IF NOT EXISTS idx_control_audit_request
                    ON control_audit(request_id, sequence);
                CREATE INDEX IF NOT EXISTS idx_control_audit_action
                    ON control_audit(action, sequence DESC);
                """
            )
            self._conn.commit()

    @property
    def hmac_enabled(self) -> bool:
        return len(self._secret) >= 32

    def append(
        self,
        *,
        actor: str,
        action: str,
        resource_type: str,
        request_id: str,
        outcome: str,
        tenant_id: str | None = None,
        resource_id: str | None = None,
        payload: dict[str, Any] | None = None,
        recorded_at: datetime | None = None,
    ) -> AuditRecord:
        actor = _bounded_text(actor, "actor", 128)
        action = _bounded_text(action, "action", 160)
        resource_type = _bounded_text(resource_type, "resource_type", 128)
        request_id = _bounded_text(request_id, "request_id", 128)
        outcome = _bounded_text(outcome, "outcome", 64)
        tenant_id = _optional_bounded_text(tenant_id, "tenant_id", 128)
        resource_id = _optional_bounded_text(resource_id, "resource_id", 256)
        safe_payload = payload or {}
        if not isinstance(safe_payload, dict):
            raise AuditLedgerError("audit payload must be an object")
        payload_json = json.dumps(
            safe_payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        if len(payload_json.encode("utf-8")) > MAX_AUDIT_PAYLOAD_BYTES:
            raise AuditLedgerError(f"audit payload exceeds {MAX_AUDIT_PAYLOAD_BYTES} bytes")
        timestamp = (recorded_at or datetime.now(UTC)).astimezone(UTC)

        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._conn.execute(
                    "SELECT sequence, record_hash FROM control_audit ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                previous_hash = str(row["record_hash"]) if row else GENESIS_HASH
                canonical = _canonical_record(
                    recorded_at=timestamp.isoformat(),
                    tenant_id=tenant_id,
                    actor=actor,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    request_id=request_id,
                    outcome=outcome,
                    payload_json=payload_json,
                    previous_hash=previous_hash,
                )
                record_hash = self._digest(canonical)
                cursor = self._conn.execute(
                    """
                    INSERT INTO control_audit
                    (recorded_at, tenant_id, actor, action, resource_type, resource_id,
                     request_id, outcome, payload_json, previous_hash, record_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        timestamp.isoformat(),
                        tenant_id,
                        actor,
                        action,
                        resource_type,
                        resource_id,
                        request_id,
                        outcome,
                        payload_json,
                        previous_hash,
                        record_hash,
                    ),
                )
                sequence = int(cursor.lastrowid)
                self._conn.commit()
            except Exception as exc:
                self._conn.rollback()
                raise AuditLedgerError(f"failed to append audit record: {exc}") from exc
        return AuditRecord(
            sequence=sequence,
            recorded_at=timestamp,
            tenant_id=tenant_id,
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id,
            outcome=outcome,
            payload=safe_payload,
            previous_hash=previous_hash,
            record_hash=record_hash,
        )

    def verify(self) -> AuditVerification:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM control_audit ORDER BY sequence ASC"
            ).fetchall()
        previous_hash = GENESIS_HASH
        last_sequence = 0
        checked = 0
        for row in rows:
            sequence = int(row["sequence"])
            if sequence <= last_sequence:
                return AuditVerification(
                    valid=False,
                    records_checked=checked,
                    last_sequence=last_sequence,
                    last_hash=previous_hash,
                    error=f"non-monotonic audit sequence at {sequence}",
                )
            if row["previous_hash"] != previous_hash:
                return AuditVerification(
                    valid=False,
                    records_checked=checked,
                    last_sequence=last_sequence,
                    last_hash=previous_hash,
                    error=f"previous hash mismatch at sequence {sequence}",
                )
            canonical = _canonical_record(
                recorded_at=row["recorded_at"],
                tenant_id=row["tenant_id"],
                actor=row["actor"],
                action=row["action"],
                resource_type=row["resource_type"],
                resource_id=row["resource_id"],
                request_id=row["request_id"],
                outcome=row["outcome"],
                payload_json=row["payload_json"],
                previous_hash=row["previous_hash"],
            )
            expected = self._digest(canonical)
            if not hmac.compare_digest(str(row["record_hash"]), expected):
                return AuditVerification(
                    valid=False,
                    records_checked=checked,
                    last_sequence=last_sequence,
                    last_hash=previous_hash,
                    error=f"record hash mismatch at sequence {sequence}",
                )
            previous_hash = expected
            last_sequence = sequence
            checked += 1
        return AuditVerification(
            valid=True,
            records_checked=checked,
            last_sequence=last_sequence,
            last_hash=previous_hash,
        )

    def list_records(
        self,
        *,
        tenant_id: str | None = None,
        limit: int = 100,
        actions: Iterable[str] | None = None,
    ) -> list[AuditRecord]:
        if limit < 1 or limit > 1000:
            raise ValueError("audit record limit must be between 1 and 1000")
        clauses: list[str] = []
        params: list[Any] = []
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        normalized_actions = [value.strip() for value in (actions or ()) if value.strip()]
        if normalized_actions:
            placeholders = ",".join("?" for _ in normalized_actions)
            clauses.append(f"action IN ({placeholders})")
            params.extend(normalized_actions)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM control_audit{where} ORDER BY sequence DESC LIMIT ?",
                params,
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _digest(self, canonical: bytes) -> str:
        if self._secret:
            return hmac.new(self._secret, canonical, hashlib.sha256).hexdigest()
        return hashlib.sha256(canonical).hexdigest()


def _canonical_record(
    *,
    recorded_at: str,
    tenant_id: str | None,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    request_id: str,
    outcome: str,
    payload_json: str,
    previous_hash: str,
) -> bytes:
    payload = {
        "action": action,
        "actor": actor,
        "outcome": outcome,
        "payload": json.loads(payload_json),
        "previous_hash": previous_hash,
        "recorded_at": recorded_at,
        "request_id": request_id,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "tenant_id": tenant_id,
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _row_to_record(row: sqlite3.Row) -> AuditRecord:
    return AuditRecord(
        sequence=int(row["sequence"]),
        recorded_at=datetime.fromisoformat(row["recorded_at"]).astimezone(UTC),
        tenant_id=row["tenant_id"],
        actor=row["actor"],
        action=row["action"],
        resource_type=row["resource_type"],
        resource_id=row["resource_id"],
        request_id=row["request_id"],
        outcome=row["outcome"],
        payload=json.loads(row["payload_json"]),
        previous_hash=row["previous_hash"],
        record_hash=row["record_hash"],
    )


def _bounded_text(value: object, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise AuditLedgerError(f"audit {field} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > limit:
        raise AuditLedgerError(f"audit {field} must be between 1 and {limit} characters")
    return normalized


def _optional_bounded_text(value: object, field: str, limit: int) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, field, limit)
