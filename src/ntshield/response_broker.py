from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

RESPONSE_SCHEMA = "ntshield-response/v1"

RESPONSE_TOOL_RISK: dict[str, str] = {
    "process.terminate": "contain",
    "host.isolate": "contain",
    "file.quarantine": "contain",
    "firewall.block": "contain",
    "firewall.port": "contain",
}

TERMINAL_STATUSES = {"succeeded", "rejected", "failed", "expired"}


@dataclass(frozen=True)
class SignedResponseLease:
    payload_b64: str
    signature_b64: str
    sha256: str

    def as_dict(self) -> dict[str, str]:
        return {
            "payload_b64": self.payload_b64,
            "signature_b64": self.signature_b64,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class ResponseAction:
    action_id: str
    tenant_id: str
    agent_id: str
    incident_id: str | None
    tool: str
    args: dict[str, Any]
    reason: str
    risk: str
    requested_by: str
    requested_at: datetime
    expires_at: datetime
    status: str
    approved_by: str | None = None
    approved_at: datetime | None = None
    dispatch_count: int = 0
    last_dispatched_at: datetime | None = None
    completed_at: datetime | None = None
    result: dict[str, Any] | None = None


def initialize_response_signing_key(private_path: Path, public_path: Path) -> None:
    if private_path.exists() or public_path.exists():
        raise FileExistsError("response signing key already exists; refusing to overwrite trust root")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = ed25519.Ed25519PrivateKey.generate()
    _atomic_write(
        private_path,
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        0o600,
    )
    _atomic_write(
        public_path,
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        0o644,
    )


def read_response_public_key(public_path: Path) -> str | None:
    try:
        content = public_path.read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    public_key = serialization.load_pem_public_key(content.encode("ascii"))
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("response signing public key must use Ed25519")
    return content


def create_signed_response_lease(
    action: ResponseAction,
    private_key_path: Path,
    *,
    lease_seconds: int = 120,
    now: datetime | None = None,
) -> SignedResponseLease:
    if action.status not in {"approved", "dispatched"}:
        raise ValueError("response action must be approved before lease signing")
    if not action.approved_by or action.approved_at is None:
        raise ValueError("response action approval metadata is incomplete")
    if lease_seconds < 15 or lease_seconds > 300:
        raise ValueError("response lease_seconds must be between 15 and 300")
    issued_at = (now or datetime.now(UTC)).astimezone(UTC)
    if action.expires_at <= issued_at:
        raise ValueError("response action has expired")
    lease_expires_at = min(action.expires_at, issued_at + timedelta(seconds=lease_seconds))
    payload = {
        "schema": RESPONSE_SCHEMA,
        "action_id": action.action_id,
        "tenant_id": action.tenant_id,
        "agent_id": action.agent_id,
        "incident_id": action.incident_id,
        "tool": action.tool,
        "args": action.args,
        "reason": action.reason,
        "risk": action.risk,
        "requested_by": action.requested_by,
        "requested_at": action.requested_at.isoformat(),
        "approved_by": action.approved_by,
        "approved_at": action.approved_at.isoformat(),
        "action_expires_at": action.expires_at.isoformat(),
        "lease_issued_at": issued_at.isoformat(),
        "lease_expires_at": lease_expires_at.isoformat(),
    }
    payload_bytes = json.dumps(
        payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=None
    )
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("response signing private key must use Ed25519")
    signature = private_key.sign(payload_bytes)
    return SignedResponseLease(
        payload_b64=base64.b64encode(payload_bytes).decode("ascii"),
        signature_b64=base64.b64encode(signature).decode("ascii"),
        sha256=hashlib.sha256(payload_bytes).hexdigest(),
    )


class ResponseBrokerStore:
    def __init__(self, database_path: str | Path):
        self._path = Path(database_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS response_actions (
                    action_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    incident_id TEXT,
                    tool TEXT NOT NULL,
                    args_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approved_by TEXT,
                    approved_at TEXT,
                    dispatch_count INTEGER NOT NULL DEFAULT 0,
                    last_dispatched_at TEXT,
                    completed_at TEXT,
                    result_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_response_actions_agent_status
                    ON response_actions(tenant_id, agent_id, status, requested_at);
                """
            )
            self._conn.commit()

    def create_action(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        tool: str,
        args: dict[str, Any],
        reason: str,
        requested_by: str,
        ttl_seconds: int = 300,
        incident_id: str | None = None,
    ) -> ResponseAction:
        tenant_id = tenant_id.strip()
        agent_id = agent_id.strip()
        tool = tool.strip()
        requested_by = requested_by.strip()
        reason = reason.strip()
        if not tenant_id or not agent_id or not requested_by or not reason:
            raise ValueError("tenant_id, agent_id, requested_by, and reason are required")
        if tool not in RESPONSE_TOOL_RISK:
            raise ValueError(f"unsupported response tool {tool!r}")
        if ttl_seconds < 30 or ttl_seconds > 900:
            raise ValueError("response ttl_seconds must be between 30 and 900")
        encoded_args = json.dumps(args, separators=(",", ":"), sort_keys=True)
        if len(encoded_args.encode("utf-8")) > 16 * 1024:
            raise ValueError("response args exceed 16 KiB")
        now = datetime.now(UTC)
        action = ResponseAction(
            action_id=f"rsp_{uuid4().hex}",
            tenant_id=tenant_id,
            agent_id=agent_id,
            incident_id=incident_id.strip() if incident_id else None,
            tool=tool,
            args=args,
            reason=reason,
            risk=RESPONSE_TOOL_RISK[tool],
            requested_by=requested_by,
            requested_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            status="proposed",
        )
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO response_actions
                (action_id, tenant_id, agent_id, incident_id, tool, args_json, reason,
                 risk, requested_by, requested_at, expires_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action.action_id,
                    action.tenant_id,
                    action.agent_id,
                    action.incident_id,
                    action.tool,
                    encoded_args,
                    action.reason,
                    action.risk,
                    action.requested_by,
                    action.requested_at.isoformat(),
                    action.expires_at.isoformat(),
                    action.status,
                ),
            )
            self._conn.commit()
        return action

    def approve(self, action_id: str, approved_by: str) -> ResponseAction:
        approved_by = approved_by.strip()
        if not approved_by:
            raise ValueError("approved_by is required")
        now = datetime.now(UTC)
        with self._lock:
            row = self._conn.execute(
                "SELECT status, expires_at FROM response_actions WHERE action_id = ?",
                (action_id,),
            ).fetchone()
            if row is None:
                raise ValueError("response action not found")
            if row["status"] != "proposed":
                raise ValueError("only proposed response actions may be approved")
            if datetime.fromisoformat(row["expires_at"]).astimezone(UTC) <= now:
                self._conn.execute(
                    "UPDATE response_actions SET status = 'expired', completed_at = ? WHERE action_id = ?",
                    (now.isoformat(), action_id),
                )
                self._conn.commit()
                raise ValueError("response action has expired")
            self._conn.execute(
                """UPDATE response_actions
                SET status = 'approved', approved_by = ?, approved_at = ?
                WHERE action_id = ?""",
                (approved_by, now.isoformat(), action_id),
            )
            self._conn.commit()
        action = self.get(action_id)
        assert action is not None
        return action

    def next_for_agent(self, tenant_id: str, agent_id: str) -> ResponseAction | None:
        now = datetime.now(UTC)
        with self._lock:
            self._conn.execute(
                """UPDATE response_actions SET status = 'expired', completed_at = ?
                WHERE tenant_id = ? AND agent_id = ?
                  AND status IN ('proposed', 'approved', 'dispatched') AND expires_at <= ?""",
                (now.isoformat(), tenant_id, agent_id, now.isoformat()),
            )
            row = self._conn.execute(
                """SELECT * FROM response_actions
                WHERE tenant_id = ? AND agent_id = ? AND status IN ('approved', 'dispatched')
                  AND expires_at > ? ORDER BY requested_at LIMIT 1""",
                (tenant_id, agent_id, now.isoformat()),
            ).fetchone()
            if row is None:
                self._conn.commit()
                return None
            self._conn.execute(
                """UPDATE response_actions
                SET status = 'dispatched', dispatch_count = dispatch_count + 1,
                    last_dispatched_at = ? WHERE action_id = ?""",
                (now.isoformat(), row["action_id"]),
            )
            self._conn.commit()
        return self.get(row["action_id"])

    def complete(
        self, action_id: str, tenant_id: str, agent_id: str, result: dict[str, Any]
    ) -> ResponseAction:
        outcome = str(result.get("status", "")).strip().lower()
        if outcome not in {"succeeded", "rejected", "failed"}:
            raise ValueError("response result status must be succeeded, rejected, or failed")
        encoded = json.dumps(result, separators=(",", ":"), sort_keys=True)
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise ValueError("response result exceeds 64 KiB")
        now = datetime.now(UTC)
        with self._lock:
            row = self._conn.execute(
                "SELECT status, tenant_id, agent_id FROM response_actions WHERE action_id = ?",
                (action_id,),
            ).fetchone()
            if row is None:
                raise ValueError("response action not found")
            if row["tenant_id"] != tenant_id or row["agent_id"] != agent_id:
                raise ValueError("response result identity does not match action")
            if row["status"] in TERMINAL_STATUSES:
                action = self.get(action_id)
                assert action is not None
                return action
            if row["status"] not in {"approved", "dispatched"}:
                raise ValueError("response action is not dispatchable")
            self._conn.execute(
                """UPDATE response_actions SET status = ?, completed_at = ?, result_json = ?
                WHERE action_id = ?""",
                (outcome, now.isoformat(), encoded, action_id),
            )
            self._conn.commit()
        action = self.get(action_id)
        assert action is not None
        return action

    def get(self, action_id: str) -> ResponseAction | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM response_actions WHERE action_id = ?", (action_id,)
            ).fetchone()
        return self._row(row) if row is not None else None

    def list_actions(
        self, tenant_id: str | None = None, agent_id: str | None = None
    ) -> list[ResponseAction]:
        clauses: list[str] = []
        params: list[str] = []
        if tenant_id:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM response_actions{where} ORDER BY requested_at DESC", params
            ).fetchall()
        return [self._row(row) for row in rows]

    @staticmethod
    def _row(row: sqlite3.Row) -> ResponseAction:
        return ResponseAction(
            action_id=row["action_id"],
            tenant_id=row["tenant_id"],
            agent_id=row["agent_id"],
            incident_id=row["incident_id"],
            tool=row["tool"],
            args=json.loads(row["args_json"]),
            reason=row["reason"],
            risk=row["risk"],
            requested_by=row["requested_by"],
            requested_at=datetime.fromisoformat(row["requested_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            status=row["status"],
            approved_by=row["approved_by"],
            approved_at=(
                datetime.fromisoformat(row["approved_at"]) if row["approved_at"] else None
            ),
            dispatch_count=int(row["dispatch_count"] or 0),
            last_dispatched_at=(
                datetime.fromisoformat(row["last_dispatched_at"])
                if row["last_dispatched_at"]
                else None
            ),
            completed_at=(
                datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None
            ),
            result=json.loads(row["result_json"]) if row["result_json"] else None,
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(content)
    os.chmod(temporary, mode)
    os.replace(temporary, path)
