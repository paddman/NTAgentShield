from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

POLICY_SCHEMA = "ntshield-policy/v1"


@dataclass(frozen=True)
class SignedPolicyBundle:
    payload_b64: str
    signature_b64: str
    sha256: str

    def as_dict(self) -> dict[str, str]:
        return {
            "payload_b64": self.payload_b64,
            "signature_b64": self.signature_b64,
            "sha256": self.sha256,
        }


def initialize_policy_signing_key(private_path: Path, public_path: Path) -> None:
    if private_path.exists() or public_path.exists():
        raise FileExistsError("policy signing key already exists; refusing to overwrite trust root")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _atomic_write(private_path, private_bytes, 0o600)
    _atomic_write(public_path, public_bytes, 0o644)


def read_policy_public_key(public_path: Path) -> str | None:
    try:
        content = public_path.read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    public_key = serialization.load_pem_public_key(content.encode("ascii"))
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("policy signing public key must use Ed25519")
    return content


def create_signed_policy_bundle(
    *,
    policy: dict[str, Any],
    tenant_id: str,
    epoch: int,
    private_key_path: Path,
    agent_ids: list[str] | None = None,
    ttl_hours: int = 720,
    now: datetime | None = None,
) -> tuple[SignedPolicyBundle, dict[str, Any]]:
    tenant_id = tenant_id.strip()
    if not tenant_id:
        raise ValueError("tenant_id is required")
    if epoch < 1:
        raise ValueError("policy epoch must be at least 1")
    version = str(policy.get("version", "")).strip()
    if not version:
        raise ValueError("policy version is required")
    if ttl_hours < 1 or ttl_hours > 24 * 365:
        raise ValueError("policy bundle ttl_hours must be between 1 and 8760")
    scope = [item.strip() for item in (agent_ids or ["*"]) if item.strip()]
    if not scope:
        raise ValueError("policy bundle must target at least one Agent or '*'")
    if "*" in scope and len(scope) != 1:
        raise ValueError("'*' Agent scope cannot be combined with explicit Agent IDs")

    issued_at = (now or datetime.now(UTC)).astimezone(UTC)
    payload = {
        "schema": POLICY_SCHEMA,
        "epoch": epoch,
        "version": version,
        "tenant_id": tenant_id,
        "agent_ids": sorted(set(scope)),
        "issued_at": issued_at.isoformat(),
        "expires_at": (issued_at + timedelta(hours=ttl_hours)).isoformat(),
        "policy": policy,
    }
    payload_bytes = json.dumps(
        payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=None
    )
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("policy signing private key must use Ed25519")
    signature = private_key.sign(payload_bytes)
    digest = hashlib.sha256(payload_bytes).hexdigest()
    return (
        SignedPolicyBundle(
            payload_b64=base64.b64encode(payload_bytes).decode("ascii"),
            signature_b64=base64.b64encode(signature).decode("ascii"),
            sha256=digest,
        ),
        payload,
    )


def verify_signed_policy_bundle(
    bundle: SignedPolicyBundle, public_key_path: Path
) -> dict[str, Any]:
    try:
        payload = base64.b64decode(bundle.payload_b64, validate=True)
        signature = base64.b64decode(bundle.signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid policy bundle base64 encoding") from exc
    if hashlib.sha256(payload).hexdigest() != bundle.sha256:
        raise ValueError("policy bundle digest mismatch")
    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("policy signing public key must use Ed25519")
    try:
        public_key.verify(signature, payload)
    except Exception as exc:
        raise ValueError("policy bundle signature verification failed") from exc
    decoded = json.loads(payload)
    if decoded.get("schema") != POLICY_SCHEMA:
        raise ValueError("unsupported policy bundle schema")
    return decoded


class PolicyBundleStore:
    def __init__(self, database_path: str | Path):
        self._path = Path(database_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS signed_policies (
                    tenant_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    version TEXT NOT NULL,
                    agent_ids_json TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    payload_b64 TEXT NOT NULL,
                    signature_b64 TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, epoch)
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_signed_policies_tenant_epoch "
                "ON signed_policies(tenant_id, epoch DESC)"
            )
            self._conn.commit()

    def publish(self, bundle: SignedPolicyBundle, payload: dict[str, Any]) -> None:
        tenant_id = str(payload["tenant_id"])
        epoch = int(payload["epoch"])
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(epoch) AS epoch FROM signed_policies WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            current_epoch = int(row["epoch"] or 0)
            if epoch <= current_epoch:
                raise ValueError(
                    f"policy epoch {epoch} must be greater than current epoch {current_epoch}"
                )
            self._conn.execute(
                """
                INSERT INTO signed_policies
                (tenant_id, epoch, version, agent_ids_json, issued_at, expires_at,
                 payload_b64, signature_b64, sha256, published_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    epoch,
                    str(payload["version"]),
                    json.dumps(payload["agent_ids"], separators=(",", ":")),
                    str(payload["issued_at"]),
                    str(payload["expires_at"]),
                    bundle.payload_b64,
                    bundle.signature_b64,
                    bundle.sha256,
                    datetime.now(UTC).isoformat(),
                ),
            )
            self._conn.commit()

    def latest_for_agent(
        self, tenant_id: str, agent_id: str, now: datetime | None = None
    ) -> SignedPolicyBundle | None:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        with self._lock:
            rows = self._conn.execute(
                """SELECT agent_ids_json, expires_at, payload_b64, signature_b64, sha256
                FROM signed_policies WHERE tenant_id = ? ORDER BY epoch DESC""",
                (tenant_id,),
            ).fetchall()
        for row in rows:
            if datetime.fromisoformat(row["expires_at"]).astimezone(UTC) <= current:
                continue
            scope = json.loads(row["agent_ids_json"])
            if "*" not in scope and agent_id not in scope:
                continue
            return SignedPolicyBundle(
                payload_b64=row["payload_b64"],
                signature_b64=row["signature_b64"],
                sha256=row["sha256"],
            )
        return None

    def list_metadata(self, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if tenant_id:
                rows = self._conn.execute(
                    """SELECT tenant_id, epoch, version, agent_ids_json, issued_at,
                    expires_at, sha256, published_at FROM signed_policies
                    WHERE tenant_id = ? ORDER BY epoch DESC""",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """SELECT tenant_id, epoch, version, agent_ids_json, issued_at,
                    expires_at, sha256, published_at FROM signed_policies
                    ORDER BY tenant_id, epoch DESC"""
                ).fetchall()
        return [
            {
                "tenant_id": row["tenant_id"],
                "epoch": int(row["epoch"]),
                "version": row["version"],
                "agent_ids": json.loads(row["agent_ids_json"]),
                "issued_at": row["issued_at"],
                "expires_at": row["expires_at"],
                "sha256": row["sha256"],
                "published_at": row["published_at"],
            }
            for row in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(content)
    os.chmod(temporary, mode)
    os.replace(temporary, path)
