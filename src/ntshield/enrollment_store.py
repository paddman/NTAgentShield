from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class AgentEnrollment:
    agent_id: str
    tenant_id: str
    certificate_pem: str
    enrolled_at: datetime
    certificate_updated_at: datetime
    expires_at: datetime
    last_seen_at: datetime | None = None
    revoked_at: datetime | None = None
    rotation_count: int = 0

    @property
    def active(self) -> bool:
        now = datetime.now(UTC)
        return self.revoked_at is None and self.expires_at > now

    @property
    def status(self) -> str:
        if self.revoked_at is not None:
            return "revoked"
        if self.expires_at <= datetime.now(UTC):
            return "expired"
        return "active"


class EnrollmentNonceStore:
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
                CREATE TABLE IF NOT EXISTS enrollment_nonces (
                    nonce TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    consumed_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agent_enrollments (
                    tenant_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    certificate_pem TEXT NOT NULL,
                    enrolled_at TEXT NOT NULL,
                    certificate_updated_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    last_seen_at TEXT,
                    revoked_at TEXT,
                    rotation_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (tenant_id, agent_id)
                );
                """
            )
            self._ensure_column(
                "agent_enrollments", "certificate_updated_at", "TEXT"
            )
            self._ensure_column("agent_enrollments", "last_seen_at", "TEXT")
            self._ensure_column(
                "agent_enrollments", "rotation_count", "INTEGER NOT NULL DEFAULT 0"
            )
            self._conn.execute(
                """UPDATE agent_enrollments
                SET certificate_updated_at = enrolled_at
                WHERE certificate_updated_at IS NULL OR certificate_updated_at = ''"""
            )
            self._conn.commit()

    def _ensure_column(self, table: str, column: str, declaration: str) -> None:
        columns = {
            row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

    def consume(self, nonce: str, tenant_id: str, expires_at: datetime) -> bool:
        now = datetime.now(UTC)
        with self._lock:
            self._conn.execute(
                "DELETE FROM enrollment_nonces WHERE expires_at < ?", (now.isoformat(),)
            )
            try:
                self._conn.execute(
                    """INSERT INTO enrollment_nonces
                    (nonce, tenant_id, consumed_at, expires_at) VALUES (?, ?, ?, ?)""",
                    (nonce, tenant_id, now.isoformat(), expires_at.isoformat()),
                )
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return False
            self._conn.commit()
            return True

    def register_agent(
        self,
        agent_id: str,
        tenant_id: str,
        certificate_pem: str,
        expires_at: datetime,
    ) -> AgentEnrollment:
        now = datetime.now(UTC)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO agent_enrollments
                    (tenant_id, agent_id, certificate_pem, enrolled_at,
                     certificate_updated_at, expires_at, last_seen_at, revoked_at,
                     rotation_count)
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, 0)
                ON CONFLICT(tenant_id, agent_id) DO UPDATE SET
                    certificate_pem = excluded.certificate_pem,
                    enrolled_at = excluded.enrolled_at,
                    certificate_updated_at = excluded.certificate_updated_at,
                    expires_at = excluded.expires_at,
                    last_seen_at = NULL,
                    revoked_at = NULL,
                    rotation_count = 0
                """,
                (
                    tenant_id,
                    agent_id,
                    certificate_pem,
                    now.isoformat(),
                    now.isoformat(),
                    expires_at.isoformat(),
                ),
            )
            self._conn.commit()
        return AgentEnrollment(
            agent_id=agent_id,
            tenant_id=tenant_id,
            certificate_pem=certificate_pem,
            enrolled_at=now,
            certificate_updated_at=now,
            expires_at=expires_at,
        )

    def rotate_agent_certificate(
        self,
        agent_id: str,
        tenant_id: str,
        certificate_pem: str,
        expires_at: datetime,
    ) -> AgentEnrollment | None:
        now = datetime.now(UTC)
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE agent_enrollments
                SET certificate_pem = ?, certificate_updated_at = ?, expires_at = ?,
                    rotation_count = rotation_count + 1
                WHERE tenant_id = ? AND agent_id = ? AND revoked_at IS NULL
                """,
                (
                    certificate_pem,
                    now.isoformat(),
                    expires_at.isoformat(),
                    tenant_id,
                    agent_id,
                ),
            )
            self._conn.commit()
            if cursor.rowcount == 0:
                return None
        return self.get_agent(tenant_id, agent_id)

    def get_agent(self, tenant_id: str, agent_id: str) -> AgentEnrollment | None:
        with self._lock:
            row = self._conn.execute(
                """SELECT tenant_id, agent_id, certificate_pem, enrolled_at,
                certificate_updated_at, expires_at, last_seen_at, revoked_at, rotation_count
                FROM agent_enrollments WHERE tenant_id = ? AND agent_id = ?""",
                (tenant_id, agent_id),
            ).fetchone()
        return self._row_to_agent(row) if row is not None else None

    def list_agents(self, tenant_id: str | None = None) -> list[AgentEnrollment]:
        with self._lock:
            if tenant_id:
                rows = self._conn.execute(
                    """SELECT tenant_id, agent_id, certificate_pem, enrolled_at,
                    certificate_updated_at, expires_at, last_seen_at, revoked_at,
                    rotation_count FROM agent_enrollments
                    WHERE tenant_id = ? ORDER BY agent_id""",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """SELECT tenant_id, agent_id, certificate_pem, enrolled_at,
                    certificate_updated_at, expires_at, last_seen_at, revoked_at,
                    rotation_count FROM agent_enrollments
                    ORDER BY tenant_id, agent_id"""
                ).fetchall()
        return [self._row_to_agent(row) for row in rows]

    def mark_seen(self, tenant_id: str, agent_id: str, seen_at: datetime | None = None) -> bool:
        # Fleet presence is Control Plane receipt time, not endpoint event time. Delayed outbox
        # delivery must not make an Agent appear to move backwards in time.
        _ = seen_at
        value = datetime.now(UTC).isoformat()
        with self._lock:
            cursor = self._conn.execute(
                """UPDATE agent_enrollments SET last_seen_at = ?
                WHERE tenant_id = ? AND agent_id = ? AND revoked_at IS NULL""",
                (value, tenant_id, agent_id),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def revoke_agent(self, tenant_id: str, agent_id: str) -> bool:
        revoked_at = datetime.now(UTC).isoformat()
        with self._lock:
            cursor = self._conn.execute(
                """UPDATE agent_enrollments SET revoked_at = ?
                WHERE tenant_id = ? AND agent_id = ? AND revoked_at IS NULL""",
                (revoked_at, tenant_id, agent_id),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    @staticmethod
    def _row_to_agent(row: sqlite3.Row) -> AgentEnrollment:
        return AgentEnrollment(
            agent_id=row["agent_id"],
            tenant_id=row["tenant_id"],
            certificate_pem=row["certificate_pem"],
            enrolled_at=datetime.fromisoformat(row["enrolled_at"]),
            certificate_updated_at=datetime.fromisoformat(
                row["certificate_updated_at"] or row["enrolled_at"]
            ),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            last_seen_at=(
                datetime.fromisoformat(row["last_seen_at"]) if row["last_seen_at"] else None
            ),
            revoked_at=(
                datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None
            ),
            rotation_count=int(row["rotation_count"] or 0),
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
