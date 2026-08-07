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
    expires_at: datetime
    revoked_at: datetime | None = None

    @property
    def active(self) -> bool:
        now = datetime.now(UTC)
        return self.revoked_at is None and self.expires_at > now


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
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    PRIMARY KEY (tenant_id, agent_id)
                );
                """
            )
            self._conn.commit()

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
        enrolled_at = datetime.now(UTC)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO agent_enrollments
                    (tenant_id, agent_id, certificate_pem, enrolled_at, expires_at, revoked_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                ON CONFLICT(tenant_id, agent_id) DO UPDATE SET
                    certificate_pem = excluded.certificate_pem,
                    enrolled_at = excluded.enrolled_at,
                    expires_at = excluded.expires_at,
                    revoked_at = NULL
                """,
                (
                    tenant_id,
                    agent_id,
                    certificate_pem,
                    enrolled_at.isoformat(),
                    expires_at.isoformat(),
                ),
            )
            self._conn.commit()
        return AgentEnrollment(
            agent_id=agent_id,
            tenant_id=tenant_id,
            certificate_pem=certificate_pem,
            enrolled_at=enrolled_at,
            expires_at=expires_at,
        )

    def get_agent(self, tenant_id: str, agent_id: str) -> AgentEnrollment | None:
        with self._lock:
            row = self._conn.execute(
                """SELECT tenant_id, agent_id, certificate_pem, enrolled_at, expires_at, revoked_at
                FROM agent_enrollments WHERE tenant_id = ? AND agent_id = ?""",
                (tenant_id, agent_id),
            ).fetchone()
        if row is None:
            return None
        return AgentEnrollment(
            agent_id=row["agent_id"],
            tenant_id=row["tenant_id"],
            certificate_pem=row["certificate_pem"],
            enrolled_at=datetime.fromisoformat(row["enrolled_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            revoked_at=(
                datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None
            ),
        )

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

    def close(self) -> None:
        with self._lock:
            self._conn.close()
