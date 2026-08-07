from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path


class EnrollmentNonceStore:
    def __init__(self, database_path: str | Path):
        self._path = Path(database_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS enrollment_nonces (
                    nonce TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    consumed_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
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

    def close(self) -> None:
        with self._lock:
            self._conn.close()
