from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from ntshield.enrollment_store import EnrollmentNonceStore


def test_last_seen_uses_control_plane_receive_time(tmp_path) -> None:
    store = EnrollmentNonceStore(tmp_path / "fleet.db")
    try:
        expires = datetime.now(UTC) + timedelta(days=1)
        store.register_agent("agent-a", "tenant-a", "certificate-a", expires)
        stale_event_time = datetime.now(UTC) - timedelta(days=7)
        before = datetime.now(UTC)
        assert store.mark_seen("tenant-a", "agent-a", stale_event_time)
        agent = store.get_agent("tenant-a", "agent-a")
        assert agent is not None
        assert agent.last_seen_at is not None
        assert agent.last_seen_at >= before
        assert agent.last_seen_at > stale_event_time
    finally:
        store.close()


def test_rotation_and_revocation_lifecycle(tmp_path) -> None:
    store = EnrollmentNonceStore(tmp_path / "fleet.db")
    try:
        expires = datetime.now(UTC) + timedelta(days=1)
        store.register_agent("agent-a", "tenant-a", "certificate-a", expires)
        rotated = store.rotate_agent_certificate(
            "agent-a",
            "tenant-a",
            "certificate-b",
            datetime.now(UTC) + timedelta(days=2),
        )
        assert rotated is not None
        assert rotated.rotation_count == 1
        assert rotated.certificate_pem == "certificate-b"
        assert rotated.status == "active"

        assert store.revoke_agent("tenant-a", "agent-a")
        revoked = store.get_agent("tenant-a", "agent-a")
        assert revoked is not None
        assert revoked.status == "revoked"
        assert not revoked.active
        assert store.rotate_agent_certificate(
            "agent-a",
            "tenant-a",
            "certificate-c",
            datetime.now(UTC) + timedelta(days=3),
        ) is None
    finally:
        store.close()


def test_registry_migrates_pr9_schema(tmp_path) -> None:
    database = tmp_path / "fleet.db"
    connection = sqlite3.connect(database)
    try:
        connection.executescript(
            """
            CREATE TABLE agent_enrollments (
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
        now = datetime.now(UTC)
        connection.execute(
            """INSERT INTO agent_enrollments
            (tenant_id, agent_id, certificate_pem, enrolled_at, expires_at, revoked_at)
            VALUES (?, ?, ?, ?, ?, NULL)""",
            (
                "tenant-a",
                "agent-old",
                "certificate-old",
                now.isoformat(),
                (now + timedelta(days=1)).isoformat(),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    store = EnrollmentNonceStore(database)
    try:
        migrated = store.get_agent("tenant-a", "agent-old")
        assert migrated is not None
        assert migrated.certificate_updated_at == migrated.enrolled_at
        assert migrated.last_seen_at is None
        assert migrated.rotation_count == 0
    finally:
        store.close()
