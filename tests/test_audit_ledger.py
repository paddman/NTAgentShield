from __future__ import annotations

import sqlite3

from ntshield.audit_ledger import AuditLedger


def test_audit_ledger_detects_record_tampering(tmp_path) -> None:
    path = tmp_path / "audit.db"
    ledger = AuditLedger(path, "audit-secret-0123456789-abcdefghijklmnopqrstuvwxyz")
    first = ledger.append(
        actor="alice",
        action="incident.read",
        resource_type="incident",
        resource_id="inc-1",
        request_id="req-1",
        outcome="succeeded",
        tenant_id="tenant-a",
        payload={"field": "value"},
    )
    second = ledger.append(
        actor="bob",
        action="response.approved",
        resource_type="response_action",
        resource_id="rsp-1",
        request_id="req-2",
        outcome="succeeded",
        tenant_id="tenant-a",
        payload={"digest": "a" * 64},
    )
    assert first.previous_hash == "0" * 64
    assert second.previous_hash == first.record_hash
    assert ledger.verify().valid

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE control_audit SET outcome = 'forged' WHERE sequence = ?", (first.sequence,)
        )
        connection.commit()
    finally:
        connection.close()
    verification = ledger.verify()
    assert not verification.valid
    assert "hash mismatch" in (verification.error or "")
    ledger.close()
