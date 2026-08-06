from __future__ import annotations

from datetime import UTC, datetime

from ntshield.models import ActionRequest, Incident
from ntshield.response_policy import ResponsePolicy


def _incident() -> Incident:
    now = datetime.now(UTC)
    return Incident(
        incident_id="inc-1",
        tenant_id="tenant-a",
        asset_id="server-1",
        title="test",
        severity="high",
        risk_score=82,
        confidence=0.9,
        created_at=now,
        updated_at=now,
        event_ids=["e1"],
        fingerprint="fp",
    )


def test_response_policy_is_read_only_by_default() -> None:
    policy = ResponsePolicy()
    incident = _incident()
    assert (
        policy.decide(
            ActionRequest(incident_id="inc-1", action="collect_process_tree"), incident
        ).decision
        == "allowed"
    )
    assert (
        policy.decide(ActionRequest(incident_id="inc-1", action="isolate_host"), incident).decision
        == "approval_required"
    )
    assert (
        policy.decide(ActionRequest(incident_id="inc-1", action="execute_shell"), incident).decision
        == "denied"
    )
