from __future__ import annotations

import hashlib
import json
from typing import Any

from ntshield.response_broker import ResponseAction


def response_action_digest(action: ResponseAction) -> str:
    """Hash the immutable, approval-relevant fields of one exact response action."""

    payload = {
        "action_id": action.action_id,
        "agent_id": action.agent_id,
        "args": action.args,
        "expires_at": action.expires_at.isoformat(),
        "incident_id": action.incident_id,
        "reason": action.reason,
        "requested_at": action.requested_at.isoformat(),
        "requested_by": action.requested_by,
        "risk": action.risk,
        "tenant_id": action.tenant_id,
        "tool": action.tool,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def response_action_summary(action: ResponseAction) -> dict[str, Any]:
    return {
        "action_id": action.action_id,
        "tenant_id": action.tenant_id,
        "agent_id": action.agent_id,
        "incident_id": action.incident_id,
        "tool": action.tool,
        "args": action.args,
        "reason": action.reason,
        "risk": action.risk,
        "status": action.status,
        "requested_by": action.requested_by,
        "requested_at": action.requested_at.isoformat(),
        "expires_at": action.expires_at.isoformat(),
        "approved_by": action.approved_by,
        "approved_at": action.approved_at.isoformat() if action.approved_at else None,
        "dispatch_count": action.dispatch_count,
        "last_dispatched_at": (
            action.last_dispatched_at.isoformat() if action.last_dispatched_at else None
        ),
        "completed_at": action.completed_at.isoformat() if action.completed_at else None,
        "result": action.result,
        "action_digest": response_action_digest(action),
        "requires_approval": action.status == "proposed",
    }
