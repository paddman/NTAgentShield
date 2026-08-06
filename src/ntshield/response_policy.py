from __future__ import annotations

from .models import ActionDecision, ActionRequest, Incident


class ResponsePolicy:
    """Decision layer only. It deliberately does not execute response actions."""

    AUTOMATIC = {
        "collect_hash",
        "collect_process_tree",
        "collect_network_connections",
        "search_ioc",
        "snapshot_metadata",
        "preserve_log_window",
    }
    APPROVAL_REQUIRED = {
        "block_ip",
        "isolate_host",
        "kill_process",
        "disable_user",
        "stop_service",
        "quarantine_file",
        "apply_waf_virtual_patch",
    }
    DENIED = {
        "delete_evidence",
        "format_disk",
        "execute_shell",
        "dump_credentials",
        "disable_auditing",
        "erase_logs",
    }

    def decide(self, request: ActionRequest, incident: Incident) -> ActionDecision:
        action = request.action.strip().lower()
        if action in self.DENIED:
            return ActionDecision(
                action=action,
                decision="denied",
                reason="Action violates evidence-preservation or least-privilege policy.",
                risk_score=incident.risk_score,
            )
        if action in self.AUTOMATIC:
            return ActionDecision(
                action=action,
                decision="allowed",
                reason="Read-only evidence collection is allowed automatically.",
                risk_score=incident.risk_score,
            )
        if action in self.APPROVAL_REQUIRED:
            return ActionDecision(
                action=action,
                decision="approval_required",
                reason=(
                    "Containment changes system state and requires a human approval or a "
                    "separately signed deterministic playbook."
                ),
                risk_score=incident.risk_score,
            )
        return ActionDecision(
            action=action,
            decision="denied",
            reason="Unknown actions fail closed.",
            risk_score=incident.risk_score,
        )
