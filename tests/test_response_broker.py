from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ntshield.response_broker import (
    RESPONSE_SCHEMA,
    ResponseBrokerStore,
    create_signed_response_lease,
    initialize_response_signing_key,
)
from ntshield.mcp_server import build_firewall_port_args, propose_firewall_port


def test_response_action_requires_explicit_approval_before_dispatch(tmp_path) -> None:
    private_key = tmp_path / "response.key"
    public_key = tmp_path / "response.pub"
    initialize_response_signing_key(private_key, public_key)
    store = ResponseBrokerStore(tmp_path / "ntshield.db")
    try:
        action = store.create_action(
            tenant_id="tenant-a",
            agent_id="agent-a",
            tool="process.terminate",
            args={"pid": 4242},
            reason="contain confirmed malicious process",
            requested_by="soc-proposer",
            ttl_seconds=300,
            incident_id="inc-1",
        )
        assert action.status == "proposed"
        assert store.next_for_agent("tenant-a", "agent-a") is None

        approved = store.approve(action.action_id, "soc-approver")
        assert approved.status == "approved"
        assert approved.approved_by == "soc-approver"

        dispatched = store.next_for_agent("tenant-a", "agent-a")
        assert dispatched is not None
        assert dispatched.action_id == action.action_id
        assert dispatched.status == "dispatched"
        assert dispatched.dispatch_count == 1

        lease = create_signed_response_lease(dispatched, private_key, lease_seconds=60)
        payload = base64.b64decode(lease.payload_b64, validate=True)
        assert hashlib.sha256(payload).hexdigest() == lease.sha256
        decoded = json.loads(payload)
        assert decoded["schema"] == RESPONSE_SCHEMA
        assert decoded["tenant_id"] == "tenant-a"
        assert decoded["agent_id"] == "agent-a"
        assert decoded["tool"] == "process.terminate"
        assert decoded["approved_by"] == "soc-approver"

        public = serialization.load_pem_public_key(public_key.read_bytes())
        assert isinstance(public, ed25519.Ed25519PublicKey)
        public.verify(base64.b64decode(lease.signature_b64, validate=True), payload)
    finally:
        store.close()


def test_response_result_is_terminal_and_identity_bound(tmp_path) -> None:
    store = ResponseBrokerStore(tmp_path / "ntshield.db")
    try:
        action = store.create_action(
            tenant_id="tenant-a",
            agent_id="agent-a",
            tool="process.terminate",
            args={"pid": 5000},
            reason="contain",
            requested_by="proposer",
        )
        store.approve(action.action_id, "approver")
        store.next_for_agent("tenant-a", "agent-a")

        result = {
            "action_id": action.action_id,
            "tenant_id": "tenant-a",
            "agent_id": "agent-a",
            "tool": "process.terminate",
            "status": "succeeded",
            "decision_reason": "exact action approved by operator",
            "error": None,
            "executed_at": datetime.now(UTC).isoformat(),
            "data": {"pid": 5000, "terminated": True},
        }
        completed = store.complete(action.action_id, "tenant-a", "agent-a", result)
        assert completed.status == "succeeded"
        assert completed.result == result
        assert store.next_for_agent("tenant-a", "agent-a") is None

        replay = store.complete(action.action_id, "tenant-a", "agent-a", result)
        assert replay.status == "succeeded"
        assert replay.result == result

        with pytest.raises(ValueError, match="identity"):
            store.complete(action.action_id, "tenant-b", "agent-a", result)
    finally:
        store.close()


def test_response_broker_rejects_unapproved_or_unknown_tool(tmp_path) -> None:
    store = ResponseBrokerStore(tmp_path / "ntshield.db")
    try:
        with pytest.raises(ValueError, match="unsupported response tool"):
            store.create_action(
                tenant_id="tenant-a",
                agent_id="agent-a",
                tool="shell.exec",
                args={"command": "whoami"},
                reason="must never become a generic shell",
                requested_by="operator",
            )

        action = store.create_action(
            tenant_id="tenant-a",
            agent_id="agent-a",
            tool="process.terminate",
            args={"pid": 6000},
            reason="contain",
            requested_by="operator",
        )
        with pytest.raises(ValueError, match="approved"):
            create_signed_response_lease(
                action,
                tmp_path / "missing.key",
                lease_seconds=60,
            )
    finally:
        store.close()


def test_response_broker_rejects_self_approval_and_invalid_firewall_args(tmp_path) -> None:
    store = ResponseBrokerStore(tmp_path / "ntshield.db")
    try:
        with pytest.raises(ValueError, match="firewall.port"):
            store.create_action(
                tenant_id="tenant-a",
                agent_id="agent-a",
                tool="firewall.port",
                args={"operation": "open", "protocol": "TCP", "direction": "inbound", "port": 0},
                reason="unsafe port",
                requested_by="operator",
            )
        action = store.create_action(
            tenant_id="tenant-a",
            agent_id="agent-a",
            tool="firewall.port",
            args={"operation": "open", "protocol": "tcp", "direction": "inbound", "port": 8443},
            reason="open approved service port",
            requested_by="operator",
        )
        assert action.args["protocol"] == "TCP"
        with pytest.raises(ValueError, match="requester"):
            store.approve(action.action_id, "operator")
        assert store.approve(action.action_id, "security-approver").status == "approved"
    finally:
        store.close()


def test_mcp_firewall_port_creates_typed_proposal_without_approval(tmp_path) -> None:
    store = ResponseBrokerStore(tmp_path / "ntshield.db")
    try:
        summary = propose_firewall_port(
            store,
            tenant_id="tenant-a",
            agent_id="agent-a",
            operation="open",
            protocol="tcp",
            direction="inbound",
            port=8443,
            reason="เปิด HTTPS ชั่วคราวสำหรับ incident inc-9",
            requested_by="central-workflow",
            incident_id="inc-9",
        )
        assert summary["tool"] == "firewall.port"
        assert summary["status"] == "proposed"
        assert summary["requires_approval"] is True
        assert summary["args"] == {
            "operation": "open",
            "protocol": "TCP",
            "direction": "inbound",
            "port": 8443,
        }
        assert store.next_for_agent("tenant-a", "agent-a") is None
    finally:
        store.close()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"operation": "delete", "protocol": "TCP", "direction": "inbound", "port": 443},
        {"operation": "open", "protocol": "ICMP", "direction": "inbound", "port": 443},
        {"operation": "open", "protocol": "TCP", "direction": "sideways", "port": 443},
        {"operation": "open", "protocol": "TCP", "direction": "inbound", "port": 65536},
    ],
)
def test_mcp_firewall_port_rejects_unsafe_schema(kwargs) -> None:
    with pytest.raises(ValueError):
        build_firewall_port_args(**kwargs)
