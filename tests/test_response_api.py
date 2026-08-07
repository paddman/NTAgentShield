from __future__ import annotations

import base64
import json
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from ntshield.app import create_app
from ntshield.enrollment import CertificateAuthority, initialize_ca
from ntshield.response_api import agent_get_message
from ntshield.response_broker import (
    ResponseBrokerStore,
    initialize_response_signing_key,
)
from ntshield.settings import Settings


def _configured_app(tmp_path):
    ca_cert = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
    response_private = tmp_path / "response-signing.key"
    response_public = tmp_path / "response-signing.pub"
    initialize_ca(ca_cert, ca_key, years=1)
    initialize_response_signing_key(response_private, response_public)
    settings = Settings(
        database_path=tmp_path / "ntshield.db",
        qwen_enabled=False,
        enrollment_enabled=True,
        enrollment_signing_secret="s" * 32,
        enrollment_ca_cert_path=ca_cert,
        enrollment_ca_key_path=ca_key,
        enrollment_client_cert_ttl_hours=24,
        response_signing_private_key_path=response_private,
        response_signing_public_key_path=response_public,
        response_lease_seconds=60,
        allowed_origins=[],
    )
    app = create_app(settings)
    agent_key = ed25519.Ed25519PrivateKey.generate()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-a")]))
        .sign(agent_key, algorithm=None)
    )
    authority = CertificateAuthority(ca_cert, ca_key)
    certificate_pem, _, expires_at = authority.issue_client_certificate(
        csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "agent-a",
        "tenant-a",
        ttl_hours=24,
    )
    app.state.ntshield.enrollment_nonces.register_agent(
        "agent-a", "tenant-a", certificate_pem, expires_at
    )
    store = ResponseBrokerStore(settings.database_path)
    try:
        action = store.create_action(
            tenant_id="tenant-a",
            agent_id="agent-a",
            tool="process.terminate",
            args={"pid": 4242},
            reason="contain",
            requested_by="proposer",
        )
        store.approve(action.action_id, "approver")
    finally:
        store.close()
    return app, settings, agent_key, action.action_id


def _get_headers(private_key: ed25519.Ed25519PrivateKey, path: str) -> dict[str, str]:
    timestamp = str(int(time.time()))
    message = agent_get_message(path, "agent-a", "tenant-a", timestamp)
    return {
        "X-NTShield-Agent-ID": "agent-a",
        "X-NTShield-Tenant-ID": "tenant-a",
        "X-NTShield-Timestamp": timestamp,
        "X-NTShield-Signature": base64.b64encode(private_key.sign(message)).decode("ascii"),
    }


def _post_headers(private_key: ed25519.Ed25519PrivateKey, body: bytes) -> dict[str, str]:
    return {
        "X-NTShield-Agent-ID": "agent-a",
        "X-NTShield-Tenant-ID": "tenant-a",
        "X-NTShield-Signature": base64.b64encode(private_key.sign(body)).decode("ascii"),
        "Content-Type": "application/json",
    }


def test_enrolled_agent_pulls_signed_lease_and_acks_signed_result(tmp_path) -> None:
    app, settings, agent_key, action_id = _configured_app(tmp_path)
    with TestClient(app) as client:
        trust = client.get(
            "/v1/agent/response-trust-root",
            headers=_get_headers(agent_key, "/v1/agent/response-trust-root"),
        )
        assert trust.status_code == 200, trust.text
        assert "BEGIN PUBLIC KEY" in trust.json()["public_key_pem"]

        response = client.get(
            "/v1/agent/responses",
            headers=_get_headers(agent_key, "/v1/agent/responses"),
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert set(payload) == {"payload_b64", "signature_b64", "sha256"}
        lease = json.loads(base64.b64decode(payload["payload_b64"]))
        assert lease["action_id"] == action_id
        assert lease["tool"] == "process.terminate"
        assert lease["approved_by"] == "approver"

        result = {
            "action_id": action_id,
            "tenant_id": "tenant-a",
            "agent_id": "agent-a",
            "tool": "process.terminate",
            "status": "succeeded",
            "decision_reason": "exact action approved by operator",
            "error": None,
            "executed_at": "2026-08-07T04:00:00Z",
            "data": {"pid": 4242, "terminated": True},
        }
        body = json.dumps(result, separators=(",", ":"), sort_keys=True).encode()
        ack = client.post(
            f"/v1/agent/responses/{action_id}/result",
            content=body,
            headers=_post_headers(agent_key, body),
        )
        assert ack.status_code == 200, ack.text
        assert ack.json()["status"] == "succeeded"

        no_more = client.get(
            "/v1/agent/responses",
            headers=_get_headers(agent_key, "/v1/agent/responses"),
        )
        assert no_more.status_code == 204

    store = ResponseBrokerStore(settings.database_path)
    try:
        terminal = store.get(action_id)
        assert terminal is not None
        assert terminal.status == "succeeded"
        assert terminal.result == result
    finally:
        store.close()


def test_response_pull_rejects_attacker_signature(tmp_path) -> None:
    app, _, _, _ = _configured_app(tmp_path)
    attacker = ed25519.Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        response = client.get(
            "/v1/agent/responses",
            headers=_get_headers(attacker, "/v1/agent/responses"),
        )
    assert response.status_code == 401
