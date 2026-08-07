from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from ntshield.app import create_app
from ntshield.enrollment import CertificateAuthority, initialize_ca
from ntshield.settings import Settings


def _configured_app(tmp_path):
    ca_cert = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
    initialize_ca(ca_cert, ca_key, years=1)
    settings = Settings(
        database_path=tmp_path / "ntshield.db",
        qwen_enabled=False,
        enrollment_enabled=True,
        enrollment_signing_secret="s" * 32,
        enrollment_ca_cert_path=ca_cert,
        enrollment_ca_key_path=ca_key,
        enrollment_client_cert_ttl_hours=24,
        allowed_origins=[],
    )
    app = create_app(settings)

    private_key = ed25519.Ed25519PrivateKey.generate()
    csr = _csr(private_key, "agent-a")
    authority = CertificateAuthority(ca_cert, ca_key)
    certificate_pem, _, expires_at = authority.issue_client_certificate(
        csr,
        "agent-a",
        "tenant-a",
        ttl_hours=24,
    )
    app.state.ntshield.enrollment_nonces.register_agent(
        "agent-a", "tenant-a", certificate_pem, expires_at
    )
    return app, private_key


def _csr(private_key: ed25519.Ed25519PrivateKey, common_name: str) -> str:
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, algorithm=None)
    )
    return request.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _event_body(tenant_id: str = "tenant-a", agent_id: str = "agent-a") -> bytes:
    payload = {
        "event_id": "evt-agent-transport-1",
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "observed_at": datetime.now(UTC).isoformat(),
        "source_type": "sysmon",
        "event_type": "process.start",
        "asset": {"id": agent_id, "hostname": "web-01", "os": "windows"},
        "process": {"name": "powershell.exe", "parent_name": "w3wp.exe"},
        "message": "signed endpoint telemetry",
        "raw": {"trust": "untrusted_telemetry"},
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _renewal_body(
    private_key: ed25519.Ed25519PrivateKey,
    tenant_id: str = "tenant-a",
    agent_id: str = "agent-a",
) -> bytes:
    payload = {
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "csr_pem": _csr(private_key, agent_id),
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _headers(private_key: ed25519.Ed25519PrivateKey, body: bytes) -> dict[str, str]:
    signature = base64.b64encode(private_key.sign(body)).decode("ascii")
    return {
        "X-NTShield-Agent-ID": "agent-a",
        "X-NTShield-Tenant-ID": "tenant-a",
        "X-NTShield-Signature": signature,
        "Content-Type": "application/json",
    }


def test_signed_agent_event_is_accepted_once_and_updates_last_seen(tmp_path) -> None:
    app, private_key = _configured_app(tmp_path)
    body = _event_body()
    headers = _headers(private_key, body)
    with TestClient(app) as client:
        first = client.post("/v1/agent/events", content=body, headers=headers)
        assert first.status_code == 200, first.text
        assert first.json()["duplicate"] is False

        enrolled = app.state.ntshield.enrollment_nonces.get_agent("tenant-a", "agent-a")
        assert enrolled is not None
        assert enrolled.last_seen_at is not None

        replay = client.post("/v1/agent/events", content=body, headers=headers)
        assert replay.status_code == 200, replay.text
        assert replay.json()["duplicate"] is True


def test_signed_agent_event_cannot_cross_tenant_boundary(tmp_path) -> None:
    app, private_key = _configured_app(tmp_path)
    body = _event_body(tenant_id="tenant-b")
    headers = _headers(private_key, body)
    with TestClient(app) as client:
        response = client.post("/v1/agent/events", content=body, headers=headers)
    assert response.status_code == 403


def test_agent_event_rejects_invalid_signature(tmp_path) -> None:
    app, _ = _configured_app(tmp_path)
    attacker_key = ed25519.Ed25519PrivateKey.generate()
    body = _event_body()
    headers = _headers(attacker_key, body)
    with TestClient(app) as client:
        response = client.post("/v1/agent/events", content=body, headers=headers)
    assert response.status_code == 401


def test_certificate_renewal_preserves_agent_identity_and_rotates_registry(tmp_path) -> None:
    app, private_key = _configured_app(tmp_path)
    before = app.state.ntshield.enrollment_nonces.get_agent("tenant-a", "agent-a")
    assert before is not None
    body = _renewal_body(private_key)
    headers = _headers(private_key, body)

    with TestClient(app) as client:
        response = client.post("/v1/agent/certificate/renew", content=body, headers=headers)
        assert response.status_code == 200, response.text

        after = app.state.ntshield.enrollment_nonces.get_agent("tenant-a", "agent-a")
        assert after is not None
        assert after.rotation_count == 1
        assert after.certificate_pem != before.certificate_pem

        renewed = x509.load_pem_x509_certificate(
            response.json()["certificate_pem"].encode("ascii")
        )
        assert renewed.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ) == private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )


def test_certificate_renewal_rejects_identity_key_replacement(tmp_path) -> None:
    app, private_key = _configured_app(tmp_path)
    replacement_key = ed25519.Ed25519PrivateKey.generate()
    payload = {
        "agent_id": "agent-a",
        "tenant_id": "tenant-a",
        "csr_pem": _csr(replacement_key, "agent-a"),
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = _headers(private_key, body)

    with TestClient(app) as client:
        response = client.post("/v1/agent/certificate/renew", content=body, headers=headers)
    assert response.status_code == 422
    assert "identity key" in response.text


def test_revoked_agent_cannot_send_or_renew(tmp_path) -> None:
    app, private_key = _configured_app(tmp_path)
    assert app.state.ntshield.enrollment_nonces.revoke_agent("tenant-a", "agent-a")

    event_body = _event_body()
    renewal_body = _renewal_body(private_key)
    with TestClient(app) as client:
        event_response = client.post(
            "/v1/agent/events", content=event_body, headers=_headers(private_key, event_body)
        )
        renewal_response = client.post(
            "/v1/agent/certificate/renew",
            content=renewal_body,
            headers=_headers(private_key, renewal_body),
        )
    assert event_response.status_code == 401
    assert renewal_response.status_code == 401
