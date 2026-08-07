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
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-a")]))
        .sign(private_key, algorithm=None)
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
    return app, private_key


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


def _headers(private_key: ed25519.Ed25519PrivateKey, body: bytes) -> dict[str, str]:
    signature = base64.b64encode(private_key.sign(body)).decode("ascii")
    return {
        "X-NTShield-Agent-ID": "agent-a",
        "X-NTShield-Tenant-ID": "tenant-a",
        "X-NTShield-Signature": signature,
        "Content-Type": "application/json",
    }


def test_signed_agent_event_is_accepted_once(tmp_path) -> None:
    app, private_key = _configured_app(tmp_path)
    body = _event_body()
    headers = _headers(private_key, body)
    with TestClient(app) as client:
        first = client.post("/v1/agent/events", content=body, headers=headers)
        assert first.status_code == 200, first.text
        assert first.json()["duplicate"] is False

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
