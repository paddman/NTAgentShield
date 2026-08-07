from __future__ import annotations

import base64
import time
from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from ntshield.app import create_app, policy_request_message
from ntshield.enrollment import CertificateAuthority, initialize_ca
from ntshield.policy_distribution import (
    PolicyBundleStore,
    SignedPolicyBundle,
    create_signed_policy_bundle,
    initialize_policy_signing_key,
    verify_signed_policy_bundle,
)
from ntshield.settings import Settings


def _policy(version: str = "2") -> dict[str, object]:
    return {
        "version": version,
        "deny_tools": ["shell.exec", "powershell.exec", "cmd.exec"],
        "auto_allow_tools": ["host.info", "file.stat"],
        "approval_required_tools": ["host.isolate"],
        "never_allow_destructive": True,
        "deny_untrusted_state_write": True,
        "max_action_ttl_seconds": 300,
    }


def test_signed_policy_bundle_round_trip_and_monotonic_publish(tmp_path) -> None:
    private_key = tmp_path / "policy.key"
    public_key = tmp_path / "policy.pub"
    initialize_policy_signing_key(private_key, public_key)
    bundle, payload = create_signed_policy_bundle(
        policy=_policy(), tenant_id="tenant-a", epoch=1, private_key_path=private_key
    )
    decoded = verify_signed_policy_bundle(bundle, public_key)
    assert decoded["tenant_id"] == "tenant-a"
    assert decoded["epoch"] == 1
    assert decoded["policy"]["version"] == "2"

    store = PolicyBundleStore(tmp_path / "ntshield.db")
    try:
        store.publish(bundle, payload)
        selected = store.latest_for_agent("tenant-a", "agent-a")
        assert selected == bundle
        with pytest.raises(ValueError, match="greater than current epoch"):
            store.publish(bundle, payload)
    finally:
        store.close()


def test_policy_store_enforces_agent_scope(tmp_path) -> None:
    private_key = tmp_path / "policy.key"
    public_key = tmp_path / "policy.pub"
    initialize_policy_signing_key(private_key, public_key)
    bundle, payload = create_signed_policy_bundle(
        policy=_policy(),
        tenant_id="tenant-a",
        epoch=3,
        private_key_path=private_key,
        agent_ids=["agent-a"],
    )
    store = PolicyBundleStore(tmp_path / "ntshield.db")
    try:
        store.publish(bundle, payload)
        assert store.latest_for_agent("tenant-a", "agent-a") == bundle
        assert store.latest_for_agent("tenant-a", "agent-b") is None
        assert store.latest_for_agent("tenant-b", "agent-a") is None
    finally:
        store.close()


def _configured_policy_app(tmp_path):
    ca_cert = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
    policy_private = tmp_path / "policy-signing.key"
    policy_public = tmp_path / "policy-signing.pub"
    initialize_ca(ca_cert, ca_key, years=1)
    initialize_policy_signing_key(policy_private, policy_public)
    settings = Settings(
        database_path=tmp_path / "ntshield.db",
        qwen_enabled=False,
        enrollment_enabled=True,
        enrollment_signing_secret="s" * 32,
        enrollment_ca_cert_path=ca_cert,
        enrollment_ca_key_path=ca_key,
        enrollment_client_cert_ttl_hours=24,
        policy_signing_private_key_path=policy_private,
        policy_signing_public_key_path=policy_public,
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
    bundle, payload = create_signed_policy_bundle(
        policy=_policy(),
        tenant_id="tenant-a",
        epoch=7,
        private_key_path=policy_private,
    )
    app.state.ntshield.policy_store.publish(bundle, payload)
    return app, agent_key, policy_public


def _policy_headers(
    private_key: ed25519.Ed25519PrivateKey, timestamp: str | None = None
) -> dict[str, str]:
    value = timestamp or str(int(time.time()))
    message = policy_request_message("agent-a", "tenant-a", value)
    return {
        "X-NTShield-Agent-ID": "agent-a",
        "X-NTShield-Tenant-ID": "tenant-a",
        "X-NTShield-Timestamp": value,
        "X-NTShield-Signature": base64.b64encode(private_key.sign(message)).decode("ascii"),
    }


def test_agent_can_pull_only_authenticated_signed_policy(tmp_path) -> None:
    app, agent_key, public_key = _configured_policy_app(tmp_path)
    with TestClient(app) as client:
        response = client.get("/v1/agent/policy", headers=_policy_headers(agent_key))
        assert response.status_code == 200, response.text
        bundle = SignedPolicyBundle(**response.json())
        decoded = verify_signed_policy_bundle(bundle, public_key)
        assert decoded["epoch"] == 7
        enrolled = app.state.ntshield.enrollment_nonces.get_agent("tenant-a", "agent-a")
        assert enrolled is not None and enrolled.last_seen_at is not None


def test_policy_pull_rejects_stale_or_bad_agent_signature(tmp_path) -> None:
    app, agent_key, _ = _configured_policy_app(tmp_path)
    stale = str(int(datetime.now(UTC).timestamp()) - 601)
    attacker = ed25519.Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        stale_response = client.get(
            "/v1/agent/policy", headers=_policy_headers(agent_key, stale)
        )
        bad_response = client.get("/v1/agent/policy", headers=_policy_headers(attacker))
    assert stale_response.status_code == 401
    assert bad_response.status_code == 401
