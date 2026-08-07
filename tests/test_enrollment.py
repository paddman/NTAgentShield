from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ntshield.enrollment import CertificateAuthority, EnrollmentTokenManager, initialize_ca
from ntshield.enrollment_store import EnrollmentNonceStore


def test_signed_enrollment_token_is_tenant_scoped() -> None:
    manager = EnrollmentTokenManager("s" * 32)
    token = manager.issue("tenant-a", 600)
    claims = manager.verify(token, "tenant-a")
    assert claims.tenant_id == "tenant-a"
    assert claims.expires_at > datetime.now(UTC)
    with pytest.raises(ValueError, match="tenant"):
        manager.verify(token, "tenant-b")


def test_enrollment_nonce_is_one_time_across_store_calls(tmp_path) -> None:
    store = EnrollmentNonceStore(tmp_path / "ntshield.db")
    try:
        expires = datetime.now(UTC) + timedelta(minutes=10)
        assert store.consume("nonce-1", "tenant-a", expires)
        assert not store.consume("nonce-1", "tenant-a", expires)
    finally:
        store.close()


def test_ca_issues_ed25519_client_certificate(tmp_path) -> None:
    cert_path = tmp_path / "ca.crt"
    key_path = tmp_path / "ca.key"
    initialize_ca(cert_path, key_path, years=1)
    authority = CertificateAuthority(cert_path, key_path)

    private_key = ed25519.Ed25519PrivateKey.generate()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent_demo")]))
        .sign(private_key, algorithm=None)
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    cert_pem, ca_pem, expires_at = authority.issue_client_certificate(
        csr_pem, "agent_demo", "tenant-a", ttl_hours=24
    )

    certificate = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    ca_certificate = x509.load_pem_x509_certificate(ca_pem.encode("ascii"))
    assert certificate.issuer == ca_certificate.subject
    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "agent_demo"
    assert (
        certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    )
    assert certificate.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) == private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert expires_at > datetime.now(UTC)
