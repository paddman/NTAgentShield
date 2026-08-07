from __future__ import annotations

import base64
import binascii
import hmac
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID


def load_active_agent_certificate(certificate_pem: str) -> x509.Certificate:
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
    except ValueError as exc:
        raise ValueError("registered Agent certificate is invalid") from exc

    now = datetime.now(UTC)
    if now < certificate.not_valid_before_utc or now >= certificate.not_valid_after_utc:
        raise ValueError("registered Agent certificate is not currently valid")

    try:
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("registered Agent certificate has no extended key usage") from exc
    if ExtendedKeyUsageOID.CLIENT_AUTH not in usages:
        raise ValueError("registered Agent certificate is not valid for client authentication")

    public_key = certificate.public_key()
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("registered Agent certificate must use Ed25519")
    return certificate


def _verify_ed25519_signature(
    certificate_pem: str, payload: bytes, signature_b64: str, failure_message: str
) -> None:
    certificate = load_active_agent_certificate(certificate_pem)
    public_key = certificate.public_key()
    assert isinstance(public_key, ed25519.Ed25519PublicKey)
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid Agent signature encoding") from exc
    try:
        public_key.verify(signature, payload)
    except Exception as exc:
        raise ValueError(failure_message) from exc


def verify_agent_payload(certificate_pem: str, payload: bytes, signature_b64: str) -> None:
    _verify_ed25519_signature(
        certificate_pem,
        payload,
        signature_b64,
        "Agent telemetry signature verification failed",
    )


def verify_agent_request_signature(
    certificate_pem: str, payload: bytes, signature_b64: str
) -> None:
    _verify_ed25519_signature(
        certificate_pem,
        payload,
        signature_b64,
        "Agent request signature verification failed",
    )


def verify_renewal_csr_identity(certificate_pem: str, csr_pem: str) -> None:
    certificate = load_active_agent_certificate(certificate_pem)
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except ValueError as exc:
        raise ValueError("invalid certificate renewal CSR") from exc
    if not csr.is_signature_valid:
        raise ValueError("certificate renewal CSR signature is invalid")

    current_public = certificate.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    requested_key = csr.public_key()
    if not isinstance(requested_key, ed25519.Ed25519PublicKey):
        raise ValueError("certificate renewal CSR must use Ed25519")
    requested_public = requested_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if not hmac.compare_digest(current_public, requested_public):
        raise ValueError("certificate renewal cannot replace the enrolled Agent identity key")
