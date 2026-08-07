from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID


def verify_agent_payload(certificate_pem: str, payload: bytes, signature_b64: str) -> None:
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

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid Agent signature encoding") from exc
    try:
        public_key.verify(signature, payload)
    except Exception as exc:
        raise ValueError("Agent telemetry signature verification failed") from exc
