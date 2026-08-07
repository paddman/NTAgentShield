from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


@dataclass(frozen=True)
class EnrollmentClaims:
    tenant_id: str
    nonce: str
    issued_at: datetime
    expires_at: datetime


class EnrollmentTokenManager:
    def __init__(self, secret: str):
        secret = secret.strip()
        if len(secret) < 32:
            raise ValueError("enrollment signing secret must contain at least 32 characters")
        self._secret = secret.encode("utf-8")

    def issue(self, tenant_id: str, ttl_seconds: int = 600) -> str:
        _validate_id("tenant_id", tenant_id)
        if ttl_seconds < 60 or ttl_seconds > 86400:
            raise ValueError("enrollment token TTL must be between 60 and 86400 seconds")
        now = datetime.now(UTC)
        payload = {
            "tenant_id": tenant_id,
            "nonce": secrets.token_urlsafe(24),
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        }
        encoded = _b64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signature = hmac.new(self._secret, encoded.encode("ascii"), hashlib.sha256).digest()
        return f"{encoded}.{_b64url_encode(signature)}"

    def verify(self, token: str, tenant_id: str) -> EnrollmentClaims:
        _validate_id("tenant_id", tenant_id)
        parts = token.strip().split(".")
        if len(parts) != 2:
            raise ValueError("invalid enrollment token format")
        encoded, supplied_signature = parts
        expected = hmac.new(self._secret, encoded.encode("ascii"), hashlib.sha256).digest()
        try:
            decoded_signature = _b64url_decode(supplied_signature)
        except Exception as exc:
            raise ValueError("invalid enrollment token signature encoding") from exc
        if not hmac.compare_digest(expected, decoded_signature):
            raise ValueError("invalid enrollment token signature")
        try:
            payload = json.loads(_b64url_decode(encoded))
            token_tenant = str(payload["tenant_id"])
            nonce = str(payload["nonce"])
            issued_at = datetime.fromtimestamp(int(payload["iat"]), tz=UTC)
            expires_at = datetime.fromtimestamp(int(payload["exp"]), tz=UTC)
        except Exception as exc:
            raise ValueError("invalid enrollment token claims") from exc
        now = datetime.now(UTC)
        if token_tenant != tenant_id:
            raise ValueError("enrollment token tenant does not match request")
        if expires_at <= now:
            raise ValueError("enrollment token has expired")
        if issued_at > now + timedelta(minutes=5):
            raise ValueError("enrollment token issued_at is in the future")
        if not nonce or len(nonce) > 256:
            raise ValueError("invalid enrollment token nonce")
        return EnrollmentClaims(
            tenant_id=token_tenant,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )


class CertificateAuthority:
    def __init__(self, cert_path: str | Path, key_path: str | Path):
        self.cert_path = Path(cert_path)
        self.key_path = Path(key_path)
        self.certificate = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        self.private_key = serialization.load_pem_private_key(
            self.key_path.read_bytes(), password=None
        )
        if not _private_key_matches_certificate(self.private_key, self.certificate):
            raise ValueError("enrollment CA private key does not match CA certificate")
        try:
            constraints = self.certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound as exc:
            raise ValueError("enrollment CA certificate is missing BasicConstraints") from exc
        if not constraints.ca:
            raise ValueError("enrollment CA certificate is not a CA")

    def issue_client_certificate(
        self,
        csr_pem: str,
        agent_id: str,
        tenant_id: str,
        ttl_hours: int = 720,
    ) -> tuple[str, str, datetime]:
        _validate_id("agent_id", agent_id)
        _validate_id("tenant_id", tenant_id)
        if ttl_hours < 1 or ttl_hours > 2160:
            raise ValueError("client certificate TTL must be between 1 and 2160 hours")
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        except ValueError as exc:
            raise ValueError("invalid enrollment CSR") from exc
        if not csr.is_signature_valid:
            raise ValueError("enrollment CSR signature is invalid")
        _validate_csr_key(csr.public_key())

        now = datetime.now(UTC)
        expires_at = min(
            now + timedelta(hours=ttl_hours),
            self.certificate.not_valid_after_utc - timedelta(minutes=1),
        )
        if expires_at <= now:
            raise ValueError("enrollment CA certificate is expired or too close to expiry")
        uri = f"spiffe://ntshield/tenant/{quote(tenant_id, safe='')}/agent/{quote(agent_id, safe='')}"
        certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, tenant_id),
                    ]
                )
            )
            .issuer_name(self.certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=2))
            .not_valid_after(expires_at)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=False
            )
            .sign(self.private_key, hashes.SHA256())
        )
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        ca_pem = self.certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        return cert_pem, ca_pem, expires_at


def initialize_ca(cert_path: str | Path, key_path: str | Path, years: int = 10) -> None:
    if years < 1 or years > 30:
        raise ValueError("CA lifetime must be between 1 and 30 years")
    cert_path = Path(cert_path)
    key_path = Path(key_path)
    if cert_path.exists() or key_path.exists():
        raise FileExistsError("refusing to overwrite an existing enrollment CA")
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NTAgentShield Enrollment CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365 * years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    key_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    key_path.write_bytes(key_bytes)
    key_path.chmod(0o600)
    cert_path.write_bytes(cert_bytes)
    cert_path.chmod(0o644)


def _validate_id(name: str, value: str) -> None:
    if not _ID_PATTERN.fullmatch(value.strip()):
        raise ValueError(f"{name} contains unsupported characters or length")


def _validate_csr_key(public_key: object) -> None:
    if public_key.__class__.__name__ != "Ed25519PublicKey":
        raise ValueError("agent enrollment CSR must use an Ed25519 public key")


def _private_key_matches_certificate(private_key: object, certificate: x509.Certificate) -> bool:
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hmac.compare_digest(private_public, certificate_public)
