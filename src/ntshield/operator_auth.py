from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Iterable

TOKEN_VERSION = "ntsop1"
MAX_TOKEN_BYTES = 8192
MIN_SECRET_BYTES = 32
MAX_TOKEN_TTL_SECONDS = 24 * 60 * 60
SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$")
TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$")

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"read"}),
    "analyst": frozenset({"read", "analyze", "fleet.read"}),
    "ingester": frozenset({"ingest"}),
    "responder": frozenset({"read", "respond.propose"}),
    "approver": frozenset({"read", "respond.approve"}),
    "auditor": frozenset({"read", "audit.read", "metrics.read"}),
    "tenant_admin": frozenset(
        {
            "read",
            "analyze",
            "ingest",
            "fleet.read",
            "respond.propose",
            "respond.approve",
            "audit.read",
            "metrics.read",
        }
    ),
    "platform_admin": frozenset({"*"}),
}


class AuthenticationError(ValueError):
    """Raised when an operator token cannot be authenticated."""


class AuthorizationError(PermissionError):
    """Raised when an authenticated operator lacks the required permission."""


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    roles: frozenset[str]
    tenant_ids: frozenset[str]
    issuer: str
    issued_at: int
    expires_at: int
    token_id: str

    @property
    def permissions(self) -> frozenset[str]:
        values: set[str] = set()
        for role in self.roles:
            values.update(ROLE_PERMISSIONS.get(role, ()))
        return frozenset(values)

    @property
    def is_platform_admin(self) -> bool:
        return "platform_admin" in self.roles

    def has_permission(self, permission: str) -> bool:
        permissions = self.permissions
        return "*" in permissions or permission in permissions

    def can_access_tenant(self, tenant_id: str) -> bool:
        return self.is_platform_admin or "*" in self.tenant_ids or tenant_id in self.tenant_ids

    def require(self, permission: str, tenant_id: str | None = None) -> None:
        if not self.has_permission(permission):
            raise AuthorizationError(f"missing permission: {permission}")
        if tenant_id is not None and not self.can_access_tenant(tenant_id):
            raise AuthorizationError("tenant access denied")

    def as_safe_dict(self) -> dict[str, object]:
        return {
            "subject": self.subject,
            "roles": sorted(self.roles),
            "tenant_ids": sorted(self.tenant_ids),
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "token_id": self.token_id,
        }


class OperatorTokenManager:
    """Issue and verify compact HMAC-bound operator bearer tokens.

    This is the built-in control-plane bootstrap mechanism. Large deployments may
    terminate OIDC/SAML at a trusted identity-aware proxy, but every request still
    needs to arrive at NTAgentShield with an authenticated principal and explicit
    tenant claims. The local token format is intentionally small and dependency-free.
    """

    def __init__(self, secret: str | bytes, issuer: str = "ntshield-control"):
        encoded = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        if len(encoded) < MIN_SECRET_BYTES:
            raise ValueError(f"operator signing secret must be at least {MIN_SECRET_BYTES} bytes")
        if not issuer or len(issuer) > 128:
            raise ValueError("operator token issuer must be between 1 and 128 characters")
        self._secret = encoded
        self.issuer = issuer

    def issue(
        self,
        *,
        subject: str,
        roles: Iterable[str],
        tenant_ids: Iterable[str],
        ttl_seconds: int = 3600,
        now: int | None = None,
        token_id: str | None = None,
    ) -> str:
        issued_at = int(time.time() if now is None else now)
        if ttl_seconds < 60 or ttl_seconds > MAX_TOKEN_TTL_SECONDS:
            raise ValueError(
                f"operator token ttl_seconds must be between 60 and {MAX_TOKEN_TTL_SECONDS}"
            )
        normalized_subject = _validate_identifier(subject, "subject", SUBJECT_RE)
        normalized_roles = _normalize_roles(roles)
        normalized_tenants = _normalize_tenants(tenant_ids, normalized_roles)
        jti = token_id or secrets.token_urlsafe(18)
        if len(jti) > 128:
            raise ValueError("operator token id exceeds 128 characters")
        claims = {
            "exp": issued_at + ttl_seconds,
            "iat": issued_at,
            "iss": self.issuer,
            "jti": jti,
            "roles": sorted(normalized_roles),
            "sub": normalized_subject,
            "tenants": sorted(normalized_tenants),
        }
        payload = json.dumps(
            claims,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        payload_b64 = _b64url_encode(payload)
        signing_input = f"{TOKEN_VERSION}.{payload_b64}".encode("ascii")
        signature = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        return f"{TOKEN_VERSION}.{payload_b64}.{_b64url_encode(signature)}"

    def verify(self, token: str, *, now: int | None = None, clock_skew_seconds: int = 30) -> Principal:
        if not token or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
            raise AuthenticationError("operator token is missing or too large")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != TOKEN_VERSION:
            raise AuthenticationError("unsupported operator token format")
        payload_b64, signature_b64 = parts[1], parts[2]
        signing_input = f"{TOKEN_VERSION}.{payload_b64}".encode("ascii")
        try:
            received_signature = _b64url_decode(signature_b64)
        except ValueError as exc:
            raise AuthenticationError("invalid operator token signature encoding") from exc
        expected_signature = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(received_signature, expected_signature):
            raise AuthenticationError("operator token signature is invalid")
        try:
            payload = json.loads(_b64url_decode(payload_b64))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthenticationError("operator token payload is invalid") from exc
        if not isinstance(payload, dict):
            raise AuthenticationError("operator token payload must be an object")
        expected_keys = {"exp", "iat", "iss", "jti", "roles", "sub", "tenants"}
        if set(payload) != expected_keys:
            raise AuthenticationError("operator token claim set is invalid")
        current = int(time.time() if now is None else now)
        try:
            issued_at = int(payload["iat"])
            expires_at = int(payload["exp"])
        except (TypeError, ValueError) as exc:
            raise AuthenticationError("operator token timestamps are invalid") from exc
        if issued_at > current + clock_skew_seconds:
            raise AuthenticationError("operator token is not yet valid")
        if expires_at <= current - clock_skew_seconds:
            raise AuthenticationError("operator token has expired")
        if expires_at <= issued_at or expires_at - issued_at > MAX_TOKEN_TTL_SECONDS:
            raise AuthenticationError("operator token lifetime is invalid")
        if payload["iss"] != self.issuer:
            raise AuthenticationError("operator token issuer is invalid")
        try:
            subject = _validate_identifier(payload["sub"], "subject", SUBJECT_RE)
            roles = _normalize_roles(payload["roles"])
            tenants = _normalize_tenants(payload["tenants"], roles)
        except ValueError as exc:
            raise AuthenticationError(str(exc)) from exc
        token_id = payload["jti"]
        if not isinstance(token_id, str) or not token_id or len(token_id) > 128:
            raise AuthenticationError("operator token id is invalid")
        return Principal(
            subject=subject,
            roles=roles,
            tenant_ids=tenants,
            issuer=self.issuer,
            issued_at=issued_at,
            expires_at=expires_at,
            token_id=token_id,
        )


def parse_bearer_header(value: str) -> str:
    if not value:
        raise AuthenticationError("missing operator bearer token")
    prefix = "Bearer "
    if not value.startswith(prefix):
        raise AuthenticationError("operator authorization must use Bearer authentication")
    token = value[len(prefix) :].strip()
    if not token:
        raise AuthenticationError("missing operator bearer token")
    return token


def _normalize_roles(values: Iterable[str]) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise ValueError("roles must be an array")
    roles = frozenset(str(value).strip() for value in values)
    if not roles or "" in roles:
        raise ValueError("at least one non-empty operator role is required")
    unknown = roles.difference(ROLE_PERMISSIONS)
    if unknown:
        raise ValueError(f"unknown operator roles: {', '.join(sorted(unknown))}")
    return roles


def _normalize_tenants(values: Iterable[str], roles: frozenset[str]) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise ValueError("tenant_ids must be an array")
    tenants = frozenset(_validate_identifier(value, "tenant_id", TENANT_RE) for value in values)
    if "platform_admin" in roles:
        return tenants or frozenset({"*"})
    if not tenants:
        raise ValueError("non-platform operator tokens require at least one tenant")
    if "*" in tenants:
        raise ValueError("wildcard tenant access requires platform_admin")
    return tenants


def _validate_identifier(value: object, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if normalized == "*" and field == "tenant_id":
        return normalized
    if not pattern.fullmatch(normalized):
        raise ValueError(f"{field} contains unsupported characters or is too long")
    return normalized


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64url value")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:  # binascii errors differ between Python versions.
        raise ValueError("invalid base64url value") from exc
