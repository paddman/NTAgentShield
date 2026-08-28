from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ntshield.operator_auth import MIN_SECRET_BYTES

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


@dataclass(frozen=True, slots=True)
class ProductionSecurityConfig:
    environment: str
    operator_auth_enabled: bool
    operator_signing_secret: str
    operator_token_issuer: str
    audit_hmac_secret: str
    audit_database_path: Path
    allowed_origins: tuple[str, ...]
    max_request_body_bytes: int
    max_json_depth: int
    max_json_items: int
    max_string_chars: int
    read_rate_limit_per_minute: int
    write_rate_limit_per_minute: int
    ingest_rate_limit_per_minute: int
    metrics_public: bool
    audit_fail_closed: bool
    trust_proxy_headers: bool

    @classmethod
    def from_env(cls, *, database_path: Path | None = None) -> "ProductionSecurityConfig":
        environment = os.getenv("NTSHIELD_ENVIRONMENT", "production").strip().lower()
        default_audit_path = (
            database_path.with_name(f"{database_path.stem}-audit.db")
            if database_path is not None
            else Path("./data/ntshield-audit.db")
        )
        origins = tuple(
            value.strip()
            for value in os.getenv("NTSHIELD_OPERATOR_ALLOWED_ORIGINS", "").split(",")
            if value.strip()
        )
        return cls(
            environment=environment,
            operator_auth_enabled=_env_bool("NTSHIELD_OPERATOR_AUTH_ENABLED", True),
            operator_signing_secret=os.getenv("NTSHIELD_OPERATOR_SIGNING_SECRET", ""),
            operator_token_issuer=os.getenv(
                "NTSHIELD_OPERATOR_TOKEN_ISSUER", "ntshield-control"
            ).strip(),
            audit_hmac_secret=os.getenv("NTSHIELD_AUDIT_HMAC_SECRET", ""),
            audit_database_path=Path(
                os.getenv("NTSHIELD_AUDIT_DATABASE_PATH", str(default_audit_path))
            ),
            allowed_origins=origins,
            max_request_body_bytes=_env_int(
                "NTSHIELD_MAX_REQUEST_BODY_BYTES", 8 * 1024 * 1024, 1024, 64 * 1024 * 1024
            ),
            max_json_depth=_env_int("NTSHIELD_MAX_JSON_DEPTH", 12, 1, 64),
            max_json_items=_env_int("NTSHIELD_MAX_JSON_ITEMS", 20_000, 100, 500_000),
            max_string_chars=_env_int("NTSHIELD_MAX_STRING_CHARS", 4096, 128, 1_000_000),
            read_rate_limit_per_minute=_env_int(
                "NTSHIELD_READ_RATE_LIMIT_PER_MINUTE", 600, 1, 100_000
            ),
            write_rate_limit_per_minute=_env_int(
                "NTSHIELD_WRITE_RATE_LIMIT_PER_MINUTE", 120, 1, 100_000
            ),
            ingest_rate_limit_per_minute=_env_int(
                "NTSHIELD_INGEST_RATE_LIMIT_PER_MINUTE", 3_000, 1, 1_000_000
            ),
            metrics_public=_env_bool("NTSHIELD_METRICS_PUBLIC", False),
            audit_fail_closed=_env_bool("NTSHIELD_AUDIT_FAIL_CLOSED", True),
            trust_proxy_headers=_env_bool("NTSHIELD_TRUST_PROXY_HEADERS", False),
        )

    @property
    def production_mode(self) -> bool:
        return self.environment in {"production", "prod"}

    def lock_reasons(self) -> tuple[str, ...]:
        reasons: list[str] = []
        if self.operator_auth_enabled and len(self.operator_signing_secret.encode("utf-8")) < MIN_SECRET_BYTES:
            reasons.append(
                f"NTSHIELD_OPERATOR_SIGNING_SECRET must be at least {MIN_SECRET_BYTES} bytes"
            )
        if len(self.audit_hmac_secret.encode("utf-8")) < MIN_SECRET_BYTES:
            reasons.append(f"NTSHIELD_AUDIT_HMAC_SECRET must be at least {MIN_SECRET_BYTES} bytes")
        if not self.operator_token_issuer or len(self.operator_token_issuer) > 128:
            reasons.append("NTSHIELD_OPERATOR_TOKEN_ISSUER must be between 1 and 128 characters")
        if self.production_mode and not self.operator_auth_enabled:
            reasons.append("operator authentication cannot be disabled in production")
        if self.production_mode and "*" in self.allowed_origins:
            reasons.append("wildcard operator CORS origin is forbidden in production")
        if self.production_mode and self.metrics_public:
            reasons.append("public metrics are forbidden in production")
        return tuple(reasons)

    @property
    def locked(self) -> bool:
        return bool(self.lock_reasons())


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be one of true/false, 1/0, yes/no, on/off")


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value
