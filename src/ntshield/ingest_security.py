from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

REDACTED = "[REDACTED]"
EVENT_SCHEMA_VERSION = "ntshield-event/v1"
MAX_BULK_EVENTS = 5000

_NORMALIZED_EVENT_FIELDS = {
    "schema_version",
    "event_id",
    "tenant_id",
    "observed_at",
    "source_type",
    "event_type",
    "asset",
    "actor",
    "process",
    "network",
    "file",
    "service",
    "registry",
    "web",
    "database",
    "action",
    "outcome",
    "message",
    "tags",
    "raw",
    "agent_id",
}
_RAW_ENVELOPE_FIELDS = {
    "schema_version",
    "tenant_id",
    "asset_id",
    "source_type",
    "data",
    "observed_at",
    "asset_role",
    "asset_criticality",
}
_SECRET_KEY_PARTS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "authorization",
    "credential",
    "clientsecret",
    "privatekey",
    "accesskey",
    "sessioncookie",
    "setcookie",
}
_BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_URI_CREDENTIAL_RE = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/@\s:]+:[^/@\s]+@")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


class IngestSecurityError(ValueError):
    """Raised when an operator-supplied telemetry payload violates the ingest boundary."""


@dataclass(frozen=True, slots=True)
class SanitizationResult:
    value: Any
    redacted_fields: int
    values_checked: int


@dataclass(slots=True)
class _SanitizationState:
    redacted_fields: int = 0
    values_checked: int = 0


def sanitize_json_document(
    value: Any,
    *,
    max_depth: int = 12,
    max_items: int = 20_000,
    max_string_chars: int = 4096,
) -> SanitizationResult:
    if max_depth < 1 or max_depth > 64:
        raise ValueError("max_depth must be between 1 and 64")
    if max_items < 1:
        raise ValueError("max_items must be positive")
    if max_string_chars < 128:
        raise ValueError("max_string_chars must be at least 128")
    state = _SanitizationState()
    sanitized = _sanitize(
        value,
        key=None,
        depth=0,
        max_depth=max_depth,
        max_items=max_items,
        max_string_chars=max_string_chars,
        state=state,
    )
    return SanitizationResult(
        value=sanitized,
        redacted_fields=state.redacted_fields,
        values_checked=state.values_checked,
    )


def validate_ingest_document(path: str, document: Any) -> None:
    if path in {"/v1/events/normalized", "/v1/ingest/async/normalized"}:
        _validate_normalized_event(document)
        return
    if path in {"/v1/events/raw", "/v1/ingest/async/raw"}:
        _validate_raw_envelope(document)
        return
    if path == "/v1/events/bulk":
        _validate_bulk(document, raw=False)
        return
    if path == "/v1/events/raw/bulk":
        _validate_bulk(document, raw=True)
        return


def extract_tenant_ids(path: str, document: Any) -> frozenset[str]:
    if document is None:
        return frozenset()
    values: set[str] = set()
    if path in {
        "/v1/events/normalized",
        "/v1/events/raw",
        "/v1/ingest/async/normalized",
        "/v1/ingest/async/raw",
        "/v1/operator/responses",
    }:
        if isinstance(document, dict):
            tenant_id = document.get("tenant_id")
            if isinstance(tenant_id, str) and tenant_id.strip():
                values.add(tenant_id.strip())
        return frozenset(values)
    if path in {"/v1/events/bulk", "/v1/events/raw/bulk"} and isinstance(document, dict):
        events = document.get("events")
        if isinstance(events, list):
            for event in events:
                if isinstance(event, dict):
                    tenant_id = event.get("tenant_id")
                    if isinstance(tenant_id, str) and tenant_id.strip():
                        values.add(tenant_id.strip())
    return frozenset(values)


def _sanitize(
    value: Any,
    *,
    key: str | None,
    depth: int,
    max_depth: int,
    max_items: int,
    max_string_chars: int,
    state: _SanitizationState,
) -> Any:
    if depth > max_depth:
        raise IngestSecurityError(f"telemetry JSON exceeds maximum depth {max_depth}")
    state.values_checked += 1
    if state.values_checked > max_items:
        raise IngestSecurityError(f"telemetry JSON exceeds maximum item count {max_items}")
    if key is not None and _is_secret_key(key):
        state.redacted_fields += 1
        return REDACTED
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) > max_string_chars:
            raise IngestSecurityError(
                f"telemetry string exceeds maximum length {max_string_chars} characters"
            )
        redacted = _redact_string(value)
        if redacted != value:
            state.redacted_fields += 1
        return redacted
    if isinstance(value, list):
        return [
            _sanitize(
                item,
                key=None,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                max_string_chars=max_string_chars,
                state=state,
            )
            for item in value
        ]
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for item_key, item_value in value.items():
            if not isinstance(item_key, str):
                raise IngestSecurityError("telemetry JSON object keys must be strings")
            if len(item_key) > 256:
                raise IngestSecurityError("telemetry JSON object key exceeds 256 characters")
            sanitized[item_key] = _sanitize(
                item_value,
                key=item_key,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                max_string_chars=max_string_chars,
                state=state,
            )
        return sanitized
    raise IngestSecurityError(f"unsupported telemetry JSON value type: {type(value).__name__}")


def _validate_normalized_event(value: Any) -> None:
    document = _require_object(value, "normalized event")
    _reject_unknown(document, _NORMALIZED_EVENT_FIELDS, "normalized event")
    _validate_schema_version(document)
    _required_string(document, "tenant_id", 128)
    _required_string(document, "source_type", 128)
    _required_string(document, "event_type", 160)
    asset = _require_object(document.get("asset"), "normalized event asset")
    _required_string(asset, "id", 256)
    tags = document.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 128:
        raise IngestSecurityError("normalized event tags must be an array with at most 128 items")


def _validate_raw_envelope(value: Any) -> None:
    document = _require_object(value, "raw event envelope")
    _reject_unknown(document, _RAW_ENVELOPE_FIELDS, "raw event envelope")
    _validate_schema_version(document)
    _required_string(document, "tenant_id", 128)
    _required_string(document, "asset_id", 256)
    _required_string(document, "source_type", 128)
    _require_object(document.get("data"), "raw event data")


def _validate_bulk(value: Any, *, raw: bool) -> None:
    document = _require_object(value, "bulk event payload")
    _reject_unknown(document, {"events"}, "bulk event payload")
    events = document.get("events")
    if not isinstance(events, list) or not events:
        raise IngestSecurityError("bulk event payload requires a non-empty events array")
    if len(events) > MAX_BULK_EVENTS:
        raise IngestSecurityError(f"bulk event payload exceeds {MAX_BULK_EVENTS} events")
    for index, event in enumerate(events):
        try:
            if raw:
                _validate_raw_envelope(event)
            else:
                _validate_normalized_event(event)
        except IngestSecurityError as exc:
            raise IngestSecurityError(f"invalid bulk event at index {index}: {exc}") from exc


def _validate_schema_version(document: dict[str, Any]) -> None:
    version = document.get("schema_version")
    if version is not None and version != EVENT_SCHEMA_VERSION:
        raise IngestSecurityError(
            f"unsupported telemetry schema_version; expected {EVENT_SCHEMA_VERSION}"
        )


def _require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IngestSecurityError(f"{name} must be a JSON object")
    return value


def _required_string(document: dict[str, Any], field: str, limit: int) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise IngestSecurityError(f"{field} must be a non-empty string up to {limit} characters")
    return value.strip()


def _reject_unknown(document: dict[str, Any], allowed: set[str], name: str) -> None:
    unknown = set(document).difference(allowed)
    if unknown:
        raise IngestSecurityError(
            f"{name} contains unsupported fields: {', '.join(sorted(unknown))}"
        )


def _is_secret_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
    return any(part in normalized for part in _SECRET_KEY_PARTS)


def _redact_string(value: str) -> str:
    redacted = _PRIVATE_KEY_RE.sub(REDACTED, value)
    redacted = _BEARER_RE.sub(REDACTED, redacted)
    redacted = _URI_CREDENTIAL_RE.sub(lambda match: f"{match.group('scheme')}{REDACTED}@", redacted)
    return redacted
