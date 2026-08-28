from __future__ import annotations

import pytest

from ntshield.ingest_security import (
    IngestSecurityError,
    REDACTED,
    sanitize_json_document,
    validate_ingest_document,
)


def normalized_event() -> dict[str, object]:
    return {
        "schema_version": "ntshield-event/v1",
        "event_id": "evt-1",
        "tenant_id": "tenant-a",
        "source_type": "test",
        "event_type": "process.start",
        "asset": {"id": "host-1"},
        "message": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
        "raw": {
            "password": "never-store-me",
            "url": "https://alice:secret@example.test/path",
        },
    }


def test_ingest_boundary_validates_schema_and_recursively_redacts() -> None:
    event = normalized_event()
    validate_ingest_document("/v1/events/normalized", event)
    result = sanitize_json_document(event)
    assert result.redacted_fields == 3
    assert result.value["raw"]["password"] == REDACTED
    assert REDACTED in result.value["raw"]["url"]
    assert REDACTED in result.value["message"]


def test_ingest_boundary_rejects_schema_drift_and_excessive_depth() -> None:
    event = normalized_event()
    event["surprise_admin_override"] = True
    with pytest.raises(IngestSecurityError, match="unsupported fields"):
        validate_ingest_document("/v1/events/normalized", event)

    nested: object = "value"
    for _ in range(10):
        nested = {"next": nested}
    with pytest.raises(IngestSecurityError, match="maximum depth"):
        sanitize_json_document(nested, max_depth=4)
