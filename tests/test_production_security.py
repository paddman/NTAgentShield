from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from ntshield.audit_ledger import AuditLedger
from ntshield.metrics import MetricsRegistry
from ntshield.operator_auth import OperatorTokenManager
from ntshield.production_config import ProductionSecurityConfig
from ntshield.production_security import ProductionSecurityMiddleware

OPERATOR_SECRET = "operator-secret-0123456789-abcdefghijklmnopqrstuvwxyz"
AUDIT_SECRET = "audit-secret-0123456789-abcdefghijklmnopqrstuvwxyz"


def config(tmp_path: Path, *, operator_secret: str = OPERATOR_SECRET) -> ProductionSecurityConfig:
    return ProductionSecurityConfig(
        environment="production",
        operator_auth_enabled=True,
        operator_signing_secret=operator_secret,
        operator_token_issuer="test-control",
        audit_hmac_secret=AUDIT_SECRET,
        audit_database_path=tmp_path / "audit.db",
        allowed_origins=(),
        max_request_body_bytes=1024 * 1024,
        max_json_depth=12,
        max_json_items=20_000,
        max_string_chars=4096,
        read_rate_limit_per_minute=100,
        write_rate_limit_per_minute=100,
        ingest_rate_limit_per_minute=100,
        metrics_public=False,
        audit_fail_closed=True,
        trust_proxy_headers=False,
    )


def build_client(tmp_path: Path, *, active_config: ProductionSecurityConfig | None = None):
    app = FastAPI()

    @app.get("/v1/findings")
    def findings(tenant_id: str) -> dict[str, str]:
        return {"tenant_id": tenant_id}

    @app.post("/v1/events/normalized")
    async def ingest(request: Request):
        return await request.json()

    @app.get("/v1/incidents/inc-a")
    def incident() -> dict[str, str]:
        return {"incident_id": "inc-a"}

    selected = active_config or config(tmp_path)
    audit = AuditLedger(selected.audit_database_path, selected.audit_hmac_secret)
    manager = None
    if selected.operator_signing_secret:
        try:
            manager = OperatorTokenManager(
                selected.operator_signing_secret, issuer=selected.operator_token_issuer
            )
        except ValueError:
            manager = None
    wrapped = ProductionSecurityMiddleware(
        app,
        config=selected,
        token_manager=manager,
        audit_ledger=audit,
        metrics=MetricsRegistry(),
        tenant_resolver=lambda path: "tenant-a" if path.endswith("inc-a") else None,
    )
    return TestClient(wrapped), audit, manager


def bearer(manager: OperatorTokenManager, *, roles: list[str], tenants: list[str]) -> dict[str, str]:
    token = manager.issue(
        subject="alice",
        roles=roles,
        tenant_ids=tenants,
        ttl_seconds=600,
    )
    return {"Authorization": f"Bearer {token}"}


def test_operator_api_is_authenticated_and_tenant_scoped(tmp_path) -> None:
    client, audit, manager = build_client(tmp_path)
    assert manager is not None
    assert client.get("/v1/findings?tenant_id=tenant-a").status_code == 401

    headers = bearer(manager, roles=["viewer"], tenants=["tenant-a"])
    assert client.get("/v1/findings?tenant_id=tenant-a", headers=headers).status_code == 200
    assert client.get("/v1/findings?tenant_id=tenant-b", headers=headers).status_code == 403
    assert client.get("/v1/incidents/inc-a", headers=headers).status_code == 200
    assert audit.verify().valid
    assert len(audit.list_records(limit=20)) >= 4
    audit.close()


def test_operator_ingest_is_strict_and_redacted_before_core(tmp_path) -> None:
    client, audit, manager = build_client(tmp_path)
    assert manager is not None
    headers = {
        **bearer(manager, roles=["ingester"], tenants=["tenant-a"]),
        "Content-Type": "application/json",
    }
    event = {
        "schema_version": "ntshield-event/v1",
        "tenant_id": "tenant-a",
        "source_type": "test",
        "event_type": "auth.test",
        "asset": {"id": "host-1"},
        "raw": {"api_key": "top-secret"},
    }
    response = client.post("/v1/events/normalized", headers=headers, json=event)
    assert response.status_code == 200
    assert response.json()["raw"]["api_key"] == "[REDACTED]"

    event["unknown"] = True
    rejected = client.post("/v1/events/normalized", headers=headers, json=event)
    assert rejected.status_code == 422
    audit.close()


def test_production_plane_locks_when_operator_secret_is_missing(tmp_path) -> None:
    locked = config(tmp_path, operator_secret="")
    client, audit, _ = build_client(tmp_path, active_config=locked)
    response = client.get("/v1/findings?tenant_id=tenant-a")
    assert response.status_code == 503
    assert response.json()["error"] == "control_plane_locked"
    audit.close()
