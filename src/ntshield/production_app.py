from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from ntshield.app import create_app
from ntshield.async_ingest import build_async_ingest_router, queue_path
from ntshield.audit_ledger import AuditLedger
from ntshield.ingest_queue import DurableIngestQueue
from ntshield.metrics import MetricsRegistry
from ntshield.operator_api import build_operator_router
from ntshield.operator_auth import OperatorTokenManager
from ntshield.production_config import ProductionSecurityConfig
from ntshield.production_security import ProductionSecurityMiddleware
from ntshield.response_broker import ResponseBrokerStore
from ntshield.settings import Settings
from ntshield.telemetry import configure_open_telemetry


def create_production_app(settings: Settings | None = None):
    active_settings = settings or Settings()
    security = ProductionSecurityConfig.from_env(database_path=active_settings.database_path)
    active_settings.allowed_origins = list(security.allowed_origins)
    core = create_app(active_settings)
    audit = AuditLedger(security.audit_database_path, security.audit_hmac_secret)
    metrics = MetricsRegistry()
    ingest_queue = DurableIngestQueue(queue_path(active_settings))
    token_manager: OperatorTokenManager | None = None
    if security.operator_auth_enabled and security.operator_signing_secret:
        try:
            token_manager = OperatorTokenManager(
                security.operator_signing_secret,
                issuer=security.operator_token_issuer,
            )
        except ValueError:
            token_manager = None

    original_lifespan = core.router.lifespan_context

    @asynccontextmanager
    async def managed_lifespan(app):
        try:
            async with original_lifespan(app):
                yield
        finally:
            ingest_queue.close()
            audit.close()

    core.router.lifespan_context = managed_lifespan
    core.state.production_security = security
    core.state.operator_token_manager = token_manager
    core.state.audit_ledger = audit
    core.state.metrics = metrics
    core.state.ingest_queue = ingest_queue
    core.include_router(
        build_operator_router(
            settings=active_settings,
            config=security,
            audit=audit,
            metrics=metrics,
        )
    )
    core.include_router(
        build_async_ingest_router(
            settings=active_settings,
            queue=ingest_queue,
        )
    )
    core.state.telemetry = configure_open_telemetry(core)

    def resolve_tenant(path: str) -> str | None:
        parts = [part for part in path.split("/") if part]
        if len(parts) >= 3 and parts[:2] == ["v1", "incidents"]:
            incident = core.state.ntshield.hunt.store.get_incident(parts[2])
            return incident.tenant_id if incident is not None else None
        if len(parts) >= 4 and parts[:3] == ["v1", "operator", "responses"]:
            store = ResponseBrokerStore(active_settings.database_path)
            try:
                action = store.get(parts[3])
            finally:
                store.close()
            return action.tenant_id if action is not None else None
        if len(parts) >= 5 and parts[:4] == ["v1", "operator", "ingest", "jobs"]:
            job = ingest_queue.get(parts[4])
            return job.tenant_id if job is not None else None
        return None

    return ProductionSecurityMiddleware(
        core,
        config=security,
        token_manager=token_manager,
        audit_ledger=audit,
        metrics=metrics,
        tenant_resolver=resolve_tenant,
    )


app: Any = create_production_app()
