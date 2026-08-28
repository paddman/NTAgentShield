from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

from ntshield.ingest_queue import DurableIngestQueue, default_queue_path
from ntshield.operator_auth import AuthorizationError, Principal
from ntshield.settings import Settings


def queue_path(settings: Settings) -> Path:
    configured = os.getenv("NTSHIELD_INGEST_QUEUE_PATH", "").strip()
    return Path(configured) if configured else default_queue_path(settings.database_path)


def build_async_ingest_router(
    *,
    settings: Settings,
    queue: DurableIngestQueue,
) -> APIRouter:
    del settings
    router = APIRouter()

    @router.post("/v1/ingest/async/normalized", status_code=202)
    async def enqueue_normalized(
        request: Request,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        return await _enqueue(request, queue, "normalized", idempotency_key)

    @router.post("/v1/ingest/async/raw", status_code=202)
    async def enqueue_raw(
        request: Request,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        return await _enqueue(request, queue, "raw", idempotency_key)

    @router.get("/v1/operator/ingest/jobs/{job_id}")
    def get_job(job_id: str, request: Request) -> dict[str, Any]:
        principal = _principal(request)
        job = queue.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="ingest job not found")
        _require(principal, "read", job.tenant_id)
        return job.as_dict(include_payload=False)

    @router.get("/v1/operator/ingest/queue")
    def queue_stats(
        request: Request,
        tenant_id: str | None = None,
    ) -> dict[str, int]:
        principal = _principal(request)
        if tenant_id is not None:
            _require(principal, "fleet.read", tenant_id)
        elif not principal.is_platform_admin:
            raise HTTPException(status_code=422, detail="tenant_id is required")
        return queue.stats(tenant_id)

    return router


async def _enqueue(
    request: Request,
    queue: DurableIngestQueue,
    kind: str,
    idempotency_key: str | None,
) -> dict[str, Any]:
    principal = _principal(request)
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=422, detail="invalid JSON payload") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="ingest payload must be an object")
    tenant_id = str(payload.get("tenant_id", "")).strip()
    _require(principal, "ingest", tenant_id)
    try:
        job, created = queue.enqueue(
            tenant_id=tenant_id,
            kind=kind,  # type: ignore[arg-type]
            payload=payload,
            idempotency_key=idempotency_key,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "job_id": job.job_id,
        "tenant_id": job.tenant_id,
        "kind": job.kind,
        "status": job.status,
        "payload_sha256": job.payload_sha256,
        "created": created,
    }


def _principal(request: Request) -> Principal:
    principal = getattr(request.state, "principal", None)
    if not isinstance(principal, Principal):
        raise HTTPException(status_code=401, detail="authenticated operator principal is missing")
    return principal


def _require(principal: Principal, permission: str, tenant_id: str) -> None:
    try:
        principal.require(permission, tenant_id)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
