from __future__ import annotations

import hmac
from datetime import datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from ntshield.audit_ledger import AuditLedger
from ntshield.enrollment_store import AgentEnrollment, EnrollmentNonceStore
from ntshield.metrics import MetricsRegistry
from ntshield.operator_auth import AuthorizationError, Principal
from ntshield.production_config import ProductionSecurityConfig
from ntshield.response_broker import ResponseBrokerStore
from ntshield.response_identity import response_action_digest, response_action_summary
from ntshield.settings import Settings


class ResponseProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    args: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=1, max_length=4096)
    incident_id: str | None = Field(default=None, max_length=128)
    ttl_seconds: int = Field(default=300, ge=30, le=900)


class ResponseApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


def build_operator_router(
    *,
    settings: Settings,
    config: ProductionSecurityConfig,
    audit: AuditLedger,
    metrics: MetricsRegistry,
) -> APIRouter:
    router = APIRouter()

    @router.get("/live", include_in_schema=False)
    def live() -> dict[str, str]:
        return {"status": "alive"}

    @router.get("/ready", include_in_schema=False)
    def ready(request: Request, response: Response) -> dict[str, Any]:
        verification = audit.verify()
        state = request.app.state.ntshield
        checks = {
            "operator_security": not config.locked,
            "audit_chain": verification.valid,
            "rules_loaded": bool(state.hunt.rules),
        }
        ready_now = all(checks.values())
        if not ready_now:
            response.status_code = 503
        metrics.set("readiness", 1.0 if ready_now else 0.0)
        return {"status": "ready" if ready_now else "not_ready", "checks": checks}

    @router.get("/metrics", include_in_schema=False)
    def prometheus_metrics() -> Response:
        return Response(
            content=metrics.render_prometheus(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @router.get("/v1/operator/whoami")
    def whoami(request: Request) -> dict[str, object]:
        return _principal(request).as_safe_dict()

    @router.post("/v1/operator/responses", status_code=201)
    def propose_response(payload: ResponseProposal, request: Request) -> dict[str, Any]:
        principal = _principal(request)
        _require(principal, "respond.propose", payload.tenant_id)
        request_id = _request_id(request)
        audit.append(
            actor=principal.subject,
            action="response.proposal.requested",
            resource_type="response_action",
            request_id=request_id,
            outcome="requested",
            tenant_id=payload.tenant_id,
            resource_id=payload.incident_id,
            payload={
                "agent_id": payload.agent_id,
                "tool": payload.tool,
                "incident_id": payload.incident_id,
                "ttl_seconds": payload.ttl_seconds,
            },
        )
        store = ResponseBrokerStore(settings.database_path)
        try:
            action = store.create_action(
                tenant_id=payload.tenant_id,
                agent_id=payload.agent_id,
                tool=payload.tool,
                args=payload.args,
                reason=payload.reason,
                requested_by=principal.subject,
                ttl_seconds=payload.ttl_seconds,
                incident_id=payload.incident_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        finally:
            store.close()
        digest = response_action_digest(action)
        audit.append(
            actor=principal.subject,
            action="response.proposed",
            resource_type="response_action",
            request_id=request_id,
            outcome="succeeded",
            tenant_id=action.tenant_id,
            resource_id=action.action_id,
            payload={
                "agent_id": action.agent_id,
                "tool": action.tool,
                "action_digest": digest,
                "incident_id": action.incident_id,
            },
        )
        metrics.inc("response_proposals_total", tool=action.tool)
        return response_action_summary(action)

    @router.get("/v1/operator/responses/{action_id}")
    def get_response(action_id: str, request: Request) -> dict[str, Any]:
        principal = _principal(request)
        action = _load_response(settings, action_id)
        _require(principal, "read", action.tenant_id)
        return response_action_summary(action)

    @router.post("/v1/operator/responses/{action_id}/approve")
    def approve_response(
        action_id: str,
        payload: ResponseApproval,
        request: Request,
    ) -> dict[str, Any]:
        principal = _principal(request)
        action = _load_response(settings, action_id)
        _require(principal, "respond.approve", action.tenant_id)
        expected_digest = response_action_digest(action)
        if not hmac.compare_digest(payload.action_digest, expected_digest):
            raise HTTPException(
                status_code=409,
                detail="approval digest does not match the exact proposed response action",
            )
        if principal.subject.casefold() == action.requested_by.casefold():
            raise HTTPException(
                status_code=409,
                detail="the authenticated requester cannot approve the same response action",
            )
        request_id = _request_id(request)
        audit.append(
            actor=principal.subject,
            action="response.approval.requested",
            resource_type="response_action",
            request_id=request_id,
            outcome="requested",
            tenant_id=action.tenant_id,
            resource_id=action.action_id,
            payload={
                "agent_id": action.agent_id,
                "tool": action.tool,
                "action_digest": expected_digest,
                "requested_by": action.requested_by,
            },
        )
        store = ResponseBrokerStore(settings.database_path)
        try:
            try:
                approved = store.approve(action_id, principal.subject)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
        finally:
            store.close()
        audit.append(
            actor=principal.subject,
            action="response.approved",
            resource_type="response_action",
            request_id=request_id,
            outcome="succeeded",
            tenant_id=approved.tenant_id,
            resource_id=approved.action_id,
            payload={
                "agent_id": approved.agent_id,
                "tool": approved.tool,
                "action_digest": expected_digest,
                "requested_by": approved.requested_by,
            },
        )
        metrics.inc("response_approvals_total", tool=approved.tool)
        return response_action_summary(approved)

    @router.get("/v1/operator/audit")
    def list_audit(
        request: Request,
        tenant_id: str | None = Query(default=None, min_length=1, max_length=128),
        limit: int = Query(default=100, ge=1, le=1000),
        action: list[str] | None = Query(default=None),
    ) -> list[dict[str, Any]]:
        principal = _principal(request)
        selected_tenant = _tenant_scope(principal, tenant_id)
        _require(principal, "audit.read", selected_tenant)
        records = audit.list_records(
            tenant_id=selected_tenant,
            limit=limit,
            actions=action,
        )
        return [record.as_dict() for record in records]

    @router.get("/v1/operator/audit/verify")
    def verify_audit(request: Request) -> dict[str, Any]:
        principal = _principal(request)
        _require(principal, "audit.read")
        return audit.verify().as_dict()

    @router.get("/v1/operator/agents")
    def list_agents(
        request: Request,
        tenant_id: str | None = Query(default=None, min_length=1, max_length=128),
    ) -> list[dict[str, Any]]:
        principal = _principal(request)
        selected_tenant = _tenant_scope(principal, tenant_id)
        _require(principal, "fleet.read", selected_tenant)
        store = EnrollmentNonceStore(settings.database_path)
        try:
            agents = store.list_agents(selected_tenant)
        finally:
            store.close()
        return [_agent_summary(agent) for agent in agents]

    return router


def _principal(request: Request) -> Principal:
    principal = getattr(request.state, "principal", None)
    if not isinstance(principal, Principal):
        raise HTTPException(status_code=401, detail="authenticated operator principal is missing")
    return principal


def _require(principal: Principal, permission: str, tenant_id: str | None = None) -> None:
    try:
        principal.require(permission, tenant_id)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _tenant_scope(principal: Principal, tenant_id: str | None) -> str | None:
    if tenant_id:
        return tenant_id
    if principal.is_platform_admin:
        return None
    tenants = sorted(value for value in principal.tenant_ids if value != "*")
    if len(tenants) == 1:
        return tenants[0]
    raise HTTPException(status_code=422, detail="tenant_id is required for this operator token")


def _load_response(settings: Settings, action_id: str):
    store = ResponseBrokerStore(settings.database_path)
    try:
        action = store.get(action_id)
    finally:
        store.close()
    if action is None:
        raise HTTPException(status_code=404, detail="response action not found")
    return action


def _request_id(request: Request) -> str:
    value = getattr(request.state, "request_id", "")
    return str(value)[:128] or "unknown"


def _agent_summary(agent: AgentEnrollment) -> dict[str, Any]:
    certificate = x509.load_pem_x509_certificate(agent.certificate_pem.encode("utf-8"))
    return {
        "tenant_id": agent.tenant_id,
        "agent_id": agent.agent_id,
        "status": agent.status,
        "enrolled_at": _iso(agent.enrolled_at),
        "certificate_updated_at": _iso(agent.certificate_updated_at),
        "certificate_expires_at": _iso(agent.expires_at),
        "certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "last_seen_at": _iso(agent.last_seen_at),
        "revoked_at": _iso(agent.revoked_at),
        "rotation_count": agent.rotation_count,
    }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None
