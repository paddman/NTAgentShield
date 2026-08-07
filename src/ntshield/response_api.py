from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ntshield.response_broker import (
    ResponseBrokerStore,
    create_signed_response_lease,
    read_response_public_key,
)
from ntshield.settings import Settings
from ntshield.transport_auth import verify_agent_payload, verify_agent_request_signature


class ResponseResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    status: Literal["succeeded", "rejected", "failed"]
    decision_reason: str = Field(default="", max_length=2048)
    error: str | None = Field(default=None, max_length=4096)
    executed_at: datetime
    data: dict[str, Any] = Field(default_factory=dict)


def agent_get_message(path: str, agent_id: str, tenant_id: str, timestamp: str) -> bytes:
    return f"GET\n{path}\n{timestamp}\n{tenant_id}\n{agent_id}".encode()


def build_response_router(settings: Settings) -> APIRouter:
    router = APIRouter()

    def authenticate_get(
        request: Request,
        path: str,
        agent_id: str,
        tenant_id: str,
        timestamp: str,
        signature: str,
    ) -> None:
        enrollment_store = request.app.state.ntshield.enrollment_nonces
        if enrollment_store is None:
            raise HTTPException(status_code=404, detail="Agent response transport is disabled")
        if not agent_id or not tenant_id or not timestamp or not signature:
            raise HTTPException(status_code=401, detail="Missing Agent authentication headers")
        enrolled = enrollment_store.get_agent(tenant_id, agent_id)
        if enrolled is None or not enrolled.active:
            raise HTTPException(status_code=401, detail="Agent is not actively enrolled")
        try:
            request_time = datetime.fromtimestamp(int(timestamp), UTC)
        except (ValueError, OverflowError) as exc:
            raise HTTPException(status_code=401, detail="Invalid Agent request timestamp") from exc
        if abs((datetime.now(UTC) - request_time).total_seconds()) > 300:
            raise HTTPException(status_code=401, detail="Agent request timestamp is outside allowed window")
        try:
            verify_agent_request_signature(
                enrolled.certificate_pem,
                agent_get_message(path, agent_id, tenant_id, timestamp),
                signature,
            )
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        enrollment_store.mark_seen(tenant_id, agent_id)

    @router.get("/v1/agent/response-trust-root", response_model=None)
    def response_trust_root(
        request: Request,
        x_ntshield_agent_id: str = Header(default=""),
        x_ntshield_tenant_id: str = Header(default=""),
        x_ntshield_timestamp: str = Header(default=""),
        x_ntshield_signature: str = Header(default=""),
    ) -> dict[str, str]:
        agent_id = x_ntshield_agent_id.strip()
        tenant_id = x_ntshield_tenant_id.strip()
        timestamp = x_ntshield_timestamp.strip()
        authenticate_get(
            request,
            "/v1/agent/response-trust-root",
            agent_id,
            tenant_id,
            timestamp,
            x_ntshield_signature.strip(),
        )
        try:
            public_key = read_response_public_key(settings.response_signing_public_key_path)
        except ValueError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        if public_key is None:
            raise HTTPException(status_code=503, detail="Response signing trust root is not initialized")
        return {"public_key_pem": public_key}

    @router.get("/v1/agent/responses", response_model=None)
    def next_response(
        request: Request,
        x_ntshield_agent_id: str = Header(default=""),
        x_ntshield_tenant_id: str = Header(default=""),
        x_ntshield_timestamp: str = Header(default=""),
        x_ntshield_signature: str = Header(default=""),
    ) -> dict[str, str] | Response:
        agent_id = x_ntshield_agent_id.strip()
        tenant_id = x_ntshield_tenant_id.strip()
        timestamp = x_ntshield_timestamp.strip()
        authenticate_get(
            request,
            "/v1/agent/responses",
            agent_id,
            tenant_id,
            timestamp,
            x_ntshield_signature.strip(),
        )
        if not settings.response_signing_private_key_path.exists():
            raise HTTPException(status_code=503, detail="Response signing key is not initialized")
        store = ResponseBrokerStore(settings.database_path)
        try:
            action = store.next_for_agent(tenant_id, agent_id)
            if action is None:
                return Response(status_code=204)
            try:
                lease = create_signed_response_lease(
                    action,
                    settings.response_signing_private_key_path,
                    lease_seconds=settings.response_lease_seconds,
                )
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            return lease.as_dict()
        finally:
            store.close()

    @router.post("/v1/agent/responses/{action_id}/result")
    async def response_result(
        action_id: str,
        request: Request,
        x_ntshield_agent_id: str = Header(default=""),
        x_ntshield_tenant_id: str = Header(default=""),
        x_ntshield_signature: str = Header(default=""),
    ) -> dict[str, Any]:
        enrollment_store = request.app.state.ntshield.enrollment_nonces
        if enrollment_store is None:
            raise HTTPException(status_code=404, detail="Agent response transport is disabled")
        agent_id = x_ntshield_agent_id.strip()
        tenant_id = x_ntshield_tenant_id.strip()
        signature = x_ntshield_signature.strip()
        if not agent_id or not tenant_id or not signature:
            raise HTTPException(status_code=401, detail="Missing Agent authentication headers")
        enrolled = enrollment_store.get_agent(tenant_id, agent_id)
        if enrolled is None or not enrolled.active:
            raise HTTPException(status_code=401, detail="Agent is not actively enrolled")
        body = await request.body()
        if not body or len(body) > 64 * 1024:
            raise HTTPException(status_code=413, detail="Response result is empty or too large")
        try:
            verify_agent_payload(enrolled.certificate_pem, body, signature)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        try:
            payload = ResponseResult.model_validate_json(body)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="Invalid response result payload") from exc
        if (
            payload.action_id != action_id
            or payload.tenant_id != tenant_id
            or payload.agent_id != agent_id
        ):
            raise HTTPException(status_code=403, detail="Response result identity does not match request")
        result = payload.model_dump(mode="json")
        store = ResponseBrokerStore(settings.database_path)
        try:
            try:
                action = store.complete(action_id, tenant_id, agent_id, result)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
        finally:
            store.close()
        enrollment_store.mark_seen(tenant_id, agent_id)
        return {"action_id": action.action_id, "status": action.status, "accepted": True}

    return router
