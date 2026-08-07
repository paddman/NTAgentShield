from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from ntshield.engine.hunt import HuntEngine
from ntshield.enrollment import CertificateAuthority, EnrollmentTokenManager
from ntshield.enrollment_store import EnrollmentNonceStore
from ntshield.llm.client import QwenAnalyst
from ntshield.models import IngestResult, RawEventEnvelope, SecurityEvent
from ntshield.normalizer import normalize
from ntshield.policy_distribution import PolicyBundleStore, read_policy_public_key
from ntshield.response_api import build_response_router
from ntshield.settings import Settings
from ntshield.transport_auth import (
    verify_agent_payload,
    verify_agent_request_signature,
    verify_renewal_csr_identity,
)


class BulkEvents(BaseModel):
    events: list[SecurityEvent] = Field(min_length=1, max_length=5000)


class BulkRawEvents(BaseModel):
    events: list[RawEventEnvelope] = Field(min_length=1, max_length=5000)


class EnrollmentRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    hostname: str | None = Field(default=None, max_length=255)
    csr_pem: str = Field(min_length=32, max_length=32768)


class CertificateRenewalRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    csr_pem: str = Field(min_length=32, max_length=32768)


class EnrollmentResponse(BaseModel):
    agent_id: str
    tenant_id: str
    certificate_pem: str
    ca_certificate_pem: str
    expires_at: datetime
    policy_signing_public_key_pem: str | None = None


class AgentIngestResponse(BaseModel):
    event_id: str
    accepted: bool = True
    duplicate: bool = False
    findings: int = 0
    incidents: int = 0


class AppState:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.hunt = HuntEngine(settings)
        self.analyst = QwenAnalyst(settings)
        self.policy_store = PolicyBundleStore(settings.database_path)
        self.enrollment_tokens: EnrollmentTokenManager | None = None
        self.enrollment_ca: CertificateAuthority | None = None
        self.enrollment_nonces: EnrollmentNonceStore | None = None
        if settings.enrollment_enabled:
            self.enrollment_tokens = EnrollmentTokenManager(settings.enrollment_signing_secret)
            self.enrollment_ca = CertificateAuthority(
                settings.enrollment_ca_cert_path, settings.enrollment_ca_key_path
            )
            self.enrollment_nonces = EnrollmentNonceStore(settings.database_path)


def policy_request_message(agent_id: str, tenant_id: str, timestamp: str) -> bytes:
    return f"GET\n/v1/agent/policy\n{timestamp}\n{tenant_id}\n{agent_id}".encode()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    state = AppState(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        state.hunt.store.close()
        state.policy_store.close()
        if state.enrollment_nonces is not None:
            state.enrollment_nonces.close()

    app = FastAPI(
        title="NTAgentShield",
        version="0.1.0",
        description="Behavioral zero-day hunting with grounded Qwen SOC analysis",
        lifespan=lifespan,
    )
    app.state.ntshield = state
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    app.include_router(build_response_router(settings))

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "rules_loaded": len(state.hunt.rules),
            "qwen_enabled": settings.qwen_enabled,
            "qwen_model": settings.qwen_model,
            "enrollment_enabled": settings.enrollment_enabled,
            "policy_signing_ready": settings.policy_signing_public_key_path.exists(),
            "response_signing_ready": settings.response_signing_public_key_path.exists(),
        }

    @app.post("/v1/enrollment", response_model=EnrollmentResponse)
    def enroll_agent(
        payload: EnrollmentRequest,
        authorization: str = Header(default=""),
    ) -> EnrollmentResponse:
        if (
            state.enrollment_tokens is None
            or state.enrollment_ca is None
            or state.enrollment_nonces is None
        ):
            raise HTTPException(status_code=404, detail="Enrollment is disabled")
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            raise HTTPException(status_code=401, detail="Missing enrollment bearer token")
        token = authorization[len(prefix) :].strip()
        try:
            claims = state.enrollment_tokens.verify(token, payload.tenant_id)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        if not state.enrollment_nonces.consume(
            claims.nonce, claims.tenant_id, claims.expires_at
        ):
            raise HTTPException(status_code=409, detail="Enrollment token was already consumed")
        try:
            certificate_pem, ca_pem, expires_at = state.enrollment_ca.issue_client_certificate(
                payload.csr_pem,
                payload.agent_id,
                payload.tenant_id,
                settings.enrollment_client_cert_ttl_hours,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        state.enrollment_nonces.register_agent(
            payload.agent_id,
            payload.tenant_id,
            certificate_pem,
            expires_at,
        )
        return EnrollmentResponse(
            agent_id=payload.agent_id,
            tenant_id=payload.tenant_id,
            certificate_pem=certificate_pem,
            ca_certificate_pem=ca_pem,
            expires_at=expires_at,
            policy_signing_public_key_pem=read_policy_public_key(
                settings.policy_signing_public_key_path
            ),
        )

    @app.post("/v1/agent/certificate/renew", response_model=EnrollmentResponse)
    async def renew_agent_certificate(
        request: Request,
        x_ntshield_agent_id: str = Header(default=""),
        x_ntshield_tenant_id: str = Header(default=""),
        x_ntshield_signature: str = Header(default=""),
    ) -> EnrollmentResponse:
        if state.enrollment_nonces is None or state.enrollment_ca is None:
            raise HTTPException(status_code=404, detail="Agent certificate renewal is disabled")
        agent_id = x_ntshield_agent_id.strip()
        tenant_id = x_ntshield_tenant_id.strip()
        signature = x_ntshield_signature.strip()
        if not agent_id or not tenant_id or not signature:
            raise HTTPException(status_code=401, detail="Missing Agent authentication headers")
        enrolled = state.enrollment_nonces.get_agent(tenant_id, agent_id)
        if enrolled is None or not enrolled.active:
            raise HTTPException(status_code=401, detail="Agent is not actively enrolled")
        body = await request.body()
        if not body or len(body) > 64 * 1024:
            raise HTTPException(status_code=413, detail="Certificate renewal payload is invalid")
        try:
            verify_agent_payload(enrolled.certificate_pem, body, signature)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        try:
            payload = CertificateRenewalRequest.model_validate_json(body)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="Invalid certificate renewal request") from exc
        if payload.agent_id != agent_id or payload.tenant_id != tenant_id:
            raise HTTPException(
                status_code=403,
                detail="Signed renewal identity does not match enrolled Agent/Tenant",
            )
        try:
            verify_renewal_csr_identity(enrolled.certificate_pem, payload.csr_pem)
            certificate_pem, ca_pem, expires_at = state.enrollment_ca.issue_client_certificate(
                payload.csr_pem,
                agent_id,
                tenant_id,
                settings.enrollment_client_cert_ttl_hours,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        rotated = state.enrollment_nonces.rotate_agent_certificate(
            agent_id,
            tenant_id,
            certificate_pem,
            expires_at,
        )
        if rotated is None:
            raise HTTPException(status_code=409, detail="Agent identity is no longer renewable")
        state.enrollment_nonces.mark_seen(tenant_id, agent_id)
        return EnrollmentResponse(
            agent_id=agent_id,
            tenant_id=tenant_id,
            certificate_pem=certificate_pem,
            ca_certificate_pem=ca_pem,
            expires_at=expires_at,
            policy_signing_public_key_pem=read_policy_public_key(
                settings.policy_signing_public_key_path
            ),
        )

    @app.get("/v1/agent/policy", response_model=None)
    def get_agent_policy(
        x_ntshield_agent_id: str = Header(default=""),
        x_ntshield_tenant_id: str = Header(default=""),
        x_ntshield_timestamp: str = Header(default=""),
        x_ntshield_signature: str = Header(default=""),
    ) -> dict[str, str] | Response:
        if state.enrollment_nonces is None:
            raise HTTPException(status_code=404, detail="Agent policy distribution is disabled")
        agent_id = x_ntshield_agent_id.strip()
        tenant_id = x_ntshield_tenant_id.strip()
        timestamp = x_ntshield_timestamp.strip()
        signature = x_ntshield_signature.strip()
        if not agent_id or not tenant_id or not timestamp or not signature:
            raise HTTPException(status_code=401, detail="Missing Agent authentication headers")
        enrolled = state.enrollment_nonces.get_agent(tenant_id, agent_id)
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
                policy_request_message(agent_id, tenant_id, timestamp),
                signature,
            )
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        state.enrollment_nonces.mark_seen(tenant_id, agent_id)
        bundle = state.policy_store.latest_for_agent(tenant_id, agent_id)
        if bundle is None:
            return Response(status_code=204)
        return bundle.as_dict()

    @app.post("/v1/agent/events", response_model=AgentIngestResponse)
    async def ingest_agent_event(
        request: Request,
        x_ntshield_agent_id: str = Header(default=""),
        x_ntshield_tenant_id: str = Header(default=""),
        x_ntshield_signature: str = Header(default=""),
    ) -> AgentIngestResponse:
        if state.enrollment_nonces is None:
            raise HTTPException(status_code=404, detail="Agent transport is disabled")
        agent_id = x_ntshield_agent_id.strip()
        tenant_id = x_ntshield_tenant_id.strip()
        if not agent_id or not tenant_id or not x_ntshield_signature.strip():
            raise HTTPException(status_code=401, detail="Missing Agent authentication headers")
        enrolled = state.enrollment_nonces.get_agent(tenant_id, agent_id)
        if enrolled is None or not enrolled.active:
            raise HTTPException(status_code=401, detail="Agent is not actively enrolled")
        body = await request.body()
        if not body or len(body) > 8 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Agent event payload is empty or too large")
        try:
            verify_agent_payload(enrolled.certificate_pem, body, x_ntshield_signature.strip())
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        try:
            event = SecurityEvent.model_validate_json(body)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="Invalid normalized Agent event") from exc
        payload_agent_id = str((event.model_extra or {}).get("agent_id", "")).strip()
        if event.tenant_id != tenant_id or payload_agent_id != agent_id:
            raise HTTPException(
                status_code=403,
                detail="Signed event identity does not match enrolled Agent/Tenant",
            )
        state.enrollment_nonces.mark_seen(tenant_id, agent_id)
        if state.hunt.store.get_event(event.event_id) is not None:
            return AgentIngestResponse(event_id=event.event_id, duplicate=True)
        result = state.hunt.ingest(event)
        return AgentIngestResponse(
            event_id=result.event_id,
            findings=len(result.findings),
            incidents=len(result.incidents),
        )

    @app.post("/v1/events/normalized", response_model=IngestResult)
    def ingest_normalized(event: SecurityEvent) -> IngestResult:
        return state.hunt.ingest(event)

    @app.post("/v1/events/raw", response_model=IngestResult)
    def ingest_raw(envelope: RawEventEnvelope) -> IngestResult:
        try:
            event = normalize(envelope)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return state.hunt.ingest(event)

    @app.post("/v1/events/bulk")
    def ingest_bulk(payload: BulkEvents) -> dict[str, Any]:
        results = [state.hunt.ingest(event) for event in payload.events]
        return {
            "accepted": len(results),
            "findings": sum(len(result.findings) for result in results),
            "incidents": list(
                {
                    incident.incident_id: incident.model_dump(mode="json")
                    for result in results
                    for incident in result.incidents
                }.values()
            ),
        }

    @app.post("/v1/events/raw/bulk")
    def ingest_raw_bulk(payload: BulkRawEvents) -> dict[str, Any]:
        results = [state.hunt.ingest(normalize(item)) for item in payload.events]
        return {
            "accepted": len(results),
            "findings": sum(len(result.findings) for result in results),
            "incidents": list(
                {
                    incident.incident_id: incident.model_dump(mode="json")
                    for result in results
                    for incident in result.incidents
                }.values()
            ),
        }

    @app.get("/v1/findings")
    def findings(
        tenant_id: str = Query(..., min_length=1), limit: int = Query(100, ge=1, le=1000)
    ) -> list[dict[str, Any]]:
        return [
            item.model_dump(mode="json")
            for item in state.hunt.store.list_findings(tenant_id, limit)
        ]

    @app.get("/v1/incidents")
    def incidents(
        tenant_id: str = Query(..., min_length=1), limit: int = Query(100, ge=1, le=1000)
    ) -> list[dict[str, Any]]:
        return [
            item.model_dump(mode="json")
            for item in state.hunt.store.list_incidents(tenant_id, limit)
        ]

    @app.get("/v1/incidents/{incident_id}")
    def incident(incident_id: str) -> dict[str, Any]:
        item = state.hunt.store.get_incident(incident_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return item.model_dump(mode="json")

    @app.post("/v1/incidents/{incident_id}/analyze")
    def analyze_incident(incident_id: str) -> dict[str, Any]:
        item = state.hunt.store.get_incident(incident_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        findings_by_id = {
            finding.finding_id: finding
            for finding in state.hunt.store.list_findings(item.tenant_id, limit=1000)
        }
        event_ids = [
            evidence.event_id
            for finding_id in item.finding_ids
            if (finding := findings_by_id.get(finding_id)) is not None
            for evidence in finding.evidence
        ]
        events = state.hunt.store.get_events(list(dict.fromkeys(event_ids)))
        try:
            report = state.analyst.analyze(item, events)
        except Exception as exc:  # Boundary around external model server.
            raise HTTPException(status_code=502, detail=f"Qwen analysis failed: {exc}") from exc
        item.analyst_report = report.model_dump(mode="json")
        state.hunt.store.upsert_incident(item)
        return item.model_dump(mode="json")

    @app.get("/v1/coverage")
    def coverage() -> list[dict[str, Any]]:
        return [rule.model_dump(mode="json") for rule in state.hunt.rules]

    @app.get("/v1/stats")
    def stats(tenant_id: str = Query(..., min_length=1)) -> dict[str, Any]:
        return {**state.hunt.store.stats(tenant_id), "rules": len(state.hunt.rules)}

    static_path = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=static_path), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(static_path / "index.html")

    return app


app = create_app()
