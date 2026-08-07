from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ntshield.engine.hunt import HuntEngine
from ntshield.enrollment import CertificateAuthority, EnrollmentTokenManager
from ntshield.enrollment_store import EnrollmentNonceStore
from ntshield.llm.client import QwenAnalyst
from ntshield.models import IngestResult, RawEventEnvelope, SecurityEvent
from ntshield.normalizer import normalize
from ntshield.settings import Settings


class BulkEvents(BaseModel):
    events: list[SecurityEvent] = Field(min_length=1, max_length=5000)


class BulkRawEvents(BaseModel):
    events: list[RawEventEnvelope] = Field(min_length=1, max_length=5000)


class EnrollmentRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    hostname: str | None = Field(default=None, max_length=255)
    csr_pem: str = Field(min_length=32, max_length=32768)


class EnrollmentResponse(BaseModel):
    agent_id: str
    tenant_id: str
    certificate_pem: str
    ca_certificate_pem: str
    expires_at: datetime


class AppState:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.hunt = HuntEngine(settings)
        self.analyst = QwenAnalyst(settings)
        self.enrollment_tokens: EnrollmentTokenManager | None = None
        self.enrollment_ca: CertificateAuthority | None = None
        self.enrollment_nonces: EnrollmentNonceStore | None = None
        if settings.enrollment_enabled:
            self.enrollment_tokens = EnrollmentTokenManager(settings.enrollment_signing_secret)
            self.enrollment_ca = CertificateAuthority(
                settings.enrollment_ca_cert_path, settings.enrollment_ca_key_path
            )
            self.enrollment_nonces = EnrollmentNonceStore(settings.database_path)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    state = AppState(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        state.hunt.store.close()
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

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "rules_loaded": len(state.hunt.rules),
            "qwen_enabled": settings.qwen_enabled,
            "qwen_model": settings.qwen_model,
            "enrollment_enabled": settings.enrollment_enabled,
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
        return EnrollmentResponse(
            agent_id=payload.agent_id,
            tenant_id=payload.tenant_id,
            certificate_pem=certificate_pem,
            ca_certificate_pem=ca_pem,
            expires_at=expires_at,
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
