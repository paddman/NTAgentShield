from __future__ import annotations

from typing import Any

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from . import __version__
from .adapters import normalize_record
from .config import Settings
from .hunt import QwenHuntAgent
from .models import ActionDecision, ActionRequest, HuntAnalysis, Incident, IngestResult, SecurityEvent
from .pipeline import HuntingPipeline
from .response_policy import ResponsePolicy


class AdapterIngestRequest(BaseModel):
    asset_id: str = Field(min_length=1, max_length=256)
    record: dict[str, Any]
    asset_criticality: int = Field(default=3, ge=1, le=5)
    sensor_confidence: float = Field(default=0.8, ge=0, le=1)


class IncidentDetail(BaseModel):
    incident: Incident
    events: list[dict[str, Any]] = Field(default_factory=list)


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or Settings.from_env()
    pipeline = HuntingPipeline(resolved)
    hunt_agent = QwenHuntAgent(resolved, pipeline.store, pipeline.rule_engine)
    response_policy = ResponsePolicy()

    app = FastAPI(
        title="NTAgentShield Behavioral Zero-Day Hunting API",
        version=__version__,
        description=(
            "Behavior-first correlation, per-asset baselines, bounded Qwen investigation, "
            "and human-gated response decisions."
        ),
    )
    app.state.settings = resolved
    app.state.pipeline = pipeline
    app.state.hunt_agent = hunt_agent
    app.state.response_policy = response_policy

    def require_incident(incident_id: str, tenant_id: str) -> Incident:
        incident = pipeline.store.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        if incident.tenant_id != tenant_id:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "rules_loaded": len(pipeline.rule_engine.rules),
            "events_stored": pipeline.store.count_events(),
            "qwen_enabled": resolved.qwen_enabled,
            "qwen_model": resolved.qwen_model,
        }

    @app.get("/v1/rules")
    def list_rules() -> list[dict[str, Any]]:
        return pipeline.rule_engine.list_rule_summaries()

    @app.post("/v1/events", response_model=IngestResult, status_code=status.HTTP_201_CREATED)
    def ingest_event(
        event: SecurityEvent,
        x_tenant_id: str = Header(alias="X-Tenant-ID"),
    ) -> IngestResult:
        if event.tenant_id != x_tenant_id:
            raise HTTPException(status_code=403, detail="Tenant header does not match event")
        return pipeline.ingest(event)

    @app.post(
        "/v1/events/batch",
        response_model=list[IngestResult],
        status_code=status.HTTP_201_CREATED,
    )
    def ingest_batch(
        events: list[SecurityEvent],
        x_tenant_id: str = Header(alias="X-Tenant-ID"),
    ) -> list[IngestResult]:
        if not events:
            return []
        if any(event.tenant_id != x_tenant_id for event in events):
            raise HTTPException(status_code=403, detail="Batch contains another tenant")
        return pipeline.ingest_batch(events)

    @app.post(
        "/v1/adapters/{adapter}",
        response_model=IngestResult,
        status_code=status.HTTP_201_CREATED,
    )
    def ingest_adapter(
        adapter: str,
        body: AdapterIngestRequest,
        x_tenant_id: str = Header(alias="X-Tenant-ID"),
    ) -> IngestResult:
        try:
            event = normalize_record(
                adapter,
                body.record,
                tenant_id=x_tenant_id,
                asset_id=body.asset_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        event.asset_criticality = body.asset_criticality
        event.sensor_confidence = body.sensor_confidence
        return pipeline.ingest(event)

    @app.get("/v1/incidents", response_model=list[Incident])
    def list_incidents(
        x_tenant_id: str = Header(alias="X-Tenant-ID"),
        incident_status: str | None = Query(default=None, alias="status"),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[Incident]:
        return pipeline.store.list_incidents(
            tenant_id=x_tenant_id,
            status=incident_status,
            limit=limit,
        )

    @app.get("/v1/incidents/{incident_id}", response_model=IncidentDetail)
    def get_incident(
        incident_id: str,
        x_tenant_id: str = Header(alias="X-Tenant-ID"),
        include_events: bool = Query(default=True),
    ) -> IncidentDetail:
        incident = require_incident(incident_id, x_tenant_id)
        events = (
            pipeline.store.get_event_payloads(incident.event_ids) if include_events else []
        )
        return IncidentDetail(incident=incident, events=events)

    @app.post("/v1/incidents/{incident_id}/hunt", response_model=HuntAnalysis)
    async def hunt_incident(
        incident_id: str,
        x_tenant_id: str = Header(alias="X-Tenant-ID"),
    ) -> HuntAnalysis:
        require_incident(incident_id, x_tenant_id)
        return await hunt_agent.hunt(incident_id)

    @app.post("/v1/response/decision", response_model=ActionDecision)
    def decide_response(
        request: ActionRequest,
        x_tenant_id: str = Header(alias="X-Tenant-ID"),
    ) -> ActionDecision:
        incident = require_incident(request.incident_id, x_tenant_id)
        return response_policy.decide(request, incident)

    return app


app = create_app()


def run() -> None:
    uvicorn.run("ntshield.api:app", host="0.0.0.0", port=8080)
