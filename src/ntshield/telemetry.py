from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class TelemetryState:
    enabled: bool
    reason: str
    endpoint: str | None = None


def configure_open_telemetry(app: Any) -> TelemetryState:
    """Configure optional OTLP traces without making OTel a hard dependency."""

    enabled = os.getenv("NTSHIELD_OTEL_ENABLED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not enabled:
        return TelemetryState(False, "disabled")
    endpoint = os.getenv(
        "NTSHIELD_OTEL_ENDPOINT",
        os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
    ).strip()
    if not endpoint.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        return TelemetryState(False, "remote OTLP endpoint must use HTTPS", endpoint)
    service_name = os.getenv("OTEL_SERVICE_NAME", "ntshield-control-plane").strip()
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ModuleNotFoundError:
        return TelemetryState(
            False,
            "install OpenTelemetry support with: pip install 'ntagentshield[otel]'",
            endpoint,
        )

    provider = TracerProvider(
        resource=Resource.create(
            {
                SERVICE_NAME: service_name,
                SERVICE_VERSION: "0.1.0",
                "deployment.environment": os.getenv(
                    "NTSHIELD_ENVIRONMENT", "production"
                ),
            }
        )
    )
    exporter = OTLPSpanExporter(endpoint=endpoint.rstrip("/") + "/v1/traces")
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=provider,
        excluded_urls="/live,/ready,/metrics",
    )
    HTTPXClientInstrumentor().instrument(tracer_provider=provider)
    return TelemetryState(True, "configured", endpoint)
