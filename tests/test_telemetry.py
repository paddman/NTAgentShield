from __future__ import annotations

from fastapi import FastAPI

from ntshield.telemetry import configure_open_telemetry


def test_otel_is_explicitly_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("NTSHIELD_OTEL_ENABLED", raising=False)
    state = configure_open_telemetry(FastAPI())
    assert not state.enabled
    assert state.reason == "disabled"


def test_remote_plain_http_otel_endpoint_is_rejected(monkeypatch) -> None:
    monkeypatch.setenv("NTSHIELD_OTEL_ENABLED", "true")
    monkeypatch.setenv("NTSHIELD_OTEL_ENDPOINT", "http://collector.example:4318")
    state = configure_open_telemetry(FastAPI())
    assert not state.enabled
    assert "HTTPS" in state.reason
