from __future__ import annotations

from ntshield.metrics import MetricsRegistry, Timer


def test_prometheus_duration_is_a_histogram(monkeypatch) -> None:
    registry = MetricsRegistry()
    monkeypatch.setattr("ntshield.metrics.perf_counter", lambda: 1.25)
    registry.observe_duration(
        "http_request_duration",
        Timer(started_at=1.0),
        method="GET",
        route_class="read",
    )
    output = registry.render_prometheus()
    assert "# TYPE ntshield_http_request_duration_seconds histogram" in output
    assert 'le="0.25"' in output
    assert "ntshield_http_request_duration_seconds_count" in output
