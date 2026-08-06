from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from ntshield.models import SecurityEvent
from ntshield.pipeline import HuntingPipeline


def _sample_events() -> list[SecurityEvent]:
    root = Path(__file__).resolve().parents[1]
    return [
        SecurityEvent.model_validate_json(line)
        for line in (root / "samples" / "webshell_chain.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]


def test_web_exploit_chain_creates_behavioral_incidents(settings) -> None:
    pipeline = HuntingPipeline(settings)
    results = pipeline.ingest_batch(_sample_events())

    rule_ids = {
        incident.rule_id
        for result in results
        for incident in result.incidents
        if incident.rule_id is not None
    }
    assert "BZH-WEB-001" in rule_ids
    assert "BZH-WEB-002" in rule_ids

    incidents = pipeline.store.list_incidents(tenant_id="tenant-demo")
    assert incidents
    primary = next(item for item in incidents if item.rule_id == "BZH-WEB-001")
    assert primary.risk_score >= 75
    assert primary.event_ids == [
        "demo-web-001",
        "demo-proc-002",
        "demo-file-003",
        "demo-net-004",
    ]


def test_rule_correlation_never_crosses_tenants(settings) -> None:
    pipeline = HuntingPipeline(settings)
    events = _sample_events()
    for index, event in enumerate(events):
        event.event_id = f"isolation-{index}"
        if index in {1, 3}:
            event.tenant_id = "tenant-b"
        else:
            event.tenant_id = "tenant-a"
        pipeline.ingest(event)

    assert pipeline.store.list_incidents(tenant_id="tenant-a") == []
    assert pipeline.store.list_incidents(tenant_id="tenant-b") == []


def test_rare_parent_child_and_command_are_high_anomaly(settings) -> None:
    pipeline = HuntingPipeline(settings)
    start = datetime(2026, 8, 1, tzinfo=UTC)
    for index in range(30):
        pipeline.ingest(
            SecurityEvent(
                event_id=f"normal-{index}",
                tenant_id="tenant-a",
                asset_id="server-01",
                observed_at=start + timedelta(minutes=index),
                event_type="process.start",
                source="sysmon",
                actor={"user": {"name": "SYSTEM"}},
                process={
                    "name": "svchost.exe",
                    "command_line": "svchost.exe -k netsvcs",
                },
                parent_process={"name": "services.exe"},
            )
        )

    rare = pipeline.ingest(
        SecurityEvent(
            event_id="rare-1",
            tenant_id="tenant-a",
            asset_id="server-01",
            observed_at=start + timedelta(hours=1),
            event_type="process.start",
            source="sysmon",
            actor={"user": {"name": "IIS APPPOOL\\App"}},
            process={
                "name": "powershell.exe",
                "command_line": "powershell.exe -enc AAAABBBBCCCCDDDDEEEEFFFF",
            },
            parent_process={"name": "w3wp.exe"},
        )
    )

    assert rare.anomaly.baseline_mature is True
    assert rare.anomaly.score >= 80
    features = {reason.feature for reason in rare.anomaly.reasons}
    assert "parent_child" in features
    assert "command_shape" in features


def test_duplicate_event_is_idempotent(settings) -> None:
    pipeline = HuntingPipeline(settings)
    event = _sample_events()[0]
    first = pipeline.ingest(event)
    second = pipeline.ingest(event)
    assert first.event_id == second.event_id
    assert pipeline.store.count_events("tenant-demo") == 1
