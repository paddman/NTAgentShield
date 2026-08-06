from __future__ import annotations

import json

from ntshield.engine.hunt import HuntEngine
from ntshield.models import SecurityEvent


def test_web_zero_day_chain_creates_grounded_incident(test_settings, repo_root) -> None:
    engine = HuntEngine(test_settings)
    results = []
    try:
        for line in (repo_root / "examples" / "zero_day_web_chain.jsonl").read_text(
            encoding="utf-8"
        ).splitlines():
            results.append(engine.ingest(SecurityEvent.model_validate(json.loads(line))))

        findings = [finding for result in results for finding in result.findings]
        assert any(finding.rule_id == "BZH-WEB-001" for finding in findings)
        finding = next(item for item in findings if item.rule_id == "BZH-WEB-001")
        assert finding.severity == "critical"
        assert {e.event_id for e in finding.evidence} == {
            "demo-web-001",
            "demo-proc-002",
            "demo-net-003",
            "demo-file-004",
        }
        incidents = engine.store.list_incidents("demo")
        assert len(incidents) >= 1
        assert finding.finding_id in incidents[0].finding_ids
    finally:
        engine.store.close()


def test_web_chain_without_request_metadata_uses_generic_rule(test_settings, repo_root) -> None:
    engine = HuntEngine(test_settings)
    try:
        events = [
            SecurityEvent.model_validate(json.loads(line))
            for line in (repo_root / "examples" / "zero_day_web_chain.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
        ][1:4]
        findings = [finding for event in events for finding in engine.ingest(event).findings]
        assert [item.rule_id for item in findings] == ["BZH-WEB-003"]
    finally:
        engine.store.close()


def test_pid_binding_blocks_unrelated_network_event(test_settings, repo_root) -> None:
    engine = HuntEngine(test_settings)
    try:
        events = [
            SecurityEvent.model_validate(json.loads(line))
            for line in (repo_root / "examples" / "zero_day_web_chain.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
        ][1:4]
        events[1].process.pid = 9999
        findings = [finding for event in events for finding in engine.ingest(event).findings]
        assert not any(item.rule_id == "BZH-WEB-003" for item in findings)
    finally:
        engine.store.close()
