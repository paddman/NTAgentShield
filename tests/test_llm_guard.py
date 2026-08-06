import json

import pytest

from ntshield.llm.guard import AnalystOutputError, validate_report


def valid_payload(event_id: str = "evt-1") -> str:
    return json.dumps(
        {
            "verdict": "suspicious",
            "confidence": 0.8,
            "executive_summary": "Suspicious behavior chain",
            "technical_summary": "A service process launched an interpreter.",
            "zero_day_hypothesis": {
                "plausible": False,
                "confidence": 0.2,
                "rationale": "Insufficient exploit evidence",
                "signature_gap": "No exploit signature supplied",
            },
            "evidence": [{"event_id": event_id, "observation": "Observed process chain"}],
            "attack_chain": [
                {
                    "stage": "Execution",
                    "technique_id": "T1059",
                    "confidence": 0.8,
                    "evidence_ids": [event_id],
                }
            ],
            "investigation_queries": ["Search sibling assets for the same lineage"],
            "recommended_actions": [
                {
                    "action": "Collect process tree",
                    "purpose": "Validate lineage",
                    "risk": "low",
                    "requires_approval": False,
                }
            ],
            "evidence_gaps": ["No memory capture"],
        }
    )


def test_valid_report_accepts_known_evidence() -> None:
    report = validate_report(valid_payload(), {"evt-1"})
    assert report.verdict == "suspicious"


def test_report_rejects_invented_evidence() -> None:
    with pytest.raises(AnalystOutputError, match="unknown evidence"):
        validate_report(valid_payload("invented-id"), {"evt-1"})


def test_report_rejects_disruptive_action_without_approval() -> None:
    payload = json.loads(valid_payload())
    payload["recommended_actions"] = [
        {
            "action": "Isolate host",
            "purpose": "Contain outbound traffic",
            "risk": "high",
            "requires_approval": False,
        }
    ]
    with pytest.raises(AnalystOutputError, match="requires approval"):
        validate_report(json.dumps(payload), {"evt-1"})


def test_report_rejects_confirmed_zero_day_claim() -> None:
    payload = json.loads(valid_payload())
    payload["executive_summary"] = "This is a confirmed zero-day"
    with pytest.raises(AnalystOutputError, match="confirmed zero-day"):
        validate_report(json.dumps(payload), {"evt-1"})
