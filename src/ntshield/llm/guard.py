from __future__ import annotations

import json
import re
from typing import Any

from ntshield.llm.schemas import AnalystReport


DISRUPTIVE_ACTIONS = {
    "isolate",
    "quarantine",
    "block",
    "kill",
    "terminate",
    "disable",
    "delete",
    "revoke",
    "reset password",
    "stop service",
    "แยกเครื่อง",
    "กักกัน",
    "บล็อก",
    "ปิดบัญชี",
    "ลบไฟล์",
    "หยุดโปรเซส",
}


class AnalystOutputError(ValueError):
    pass


def extract_json(text: str) -> dict[str, Any]:
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE).strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        value = json.loads(cleaned)
        if not isinstance(value, dict):
            raise AnalystOutputError("The analyst response was not a JSON object")
        return value
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start < 0 or end <= start:
            raise AnalystOutputError("No JSON object found in analyst response")
        try:
            value = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError as exc:
            raise AnalystOutputError(f"Invalid analyst JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise AnalystOutputError("The analyst response was not a JSON object")
        return value


def validate_report(text: str, allowed_event_ids: set[str]) -> AnalystReport:
    report = AnalystReport.model_validate(extract_json(text))
    referenced: set[str] = {item.event_id for item in report.evidence}
    for stage in report.attack_chain:
        referenced.update(stage.evidence_ids)
    unknown = referenced - allowed_event_ids
    if unknown:
        raise AnalystOutputError(
            f"Analyst invented or referenced unknown evidence IDs: {sorted(unknown)}"
        )
    if report.verdict == "malicious" and not report.evidence:
        raise AnalystOutputError("A malicious verdict requires explicit evidence")
    report_text = " ".join(
        [report.executive_summary, report.technical_summary, report.zero_day_hypothesis.rationale]
    ).casefold()
    if "confirmed zero-day" in report_text or "ยืนยันว่าเป็น zero-day" in report_text:
        raise AnalystOutputError("The analyst may not claim a confirmed zero-day")
    for action in report.recommended_actions:
        action_text = f"{action.action} {action.purpose}".casefold()
        if any(keyword in action_text for keyword in DISRUPTIVE_ACTIONS):
            if not action.requires_approval:
                raise AnalystOutputError(
                    f"Disruptive action requires approval: {action.action}"
                )
    return report
