from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from .models import RuleMatch, SecurityEvent
from .utils import get_path, stable_hash


class RuleCondition(BaseModel):
    field: str
    op: Literal[
        "eq",
        "neq",
        "in",
        "not_in",
        "contains",
        "regex",
        "not_regex",
        "exists",
        "gt",
        "gte",
        "lt",
        "lte",
        "is_public_ip",
    ] = "eq"
    value: Any = None


class RuleStep(BaseModel):
    name: str
    event_types: list[str] = Field(min_length=1)
    where: list[RuleCondition] = Field(default_factory=list)


class BehaviorRule(BaseModel):
    id: str
    title: str
    description: str = ""
    enabled: bool = True
    severity: Literal["informational", "low", "medium", "high", "critical"] = "medium"
    confidence: float = Field(default=0.8, ge=0, le=1)
    window_seconds: int = Field(default=300, ge=1, le=86400)
    ordered: bool = True
    group_by: list[str] = Field(default_factory=lambda: ["tenant_id", "asset_id"])
    tags: list[str] = Field(default_factory=list)
    steps: list[RuleStep] = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def normalize_id(cls, value: str) -> str:
        return value.strip().upper()


class RuleEngine:
    def __init__(self, rules: list[BehaviorRule]):
        self.rules = [rule for rule in rules if rule.enabled]
        self.by_id = {rule.id: rule for rule in self.rules}
        self.max_window_seconds = max((rule.window_seconds for rule in self.rules), default=300)

    @classmethod
    def from_directory(cls, directory: Path | str) -> "RuleEngine":
        path = Path(directory)
        rules: list[BehaviorRule] = []
        if not path.exists():
            raise FileNotFoundError(f"Behavior rule directory does not exist: {path}")
        for rule_file in sorted([*path.glob("*.yml"), *path.glob("*.yaml")]):
            raw = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
            documents = raw if isinstance(raw, list) else [raw]
            for document in documents:
                if document:
                    rules.append(BehaviorRule.model_validate(document))
        if not rules:
            raise ValueError(f"No behavior rules found in {path}")
        return cls(rules)

    def list_rule_summaries(self) -> list[dict[str, Any]]:
        return [
            {
                "id": rule.id,
                "title": rule.title,
                "description": rule.description,
                "severity": rule.severity,
                "confidence": rule.confidence,
                "window_seconds": rule.window_seconds,
                "ordered": rule.ordered,
                "steps": [step.name for step in rule.steps],
                "tags": rule.tags,
            }
            for rule in self.rules
        ]

    def evaluate(
        self, current_event: SecurityEvent, recent_payloads: list[dict[str, Any]]
    ) -> list[RuleMatch]:
        current_payload = current_event.model_dump(mode="json")
        matches: list[RuleMatch] = []
        for rule in self.rules:
            group = tuple(get_path(current_payload, field) for field in rule.group_by)
            if any(value is None or value == "" for value in group):
                continue
            candidates = [
                payload
                for payload in recent_payloads
                if tuple(get_path(payload, field) for field in rule.group_by) == group
            ]
            candidates.sort(key=lambda item: self._timestamp(item.get("observed_at")))
            selected = (
                self._match_ordered(rule, candidates)
                if rule.ordered
                else self._match_unordered(rule, candidates)
            )
            if not selected:
                continue
            event_ids = [str(payload.get("event_id")) for payload in selected]
            if current_event.event_id not in event_ids:
                continue
            fingerprint = stable_hash(rule.id, *event_ids)
            matches.append(
                RuleMatch(
                    rule_id=rule.id,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    event_ids=event_ids,
                    step_names=[step.name for step in rule.steps],
                    tags=rule.tags,
                    fingerprint=fingerprint,
                )
            )
        return matches

    def _match_ordered(
        self, rule: BehaviorRule, candidates: list[dict[str, Any]]
    ) -> list[dict[str, Any]] | None:
        if not candidates:
            return None
        for start_index, candidate in enumerate(candidates):
            if not self._event_matches(candidate, rule.steps[0]):
                continue
            selected = [candidate]
            cursor = start_index + 1
            for step in rule.steps[1:]:
                found_index = None
                for index in range(cursor, len(candidates)):
                    if self._event_matches(candidates[index], step):
                        found_index = index
                        break
                if found_index is None:
                    break
                selected.append(candidates[found_index])
                cursor = found_index + 1
            if len(selected) == len(rule.steps):
                first = self._timestamp(selected[0].get("observed_at"))
                last = self._timestamp(selected[-1].get("observed_at"))
                if (last - first).total_seconds() <= rule.window_seconds:
                    return selected
        return None

    def _match_unordered(
        self, rule: BehaviorRule, candidates: list[dict[str, Any]]
    ) -> list[dict[str, Any]] | None:
        selected: list[dict[str, Any]] = []
        used_ids: set[str] = set()
        for step in rule.steps:
            found = next(
                (
                    payload
                    for payload in candidates
                    if str(payload.get("event_id")) not in used_ids
                    and self._event_matches(payload, step)
                ),
                None,
            )
            if found is None:
                return None
            selected.append(found)
            used_ids.add(str(found.get("event_id")))
        timestamps = [self._timestamp(item.get("observed_at")) for item in selected]
        if (max(timestamps) - min(timestamps)).total_seconds() > rule.window_seconds:
            return None
        selected.sort(key=lambda item: self._timestamp(item.get("observed_at")))
        return selected

    def _event_matches(self, payload: dict[str, Any], step: RuleStep) -> bool:
        event_type = str(payload.get("event_type", ""))
        if "*" not in step.event_types and event_type not in step.event_types:
            return False
        return all(self._condition_matches(payload, condition) for condition in step.where)

    def _condition_matches(self, payload: dict[str, Any], condition: RuleCondition) -> bool:
        actual = get_path(payload, condition.field)
        expected = condition.value
        op = condition.op
        if op == "exists":
            return (actual is not None) is bool(expected if expected is not None else True)
        if op == "eq":
            return self._lower(actual) == self._lower(expected)
        if op == "neq":
            return self._lower(actual) != self._lower(expected)
        if op == "in":
            values = expected if isinstance(expected, list) else [expected]
            return self._lower(actual) in {self._lower(item) for item in values}
        if op == "not_in":
            values = expected if isinstance(expected, list) else [expected]
            return self._lower(actual) not in {self._lower(item) for item in values}
        if op == "contains":
            values = expected if isinstance(expected, list) else [expected]
            actual_text = str(actual or "").lower()
            return any(str(item).lower() in actual_text for item in values)
        if op in {"regex", "not_regex"}:
            patterns = expected if isinstance(expected, list) else [expected]
            matched = any(
                re.search(str(pattern), str(actual or ""), flags=re.IGNORECASE) is not None
                for pattern in patterns
            )
            return matched if op == "regex" else not matched
        if op in {"gt", "gte", "lt", "lte"}:
            try:
                actual_number = float(actual)
                expected_number = float(expected)
            except (TypeError, ValueError):
                return False
            return {
                "gt": actual_number > expected_number,
                "gte": actual_number >= expected_number,
                "lt": actual_number < expected_number,
                "lte": actual_number <= expected_number,
            }[op]
        if op == "is_public_ip":
            try:
                ip = ipaddress.ip_address(str(actual))
            except ValueError:
                return False
            is_public = not (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            )
            return is_public is bool(expected if expected is not None else True)
        return False

    @staticmethod
    def _lower(value: Any) -> Any:
        return value.lower() if isinstance(value, str) else value

    @staticmethod
    def _timestamp(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
