from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ntshield.engine.matcher import get_field, matches
from ntshield.engine.rules import BehaviorRule
from ntshield.models import SecurityEvent


@dataclass
class PartialMatch:
    next_step: int
    event_ids: list[str]
    started_at: datetime
    last_at: datetime
    max_anomaly_score: float
    bindings: dict[str, Any]


@dataclass
class SequenceMatch:
    rule: BehaviorRule
    event_ids: list[str]
    first_seen: datetime
    last_seen: datetime
    max_anomaly_score: float


def _step_matches(event: SecurityEvent, step: Any, bindings: dict[str, Any]) -> bool:
    if not matches(event, step.match):
        return False
    for field_path, variable in step.where.items():
        variable_name = variable[1:] if variable.startswith("$") else variable
        if variable_name not in bindings:
            return False
        actual = get_field(event, field_path)
        expected = bindings[variable_name]
        if isinstance(actual, str) and isinstance(expected, str):
            if actual.casefold() != expected.casefold():
                return False
        elif actual != expected:
            return False
    return True


def _apply_bindings(event: SecurityEvent, step: Any, bindings: dict[str, Any]) -> dict[str, Any]:
    updated = dict(bindings)
    for variable, field_path in step.bind.items():
        value = get_field(event, field_path)
        if value is not None:
            updated[variable] = value
    return updated


class SequenceEngine:
    def __init__(self, rules: list[BehaviorRule]):
        self.rules = rules
        self._state: dict[tuple[str, tuple[Any, ...]], list[PartialMatch]] = {}
        self._emitted: dict[tuple[str, tuple[str, ...]], datetime] = {}
        self._max_window_seconds = max((rule.window_seconds for rule in rules), default=600)

    @staticmethod
    def _group(rule: BehaviorRule, event: SecurityEvent) -> tuple[Any, ...]:
        return tuple(get_field(event, path) for path in rule.group_by)

    def _prune_emitted(self, now: datetime) -> None:
        retention = self._max_window_seconds * 2
        self._emitted = {
            signature: emitted_at
            for signature, emitted_at in self._emitted.items()
            if 0 <= (now - emitted_at).total_seconds() <= retention
        }

    def process(self, event: SecurityEvent, anomaly_score: float) -> list[SequenceMatch]:
        self._prune_emitted(event.observed_at)
        emitted: list[SequenceMatch] = []
        for rule in self.rules:
            group = self._group(rule, event)
            state_key = (rule.id, group)
            existing = self._state.get(state_key, [])
            alive: list[PartialMatch] = []

            for partial in existing:
                age = (event.observed_at - partial.started_at).total_seconds()
                if age < 0 or age > rule.window_seconds:
                    continue
                step = rule.steps[partial.next_step]
                step_age = (event.observed_at - partial.last_at).total_seconds()
                if step.within_seconds is not None and step_age > step.within_seconds:
                    alive.append(partial)
                    continue
                if event.event_id in partial.event_ids:
                    alive.append(partial)
                    continue
                if _step_matches(event, step, partial.bindings):
                    advanced = PartialMatch(
                        next_step=partial.next_step + 1,
                        event_ids=[*partial.event_ids, event.event_id],
                        started_at=partial.started_at,
                        last_at=event.observed_at,
                        max_anomaly_score=max(partial.max_anomaly_score, anomaly_score),
                        bindings=_apply_bindings(event, step, partial.bindings),
                    )
                    if advanced.next_step == len(rule.steps):
                        signature = (rule.id, tuple(advanced.event_ids))
                        if (
                            signature not in self._emitted
                            and advanced.max_anomaly_score >= rule.minimum_anomaly_score
                        ):
                            self._emitted[signature] = advanced.last_at
                            emitted.append(
                                SequenceMatch(
                                    rule=rule,
                                    event_ids=advanced.event_ids,
                                    first_seen=advanced.started_at,
                                    last_seen=advanced.last_at,
                                    max_anomaly_score=advanced.max_anomaly_score,
                                )
                            )
                    else:
                        alive.append(advanced)
                alive.append(partial)

            first_step = rule.steps[0]
            if _step_matches(event, first_step, {}):
                alive.append(
                    PartialMatch(
                        next_step=1,
                        event_ids=[event.event_id],
                        started_at=event.observed_at,
                        last_at=event.observed_at,
                        max_anomaly_score=anomaly_score,
                        bindings=_apply_bindings(event, first_step, {}),
                    )
                )

            # Bound memory in noisy environments while preserving recent candidates.
            alive.sort(key=lambda item: item.last_at, reverse=True)
            if alive:
                self._state[state_key] = alive[:200]
            else:
                self._state.pop(state_key, None)
        return emitted
