from __future__ import annotations

import math
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass

from ntshield.models import BaselineObservation, SecurityEvent
from ntshield.storage import SQLiteStore


@dataclass(frozen=True)
class Feature:
    name: str
    value: str
    weight: float


@dataclass(frozen=True)
class Scope:
    key: str
    label: str
    weight: float


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip().casefold()
    return value or None


def _query_shape(statement: str | None) -> str | None:
    if not statement:
        return None
    shaped = re.sub(r"'(?:''|[^'])*'", "?", statement)
    shaped = re.sub(r"\b\d+(?:\.\d+)?\b", "?", shaped)
    shaped = re.sub(r"\s+", " ", shaped).strip().casefold()
    return shaped[:300]


def extract_features(event: SecurityEvent) -> list[Feature]:
    features: list[Feature] = []
    proc = _clean(event.process.name)
    parent = _clean(event.process.parent_name)
    user = _clean(event.actor.user)
    dst = _clean(event.network.destination_ip or event.network.domain)
    file_path = _clean(event.file.path)

    if proc:
        features.append(Feature("process_name", proc, 1.0))
    if proc and parent:
        features.append(Feature("process_lineage", f"{parent}>{proc}", 1.6))
    if proc and dst:
        port = event.network.destination_port or 0
        features.append(Feature("process_destination", f"{proc}>{dst}:{port}", 1.8))
    if user:
        features.append(Feature("user_asset", user, 0.8))
        features.append(Feature("user_hour", f"{user}:{event.observed_at.hour:02d}", 0.7))
    if file_path:
        directory = os.path.dirname(file_path.replace("\\", "/")) or "/"
        features.append(Feature("file_directory", directory, 1.0))
    if event.service.binary_path:
        features.append(
            Feature("service_binary", _clean(event.service.binary_path) or "", 1.7)
        )
    if event.web.method and event.web.route:
        features.append(
            Feature(
                "web_route_method",
                f"{event.web.method.casefold()}:{event.web.route.casefold()}",
                0.8,
            )
        )
    query_shape = event.database.query_shape or _query_shape(event.database.statement)
    if query_shape:
        features.append(Feature("database_query_shape", query_shape, 1.4))
    features.append(Feature("event_type", event.event_type.casefold(), 0.5))
    return [feature for feature in features if feature.value]


class BaselineEngine:
    def __init__(self, store: SQLiteStore, warmup_events: int = 30):
        self.store = store
        self.warmup_events = warmup_events

    @staticmethod
    def scopes(event: SecurityEvent) -> list[Scope]:
        role = (event.asset.role or "unknown").casefold()
        return [
            Scope(key=f"asset:{event.asset.id}", label="asset", weight=0.65),
            Scope(key=f"role:{role}", label="peer_role", weight=0.35),
        ]

    def _scope_surprise(
        self,
        event: SecurityEvent,
        scope: Scope,
        feature: Feature,
    ) -> tuple[float, bool, int, int]:
        count, total = self.store.get_feature_count(
            event.tenant_id, scope.key, feature.name, feature.value
        )
        cold = total < self.warmup_events
        probability = (count + 0.5) / (total + 10.0)
        surprise = min(1.0, max(0.0, -math.log10(probability) / 2.5))
        if cold:
            warmup_ratio = total / max(self.warmup_events, 1)
            surprise *= min(0.45, max(0.15, warmup_ratio))
        return surprise, cold, count, total

    def assess(self, event: SecurityEvent) -> BaselineObservation:
        scores: dict[str, float] = {}
        rare: list[str] = []
        weighted_sum = 0.0
        weight_total = 0.0
        cold_features = 0
        features = extract_features(event)
        scopes = self.scopes(event)

        for feature in features:
            feature_score = 0.0
            all_scopes_cold = True
            for scope in scopes:
                surprise, cold, count, total = self._scope_surprise(event, scope, feature)
                all_scopes_cold = all_scopes_cold and cold
                feature_score += surprise * scope.weight
                scores[f"{scope.label}:{feature.name}:{feature.value}"] = round(
                    surprise * 100, 2
                )
                if count <= 1 and total >= self.warmup_events:
                    rare.append(f"{scope.label}:{feature.name}={feature.value}")
            cold_features += int(all_scopes_cold)
            weighted_sum += feature_score * feature.weight
            weight_total += feature.weight

        overall = 0.0 if weight_total == 0 else (weighted_sum / weight_total) * 100
        return BaselineObservation(
            score=round(min(100.0, overall), 2),
            cold_start=bool(features) and cold_features == len(features),
            rare_features=list(dict.fromkeys(rare))[:12],
            feature_scores=scores,
        )

    def learn(self, event: SecurityEvent) -> None:
        observed_at = event.observed_at.isoformat()
        for scope in self.scopes(event):
            for feature in extract_features(event):
                self.store.increment_feature(
                    event.tenant_id,
                    scope.key,
                    feature.name,
                    feature.value,
                    observed_at,
                )

    def train(self, events: Iterable[SecurityEvent]) -> None:
        for event in events:
            self.learn(event)
