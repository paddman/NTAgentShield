from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from .models import AnomalyReason, AnomalyResult, SecurityEvent
from .store import SQLiteStore
from .utils import (
    command_shape,
    destination_bucket,
    file_bucket,
    get_path,
    normalize_name,
    safe_text,
)


@dataclass(frozen=True, slots=True)
class FeatureObservation:
    name: str
    value: str
    weight: float
    label: str


@dataclass(frozen=True, slots=True)
class NumericObservation:
    name: str
    value: float
    weight: float
    label: str


class BehavioralBaseline:
    """Online per-tenant, per-asset baseline.

    The engine evaluates categorical relationships and numeric distributions before updating
    them with the current event. Scoring before learning prevents the event being assessed
    from immediately reducing its own novelty.
    """

    def __init__(self, store: SQLiteStore, min_observations: int = 20):
        self.store = store
        self.min_observations = max(5, min_observations)

    def score(self, event: SecurityEvent, *, learn: bool = True) -> AnomalyResult:
        categorical = self._categorical_features(event)
        numeric = self._numeric_features(event)
        reasons: list[AnomalyReason] = []
        components: list[float] = []
        maturity_flags: list[bool] = []

        for feature in categorical:
            count, total = self.store.get_categorical_stats(
                event.tenant_id, event.asset_id, feature.name, feature.value
            )
            mature = total >= self.min_observations
            maturity_flags.append(mature)
            novelty = self._categorical_novelty(count, total)
            component = min(0.82, novelty * feature.weight * 0.72)
            if novelty >= 0.22:
                reasons.append(
                    AnomalyReason(
                        feature=feature.name,
                        value=feature.value,
                        novelty=round(novelty, 4),
                        weight=feature.weight,
                        prior_count=count,
                        prior_total=total,
                        explanation=(
                            f"{feature.label} ไม่เคยพบใน baseline"
                            if count == 0
                            else f"{feature.label} พบเพียง {count} จาก {total} ครั้ง"
                        ),
                    )
                )
            if component > 0:
                components.append(component)

        for feature in numeric:
            n, mean, m2 = self.store.get_numeric_stats(
                event.tenant_id, event.asset_id, feature.name
            )
            mature = n >= self.min_observations
            maturity_flags.append(mature)
            novelty, z_score = self._numeric_novelty(feature.value, n, mean, m2)
            component = min(0.82, novelty * feature.weight * 0.72)
            if novelty >= 0.22:
                reasons.append(
                    AnomalyReason(
                        feature=feature.name,
                        value=f"{feature.value:g}",
                        novelty=round(novelty, 4),
                        weight=feature.weight,
                        prior_count=n,
                        prior_total=n,
                        explanation=(
                            f"{feature.label} สูงกว่าค่าปกติประมาณ {z_score:.1f} standard deviations"
                        ),
                    )
                )
            if component > 0:
                components.append(component)

        probability_normal = 1.0
        for component in sorted(components, reverse=True)[:6]:
            probability_normal *= 1.0 - component
        score = round(min(100.0, (1.0 - probability_normal) * 100.0), 2)
        reasons.sort(key=lambda item: item.novelty * item.weight, reverse=True)

        if learn:
            for feature in categorical:
                self.store.increment_categorical(
                    event.tenant_id,
                    event.asset_id,
                    feature.name,
                    feature.value,
                    event.observed_at,
                )
            for feature in numeric:
                self.store.update_numeric(
                    event.tenant_id,
                    event.asset_id,
                    feature.name,
                    feature.value,
                    event.observed_at,
                )

        return AnomalyResult(
            score=score,
            reasons=reasons[:10],
            baseline_mature=any(maturity_flags),
        )

    def _categorical_novelty(self, count: int, total: int) -> float:
        if total < self.min_observations:
            return 0.18 if count == 0 else 0.0
        if count == 0:
            return 1.0
        frequency = (count + 0.5) / (total + 1.0)
        return min(1.0, max(0.0, (-math.log10(frequency) - 0.25) / 2.0))

    def _numeric_novelty(
        self, value: float, n: int, mean: float, m2: float
    ) -> tuple[float, float]:
        if n < self.min_observations or n < 2:
            return (0.0, 0.0)
        variance = m2 / (n - 1)
        if variance <= 1e-12:
            if value <= mean:
                return (0.0, 0.0)
            relative = (value - mean) / max(abs(mean), 1.0)
            return (min(1.0, relative / 5.0), relative)
        z_score = (value - mean) / math.sqrt(variance)
        if z_score <= 2.0:
            return (0.0, z_score)
        return (min(1.0, (z_score - 2.0) / 5.0), z_score)

    def _categorical_features(self, event: SecurityEvent) -> list[FeatureObservation]:
        payload = event.model_dump(mode="python")
        process_name = normalize_name(get_path(payload, "process.name"))
        parent_name = normalize_name(get_path(payload, "parent_process.name"))
        user_name = safe_text(
            get_path(payload, "actor.user.name", get_path(payload, "actor.user")), 256
        ).lower()
        command = command_shape(get_path(payload, "process.command_line"))
        destination = destination_bucket(
            get_path(payload, "network.dst.ip"),
            get_path(payload, "network.dst.domain"),
            get_path(payload, "network.dst.port"),
        )
        path_bucket = file_bucket(get_path(payload, "file.path"))
        auth_source = destination_bucket(
            get_path(payload, "auth.src_ip", get_path(payload, "network.src.ip")),
            None,
            get_path(payload, "auth.src_port", get_path(payload, "network.src.port")),
        )
        service_name = safe_text(get_path(payload, "service.name"), 256).lower()
        process_hour = f"{process_name}|{event.observed_at.hour:02d}" if process_name else ""

        candidates = [
            FeatureObservation("process_name", process_name, 0.50, "ชื่อ process"),
            FeatureObservation(
                "parent_child",
                f"{parent_name}->{process_name}" if parent_name and process_name else "",
                1.00,
                "ความสัมพันธ์ parent-child process",
            ),
            FeatureObservation(
                "user_process",
                f"{user_name}->{process_name}" if user_name and process_name else "",
                0.72,
                "ผู้ใช้ที่เรียก process",
            ),
            FeatureObservation(
                "command_shape",
                f"{process_name}|{command}" if process_name and command else "",
                0.90,
                "รูปแบบ command line",
            ),
            FeatureObservation(
                "process_destination",
                f"{process_name}->{destination}" if process_name and destination else "",
                1.00,
                "ปลายทางเครือข่ายของ process",
            ),
            FeatureObservation(
                "file_write_bucket",
                f"{process_name}->{path_bucket}" if process_name and path_bucket else "",
                0.78,
                "ตำแหน่งและชนิดไฟล์ที่ process เขียน",
            ),
            FeatureObservation(
                "login_source",
                f"{user_name}<-{auth_source}" if user_name and auth_source else "",
                0.90,
                "ต้นทางการเข้าสู่ระบบ",
            ),
            FeatureObservation(
                "service_process",
                f"{service_name}->{process_name}" if service_name and process_name else "",
                0.82,
                "process ที่ผูกกับ service",
            ),
            FeatureObservation("process_hour", process_hour, 0.34, "ช่วงเวลาที่ process ทำงาน"),
        ]
        return [feature for feature in candidates if feature.value]

    def _numeric_features(self, event: SecurityEvent) -> list[NumericObservation]:
        payload = event.model_dump(mode="python")
        candidates: list[tuple[str, Any, float, str]] = [
            ("network_bytes_out", get_path(payload, "network.bytes_out"), 1.0, "ข้อมูลขาออก"),
            (
                "database_rows_returned",
                get_path(payload, "database.rows_returned"),
                0.95,
                "จำนวนแถวที่ฐานข้อมูลส่งกลับ",
            ),
            ("file_bytes_written", get_path(payload, "file.bytes_written"), 0.75, "ขนาดไฟล์ที่เขียน"),
            ("process_cpu_percent", get_path(payload, "process.cpu_percent"), 0.45, "CPU ของ process"),
        ]
        observations: list[NumericObservation] = []
        for name, value, weight, label in candidates:
            try:
                numeric_value = float(value)
            except (TypeError, ValueError):
                continue
            if numeric_value < 0 or not math.isfinite(numeric_value):
                continue
            observations.append(NumericObservation(name, numeric_value, weight, label))
        return observations
