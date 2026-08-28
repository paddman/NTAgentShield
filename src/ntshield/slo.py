from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ServiceLevelObjective:
    name: str
    objective: float
    window_days: int
    description: str
    indicator: str


DEFAULT_SLOS = (
    ServiceLevelObjective(
        name="operator_api_availability",
        objective=99.9,
        window_days=30,
        description="Protected operator requests complete without 5xx responses.",
        indicator="1 - rate(5xx) / rate(all protected requests)",
    ),
    ServiceLevelObjective(
        name="operator_api_latency",
        objective=99.0,
        window_days=30,
        description="Protected operator requests complete within 500 ms.",
        indicator="histogram fraction <= 0.5 seconds",
    ),
    ServiceLevelObjective(
        name="ingest_delivery",
        objective=99.9,
        window_days=30,
        description="Accepted async ingest jobs leave queued state within five minutes.",
        indicator="queued jobs younger than five minutes / accepted jobs",
    ),
    ServiceLevelObjective(
        name="audit_durability",
        objective=100.0,
        window_days=30,
        description="Protected state-changing requests have a durable audit record.",
        indicator="1 - audit append failures / protected writes",
    ),
)


def slo_catalog() -> list[dict[str, Any]]:
    return [asdict(item) for item in DEFAULT_SLOS]
