from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class Settings:
    db_path: Path
    rules_dir: Path
    incident_threshold: float
    anomaly_threshold: float
    baseline_min_observations: int
    max_event_raw_chars: int
    qwen_enabled: bool
    qwen_base_url: str
    qwen_api_key: str
    qwen_model: str
    qwen_max_tool_rounds: int
    qwen_timeout_seconds: float

    @classmethod
    def from_env(cls) -> "Settings":
        repository_root = Path(__file__).resolve().parents[2]
        default_rules = repository_root / "rules" / "behavioral"
        return cls(
            db_path=Path(os.getenv("NTSHIELD_DB_PATH", "data/ntshield.db")),
            rules_dir=Path(os.getenv("NTSHIELD_RULES_DIR", str(default_rules))),
            incident_threshold=float(os.getenv("NTSHIELD_INCIDENT_THRESHOLD", "65")),
            anomaly_threshold=float(os.getenv("NTSHIELD_ANOMALY_THRESHOLD", "72")),
            baseline_min_observations=int(
                os.getenv("NTSHIELD_BASELINE_MIN_OBSERVATIONS", "20")
            ),
            max_event_raw_chars=int(os.getenv("NTSHIELD_MAX_EVENT_RAW_CHARS", "4096")),
            qwen_enabled=_env_bool("QWEN_ENABLED", True),
            qwen_base_url=os.getenv("QWEN_BASE_URL", "http://127.0.0.1:8000/v1").rstrip("/"),
            qwen_api_key=os.getenv("QWEN_API_KEY", "EMPTY"),
            qwen_model=os.getenv("QWEN_MODEL", "Qwen/Qwen3.5-9B"),
            qwen_max_tool_rounds=int(os.getenv("QWEN_MAX_TOOL_ROUNDS", "4")),
            qwen_timeout_seconds=float(os.getenv("QWEN_TIMEOUT_SECONDS", "90")),
        )
