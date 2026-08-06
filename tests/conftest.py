from __future__ import annotations

from pathlib import Path

import pytest

from ntshield.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    root = Path(__file__).resolve().parents[1]
    return Settings(
        db_path=tmp_path / "test.db",
        rules_dir=root / "rules" / "behavioral",
        incident_threshold=65,
        anomaly_threshold=72,
        baseline_min_observations=10,
        max_event_raw_chars=4096,
        qwen_enabled=False,
        qwen_base_url="http://127.0.0.1:8000/v1",
        qwen_api_key="EMPTY",
        qwen_model="Qwen/Qwen3.5-9B",
        qwen_max_tool_rounds=4,
        qwen_timeout_seconds=5,
    )
