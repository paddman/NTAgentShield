from __future__ import annotations

from pathlib import Path

import pytest

from ntshield.settings import Settings


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def test_settings(tmp_path: Path, repo_root: Path) -> Settings:
    return Settings(
        database_path=tmp_path / "test.db",
        rules_path=repo_root / "rules" / "behavioral",
        baseline_warmup_events=3,
        anomaly_finding_threshold=85,
        qwen_enabled=False,
    )
