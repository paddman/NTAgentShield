from datetime import UTC, datetime, timedelta

from ntshield.engine.baseline import BaselineEngine
from ntshield.models import AssetContext, ProcessContext, SecurityEvent
from ntshield.storage import SQLiteStore


def make_event(index: int, process: str, parent: str = "explorer.exe") -> SecurityEvent:
    return SecurityEvent(
        event_id=f"event-{index}-{process}",
        tenant_id="tenant-a",
        observed_at=datetime(2026, 8, 1, 9, 0, tzinfo=UTC) + timedelta(minutes=index),
        source_type="sysmon",
        event_type="process.start",
        asset=AssetContext(id="host-01", role="workstation"),
        process=ProcessContext(name=process, parent_name=parent),
    )


def test_baseline_marks_new_lineage_as_rare(tmp_path) -> None:
    store = SQLiteStore(tmp_path / "baseline.db")
    baseline = BaselineEngine(store, warmup_events=3)
    for index in range(5):
        baseline.learn(make_event(index, "chrome.exe"))

    observation = baseline.assess(make_event(10, "rundll32.exe", "winword.exe"))
    assert observation.cold_start is False
    assert observation.score > 40
    assert any("process_lineage" in item for item in observation.rare_features)
    store.close()
