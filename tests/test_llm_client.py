from ntshield.llm.client import QwenAnalyst
from ntshield.models import AssetContext, SecurityEvent


def test_safe_event_redacts_obvious_secrets(test_settings) -> None:
    event = SecurityEvent(
        tenant_id="tenant-a",
        source_type="app",
        event_type="application.log",
        asset=AssetContext(id="app-01"),
        message="password=hunter2 token=abc123",
        raw={
            "authorization": "Bearer secret-token",
            "nested": {"api_key": "private-key", "safe": "visible"},
        },
    )
    safe = QwenAnalyst(test_settings)._safe_event(event, 2048)
    assert "hunter2" not in safe["message"]
    assert "abc123" not in safe["message"]
    assert "secret-token" not in safe["raw"]
    assert "private-key" not in safe["raw"]
    assert "visible" in safe["raw"]
