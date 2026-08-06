from __future__ import annotations

import json

from fastapi.testclient import TestClient

from ntshield.app import create_app


def test_api_replay_and_stats(test_settings, repo_root) -> None:
    events = [
        json.loads(line)
        for line in (repo_root / "examples" / "zero_day_web_chain.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
    ]
    app = create_app(test_settings)
    with TestClient(app) as client:
        response = client.post("/v1/events/bulk", json={"events": events})
        assert response.status_code == 200, response.text
        assert response.json()["accepted"] == len(events)
        stats = client.get("/v1/stats", params={"tenant_id": "demo"})
        assert stats.status_code == 200
        assert stats.json()["events"] == len(events)
        assert stats.json()["incidents"] >= 1
        health = client.get("/health")
        assert health.json()["rules_loaded"] == 13
