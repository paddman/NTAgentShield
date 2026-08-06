from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import Settings
from .models import SecurityEvent
from .pipeline import HuntingPipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay canonical JSONL events into NTAgentShield")
    parser.add_argument("path", type=Path)
    args = parser.parse_args()

    settings = Settings.from_env()
    pipeline = HuntingPipeline(settings)
    incidents = {}
    with args.path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                event = SecurityEvent.model_validate_json(line)
            except Exception as exc:  # noqa: BLE001 - CLI should report the source line
                raise SystemExit(f"Invalid event at line {line_number}: {exc}") from exc
            result = pipeline.ingest(event)
            print(
                json.dumps(
                    {
                        "event_id": result.event_id,
                        "anomaly_score": result.anomaly.score,
                        "incident_ids": [item.incident_id for item in result.incidents],
                    },
                    ensure_ascii=False,
                )
            )
            for incident in result.incidents:
                incidents[incident.incident_id] = incident

    print(f"replay_complete incidents={len(incidents)}")


if __name__ == "__main__":
    main()
