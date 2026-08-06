from __future__ import annotations

import argparse
import json
from pathlib import Path

import uvicorn

from ntshield.engine.hunt import HuntEngine
from ntshield.models import SecurityEvent
from ntshield.settings import Settings


def replay(path: Path, settings: Settings) -> int:
    engine = HuntEngine(settings)
    accepted = findings = 0
    incident_ids: set[str] = set()
    try:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                event = SecurityEvent.model_validate(json.loads(line))
            except Exception as exc:
                raise ValueError(f"Invalid event at {path}:{line_number}: {exc}") from exc
            result = engine.ingest(event)
            accepted += 1
            findings += len(result.findings)
            incident_ids.update(item.incident_id for item in result.incidents)
            for finding in result.findings:
                print(
                    f"[{finding.severity.upper()} {finding.risk_score:.1f}] "
                    f"{finding.rule_id}: {finding.title}"
                )
        print(
            json.dumps(
                {
                    "accepted": accepted,
                    "findings": findings,
                    "incidents": len(incident_ids),
                    "incident_ids": sorted(incident_ids),
                },
                indent=2,
            )
        )
        return 0
    finally:
        engine.store.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ntshield")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Run API and dashboard")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", default=8080, type=int)
    serve.add_argument("--reload", action="store_true")

    replay_parser = subparsers.add_parser("replay", help="Replay normalized JSONL events")
    replay_parser.add_argument("path", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    settings = Settings()
    if args.command == "serve":
        uvicorn.run("ntshield.app:app", host=args.host, port=args.port, reload=args.reload)
        return 0
    if args.command == "replay":
        return replay(args.path, settings)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
