from __future__ import annotations

import argparse
import json
import ssl
from pathlib import Path

import uvicorn

from ntshield.engine.hunt import HuntEngine
from ntshield.enrollment import EnrollmentTokenManager, initialize_ca
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
    serve.add_argument("--ssl-certfile", type=Path)
    serve.add_argument("--ssl-keyfile", type=Path)
    serve.add_argument("--ssl-ca-certs", type=Path)
    serve.add_argument("--require-client-cert", action="store_true")

    replay_parser = subparsers.add_parser("replay", help="Replay normalized JSONL events")
    replay_parser.add_argument("path", type=Path)

    init_ca = subparsers.add_parser("init-ca", help="Create the enrollment certificate authority")
    init_ca.add_argument("--cert", type=Path)
    init_ca.add_argument("--key", type=Path)
    init_ca.add_argument("--years", type=int, default=10)

    token = subparsers.add_parser("enrollment-token", help="Issue a short-lived signed enrollment token")
    token.add_argument("--tenant", required=True)
    token.add_argument("--ttl", type=int, default=600, help="token lifetime in seconds")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    settings = Settings()
    if args.command == "serve":
        if args.require_client_cert and not (
            args.ssl_certfile and args.ssl_keyfile and args.ssl_ca_certs
        ):
            raise ValueError(
                "--require-client-cert requires --ssl-certfile, --ssl-keyfile and --ssl-ca-certs"
            )
        uvicorn.run(
            "ntshield.app:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            ssl_certfile=str(args.ssl_certfile) if args.ssl_certfile else None,
            ssl_keyfile=str(args.ssl_keyfile) if args.ssl_keyfile else None,
            ssl_ca_certs=str(args.ssl_ca_certs) if args.ssl_ca_certs else None,
            ssl_cert_reqs=ssl.CERT_REQUIRED if args.require_client_cert else ssl.CERT_NONE,
        )
        return 0
    if args.command == "replay":
        return replay(args.path, settings)
    if args.command == "init-ca":
        cert_path = args.cert or settings.enrollment_ca_cert_path
        key_path = args.key or settings.enrollment_ca_key_path
        initialize_ca(cert_path, key_path, args.years)
        print(json.dumps({"certificate": str(cert_path), "private_key": str(key_path)}))
        return 0
    if args.command == "enrollment-token":
        manager = EnrollmentTokenManager(settings.enrollment_signing_secret)
        print(manager.issue(args.tenant, args.ttl))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
