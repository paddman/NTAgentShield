from __future__ import annotations

import argparse
import json
import ssl
from pathlib import Path

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from ntshield.engine.hunt import HuntEngine
from ntshield.enrollment import EnrollmentTokenManager, initialize_ca
from ntshield.enrollment_store import AgentEnrollment, EnrollmentNonceStore
from ntshield.models import SecurityEvent
from ntshield.policy_distribution import (
    PolicyBundleStore,
    create_signed_policy_bundle,
    initialize_policy_signing_key,
)
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


def agent_summary(agent: AgentEnrollment) -> dict[str, object]:
    certificate = x509.load_pem_x509_certificate(agent.certificate_pem.encode("utf-8"))
    return {
        "tenant_id": agent.tenant_id,
        "agent_id": agent.agent_id,
        "status": agent.status,
        "enrolled_at": agent.enrolled_at.isoformat(),
        "certificate_updated_at": agent.certificate_updated_at.isoformat(),
        "certificate_expires_at": agent.expires_at.isoformat(),
        "certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "last_seen_at": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
        "revoked_at": agent.revoked_at.isoformat() if agent.revoked_at else None,
        "rotation_count": agent.rotation_count,
    }


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

    agents = subparsers.add_parser("agents", help="List enrolled Agent identities from the local Control Plane database")
    agents.add_argument("--tenant", help="optional tenant filter")

    revoke = subparsers.add_parser("revoke-agent", help="Revoke one enrolled Agent identity in the local Control Plane database")
    revoke.add_argument("--tenant", required=True)
    revoke.add_argument("--agent", required=True)

    init_policy = subparsers.add_parser(
        "init-policy-key", help="Create the independent Ed25519 policy signing trust root"
    )
    init_policy.add_argument("--private-key", type=Path)
    init_policy.add_argument("--public-key", type=Path)

    publish_policy = subparsers.add_parser(
        "publish-policy", help="Sign and publish a monotonic policy bundle into the local Control Plane database"
    )
    publish_policy.add_argument("--tenant", required=True)
    publish_policy.add_argument("--epoch", required=True, type=int)
    publish_policy.add_argument("--policy", required=True, type=Path)
    publish_policy.add_argument(
        "--agent", action="append", dest="agents", help="target Agent ID; repeat for multiple Agents; default '*'"
    )
    publish_policy.add_argument("--ttl-hours", type=int, default=720)

    policies = subparsers.add_parser("policies", help="List published signed policy metadata")
    policies.add_argument("--tenant", help="optional tenant filter")
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
    if args.command == "agents":
        store = EnrollmentNonceStore(settings.database_path)
        try:
            agents = store.list_agents(args.tenant)
            print(json.dumps([agent_summary(agent) for agent in agents], indent=2))
        finally:
            store.close()
        return 0
    if args.command == "revoke-agent":
        store = EnrollmentNonceStore(settings.database_path)
        try:
            if not store.revoke_agent(args.tenant, args.agent):
                raise ValueError("Agent was not found or is already revoked")
            agent = store.get_agent(args.tenant, args.agent)
            assert agent is not None
            print(json.dumps(agent_summary(agent), indent=2))
        finally:
            store.close()
        return 0
    if args.command == "init-policy-key":
        private_path = args.private_key or settings.policy_signing_private_key_path
        public_path = args.public_key or settings.policy_signing_public_key_path
        initialize_policy_signing_key(private_path, public_path)
        print(json.dumps({"private_key": str(private_path), "public_key": str(public_path)}))
        return 0
    if args.command == "publish-policy":
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        if not isinstance(policy, dict):
            raise ValueError("policy JSON must be an object")
        bundle, payload = create_signed_policy_bundle(
            policy=policy,
            tenant_id=args.tenant,
            epoch=args.epoch,
            private_key_path=settings.policy_signing_private_key_path,
            agent_ids=args.agents,
            ttl_hours=args.ttl_hours,
        )
        store = PolicyBundleStore(settings.database_path)
        try:
            store.publish(bundle, payload)
        finally:
            store.close()
        print(
            json.dumps(
                {
                    "tenant_id": payload["tenant_id"],
                    "epoch": payload["epoch"],
                    "version": payload["version"],
                    "agent_ids": payload["agent_ids"],
                    "expires_at": payload["expires_at"],
                    "sha256": bundle.sha256,
                },
                indent=2,
            )
        )
        return 0
    if args.command == "policies":
        store = PolicyBundleStore(settings.database_path)
        try:
            print(json.dumps(store.list_metadata(args.tenant), indent=2))
        finally:
            store.close()
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
