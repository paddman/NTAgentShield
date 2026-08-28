from __future__ import annotations

import argparse
import json

from ntshield.operator_auth import ROLE_PERMISSIONS, OperatorTokenManager
from ntshield.production_config import ProductionSecurityConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ntshield-operator-token",
        description="Issue a short-lived, tenant-bound NTAgentShield operator token",
    )
    parser.add_argument("--subject", required=True, help="authenticated operator identity")
    parser.add_argument(
        "--role",
        action="append",
        dest="roles",
        required=True,
        choices=sorted(ROLE_PERMISSIONS),
        help="RBAC role; repeat to grant multiple roles",
    )
    parser.add_argument(
        "--tenant",
        action="append",
        dest="tenants",
        default=[],
        help="allowed tenant ID; repeat for multiple tenants",
    )
    parser.add_argument("--ttl", type=int, default=3600, help="token lifetime in seconds")
    parser.add_argument("--json", action="store_true", help="emit token metadata as JSON")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config = ProductionSecurityConfig.from_env()
    manager = OperatorTokenManager(
        config.operator_signing_secret,
        issuer=config.operator_token_issuer,
    )
    token = manager.issue(
        subject=args.subject,
        roles=args.roles,
        tenant_ids=args.tenants,
        ttl_seconds=args.ttl,
    )
    if args.json:
        principal = manager.verify(token)
        print(json.dumps({"token": token, "principal": principal.as_safe_dict()}, indent=2))
    else:
        print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
