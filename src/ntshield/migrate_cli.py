from __future__ import annotations

import argparse
import json
import os

from ntshield.migrations import DatabaseMigrator, default_migrations_root


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ntshield-migrate")
    parser.add_argument(
        "--database-url",
        default=os.getenv("NTSHIELD_DATABASE_URL", ""),
        help="postgresql:// or sqlite:/// URL; may also use NTSHIELD_DATABASE_URL",
    )
    parser.add_argument("--migrations", default=str(default_migrations_root()))
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--target", type=int)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.database_url:
        raise SystemExit("--database-url or NTSHIELD_DATABASE_URL is required")
    migrator = DatabaseMigrator(args.database_url, args.migrations)
    if args.command == "status":
        status = migrator.status()
        print(
            json.dumps(
                {
                    "dialect": migrator.dialect,
                    "current_version": status.current_version,
                    "pending": [item.identifier for item in status.pending],
                    "applied": [
                        {"version": version, "name": name, "checksum": checksum}
                        for version, name, checksum in status.applied
                    ],
                },
                indent=2,
            )
        )
        return 0
    applied = migrator.apply(target_version=args.target)
    print(json.dumps({"applied": [item.identifier for item in applied]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
