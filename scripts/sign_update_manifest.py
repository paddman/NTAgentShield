#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

VERSION_RE = re.compile(r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)$")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Sign an NTAgentShield update manifest")
    value.add_argument("--artifact", type=Path, required=True)
    value.add_argument("--artifact-url", required=True)
    value.add_argument("--version", required=True)
    value.add_argument("--os", required=True, choices=["windows", "linux"])
    value.add_argument("--arch", required=True, choices=["amd64", "arm64"])
    value.add_argument("--key-id", required=True)
    value.add_argument("--output", type=Path, required=True)
    value.add_argument("--ttl-hours", type=int, default=168)
    return value


def main() -> int:
    args = parser().parse_args()
    match = VERSION_RE.fullmatch(args.version.strip())
    if match is None:
        raise SystemExit("--version must use vMAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH")
    version = ".".join(match.groups())
    if args.ttl_hours < 1 or args.ttl_hours > 24 * 30:
        raise SystemExit("--ttl-hours must be between 1 and 720")
    artifact = args.artifact.resolve(strict=True)
    artifact_url = args.artifact_url.strip()
    if not artifact_url.startswith("https://") or "@" in artifact_url.split("/", 3)[2]:
        raise SystemExit("--artifact-url must be credential-free HTTPS")
    secret = os.getenv("UPDATE_SIGNING_PRIVATE_KEY_PEM_B64", "").strip()
    if not secret:
        raise SystemExit("UPDATE_SIGNING_PRIVATE_KEY_PEM_B64 is required")
    try:
        private_pem = base64.b64decode(secret, validate=True)
    except ValueError as exc:
        raise SystemExit("update signing private key is not valid base64") from exc
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise SystemExit("update signing private key must use Ed25519")

    content = artifact.read_bytes()
    published_at = datetime.now(UTC).replace(microsecond=0)
    manifest = {
        "arch": args.arch,
        "artifact_url": artifact_url,
        "expires_at": (published_at + timedelta(hours=args.ttl_hours)).isoformat(),
        "os": args.os,
        "published_at": published_at.isoformat(),
        "schema": "ntshield-update/v1",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "version": version,
    }
    payload = json.dumps(
        manifest,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    envelope = {
        "key_id": args.key_id,
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "signature_b64": base64.b64encode(private_key.sign(payload)).decode("ascii"),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
