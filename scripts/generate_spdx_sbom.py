#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Generate a minimal SPDX 2.3 file SBOM")
    value.add_argument("--directory", type=Path, required=True)
    value.add_argument("--name", required=True)
    value.add_argument("--namespace", required=True)
    value.add_argument("--output", type=Path, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    root = args.directory.resolve(strict=True)
    files = []
    relationships = []
    for index, path in enumerate(sorted(item for item in root.rglob("*") if item.is_file()), 1):
        if path.resolve() == args.output.resolve():
            continue
        relative = path.relative_to(root).as_posix()
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        spdx_id = f"SPDXRef-File-{index}"
        files.append(
            {
                "SPDXID": spdx_id,
                "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}],
                "fileName": f"./{relative}",
            }
        )
        relationships.append(
            {
                "relatedSpdxElement": spdx_id,
                "relationshipType": "CONTAINS",
                "spdxElementId": "SPDXRef-Package",
            }
        )
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "creators": ["Tool: NTAgentShield-generate-spdx-sbom/1"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": args.namespace,
        "files": files,
        "name": args.name,
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "name": args.name,
                "verificationCode": {
                    "packageVerificationCodeValue": hashlib.sha1(  # noqa: S324 - SPDX requires SHA-1.
                        "".join(item["checksums"][0]["checksumValue"] for item in files).encode()
                    ).hexdigest()
                },
            }
        ],
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
