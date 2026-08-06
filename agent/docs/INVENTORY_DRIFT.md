# Inventory Drift and Exposure Correlation

NTAgentShield compares periodic native asset inventory with a local, tamper-evident baseline. The feature turns state changes into normalized security evidence without treating every software update as an incident or silently interpreting incomplete inventory as removal.

## Processing order

```text
collect native snapshot
  -> redact and append full snapshot to evidence journal
  -> project a minimal drift baseline
  -> compare previous and current baseline
  -> append drift events and deterministic findings
  -> atomically commit the new baseline
```

The baseline does not advance when snapshot, drift-event, finding, or baseline persistence fails. A later scan can retry the same transition. Drift event IDs include stable baseline hashes and change keys so downstream systems can deduplicate retries.

## Baseline contents

The baseline contains only the fields required to compare host state:

- service name, state, display name, and start mode
- listening protocol, address, port, owning PID, and process image
- installed software name, version, publisher, and package source
- interface name, address set, state, and a scoped SHA-256 MAC hash
- unique process image names and executable paths

The baseline does **not** store:

- process command lines
- environment variables
- raw machine or boot identifiers
- raw MAC addresses
- authentication tokens or credentials
- full event messages

The full inventory event still passes recursive redaction before entering the hash-chained evidence journal.

## Integrity model

The baseline is stored at:

```text
<data_dir>/inventory-baseline.json
```

It is wrapped in an envelope containing a SHA-256 hash of the canonical JSON payload. Writes use a restrictive temporary file followed by atomic replacement. The store rejects stale plans so an older collection cannot overwrite a newer in-memory baseline.

When loading fails because of malformed JSON, unsupported schema, excessive size, invalid content, or a hash mismatch, the file is renamed to a `.corrupt-<timestamp>` quarantine name. The agent records a `security.inventory_baseline_integrity` event and critical finding before establishing a fresh baseline.

This hash detects accidental or unsophisticated local modification. It is not a cryptographic signature and does not protect against an attacker who can replace both payload and hash. Signed state and hardware-backed identity belong to the enrollment/update milestone.

## Incomplete inventory

Each inventory category has a result cap. A cap is useful because shipping an unlimited process or package list is a fine way to turn monitoring into self-inflicted denial of service.

If the current snapshot marks a category as truncated, drift comparison does not infer removals from that category. The last complete category baseline remains active until a complete collection succeeds.

## Drift event types

| Event kind | Meaning | Typical local severity |
|---|---|---|
| `asset.service_added` | New service appeared | low or medium |
| `asset.service_changed` | Service state/start mode changed | info or medium |
| `asset.service_removed` | Service disappeared | low |
| `security.control_disabled` | Recognized security service stopped/disabled | critical |
| `security.control_removed` | Recognized security service/software disappeared | high or critical |
| `asset.listener_added` | New listening socket | low to high |
| `asset.listener_owner_changed` | Existing socket is now owned by another image | medium or high |
| `asset.listener_removed` | Listening socket disappeared | info |
| `asset.software_added` | Software/package appeared | info |
| `asset.software_version_changed` | Version or publisher changed | info |
| `asset.software_removed` | Software/package disappeared | low |
| `asset.interface_added` | Network interface appeared | low |
| `asset.interface_changed` | Address, MAC hash, or state changed | low |
| `asset.interface_removed` | Interface disappeared | low |
| `asset.process_image_added` | New image appeared in a writable/temp location | high |
| `asset.inventory_delta_truncated` | Change count exceeded the event cap | medium |

## Exposure scoring

A newly observed listener receives higher severity when:

- it binds to a non-loopback or wildcard address
- the port is commonly security-sensitive or externally administered
- the owning image runs from a temporary or user-writable path

Examples include SSH, RDP, database ports, container APIs, Kubernetes API, Redis, Elasticsearch, VNC, WinRM, and common web/admin ports. The list is a prioritization hint, not proof of compromise.

## Security-control recognition

The first rule set recognizes common endpoint, audit, and network-security products by normalized service/software metadata. A match only influences drift severity. It never authorizes automatic remediation.

False positives remain possible when a legitimate upgrade renames, replaces, or temporarily stops a component. Correlate drift with native service creation, package activity, process telemetry, authentication, and the approved maintenance window.

## Configuration

```json
{
  "inventory": {
    "enabled": true,
    "interval": "15m",
    "command_timeout": "15s",
    "include_processes": true,
    "include_services": true,
    "include_listeners": true,
    "include_software": true,
    "max_items": 1000,
    "drift": {
      "enabled": true,
      "max_events": 256
    }
  }
}
```

`max_events` must be between 1 and 5000. When a scan produces more transitions, the agent emits the highest deterministic subset allowed by the cap and appends an `asset.inventory_delta_truncated` summary.

## Response boundary

Inventory drift creates evidence and findings only. It cannot stop a service, close a port, uninstall software, kill a process, or isolate a host. State-changing response remains behind typed tools, deterministic policy, exact-action approval, expiry, audit, and rollback requirements.
