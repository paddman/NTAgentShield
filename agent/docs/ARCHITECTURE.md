# Architecture

## Current foundation

```text
+---------------- Server / Endpoint ----------------+
|                                                   |
| Log files / normalized sensor events / code       |
|                 |                                 |
|                 v                                 |
|        Collector + format parser                  |
|                 |                                 |
|                 v                                 |
|          Redaction + provenance                   |
|             /             \                       |
|            v               v                      |
|  Hash-chain journal   Detection engine            |
|                            |                      |
|                            v                      |
|                         Finding                   |
|                         /     \                   |
|                        v       v                  |
|              Read-only AI   Policy engine         |
|              no tools       typed tools only      |
|                                                   |
+---------------------------------------------------+
```

## Components

### Agent runtime

The runtime loads configuration, creates a stable local identity, opens the evidence journal, initializes collectors, starts the loopback API, processes events, and records findings. It runs without third-party runtime dependencies.

### Collectors and parsers

The foundation tails bounded log increments and supports IIS W3C, Nginx combined, MySQL general, Syslog, normalized JSON, and raw text. Future native sensors will produce the same normalized event model.

### Redaction

Redaction occurs before persistence and before AI transfer. It handles bearer tokens, common secret assignments, private keys, payment-number patterns, and nested secret-like fields. Redaction is defense in depth, not a substitute for collecting the minimum necessary fields.

### Evidence journal

Each JSONL record contains sequence, timestamp, type, previous hash, payload hash, and record hash. Verification detects modification, deletion within the chain, insertion, and reordering. The foundation journal is tamper-evident, not tamper-proof; production will anchor checkpoints to the control plane or a trusted signing service.

### Detection engine

Detections are deterministic and evidence-backed. Stateful correlation currently includes authentication bursts. Planned engines add Sigma conversion, YARA/YARA-X, eBPF/ETW behavior sequences, per-asset baselines, and cross-host graphs.

### Code scanner

The current scanner is a bounded lexical layer with secret-safe excerpts. Planned adapters add Tree-sitter data flow, Semgrep, SBOM/dependency analysis, IaC scanners, and sandboxed patch validation.

### AI investigator

The AI client speaks to an OpenAI-compatible endpoint. It receives redacted evidence enclosed as untrusted JSON, receives no tools, and returns analysis only. The model is not an authorization authority and its confidence does not trigger response.

### Policy and tools

Tools declare canonical risk. The policy denies generic command tools, caps action TTL, blocks destructive actions in the foundation, and prevents untrusted evidence from directly causing state changes. Read-only file tools resolve symlinks and enforce configured roots.

### Local API

The local API binds to loopback, uses a generated bearer token, and exposes only health, status, and event ingestion. Remote event payloads are forcibly marked `untrusted_network`. No command or tool endpoint exists.

## Planned privilege separation

Production state-changing response will use a separate privileged broker:

```text
Unprivileged Agent / Investigator
              |
       signed typed request
              v
Deterministic Policy Gate
              |
   exact approval / pre-policy
              v
Privileged Response Broker
              |
    bounded OS-specific adapter
              v
Verify outcome + append audit + rollback
```

The investigator process should remain unprivileged. Only the broker owns narrow OS permissions.

## Control-plane integration

Planned NT Shield integration includes:

- mTLS enrollment and short-lived workload identity;
- tenant-scoped policy and rule distribution;
- central incident correlation and evidence graph;
- local/central Qwen model routing;
- signed update manifests and staged rollout;
- audit, retention, reporting, and usage accounting;
- air-gapped deployment mode;
- strict tenant partitioning with platform-admin oversight.

## Event compatibility

The internal event schema is intentionally compact. A control-plane adapter will map it to OCSF classes and export via OTLP where appropriate. Security meaning and telemetry transport remain separate concerns.
