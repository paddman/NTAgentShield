# NTAgentShield Endpoint Agent

**AI Security Operator for Windows and Linux servers/endpoints**

The Go agent collects local operational and security telemetry, normalizes evidence, applies deterministic detections, records tamper-evident evidence, and performs optional read-only AI investigation. Every state-changing response remains behind a deterministic policy and approval boundary.

> ภาษาไทย: Agent ติดตั้งใน Server หรือ Endpoint เพื่อเก็บ Asset Inventory, อ่าน Log, ตรวจพฤติกรรม, ตรวจ Source Code และให้ AI ช่วยสืบสวน โดย AI ไม่มีสิทธิ์รัน shell หรือเปลี่ยนระบบโดยตรง

## Implemented

- Cross-platform Go agent daemon and operator CLI with no third-party runtime dependencies.
- Native Windows/Linux asset inventory for OS, interfaces, processes, services, listening sockets, and installed software.
- File-tail collectors and parsers for IIS W3C, Nginx combined, MySQL general log, Syslog, raw text, and normalized JSON events.
- Deterministic detections for prompt injection in telemetry, encoded PowerShell, web-worker-to-shell execution, path traversal, high-risk SQL, security-control disabling, webroot script writes, and authentication bursts.
- Code-security scanner for hard-coded secrets, TLS verification bypass, unsafe deserialization, command execution, SQL string concatenation, dynamic evaluation, public exposure, PHP web-shell chains, GitHub Actions trust-boundary mistakes, and remote scripts piped to shell.
- SHA-256 hash-chained evidence journal.
- Recursive secret redaction, including command-line flags, URI credentials, maps, arrays, and nested Go structs.
- Typed read-only tools (`host.info`, `file.stat`, `file.sha256`, `file.read_lines`) with path allowlists.
- Policy engine that denies generic shell tools and prevents untrusted telemetry from directly triggering state changes.
- Loopback-only authenticated local API for health, status, and event ingestion. It exposes no command endpoint.
- Optional Shield Central bridge that registers this agent, persists the per-agent API key, sends heartbeats, and forwards redacted events/findings to `/api/v1/ingest`.
- Optional OpenAI-compatible investigator for local Qwen/Ollama/vLLM endpoints. The request contains no tools and all evidence is marked untrusted.

## Security invariants

1. Logs, HTTP fields, SQL comments, source comments, process command lines, RAG documents, and network data are untrusted evidence.
2. The AI investigator is read-only and receives no tool definitions.
3. There is no generic `shell.exec`, `cmd.exec`, or `powershell.exec` tool.
4. Tool risk is defined by the registered tool, never by model-supplied arguments.
5. Untrusted evidence cannot directly trigger containment, modification, or destructive actions.
6. Approvals bind to the digest of one exact action and expire.
7. Local file tools are restricted to configured roots and resolve symlinks before access.
8. Secrets are redacted before journal persistence or AI transfer.
9. Machine and boot identifiers are stored as scoped SHA-256 hashes rather than raw OS identifiers.
10. Native inventory commands and arguments are fixed in code, bounded by timeouts and result caps, and cannot be supplied by a model.
11. The local HTTP API binds to loopback only and has no action endpoint.
12. Zero-day protection is behavior-based risk reduction, not a promise to detect every unknown vulnerability.

See [Threat Model](docs/THREAT_MODEL.md), [AI Security](docs/AI_SECURITY.md), and [Response Safety](docs/RESPONSE_SAFETY.md).

## Architecture

```text
Native Inventory / Log / Event / Code / HTTP ingest
                        |
                        v
                Parser + Normalizer
                        |
                        v
                 Secret Redaction
                        |
                        +--------------------+
                        |                    |
                        v                    v
           Tamper-evident Journal    Deterministic Detection
                                             |
                                             v
                                         Findings
                                             |
                               +-------------+-------------+
                               |                           |
                               v                           v
                     Read-only AI Investigator      Policy + Typed Tools
                     (no tools, no actions)         (observe-only today)
```

## Quick start

Requirements: Go 1.23 or later. The Windows package also builds the desktop app and requires the .NET 10 SDK.

```bash
go test ./...
go build ./cmd/ntagentshield-agent \
  ./cmd/ntagentshieldctl \
  ./cmd/ntagentshield-inventory
```

### Windows package

Build a redistributable Windows amd64 package from PowerShell:

```powershell
.\packaging\windows\build-package.ps1 -Version 0.1.0
```

Extract the generated zip and run `install.ps1` as Administrator. The installer preserves the existing configuration and evidence on upgrade, installs a Start Menu dashboard app, then runs the Agent as `SYSTEM` through the `NTAgentShield` Scheduled Task at startup. See [packaging/windows/README.md](packaging/windows/README.md).

### Inspect local asset inventory

```bash
go run ./cmd/ntagentshield-inventory \
  --processes=true \
  --services=true \
  --listeners=true \
  --software=true \
  --max-items 512 \
  --command-timeout 15s
```

Inventory is collected at agent startup and then according to the configured interval:

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
    "max_items": 1000
  }
}
```

Linux uses `/proc`, `/etc/os-release`, systemd, and `dpkg-query` or `rpm`. Windows uses fixed WMI/PowerShell queries, Registry reads, and `netstat`, with limited command fallbacks. No command text is accepted from the AI or telemetry.

### Scan IIS logs

```bash
go run ./cmd/ntagentshieldctl scan-log \
  --format iis_w3c \
  --file examples/logs/iis.log
```

### Scan a normalized endpoint event

```bash
go run ./cmd/ntagentshieldctl scan-event \
  --file examples/events/web-worker-shell.json
```

### Scan source code

```bash
go run ./cmd/ntagentshieldctl scan-code \
  --path examples/code
```

### Validate configuration and policy

```bash
go run ./cmd/ntagentshieldctl doctor \
  --config config/agent.example.json
```

### Run the agent

```bash
go run ./cmd/ntagentshield-agent \
  --config config/agent.example.json
```

The API token is generated in the configured data directory. Query local status:

```bash
TOKEN="$(cat data/agent-api.token)"
curl -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:9477/v1/status
```

Status includes `inventory_enabled`, `inventory_runs`, `last_inventory_at`, and `inventory_interval`.

### Connect to Shield Central

The existing `transport` block is the signed mTLS transport for the repository's Control Plane. Use the separate `central` block when this agent is paired with the Shield Central service:

```json
{
  "central": {
    "enabled": true,
    "url": "https://yaksaonline.com",
    "enrollment_token_file": "/etc/ntagentshield/central-enrollment.token",
    "api_key_file": "central-api.key",
    "allow_untrusted_server_certificate": false,
    "heartbeat_interval": "60s",
    "batch_interval": "10s",
    "max_batch": 100,
    "queue_size": 2000
  }
}
```

The enrollment token is read only during registration. Central returns a per-agent API key, which is stored under `data_dir/central-api.key` with mode `0600`. Keep certificate verification enabled for production; the untrusted-certificate flag is only for controlled testing.

### Verify the evidence chain

```bash
go run ./cmd/ntagentshieldctl verify-store \
  --path data/evidence.journal.jsonl
```

## AI investigator

Copy `config/agent.local-ai.json`, set the local OpenAI-compatible endpoint and model, then enable AI. Remote endpoints are denied unless `allow_remote` is explicitly enabled; remote HTTP without TLS is rejected.

```bash
go run ./cmd/ntagentshieldctl ai-analyze \
  --config config/agent.local-ai.json \
  --event examples/events/web-worker-shell.json \
  --objective "Explain the likely exploit chain and missing evidence"
```

The model produces analysis only. It cannot invoke tools or apply changes.

## Supported input formats

| Format | Configuration value | Current scope |
|---|---|---|
| IIS W3C | `iis_w3c` | Dynamic `#Fields`, request metadata, status, latency, source IP |
| Nginx combined | `nginx_combined` | Request, status, bytes, referer, user agent |
| MySQL general | `mysql_general` | Query/execute events, normalized query, fingerprint, verbs |
| Syslog | `syslog` | RFC3164-style messages with priority and program |
| Normalized JSON | `jsonl` | Full NTAgentShield event schema |
| Raw text | `raw` | Generic evidence and prompt-injection/control-disable detection |

Planned collectors are listed in [Telemetry Matrix](docs/TELEMETRY_MATRIX.md).

## CLI commands

```text
ntagentshield-inventory
ntagentshieldctl doctor
ntagentshieldctl scan-log
ntagentshieldctl scan-event
ntagentshieldctl scan-code
ntagentshieldctl ai-analyze
ntagentshieldctl policy-check
ntagentshieldctl tool
ntagentshieldctl verify-store
ntagentshieldctl version
```

Example policy denial:

```bash
go run ./cmd/ntagentshieldctl policy-check \
  --policy policies/default-policy.json \
  --tool host.isolate \
  --risk contain \
  --trust untrusted_telemetry \
  --mode auto
```

The result must be denied because attacker-controlled evidence is not an operator.

## Repository layout

```text
cmd/                         Agent daemon, inventory CLI, operator CLI
internal/agent/              Runtime and event pipeline
internal/inventory/          Native Windows/Linux asset inventory
internal/collector/          Log collectors
internal/parser/             IIS, Nginx, MySQL, Syslog, JSON, raw parsers
internal/detection/          Deterministic behavior and correlation rules
internal/codescan/           Source-code security scanner
internal/ai/                 Read-only OpenAI-compatible investigator
internal/policy/             Action policy and exact-action approvals
internal/tools/              Typed, allowlisted read-only tools
internal/store/              Hash-chained evidence journal
config/                      Demo and OS configuration templates
policies/                    Deterministic action policy
rules/                       Detection catalog metadata
schemas/                     Event, finding, and action schemas
docs/                        Architecture, threat model, safety, roadmap
packaging/                   systemd and Windows service helpers
```

## Next engineering milestones

- Native Windows Event Log, Sysmon, and ETW collectors.
- Native Linux journald, auditd, and eBPF telemetry.
- Inventory-delta detections for new services, listeners, software drift, and suspicious process ancestry.
- Signed enrollment, mTLS policy distribution, and signed updates.
- Production response broker for quarantine, process containment, and host isolation.

## Design relationship to Cline

NTAgentShield adopts the useful operator experience of Observe/Plan/Act, structured tools, diffs, and approvals. It is not a Cline fork and does not copy Cline source code. A general coding agent and a privileged security service have different trust boundaries.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
