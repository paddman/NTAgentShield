# NTAgentShield

**AI Security Operator for Windows and Linux servers/endpoints**

NTAgentShield is an endpoint/server security agent that collects operational and security telemetry, normalizes evidence, applies deterministic detections, performs read-only AI investigation, and places every state-changing response behind a policy and approval boundary.

> ภาษาไทย: NTAgentShield คือ Agent ความปลอดภัยที่ติดตั้งใน Server หรือ Endpoint เพื่ออ่าน Log, ตรวจพฤติกรรม, ตรวจ Source Code, เชื่อมเหตุการณ์ และให้ AI ช่วยสืบสวน โดย AI ไม่มีสิทธิ์รัน shell หรือเปลี่ยนระบบโดยตรง

## Foundation status

This repository currently implements the secure foundation, not a finished EDR product. The code is runnable and tested, while deep ETW/eBPF sensors, central multi-tenant fleet management, signed updates, and production containment adapters remain on the roadmap.

Implemented now:

- Cross-platform Go agent daemon and CLI with no third-party runtime dependencies.
- File-tail collectors and parsers for IIS W3C, Nginx combined logs, MySQL general logs, Syslog, raw text, and normalized JSON events.
- Deterministic detections for prompt injection in telemetry, encoded PowerShell, web-worker-to-shell execution, path traversal, high-risk SQL, security-control disabling, webroot script writes, and authentication bursts.
- Code-security scanner for hard-coded secrets, TLS verification bypass, unsafe deserialization, command execution, SQL string concatenation, dynamic evaluation, public network exposure, PHP web-shell chains, GitHub Actions trust-boundary mistakes, and remote scripts piped to shell.
- Tamper-evident SHA-256 hash-chained evidence journal.
- Secret redaction before persistence or AI transfer.
- Typed read-only tools (`host.info`, `file.stat`, `file.sha256`, `file.read_lines`) with path allowlists.
- Deterministic policy engine that denies generic shell tools and blocks untrusted telemetry from directly triggering state changes.
- Loopback-only authenticated local API for health, status, and event ingestion. It deliberately exposes no command endpoint.
- Optional OpenAI-compatible AI investigator for local Qwen/Ollama/vLLM endpoints. The request contains no tools and all evidence is explicitly marked untrusted.

## Security invariants

These rules are architectural, not polite suggestions written in a prompt:

1. Logs, HTTP fields, SQL comments, source comments, RAG documents, and network data are always untrusted evidence.
2. The AI investigator is read-only and receives no tool definitions.
3. There is no generic `shell.exec`, `cmd.exec`, or `powershell.exec` tool.
4. Tool risk is defined by the registered tool, never by model-supplied arguments.
5. Untrusted evidence cannot directly trigger containment, modification, or destructive actions.
6. Approvals are bound to the digest of one exact action and expire.
7. Local file tools are restricted to configured roots and resolve symlinks before access.
8. Raw secrets are redacted before journal persistence and AI transfer.
9. The local HTTP API binds to loopback only and has no action endpoint.
10. Zero-day protection is behavior-based risk reduction, not a dishonest promise to detect every unknown vulnerability.

See [Threat Model](docs/THREAT_MODEL.md), [AI Security](docs/AI_SECURITY.md), and [Response Safety](docs/RESPONSE_SAFETY.md).

## Architecture

```text
Log / Event / Code / HTTP ingest
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

The future NT Shield control plane will add tenant enrollment, fleet policy, centralized correlation, model hosting, rule distribution, incident workflow, and reporting. Endpoint privilege separation remains local and explicit.

## Quick start

Requirements: Go 1.23 or later.

```bash
go test ./...
go build ./cmd/ntagentshield-agent ./cmd/ntagentshieldctl
```

Run the deterministic demo against IIS logs:

```bash
go run ./cmd/ntagentshieldctl scan-log \
  --format iis_w3c \
  --file examples/logs/iis.log
```

Scan a normalized endpoint event:

```bash
go run ./cmd/ntagentshieldctl scan-event \
  --file examples/events/web-worker-shell.json
```

Scan source code:

```bash
go run ./cmd/ntagentshieldctl scan-code \
  --path examples/code
```

Validate configuration and policy:

```bash
go run ./cmd/ntagentshieldctl doctor \
  --config config/agent.example.json
```

Run the agent using demo sources:

```bash
go run ./cmd/ntagentshield-agent \
  --config config/agent.example.json
```

The API token is generated at `data/agent-api.token`. Query local status:

```bash
TOKEN="$(cat data/agent-api.token)"
curl -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:9477/v1/status
```

Verify the evidence chain:

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

Recommended local targets include Qwen behind vLLM/SGLang/Ollama or another OpenAI-compatible service. The model produces analysis only. It cannot invoke tools or apply changes.

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

## Build targets

```bash
make fmt
make test
make vet
make build
make cross
```

`make cross` builds Windows amd64 and Linux amd64 binaries. Service templates are available under `packaging/`.

## Repository layout

```text
cmd/                    Agent daemon and operator CLI
internal/agent/         Runtime and event pipeline
internal/collector/     Log collectors
internal/parser/        IIS, Nginx, MySQL, Syslog, JSON, raw parsers
internal/detection/     Deterministic behavior and correlation rules
internal/codescan/      Source-code security scanner
internal/ai/            Read-only OpenAI-compatible investigator
internal/policy/        Action policy and exact-action approvals
internal/tools/         Typed, allowlisted read-only tools
internal/store/         Hash-chained evidence journal
config/                 Demo and OS configuration templates
policies/               Deterministic action policy
rules/                  Detection catalog metadata
schemas/                Event, finding, and action schemas
docs/                   Architecture, threat model, safety, roadmap
packaging/               systemd and Windows service helpers
```

## Design relationship to Cline

NTAgentShield adopts the useful operator experience of Observe/Plan/Act, structured tools, diffs, and approvals. It is not a Cline fork and does not copy Cline source code. A general coding agent and a privileged security service have radically different trust boundaries, despite the software industry occasionally pretending otherwise.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
