# NTAgentShield

**Behavioral Zero-Day Hunting for servers and endpoints, with a bounded local Qwen SOC analyst.**

NTAgentShield detects suspicious *behavior chains* instead of waiting for a malware hash or CVE signature. It correlates process, file, identity, web, database, service, and network events; learns a per-tenant/per-asset baseline; opens evidence-backed incidents; and lets Qwen3.5-9B investigate through a small set of read-only tools.

> เป้าหมายคือจับพฤติกรรมหลังการ exploit เช่น web worker สร้าง shell, เขียน payload, แล้วเชื่อมออกภายนอก แม้ยังไม่มีชื่อ CVE หรือ signature มาก่อน โมเดลภาษาใช้วิเคราะห์หลักฐาน ไม่ได้ใช้แทน sensor และไม่ถือสิทธิ์สั่ง block หรือ kill process เอง

## What is implemented

- Canonical, OCSF-inspired security event model with strict `tenant_id` and `asset_id` boundaries.
- Online behavioral baselines for rare parent-child process relationships, command shapes, user-process pairs, process destinations, file-write locations, login sources, service execution, time-of-day, and numeric volume anomalies.
- Ordered multi-event behavior correlation loaded from YAML rules.
- Initial behavior packs for web exploitation, service persistence, credential dumping, defense evasion, database exfiltration, supply-chain execution, and compromised-account persistence.
- Adapters for Windows Sysmon, Windows Event Log, IIS, Nginx, Apache, and Linux auditd records.
- SQLite/WAL evidence store for a runnable MVP and deterministic replay.
- Qwen hunt loop using OpenAI-compatible tool calling, bounded to four read-only rounds by default.
- Prompt-injection boundaries: all logs, command lines, filenames, URLs, SQL text, and tool results are treated as untrusted evidence.
- Response policy that permits evidence collection, requires approval for containment, and rejects destructive or unknown actions.
- Tenant-isolation, behavior-chain, anomaly, adapter, guardrail, and response-policy tests.

## Detection flow

```text
Endpoint / Server / Web / DB / Network telemetry
                    │
                    ▼
        Source adapters + validation
                    │
                    ▼
        Canonical tenant-scoped events
                    │
        ┌───────────┼────────────┐
        ▼           ▼            ▼
Behavior rules   Online       Numeric
and sequences    rarity       baselines
        └───────────┼────────────┘
                    ▼
          Incident risk scoring
                    │
                    ▼
        Evidence bundle with event IDs
                    │
                    ▼
     Qwen3.5-9B bounded hunt analyst
       search / lineage / baseline / rule
                    │
                    ▼
       Response policy + human approval
```

The LLM never receives an unbounded firehose. It receives an incident bundle and can request additional evidence only through tenant-bound, read-only tools. Access control, evidence scope, and resource limits remain deterministic outside the model.

## Quick start

Requirements: Python 3.11+.

```bash
cp .env.example .env
python -m pip install -e '.[dev]'
pytest
uvicorn ntshield.api:app --host 0.0.0.0 --port 8080
```

Replay the included IIS/Sysmon web-exploitation chain:

```bash
QWEN_ENABLED=false \
NTSHIELD_DB_PATH=/tmp/ntshield-demo.db \
ntshield-replay samples/webshell_chain.jsonl
```

Expected result: the final network event opens `BZH-WEB-001` and `BZH-WEB-002` incidents. Detection does not depend on the payload hash, domain reputation, or a CVE identifier.

## API examples

Ingest one canonical event:

```bash
curl -sS http://127.0.0.1:8080/v1/events \
  -H 'Content-Type: application/json' \
  -H 'X-Tenant-ID: tenant-demo' \
  -d '{
    "tenant_id": "tenant-demo",
    "asset_id": "web-01",
    "event_type": "process.start",
    "source": "windows-sysmon",
    "process": {
      "name": "powershell.exe",
      "command_line": "powershell.exe -NoProfile -EncodedCommand ..."
    },
    "parent_process": {"name": "w3wp.exe"},
    "asset_criticality": 5
  }'
```

Normalize and ingest a Sysmon record:

```bash
curl -sS http://127.0.0.1:8080/v1/adapters/sysmon \
  -H 'Content-Type: application/json' \
  -H 'X-Tenant-ID: tenant-demo' \
  -d '{
    "asset_id": "web-01",
    "asset_criticality": 5,
    "record": {
      "EventID": 1,
      "UtcTime": "2026-08-06T10:00:00Z",
      "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "CommandLine": "powershell.exe -enc AAAA",
      "ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe"
    }
  }'
```

List incidents and invoke the bounded hunt analyst:

```bash
curl -sS http://127.0.0.1:8080/v1/incidents \
  -H 'X-Tenant-ID: tenant-demo'

curl -sS -X POST \
  http://127.0.0.1:8080/v1/incidents/INCIDENT_ID/hunt \
  -H 'X-Tenant-ID: tenant-demo'
```

## Canonical event shape

```json
{
  "event_id": "uuid-or-source-id",
  "tenant_id": "tenant-a",
  "asset_id": "server-01",
  "observed_at": "2026-08-06T10:00:00Z",
  "event_type": "network.connect",
  "source": "windows-sysmon",
  "sensor_confidence": 0.9,
  "asset_criticality": 5,
  "actor": {"user": {"name": "svc-web"}},
  "process": {"name": "powershell.exe", "guid": "..."},
  "parent_process": {"name": "w3wp.exe"},
  "network": {
    "src": {"ip": "10.0.0.10", "port": 51234},
    "dst": {"ip": "45.77.100.20", "port": 443},
    "bytes_out": 24576
  },
  "raw": "original source record"
}
```

The current schema is deliberately compact. Production deployments should maintain versioned OCSF mappings at ingestion and retain the untouched source record for evidence.

## Qwen3.5-9B role

Qwen is used after deterministic evidence collection and scoring. It may call only:

- `search_events`
- `get_process_lineage`
- `get_baseline_stats`
- `get_rule`
- `get_asset_context`

Tool calls are forcibly scoped to the incident tenant and asset, time-bounded, result-limited, and read-only. The model returns structured JSON with a verdict, confidence, Thai summary, behavior chain, hypotheses, event-ID references, ATT&CK techniques, next queries, and response recommendations.

Containment remains behind `ResponsePolicy`:

| Action class | Examples | Decision |
|---|---|---|
| Evidence collection | collect hash, process tree, connections, preserve log window | Automatic |
| State-changing containment | isolate host, block IP, kill process, disable user, virtual patch | Human approval |
| Destructive or unsafe | delete evidence, erase logs, execute shell, dump credentials | Denied |

## Production topology

The repository is a runnable control-plane MVP, not yet a full kernel EDR. For production scale, preserve these interfaces and replace components as follows:

| MVP | Production target |
|---|---|
| Direct HTTP ingestion | mTLS agents → gateway → Redpanda/NATS JetStream |
| SQLite events | ClickHouse or equivalent immutable security lake |
| SQLite baseline state | Redis/RocksDB/Flink state with checkpoints |
| Single-process correlation | partitioned stream correlation by tenant/asset/entity |
| Local YAML reload | signed rule registry, canary deployment, replay validation |
| Header tenant context | enrollment certificate + workload identity + RBAC |
| Manual asset context | CMDB/topology/criticality synchronization |

See [Architecture](docs/ARCHITECTURE.md), [Detection Model](docs/DETECTION_MODEL.md), [A100 Deployment](docs/DEPLOY_A100.md), and [Threat Model](docs/THREAT_MODEL.md).

## Repository layout

```text
src/ntshield/
  adapters.py          source normalization
  baseline.py          online behavioral rarity and numeric baselines
  rules.py             ordered multi-event correlation engine
  pipeline.py          ingestion and incident creation
  hunt.py              bounded Qwen read-only hunt loop
  response_policy.py   allow / approval / deny decisions
  store.py             SQLite evidence and baseline state
rules/behavioral/      behavior-chain rules
samples/               replayable attack sequences
tests/                 tenant, detection, guardrail, and policy tests
docs/                  production design and deployment guidance
```

## Current limitations

- SQLite is appropriate for a demo or a small isolated deployment, not high-volume fleet telemetry.
- Baselines are online statistical heuristics and do not provide certainty about an unknown vulnerability.
- Source adapters cover common fields, but real vendor formats need versioned fixtures and mapping tests.
- No endpoint kernel sensor, packet capture service, authentication server, dashboard, rule signing, or automated containment executor is included in this first increment.
- A behavior alert is a hunt candidate. It still requires evidence quality, asset context, tuning, and measurable false-positive review.

## Next engineering increments

1. Signed Windows agent telemetry: ETW, Event Log, Sysmon, service health, file/process/network lineage, local spool, mTLS enrollment.
2. Linux agent telemetry: eBPF plus auditd fallback, process/file/socket lineage, package manager and persistence sensors.
3. Distributed ingestion, OCSF mapping registry, ClickHouse event lake, replay service, and per-tenant retention.
4. Entity graph and sequence features across endpoint, WAF, firewall, DNS, identity, web, and database telemetry.
5. Rule validation lab, attack emulation, false-positive budgets, canary rollout, and analyst feedback learning.
6. Multi-tenant SOC dashboard, incident timeline, topology canvas, evidence views, approvals, and reporting.
