# NTAgentShield Behavioral Zero-Day Hunting Architecture

## Objective

Detect previously unseen exploitation and post-exploitation activity by observing changes in system behavior and relationships, not by claiming to identify an unknown vulnerability directly. The system must answer four questions:

1. What changed from the asset's normal behavior?
2. Which events form one causal or temporal chain?
3. What evidence supports the incident and what evidence is missing?
4. Which response actions are safe to automate?

## Production reference architecture

```text
┌──────────────────────────────── Sensors ────────────────────────────────┐
│ Windows: ETW, Event Log, Sysmon, AMSI metadata, WFP, service health    │
│ Linux: eBPF, auditd, journald, fanotify/inotify, package and auth logs │
│ Network: Zeek, Suricata, DNS, NetFlow, firewall, load balancer, WAF    │
│ Apps: IIS, Nginx, Apache, Java, API gateway, DB audit, object storage  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ mTLS, signed agent identity
                                     ▼
┌──────────────────────────── Ingestion Gateway ─────────────────────────┐
│ Enrollment identity │ tenant routing │ replay protection │ rate limits │
│ source validation   │ PII controls   │ health telemetry  │ dead-letter │
└────────────────────────────────────┬────────────────────────────────────┘
                                     ▼
                          Redpanda / NATS JetStream
                                     │
                 ┌───────────────────┼───────────────────┐
                 ▼                   ▼                   ▼
        Parser + OCSF map    Raw evidence archive   Sensor health
                 │
                 ▼
       Canonical immutable event stream
                 │
       ┌─────────┼─────────────┬──────────────┐
       ▼         ▼             ▼              ▼
 Atomic rules  Sequence     Baseline       Entity graph
               correlation  anomalies      relationships
       └─────────┼─────────────┴──────────────┘
                 ▼
        Incident assembler + risk scorer
                 │
       ┌─────────┴─────────────┐
       ▼                       ▼
Evidence lake             Incident store
ClickHouse/Object         PostgreSQL
       └─────────┬─────────────┘
                 ▼
       Qwen3.5-9B Hunt Orchestrator
 read-only tools, evidence IDs, bounded rounds
                 │
                 ▼
    Policy engine + human approval + SOAR
```

## Trust boundaries

### Agent to gateway

- Every agent receives a short-lived workload identity after enrollment.
- Tenant identity comes from the certificate or enrollment token, never from a freely supplied event field.
- Events include a monotonic sequence number and source timestamp; the gateway detects replay, gaps, and clock drift.
- The agent locally spools encrypted events when disconnected and applies backpressure instead of silently discarding high-value process or identity telemetry.

### Gateway to processing

- Parsers are isolated by source type and version.
- Raw records are immutable and content-addressed where feasible.
- Canonical mappings record parser version, schema version, source offset, and transformation errors.
- High-cardinality or sensitive fields are retained for evidence but excluded from uncontrolled labels and metrics.

### Processing to LLM

- The model receives incident bundles, not raw fleet-wide telemetry.
- Evidence is explicitly marked as untrusted data; log text can contain prompt injection.
- Tool authorization is enforced by application code, not model instructions.
- Tenant, asset, time window, row limit, and allowed operation are injected by the server and cannot be widened by tool arguments.
- Every model conclusion must reference real event IDs. Unknown references are removed.
- Model output is advisory. Deterministic policy controls response.

## Event families required for useful behavior hunting

### Endpoint process lineage

- Process start/stop, parent process, process GUID, executable path, command line shape, user, integrity level, signer, hash, loaded module metadata.
- Cross-process access, injection indicators, handle access, memory protection changes where supported.
- Process-linked network connection and DNS query.

### File and persistence

- File create/write/rename/delete, executable or script metadata, webroot and temporary directories, autoruns, services, scheduled tasks, cron/systemd units, shell profiles, kernel modules and drivers.

### Identity

- Success/failure, logon type, source, MFA and device context, privilege assignment, group/account changes, service account behavior, token use, session creation and termination.

### Web and application

- Request route, method, response code, latency, request size, authenticated identity, WAF decision, upstream worker, application exception, file upload and application deployment events.
- Request content should be minimized or redacted by policy; detection should favor structure and behavior over storing secrets.

### Database

- Login identity and source, statement category, touched objects, rows scanned/returned/changed, duration, export/dump operations, privilege changes, audit configuration changes.
- Full SQL text should be access-controlled and redacted before LLM use unless explicitly required for an investigation.

### Network

- Process-linked endpoint connections where possible, DNS, TLS metadata, flow duration and byte counts, new listener creation, inbound-to-outbound pivots, east-west movement, protocol anomalies.

### Sensor health

- Agent start/stop, queue pressure, dropped-event count, parser failures, clock offset, policy version, rule version and collection coverage. A lack of events is not treated as proof of safety; collector health and coverage are monitored separately.

## Detection layers

### Layer 1: Atomic behavior facts

Examples:

- Web worker creates a command interpreter.
- Office/browser process creates a script host.
- Unsigned executable starts from a user-writable directory.
- Security service or audit policy changes.
- Database returns an unusually large result set.
- New listener appears on a server role that never listens on that port.

Atomic facts are explainable and cheap. They should normally enrich a chain rather than page an analyst by themselves.

### Layer 2: Ordered and temporal sequences

Rules connect different event types under a stable entity key and time window. Examples:

```text
HTTP POST → w3wp.exe → powershell.exe → webroot write → external TLS
remote login → shell → scheduled task → first external connection
package manager → executable write → first execution → egress
DB bulk read → dump/archive → external transfer
```

Sequence correlation should use process GUID, session ID, user, asset, request ID, trace ID, container/pod ID or network tuple when available. Asset-only grouping, used by this MVP, is a fallback with lower causal confidence.

### Layer 3: Per-entity baselines

Baselines are partitioned by tenant and asset, then optionally by user, process, service, application route or workload. Useful features include:

- parent → child process frequency
- user → process frequency
- process → destination network frequency
- command shape frequency
- signer/path combinations
- process → file directory/extension behavior
- login source and hour
- service → executable behavior
- bytes, rows, file size, process rate and connection rate distributions

Cold-start events must not produce high-confidence anomaly incidents without supporting behavior facts. Baseline learning must be robust against duplicate events and poisoning.

### Layer 4: Entity graph and cross-source context

The production graph should connect:

```text
request → worker process → child process → file → hash → destination
user → session → process → service/task → host → peer host
query → database object → dump file → archive → flow
```

Edges need source event IDs, timestamps, confidence and expiry. The graph supports lateral movement, multi-stage incidents and Qwen evidence retrieval without making the LLM invent causal links.

## Incident assembly

An incident contains:

- tenant and affected assets
- rule and anomaly results
- ordered evidence event IDs
- process/session/request lineage
- asset role and criticality
- baseline comparison
- sensor coverage and missing telemetry
- risk score and confidence
- status and response approvals
- model analysis with exact evidence references

Alerts sharing an entity chain and time range should merge into one incident. Deduplication fingerprints must include rule version and stable event IDs.

## Storage

### Hot event lake

ClickHouse is a practical target for high-volume immutable security events, aggregations and bounded hunt searches. Partitioning should include time and tenant; primary ordering should support tenant, asset, timestamp and event type queries. Row-level tenant isolation must also exist at the service layer.

### Baseline state

For streaming production workloads, use checkpointed state keyed by tenant/entity/feature. Redis can serve low-latency counters, while RocksDB/Flink-style state is preferable for durable large-scale windows. Baseline updates should be reversible or rebuildable from the event lake.

### Evidence archive

Raw source records, PCAP slices, memory artifacts and files belong in an immutable object store with encryption, retention, legal-hold controls and hash verification. Do not put binary evidence into an LLM context.

## Failure modes

- **Collector blind spot:** display coverage and sensor health in every incident.
- **Clock skew:** maintain source and receive time, estimate offset, and avoid strict ordering when skew is high.
- **Baseline poisoning:** deduplicate, delay learning for high-risk events, cap per-source contributions and retain model version history.
- **Prompt injection:** isolate evidence, enforce tools in code, reject unknown event IDs and never expose write tools.
- **Correlation explosion:** partition by tenant/entity, cap windows, use deterministic joins and expire graph edges.
- **LLM outage:** deterministic detection and incident creation continue; a fallback summary remains available.
- **Storage outage:** agents spool locally, gateway buffers, and the platform exposes loss counters.
