# Behavioral Detection Model

## What “zero-day hunting” means here

NTAgentShield does not claim to know an unknown vulnerability before anyone else. It hunts for behavior that should remain suspicious regardless of the exploit's name:

- an externally reachable worker starts an interpreter
- a process relationship has never occurred on the asset
- a new execution path writes a payload and immediately creates egress
- an identity uses a new source, tool and persistence mechanism in one session
- a database workload suddenly stages and transfers a large export
- security telemetry is weakened just before privileged execution

This approach can detect exploitation effects and attacker objectives while signatures catch known artifacts.

## MVP anomaly model

The current implementation learns categorical counts and numeric running statistics per tenant and asset.

### Categorical features

| Feature | Example | Purpose |
|---|---|---|
| `process_name` | `powershell.exe` | new executable on the asset |
| `parent_child` | `w3wp.exe→powershell.exe` | abnormal execution lineage |
| `user_process` | `svc-web→powershell.exe` | identity behavior change |
| `command_shape` | normalized PowerShell command | novel invocation pattern without storing every token as a unique feature |
| `process_destination` | `powershell.exe→45.77.100.0/24:443` | new process-to-network relationship |
| `file_write_bucket` | `powershell.exe→wwwroot/uploads|.aspx` | new write location/type relationship |
| `login_source` | `admin←203.0.113.0/24` | identity source novelty |
| `service_process` | `backup-agent→tool.exe` | service execution drift |
| `process_hour` | `backup.exe|03` | coarse time-of-day change |

Destination IPs are bucketed to reduce cardinality. Command lines replace URLs, IPs, long tokens and large numbers before frequency learning. This is not a secrecy guarantee; sensitive command-line collection still needs policy controls.

### Numeric features

- outbound bytes
- database rows returned
- bytes written
- process CPU percentage

The engine uses Welford's online mean and variance. Positive deviations above two standard deviations begin contributing to anomaly risk after the minimum observation count is met.

### Cold start

Before a feature has enough observations, unseen values receive only a small novelty contribution. A standalone anomaly incident requires:

- mature baseline state, and
- anomaly score above threshold, and
- at least two independent strong novelty reasons

Behavior rules can still create incidents during cold start because they describe risky relationships directly.

### Combined anomaly score

Each feature contributes a bounded novelty component. The score combines the strongest components as a probability-style union:

```text
score = 100 × (1 - Π(1 - component_i))
```

Only the six strongest components are combined. This prevents a large number of weak fields from manufacturing high confidence.

## Rule model

Rules are YAML documents with:

- stable rule ID
- severity and confidence
- time window
- grouping fields
- ordered or unordered steps
- event types and field conditions
- ATT&CK and product tags

Example:

```yaml
id: BZH-WEB-001
severity: critical
window_seconds: 90
ordered: true
group_by: [tenant_id, asset_id]
steps:
  - name: web_request
    event_types: [web.request]
    where:
      - field: http.method
        op: in
        value: [POST, PUT, PATCH]
  - name: worker_shell
    event_types: [process.start]
    where:
      - field: parent_process.name
        op: regex
        value: '^(w3wp|httpd|nginx)(\.exe)?$'
      - field: process.name
        op: regex
        value: '^(powershell|cmd|bash|sh)(\.exe)?$'
```

Supported condition operators include equality, membership, substring, regular expression, numeric comparisons, existence and public-IP classification.

## Risk score

Rule incidents combine:

- rule severity: 48%
- maximum event anomaly: 25%
- asset criticality: 17%
- sensor confidence: 10%
- small confidence bonus above 0.8

Standalone anomaly incidents weigh anomaly more heavily. Risk controls prioritization; it must not be presented as a calibrated probability of compromise until validated against labeled data.

## High-value behavior hunts

The following hunts should be added as telemetry becomes available:

1. Inbound web request → worker exception → child interpreter → egress.
2. Worker process → memory protection change → unsigned module → egress.
3. Browser/Office → child shell → credential store access → archive.
4. Remote login → discovery burst → new service/task → lateral connection.
5. New privileged account → first login → policy change → remote execution.
6. Security sensor stop → log gap → privileged process → external connection.
7. New kernel driver/module → process tampering → network beacon.
8. Package install/build hook → executable write → first run → egress.
9. IDE extension update → child process → credential file read → network.
10. Database bulk read → local staging → compression → transfer.
11. Object storage listing burst → download spike → new destination.
12. DNS process anomaly → high-entropy queries → periodic beacon.
13. New listener → firewall change → first inbound session → shell.
14. Service account interactive login → shell → secret access.
15. Container exec → host mount access → namespace escape indicators.
16. Web upload → executable/script write → first execution.
17. New signed binary path or signature mismatch → rare parent → egress.
18. Snapshot/backup access outside maintenance → export → deletion attempt.
19. Authentication failure burst → success → token theft indicators.
20. Management tool used by a new identity/asset pair → file transfer → execution.

## Evaluation plan

### Replay corpus

Build source-specific fixtures with known benign and adversarial sequences:

- Windows Event Log and Sysmon
- Linux auditd and eBPF
- IIS, Nginx and Apache
- WAF/firewall/DNS/Zeek/Suricata
- MySQL, PostgreSQL and SQL Server audit
- cloud identity and workload events

Every parser and rule should have positive, negative, malformed and cross-tenant tests.

### Attack emulation

Use an isolated lab to execute ATT&CK-aligned techniques and record the exact telemetry chain. Evaluation measures collection coverage first because a detector cannot identify an event that the sensor never emitted.

### Metrics

Track per rule, tenant segment and asset role:

- recall against lab scenarios
- alerts per 1,000 assets per day
- analyst-confirmed true-positive rate
- time to first evidence and time to incident assembly
- duplicate incident rate
- percentage of incidents with complete process lineage
- model evidence-reference validity
- model/tool latency and failure rate
- containment recommendation acceptance and rejection reasons

### Promotion gates

```text
Draft rule
→ schema validation
→ unit fixtures
→ historical replay
→ false-positive budget
→ canary tenants
→ analyst review
→ staged production
```

LLM-generated rules enter at the first validation step and must pass the same schema, replay, false-positive, and rollout controls as human-authored rules.

## Baseline improvements planned

- exponential decay and seasonal time buckets
- peer-group baselines by server role and software stack
- robust quantiles for heavy-tailed numeric features
- sketch structures for high-cardinality destinations
- delayed learning for incidents and untrusted software deployment windows
- entity-level graph embeddings used as supporting features, not opaque final verdicts
- analyst feedback with explicit labels, provenance and rollback
