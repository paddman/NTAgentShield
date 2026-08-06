# Threat Model

## Assets to protect

- tenant security telemetry and raw logs
- credentials, tokens and enrollment identities
- incident evidence and chain of custody
- behavior rules and response policies
- model prompts, tool results and analysis
- response approval records
- customer separation and retention policy

## Adversaries

- external attackers exploiting monitored systems
- compromised endpoint or server agents
- malicious or careless tenant users
- compromised SOC analyst account
- supply-chain compromise in parsers, rules, dependencies or model artifacts
- prompt-injection content planted in logs, filenames, URLs, HTTP fields, SQL comments or source code

## Principal risks and controls

### Cross-tenant access

**Risk:** an event or model tool call retrieves another customer's telemetry.

**Controls:** tenant identity must come from authenticated enrollment; partition processing keys by tenant; enforce tenant filters in every store call; expose tenant-scoped APIs; test cross-tenant event chains; audit all administrative access.

The MVP requires `X-Tenant-ID` and verifies event consistency, but this header is not authentication. Production must replace it with workload identity and RBAC.

### Agent impersonation and replay

**Risk:** an attacker injects false events, poisons baselines or hides gaps.

**Controls:** mTLS enrollment, rotating certificates, sequence numbers, signed policy, replay windows, sensor health, local spool integrity and server-side clock/gap analysis.

### Baseline poisoning

**Risk:** repeated malicious behavior becomes normal.

**Controls:** event deduplication, delayed learning for high-risk events, contribution caps, baseline snapshots, analyst labels, rebuild from immutable events, maintenance/deployment context and sensor trust weighting.

### Prompt injection

**Risk:** attacker-controlled evidence tells Qwen to ignore policy, whitelist activity or invoke a tool.

**Controls:** all evidence is marked untrusted; model has read-only tools only; application forces tenant/asset/time bounds; unknown tools fail closed; event IDs are validated; response actions go through deterministic policy; model service has no endpoint credentials.

### Destructive model action

**Risk:** hallucinated or manipulated analysis isolates critical infrastructure or destroys evidence.

**Controls:** the hunt agent has no write tools. Evidence collection may be automatic; containment requires human approval or a separately signed deterministic playbook; destructive actions are denied.

### Parser exploitation

**Risk:** malformed logs trigger parser vulnerabilities or resource exhaustion.

**Controls:** isolated parsers, size/depth limits, safe serialization, source fixtures, fuzzing, dead-letter queues, dependency scanning and no dynamic code execution.

### Evidence tampering

**Risk:** attacker or operator modifies records after an incident.

**Controls:** immutable raw storage, hashes, append-only audit, retention/legal hold, signed export manifests and separation of analyst notes from source evidence.

### Denial of service

**Risk:** event flood, high-cardinality fields or huge LLM contexts exhaust resources.

**Controls:** source quotas, backpressure, priority classes, cardinality controls, bounded windows, context caps, result limits, circuit breakers and deterministic detection independent of inference.

## Security invariants

1. No model output can directly execute a state-changing action.
2. Every retrieved event is tenant-scoped by server-side context.
3. Every incident conclusion can be traced to source event IDs.
4. Detection continues when Qwen is unavailable.
5. Unknown response actions are denied.
6. Duplicate events do not repeatedly train the baseline.
7. Raw logs are evidence, never trusted instructions.
