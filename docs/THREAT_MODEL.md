# Threat Model

## Protected assets

- Host integrity and availability.
- Credentials, tokens, private keys, and customer data.
- Evidence authenticity and incident timelines.
- Agent identity, policy, rule, model, and update integrity.
- Operator approvals and response authority.
- Tenant separation and data residency.
- AI context, memory, tool catalog, and model endpoint.

## Adversaries

- Remote attacker exploiting a web, API, database, or AI service.
- Local unprivileged user attempting privilege escalation.
- Compromised administrator or stolen operator token.
- Malicious dependency, plugin, model, adapter, or update source.
- Attacker who controls log fields, source comments, tickets, RAG documents, or tool descriptions.
- Compromised control plane attempting to overreach endpoint policy.
- Insider attempting to access another tenant’s evidence.

## Trust boundaries

### Untrusted evidence boundary

The following remain untrusted regardless of how plausible they look:

- HTTP method/path/query/header/body metadata;
- IIS, Nginx, Apache, firewall, database, and application logs;
- filenames, process command lines, DNS names, and certificate fields;
- source code, comments, commit messages, CI output, and dependencies;
- email, ticket, chat, RAG document, vector-store content, and MCP descriptions;
- AI model output.

Authentication proves the sender’s identity, not the truth or authority of payload content.

### Policy boundary

Only deterministic policy decides whether a typed action may run. Model output is never an approval. Tool risk is defined in code, not supplied by the caller.

### Privilege boundary

The foundation has read-only tools. Future response runs in a separate broker with minimum OS rights. The AI process does not inherit broker privileges.

### Tenant boundary

Every event, finding, policy, action, model request, and audit record must carry tenant identity. Central storage, queues, caches, vector indexes, and object paths must enforce the same boundary.

## Primary attack scenarios and controls

| Attack | Control |
|---|---|
| Indirect prompt injection through User-Agent or log text | Trust labels, evidence envelope, no tools in AI request, deterministic policy |
| AI asks for `shell.exec` | Generic shell tools do not exist and are explicitly denied |
| Caller lies about tool risk | Registry overwrites caller risk with canonical tool risk |
| Path traversal through file tool | Absolute path, symlink resolution, allowlisted roots |
| Approval replay for a modified action | Digest binds tool, arguments, reason, risk, and trigger trust; expiry enforced |
| Journal modification | Payload hash and chained record hash verification |
| Secret leakage to journal/model | Pre-persistence redaction, bounded evidence, minimal collection |
| Remote API exposure | Config rejects non-loopback binding; token authentication; no action endpoint |
| Oversized log/API payload | Scanner and HTTP body limits, bounded file reads, per-poll limits |
| Malicious model response | Output remains analysis only; no automatic action path |
| Poisoned rule/plugin/update | Planned signatures, hash pinning, staged rollout, revocation |
| Compromised endpoint forges clean evidence | Planned control-plane checkpoint anchoring and cross-source correlation |
| DoS via high event volume | Planned backpressure, durable queue, rate limits, priority tiers, sampling policy |

## Residual risks in 0.1

- The journal is not encrypted at rest and is not anchored externally.
- File-tail offsets are in memory; restarts can intentionally start at configured end/beginning but do not persist exact cursors.
- Native Windows Event Log, ETW, auditd, journald, and eBPF collectors are not implemented.
- Detection rules are compiled into the binary and not signed separately.
- No privileged response broker exists yet.
- AI output is redacted with the same general redactor but requires stronger output DLP before production.
- Lexical code scanning lacks full interprocedural data flow.

These are explicit roadmap items, not hidden beneath a dashboard animation.
