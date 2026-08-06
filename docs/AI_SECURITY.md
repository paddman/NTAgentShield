# AI Security Model

## Two different threats

### AI-assisted attackers

Packets and processes do not reliably reveal whether a human or model wrote the payload. NTAgentShield therefore detects behavior, execution chains, rate, credential use, evasion, persistence, and impact rather than claiming an “AI-generated attack detector.”

### Attacks against the defensive AI

The defensive AI itself can be attacked through prompt injection, RAG poisoning, context poisoning, tool poisoning, identity abuse, model supply chain compromise, memory poisoning, and exfiltration. This is the priority AI-specific boundary.

## Context trust model

| Trust label | Examples | Instruction authority |
|---|---|---|
| `system` | compiled safety policy, process invariants | high, internal only |
| `signed_policy` | verified tenant response policy | high within scope |
| `operator` | authenticated operator request | bounded by role and policy |
| `trusted_config` | local protected configuration | configuration only |
| `untrusted_telemetry` | logs, process events, database queries | none |
| `untrusted_code` | source, comments, dependencies | none |
| `untrusted_network` | local API event payload, remote content | none |

Untrusted data can change the investigation conclusion. It cannot change the rules of investigation or grant action authority.

## Foundation AI request

The AI client:

- redacts events before serialization;
- rewrites event trust to untrusted telemetry;
- enforces a 256 KiB evidence limit;
- sends a system instruction declaring evidence non-authoritative;
- encloses evidence inside an explicit JSON boundary;
- sends no tool declarations;
- uses a bounded response size and timeout;
- rejects remote endpoints unless explicitly allowed;
- requires HTTPS for non-loopback endpoints;
- returns `read_only=true` and `tools_exposed=false` metadata.

## Production controls

Planned production controls include:

- policy-signed model routing and endpoint allowlists;
- tenant-specific encryption and context isolation;
- canary secrets and output DLP;
- model/adapter hash verification and AIBOM inventory;
- RAG source signatures, ACL propagation, provenance, version, and expiry;
- immutable tool schemas and signed plugin registry;
- action budget, rate limit, circuit breaker, and kill switch;
- memory writes requiring provenance, TTL, and approval;
- model-response evaluation against evidence citations;
- prevention of cross-tenant prompt cache or vector-index leakage;
- red-team suites for direct/indirect injection in Thai and English.

## Rule for implementation

A prompt is not a security boundary. Every important safety statement in a prompt must also exist as code, policy, privilege separation, schema validation, network control, or audit verification.
