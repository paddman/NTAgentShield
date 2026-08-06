# Product Definition

## Product statement

NTAgentShield is an installable AI-assisted security operator for servers and endpoints. It observes local telemetry, detects known and unknown-threat behavior, investigates incidents, audits code and configuration, and performs only explicitly authorized response actions.

## Primary users

- Organizations without a 24×7 SOC.
- Government and state-enterprise environments requiring data residency and auditability.
- NT Cloud/IDC customers running IIS, Nginx, databases, APIs, virtual machines, and containers.
- SOC/MDR teams that need endpoint evidence and controlled investigation at scale.
- Developers and DevSecOps teams that need local code-security review.

## Jobs to be done

1. Explain why a server or endpoint is behaving abnormally.
2. Correlate web, process, file, network, database, and identity evidence.
3. Detect exploit behavior even when no CVE-specific signature exists.
4. Prevent attacker-controlled telemetry from hijacking the defensive AI.
5. Review code and configuration before deployment.
6. Preserve evidence and provide auditable, reversible response workflows.
7. Connect securely to a multi-tenant NT Shield control plane.

## Operating modes

### Observe

Read telemetry, calculate hashes, inspect bounded file ranges, and produce findings. No state changes.

### Plan

Build a read-only investigation plan, list missing evidence, and propose exact actions. No execution.

### Act

Execute a typed action only after deterministic policy evaluation and exact operator approval.

### Guard

Automatically perform low-risk evidence preservation or monitoring actions defined in signed policy. This mode is planned, not enabled in the foundation.

### Incident

Apply pre-approved containment under narrowly defined high-confidence conditions. This mode requires a separate privileged response broker and is planned.

## Product non-goals

- Claiming 100% zero-day detection.
- Determining whether an attack was “written by AI” from packet style.
- Allowing an LLM to execute arbitrary shell commands.
- Replacing backups, patch management, IAM, WAF, EDR, or human incident command by itself.
- Sending raw customer logs to an external model without governance approval.

## Success measures

- Mean time from event to evidence-backed finding.
- Percentage of findings with reproducible evidence and rule rationale.
- False-positive rate per asset role.
- Time to validate or reject an incident hypothesis.
- Percentage of actions with dry-run, approval, audit, verification, and rollback.
- Resource overhead on representative Windows/Linux hosts.
- Tenant isolation and data-residency compliance.
