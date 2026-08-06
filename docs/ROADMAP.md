# Roadmap

## PR 1: Behavioral MVP (this scaffold)

Normalization, baseline rarity, ordered sequence rules, incident correlation, Qwen grounded report,
War Room, demo replay and Go transport agent.

## PR 2: Native endpoint telemetry

- Windows service in Rust or Go with Event Log subscription, ETW process/network providers,
  signed binary inventory and tamper protection.
- Linux service in Rust with auditd/journald readers and optional CO-RE eBPF sensors.
- mTLS enrollment, key rotation, signed configuration and local disk queue.

## PR 3: Scalable control plane

PostgreSQL tenant control data, ClickHouse telemetry, Redis sequence state, Kafka/Redpanda ingestion,
RBAC, audit logs, retention and per-tenant quotas.

## PR 4: Detection engineering lifecycle

Rule versioning, unit tests, historical replay, suppression scopes, canary deployment, precision
metrics, ATT&CK coverage and Sigma import/export.

## PR 5: Response policy

Read-only enrichment first. Then approval-gated block IP, isolate host, stop process, disable account
and virtual patch. Every action requires idempotency, rollback, blast-radius limits and audit trails.

## PR 6: Model improvement

SOC benchmark dataset, Thai incident report evaluation, LoRA only after prompt/RAG/tool baselines,
model routing, confidence calibration and red-team tests for prompt injection and evidence forgery.
