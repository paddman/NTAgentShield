# Roadmap

## PR 0: Product boundary and threat model

Status: **implemented in foundation**

- product definition;
- architecture and trust boundaries;
- AI security and response-safety model;
- language and no-generic-shell ADRs.

## PR 1: Secure agent core

Status: **foundation implemented**

- stable local identity;
- configuration validation;
- loopback API and token;
- evidence journal;
- policy engine;
- typed read-only tools;
- CI and cross-platform builds.

## PR 2: Native asset inventory and endpoint telemetry

- Windows Event Log and Sysmon collectors;
- Linux journald and auditd collectors;
- process, service, package, listening-port, user, and persistence inventory;
- durable collector cursors and backpressure;
- resource-budget telemetry.

## PR 3: Web, database, firewall, and container collectors

- production IIS/Nginx/Apache adapters;
- PostgreSQL and SQL Server audit adapters;
- database query fingerprint/redaction policy;
- firewall/WAF vendor parsers;
- Docker/Podman/Kubernetes telemetry.

## PR 4: Detection fabric

- external signed rule packs;
- Sigma conversion;
- YARA/YARA-X and Suricata adapters;
- temporal behavior DSL;
- per-role baselines and anomaly scoring;
- ATT&CK/ATLAS mapping and test corpus.

## PR 5: Code-security workspace

Foundation lexical scanner exists. Planned:

- Tree-sitter AST and data flow;
- Semgrep adapter;
- SBOM, dependency, secret, IaC, container, and CI scanners;
- repository indexing and incremental scan;
- security diff, patch proposal, sandbox tests, checkpoint and rollback.

## PR 6: Cline-style security console

- desktop console and terminal TUI;
- Observe/Plan/Act modes;
- evidence timeline and graph;
- tool-call preview;
- diff review and approval;
- incident notebooks and export.

## PR 7: AI investigator and AI runtime guard

Foundation read-only AI client exists. Planned:

- central/local model routing;
- structured evidence citations;
- output DLP and canary-secret detection;
- RAG provenance and poisoning controls;
- MCP/tool manifest signatures;
- memory-write policy;
- Thai/English injection red-team suite.

## PR 8: Privileged response broker

- separate service identity and OS permissions;
- Windows/Linux containment adapters;
- dry-run, exact approval, audit, verification, rollback;
- emergency kill switch and action budget.

## PR 9: Unknown-threat hunter

- web-request-to-process-to-file-to-network chains;
- database-to-process/file correlation;
- rare parent-child and destination behavior;
- exploit primitive and post-exploitation detections;
- virtual WAF patch proposal.

## PR 10: NT Shield control-plane integration

- mTLS enrollment and rotation;
- tenant-scoped fleet and policy;
- central evidence graph and incidents;
- Qwen inference on NT infrastructure;
- signed rule/model/update distribution;
- reporting, SLA, retention, billing, and air-gap mode.
