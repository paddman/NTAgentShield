# Telemetry Matrix

Legend: **Now** implemented in the foundation, **Next** planned for near-term agent work, **Later** requires deeper platform/control-plane integration.

| Domain | Source | Status | Primary detections |
|---|---|---:|---|
| Web | IIS W3C logs | Now | auth burst, traversal, prompt injection in fields, status/latency context |
| Web | Nginx combined logs | Now | traversal, probes, prompt injection in user agent |
| Database | MySQL general logs | Now | query fingerprint, privilege/file/OS-risk operations |
| Network/System | RFC3164-style Syslog | Now | security-control disable patterns, generic evidence |
| Endpoint | Normalized JSON events | Now | process/file/network behavior rules |
| Code | Local source tree | Now | secrets, injection precursors, unsafe APIs, supply-chain patterns |
| Windows | Windows Event Log | Next | logon, process, service, scheduled task, account changes |
| Windows | Sysmon | Next | process tree, network, file, registry, tampering |
| Windows | ETW | Next | PowerShell, DNS, process/image, service-specific telemetry |
| Linux | journald | Next | service, auth, kernel, application events |
| Linux | auditd | Next | exec, file, identity, privilege changes |
| Linux | eBPF | Next | process, syscall, file, socket behavior with bounded overhead |
| Web | IIS Failed Request Tracing | Next | exploit request-to-error correlation |
| Web | Nginx/Apache error logs | Next | upstream failures, module/config anomalies |
| Database | PostgreSQL + pgAudit | Next | role, extension, query and schema behavior |
| Database | SQL Server Audit/Extended Events | Next | login, role, procedure and administrative behavior |
| Network | Suricata EVE | Next | IDS events correlated with endpoint execution |
| Network | DNS and NetFlow/IPFIX | Next | beaconing, rare destinations, exfiltration |
| Container | Docker/Podman events | Next | privileged execution, image drift, host mount |
| Kubernetes | Audit API | Next | secret access, exec, RBAC and workload changes |
| Firewall/WAF | Vendor Syslog/API | Next | policy changes, scanning, brute force, egress anomalies |
| AI | Model gateway request metadata | Next | injection, abuse rate, extraction, context leakage |
| AI | MCP/tool calls | Next | tool poisoning, scope abuse, unexpected side effects |
| AI | RAG/vector ingestion | Next | poisoned source, ACL mismatch, unsigned document |
| Fleet | Cross-host correlation | Later | lateral movement, campaign graph, distributed brute force |
| Vulnerability | SBOM/CVE/KEV | Later | exposure-prioritized vulnerability risk |
| Packet | Selective PCAP | Later | incident-scoped protocol reconstruction with privacy controls |

## Collection principles

- Collect metadata before content.
- Apply redaction and minimization at the endpoint.
- Keep high-volume raw data local unless an incident policy requires transfer.
- Preserve source, collector, path, line/record ID, timestamp, and content hash.
- Do not silently enable database general query logging on production systems; use native audit facilities and fingerprints where possible.
- Measure CPU, memory, disk, and event-loss overhead per collector.
