# Architecture

## Design goal

Detect unknown attacks from observable effects rather than waiting for a CVE, signature, hash or
vendor advisory. The platform keeps deterministic detection and response policy outside the LLM.

## Data path

1. **Collection**: existing sources produce Sysmon, Windows Event Log, auditd, journald, Zeek,
   Suricata, firewall, web and database audit events.
2. **Normalization**: vendor fields map into a compact OCSF-inspired event envelope.
3. **Baseline**: online feature counts estimate rarity for process lineage, process-to-destination,
   user-to-asset, execution hour, file directory, service binary and database query shape.
4. **Sequence engine**: YAML rules correlate ordered events by tenant and asset within bounded
   windows.
5. **Scoring**: rule confidence combines with rarity, asset criticality and source diversity.
6. **Correlation**: findings sharing an asset or entity become one incident.
7. **Grounded analysis**: Qwen receives only incident evidence, not unrestricted log storage.
8. **Response**: future policy engine evaluates analyst recommendations. The model never acts
   directly on endpoints.

## Multi-tenant boundary

Every event, baseline counter, finding and incident includes `tenant_id`. Production deployment
must add authenticated tenant claims and database row-level security. The demo API does not yet
implement identity because pretending an unauthenticated prototype is tenant-safe would be a
particularly dull form of fiction.

## Storage evolution

| Phase | Event store | State | Use |
|---|---|---|---|
| MVP | SQLite WAL | local process | demo, lab, single site |
| Pilot | ClickHouse | Redis | high-rate telemetry, replay |
| Service | ClickHouse cluster + object storage | Redis cluster | multi-tenant MDR |

PostgreSQL should hold tenants, users, assets, policy and audit metadata. ClickHouse should hold
high-volume immutable telemetry. Redis should hold short-lived sequence state and rate limits.

## Trust boundaries

- Telemetry is untrusted.
- Rule files are trusted configuration and require code review.
- Qwen output is untrusted until schema and evidence validation passes.
- Any disruptive response requires policy evaluation and human approval.
- Agents use tenant-scoped enrollment credentials, mTLS and signed updates in later phases.
