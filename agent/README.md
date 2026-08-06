# NTAgentShield transport agent

The Go agent is deliberately small. It reads structured JSON lines from an existing collector,
wraps each record with tenant and asset identity, and sends it to the central normalizer. Failed
deliveries are written to a local mode-0600 spool and retried on the next start.

It is not yet an EDR sensor. Native collectors should be attached in later PRs:

- Windows: Event Log subscriptions, Sysmon, ETW, AMSI metadata, Defender events.
- Linux: auditd, journald, eBPF process/network/file telemetry.
- Network and services: Zeek, Suricata, firewall syslog, IIS, Nginx, Apache and database audit logs.

```bash
cd agent
go build -o ntshield-agent ./cmd/ntshield-agent

./ntshield-agent \
  --server http://shield-control-plane:8080 \
  --tenant customer-a \
  --asset web-01 \
  --role public-web \
  --criticality 5 \
  --source sysmon \
  --input ./sysmon.jsonl
```
