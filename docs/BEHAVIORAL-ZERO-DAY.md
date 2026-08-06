# Behavioral Zero-Day Hunting

## What the term means here

A zero-day is not detected by naming the unknown vulnerability. NTAgentShield instead identifies a
high-fidelity chain whose effects are inconsistent with normal operation, such as:

```text
novel public request
  -> web worker spawns shell
  -> shell connects to first-seen external destination
  -> payload appears in webroot
  -> persistence is created
```

The system may state that an unknown exploit is plausible. It must not state that a zero-day is
confirmed without vulnerability reproduction and version-level evidence.

## Detection layers

### 1. Invariants

These should almost never occur regardless of baseline:

- IIS, Nginx, Apache or a database daemon spawning a shell.
- A web worker reading LSASS, SAM, NTDS or `/etc/shadow`.
- Security controls disabled and logs cleared before outbound traffic.
- Services launched from user-writable directories.
- Recovery deletion followed by mass file modification.

### 2. Rarity

Rarity raises or lowers confidence but does not replace behavioral logic. Current features include:

- parent process -> child process
- process -> destination IP/domain/port
- user -> asset and hour
- file directory
- service binary path
- web route + method
- database query shape

Cold-start scores are deliberately suppressed until enough observations exist.

### 3. Ordered sequences

Rules require cause-and-effect order within a time window. A PowerShell process existing somewhere
and an external IP existing somewhere else are not an attack chain merely because a dashboard can
put them on the same screen.

### 4. Cross-source diversity

Confidence increases when independent telemetry supports the chain, for example web access log,
Sysmon process creation, firewall egress and file integrity monitoring.

### 5. Analyst reasoning

Qwen receives the reduced evidence bundle to explain the chain, identify gaps, recommend
read-only hunts and produce a customer report. It cannot invent evidence or execute actions.

## Tuning workflow

1. Label assets by role and criticality.
2. Collect at least 7-14 days for stable enterprise baselines where possible.
3. Replay known administrative activity and deployment jobs.
4. Add scoped exceptions, never global blanket exclusions.
5. Measure findings per 1,000 endpoints per day, precision and mean investigation time.
6. Promote rules from `test` to `pilot` and then `production` after replay and canary validation.

## Minimum telemetry for useful coverage

### Windows

- Security 4624, 4625, 4648, 4672, 4688, 4697, 4698, 5156, 5157, 1102
- System 7045
- Sysmon 1, 3, 6, 10, 11, 13, 22, 23, 25
- PowerShell 4103/4104 where policy allows
- Defender/EDR control changes

### Linux

- auditd `execve`, file writes, identity and service changes
- journald/systemd service events
- eBPF process, file and network metadata
- auth, sudo, SSH and cron

### Network and application

- firewall allow/deny with bytes
- Zeek connection, DNS, HTTP and TLS metadata
- Suricata alerts
- IIS/Nginx/Apache structured access and error logs
- WAF request ID and anomaly metadata
- database audit with user, rows, duration and query shape
