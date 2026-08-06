# Native Event Telemetry

NTAgentShield collects operating-system security telemetry directly from Windows Event Log, Sysmon, Linux journald, and auditd. Native collectors feed the same redaction, tamper-evident journal, deterministic detection, and policy boundary used by file and API ingestion.

## Security boundary

Native telemetry is evidence, not instruction.

- Every event is marked `untrusted_telemetry`.
- Process command lines, event messages, account names, paths, journal fields, and audit fields are recursively redacted before persistence or AI transfer.
- The AI investigator receives no action tools.
- Native source configuration does not accept arbitrary shell commands, PowerShell snippets, XPath, or journalctl arguments.
- Windows channels, Event IDs, journald units/identifiers, and audit paths are schema-validated.
- Operating-system commands and arguments are fixed in the collector implementation.
- Each command has a timeout and bounded output.
- Cursor files are local state, not model context.

## At-least-once evidence delivery

Each source returns a batch plus a proposed cursor. Runtime processing follows this order:

```text
collect batch
  -> normalize events
  -> redact secrets
  -> append events to evidence journal
  -> run deterministic detections
  -> append findings
  -> acknowledge and persist source cursor
```

The cursor does not advance if event or finding persistence fails. A retry may therefore produce the same event again. Native event IDs are deterministic from stable source coordinates such as Windows `EventRecordID`, journald cursor, or audit serial plus line hash, allowing downstream deduplication without accepting silent evidence loss.

Cursor state is stored below:

```text
<data_dir>/cursors/<source-id>.json
```

Cursor files and directories are created with restrictive permissions. Source IDs are constrained to safe filename characters.

## First-run behavior

`from_start` controls initial position:

- `false` records the current tail and begins with newly arriving evidence.
- `true` starts from the oldest available Windows/journal record or byte zero for auditd.

For auditd, a `from_start=true` source initializes byte offset zero on the first poll and starts producing events on the next poll. This keeps cursor initialization explicit and replayable.

## Windows Event Log and Sysmon

The Windows collector invokes `wevtutil.exe` directly. It does not invoke `cmd.exe` or PowerShell and does not accept free-form XPath.

Supported configuration:

```json
{
  "id": "sysmon-operational",
  "enabled": true,
  "kind": "sysmon",
  "channel": "Microsoft-Windows-Sysmon/Operational",
  "event_ids": [1, 3, 6, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 25, 26, 29],
  "from_start": false,
  "max_batch": 512,
  "command_timeout": "20s"
}
```

Important mappings:

| Provider/Event | NTAgentShield kind |
|---|---|
| Sysmon 1 | `process.start` |
| Sysmon 3 | `network.connect` |
| Sysmon 8 | `process.remote_thread` |
| Sysmon 10 | `process.access` |
| Sysmon 11 | `file.write` |
| Sysmon 12-14 | `registry.modify` |
| Sysmon 19-21 | `persistence.wmi` |
| Sysmon 22 | `dns.query` |
| Sysmon 25 | `process.tamper` |
| Security 4624/4625 | `auth.success` / `auth.failure` |
| Security 4688 | `process.start` |
| Security 4697 or System 7045 | `service.create` |
| Security 4698 | `persistence.scheduled_task` |
| Security 4720 | `identity.account_create` |
| Security 5156/5157 | `network.connect` / `network.block` |
| Security 1102 | `security.log_clear` |

### Windows permissions

The service account must be able to query configured channels. Practical deployment choices are:

- Run the Windows service as `LocalSystem`, then harden service ACLs and binary/update paths.
- Use a dedicated service identity with membership in `Event Log Readers`, plus channel-specific ACLs where required.
- Sysmon must be installed and its Operational channel enabled before enabling that source.
- Security log access can require additional local policy depending on the service identity and Windows version.

Do not grant interactive logon to the agent service identity.

## Linux journald

The journald collector invokes `journalctl` directly with fixed flags and validated `--unit` or `--identifier` filters. It requests JSON output and persists the opaque journald cursor.

```json
{
  "id": "linux-auth-journal",
  "enabled": true,
  "kind": "journald",
  "identifiers": ["sshd", "sudo"],
  "from_start": false,
  "max_batch": 512,
  "command_timeout": "15s"
}
```

Current normalization includes:

- SSH accepted and failed authentication
- SSH session open/close
- sudo activity
- systemd service start/stop messages
- kernel messages
- generic journal evidence

The raw journald cursor is never copied into event attributes. `_BOOT_ID` is replaced with a scoped SHA-256 hash before persistence.

### Journald permissions

On systemd systems, use one of these approaches:

- Run the service with the minimum privileges needed for selected journals.
- Add a dedicated agent identity to `systemd-journal` where distribution policy permits.
- Use ACLs for journal files instead of broad root access.

Availability of fields varies by distribution, journal storage mode, unit, and service identity.

## Linux auditd

The auditd collector reads a validated absolute path, normally:

```text
/var/log/audit/audit.log
```

```json
{
  "id": "linux-audit",
  "enabled": true,
  "kind": "auditd",
  "path": "/var/log/audit/audit.log",
  "from_start": false,
  "max_batch": 512,
  "command_timeout": "15s"
}
```

The collector tracks device, inode, and byte offset. It resets to byte zero when rotation changes the file identity or truncation moves the file behind the stored offset. A non-newline-terminated fragment is not emitted and does not advance the acknowledged offset.

Current mappings include:

| Audit type | NTAgentShield kind |
|---|---|
| `EXECVE`, `USER_CMD` | `process.start` |
| `SYSCALL` | `process.syscall` |
| `PATH`, `CWD` | `file.access` |
| `USER_AUTH`, `USER_LOGIN`, `USER_ACCT` | `auth.success` or `auth.failure` |
| `SERVICE_START`, `SERVICE_STOP` | `service.start`, `service.stop` |
| `CONFIG_CHANGE` | `security.audit_config` |
| `AVC`, `USER_AVC`, `SELINUX_ERR` | `security.selinux_denial` |
| `ADD_USER`, `DEL_USER` | identity changes |
| `ANOM_*`, `RESP_*` | `security.anomaly` |

### auditd permissions

The agent identity needs read access to the audit log and execute/search permission on parent directories. Prefer ACLs or a narrowly scoped service capability over making the entire process unrestricted. Keep audit log rotation settings compatible with inode/offset tracking.

## High-signal native detections

The deterministic engine raises dedicated findings for:

- Windows Security log clear
- Sysmon process tampering
- Sysmon remote thread creation
- Scheduled task persistence
- Service creation
- Account creation
- Linux audit disablement or weakening
- SELinux denials correlated as security evidence

These detections produce findings, not automatic containment. Response still requires deterministic policy and, for state-changing actions, an exact action approval.

## Operational checks

Validate configuration:

```bash
go run ./cmd/ntagentshieldctl doctor --config config/windows.example.json
```

Run the agent and inspect status:

```bash
go run ./cmd/ntagentshield-agent --config config/windows.example.json
```

```bash
TOKEN="$(cat <data_dir>/agent-api.token)"
curl -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:9477/v1/status
```

Status exposes file/native source counts and the number of processed native events.

Verify the evidence chain after collection:

```bash
go run ./cmd/ntagentshieldctl verify-store --path <data_dir>/evidence.journal.jsonl
```

## Current limitations

- Windows collection uses bounded polling through `wevtutil`, not a push subscription or ETW callback yet.
- Windows XML rendering varies by provider and locale; normalized fields are extracted from provider data first, with rendered text retained as evidence.
- Journald field availability depends on permissions and source service.
- auditd records that share the same serial are currently emitted as individual evidence events; multi-record serial correlation belongs in the next correlation milestone.
- Kernel-level ETW/eBPF sensors and production response adapters remain separate milestones.
