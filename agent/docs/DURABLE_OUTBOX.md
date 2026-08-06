# Durable Evidence Outbox

The NTAgentShield forwarder converts records from the local hash-chained evidence journal into deterministic, sequence/hash-chained transport batches. Network availability never controls whether the endpoint can continue collecting evidence. When the gateway is unavailable, batches remain in a restrictive local spool until an exact receipt is recorded.

```text
agent collectors and detections
          |
          v
hash-chained evidence journal  (source of truth)
          |
          v
strict journal exporter
          |
          v
atomic spool batch + hashed outbox state
          |
          v
TLS 1.3 mutual-auth transport
          |
          v
exact receipt -> state acknowledgement -> spool deletion
```

## Delivery semantics

Delivery is **at least once**:

- A batch uses a stable tenant, agent, sequence, previous-batch hash and payload hash.
- A retry sends the same batch bytes and identity.
- The gateway returns `duplicate` when it already accepted that exact sequence and hash.
- A reused sequence with different content is a fork and permanently blocks the oldest pending batch.
- The forwarder never skips a blocked sequence to deliver newer evidence.
- A batch is removed only after the receipt tenant, agent, sequence and payload hash exactly match local state.

This is intentionally not described as exactly-once delivery. Crash boundaries and distributed acknowledgements exist even when a slide deck politely omits them.

## Crash recovery

### Spool written, state not written

The batch filename contains its sequence and payload hash. On restart, the outbox validates the file, tenant/agent identity, previous hash and journal range. It recovers the orphan only when it extends the persisted chain exactly.

### Gateway accepted, local acknowledgement not written

The same batch is resent. The gateway returns `duplicate`, and the forwarder records the acknowledgement.

### Acknowledgement written, spool file not deleted

On restart, files at or below the last acknowledged sequence are removed after validation.

### State file corrupted or modified

The state envelope payload hash fails. The file is quarantined and the forwarder refuses to invent a replacement sequence. Operator review is required because silently resetting sequence state would create a transport fork.

## Journal safety

The exporter requires:

- monotonically contiguous journal sequences
- a valid SHA-256 record hash
- one valid JSON payload per record
- payload size within the transport item limit

It recognizes journal record type fields named `type`, `record_type` or `kind`; and sequence fields named `sequence` or `seq`. Unknown record categories are transported as `audit` evidence. Invalid lines are not skipped.

The forwarder opens the journal read-only. The systemd unit prevents it from writing the Agent data directory.

## Backpressure and quotas

Default limits:

| Setting | Default |
|---|---:|
| Pending batches | 1,024 |
| Total spool size | 1 GiB |
| Items per batch | 256 |
| Encoded batch size | 4 MiB |
| Initial retry delay | 2 seconds |
| Maximum retry delay | 5 minutes |

When either pending-count or byte quota is reached, batch creation stops. The Agent journal continues collecting subject to its own disk policy. The outbox never deletes unacknowledged evidence to make the dashboard look healthy.

## Retry policy

Network failures, HTTP 408, 425, 429 and 5xx responses use exponential backoff with deterministic jitter. Authentication, identity, validation and sequence conflicts are non-retryable and block the oldest batch.

After correcting the cause, an operator can unblock one exact sequence:

```bash
ntagentshield-forwarder \
  --identity-dir /var/lib/ntagentshield/identity \
  --journal /var/lib/ntagentshield/evidence.journal.jsonl \
  --outbox-dir /var/lib/ntagentshield-forwarder \
  --unblock 42
```

Unblocking does not alter batch content, sequence or hash. It only permits another delivery attempt.

## Run the forwarder

```bash
ntagentshield-forwarder \
  --identity-dir /var/lib/ntagentshield/identity \
  --journal /var/lib/ntagentshield/evidence.journal.jsonl \
  --outbox-dir /var/lib/ntagentshield-forwarder \
  --status-file /run/ntagentshield-forwarder/status.json
```

The forwarder reads the control-plane URL and tenant/agent identity from enrollment metadata. `--endpoint` and `--server-name` exist for controlled deployment overrides and diagnostics.

`--once` runs one build/delivery cycle, which is useful for deployment validation and scheduled environments.

## Files

```text
outbox-directory/
├── state.json
├── spool/
│   └── batch-00000000000000000001-<sha256>.json
└── .outbox.lock/
    └── heartbeat
```

Files and directories use restrictive permissions where the operating system supports Unix modes. Windows deployment must additionally set explicit NTFS ACLs during service installation.

## Current boundary

This milestone provides the durable forwarder, spool, retry scheduler, quotas, status output and journal bridge. It does not yet provide:

- central multi-tenant database ingestion from gateway JSONL
- remote fleet delivery status and queue management
- certificate renewal or revocation
- compression, content-addressed object attachments or PCAP chunk upload
- administrator-signed skip/reset procedures for an irrecoverable sequence fork

Those belong in later control-plane and identity-lifecycle milestones. The forwarder has no response tools and cannot mutate endpoint security policy.
