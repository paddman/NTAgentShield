# Production operations foundation

This phase adds operational controls without pretending that a single SQLite process has somehow
become a distributed database because a diagram contains more rectangles.

## PostgreSQL migration runner

Install the optional driver and apply checksum-verified migrations:

```bash
python -m pip install '.[postgres]'
export NTSHIELD_DATABASE_URL='postgresql://ntshield@db.example/ntshield'
ntshield-migrate status
ntshield-migrate apply
```

Migrations are ordered, immutable and guarded by a PostgreSQL transaction-scoped advisory lock.
Changing an applied migration causes a checksum-drift failure. The initial schema provides tenants,
operator tenant roles, cases, case timeline, audit anchors and row-level security policies based on
`ntshield.tenant_id` or `ntshield.platform_admin` session settings.

The existing behavioral event/finding store still uses SQLite in this phase. The migration runner
and normalized control schema are production-ready foundations, but replacing every high-volume
storage path with PostgreSQL/ClickHouse adapters is a separate data-plane migration and must be
load-tested before activation.

## Durable asynchronous ingestion

Authenticated ingesters can submit already schema-checked and redacted telemetry to:

```text
POST /v1/ingest/async/normalized
POST /v1/ingest/async/raw
Idempotency-Key: <caller-generated stable key>
```

The queue persists canonical JSON, SHA-256, tenant, attempts, lease owner and result. Workers claim
jobs with expiring leases. A crashed worker's lease is reclaimed; failures use exponential backoff;
and exhausted jobs enter `dead_letter` rather than circulating forever like an unresolved meeting.

Run a worker:

```bash
ntshield-worker --batch 200 --lease-seconds 120
```

The supplied Compose file starts a separate worker sharing the data volume. For higher throughput,
replace the SQLite queue with Kafka/Redpanda while retaining the same idempotency and lease tests.

## Prometheus, OpenTelemetry and SLOs

`/metrics` exposes Prometheus counters, gauges and request-duration histograms. The observability
folder contains recording and alerting rules for:

- operator API availability;
- p95 request latency;
- readiness failure; and
- audit append failure.

OTLP trace export is optional:

```bash
python -m pip install '.[otel]'
export NTSHIELD_OTEL_ENABLED=true
export NTSHIELD_OTEL_ENDPOINT=https://otel-collector.example:4318
```

Plain HTTP is accepted only for loopback. Production traces should be sent to an OpenTelemetry
Collector over TLS, then exported to the organization's backend.

## Signed release workflow

The root release workflow builds Python distributions, cross-platform Go binaries and the Windows
package. A tag release fails closed unless these secrets exist:

- `WINDOWS_SIGNING_PFX`, a base64 PFX for Authenticode;
- `WINDOWS_SIGNING_PASSWORD`; and
- `UPDATE_SIGNING_PRIVATE_KEY_PEM_B64`, a base64 Ed25519 PKCS#8 key.

The workflow Authenticode-signs Windows executables, creates signed update envelopes, generates an
SPDX 2.3 SBOM and SHA-256 manifest, and produces GitHub artifact attestations before publishing.
Consumers can verify provenance with GitHub CLI and verify updater envelopes offline with the
pinned Ed25519 public key.

## Windows Service and updater

The Agent now hosts itself under the Windows Service Control Manager and handles stop, shutdown and
preshutdown controls through context cancellation. The installer removes the old Scheduled Task,
registers a delayed automatic service, configures recovery restarts and preserves existing data.

`ntagentshield-updater.exe` validates an exact signed manifest that binds version, expiry, target
OS/architecture, HTTPS URL, byte size and SHA-256. It stages on the same volume, stops the service,
keeps the old executable as `.previous`, installs atomically and rolls back if the service does not
return to `RUNNING`.
