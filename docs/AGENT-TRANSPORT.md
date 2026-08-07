# Durable Signed Agent Telemetry Transport

NTAgentShield can send endpoint telemetry from the Go Agent to the Python Control Plane without exposing the Agent's loopback-only local API.

The transport deliberately uses multiple independent checks. A TLS certificate proving that a client was signed by the NTAgentShield CA is not, by itself, enough to let that client claim another tenant in JSON.

## Authentication model

Each Agent telemetry request uses all of the following:

1. **Mutual TLS** using the client certificate issued during Agent enrollment.
2. **Enrollment registry lookup** using the requested Tenant ID and Agent ID.
3. **Ed25519 signature** over the exact HTTP request body using the persistent Agent identity key.
4. **Signed-body identity binding**. `tenant_id` and `agent_id` inside the signed event must match the authenticated request headers and the enrolled registry record.
5. **Event ID replay protection**. An event already stored by the Control Plane returns a successful duplicate acknowledgement and is not processed by the behavioral engine a second time.

The Agent sends these headers:

```text
X-NTShield-Agent-ID: <agent-id>
X-NTShield-Tenant-ID: <tenant-id>
X-NTShield-Signature: <base64 Ed25519 signature of exact request body>
```

The endpoint is:

```text
POST /v1/agent/events
```

## Explicit event-schema mapping

The Go Agent model and Python Control Plane model are intentionally different. The transport does not forward the Go object and hope Pydantic guesses correctly.

The Agent explicitly maps high-value fields into the Control Plane schema:

- event ID, Agent ID, Tenant ID, timestamp, source type and event type
- asset hostname, IP, OS and stable asset ID
- actor/user/session context
- process image, parent image, PID/PPID, command line, hash and signer
- source/destination network context, protocol, direction and external-address classification
- file path, operation, hash and extension
- HTTP method, path, status, user agent and request ID
- database engine, database, statement/query shape, rows and duration
- service and registry context when present

Fields that do not have a first-class Control Plane field are retained under `raw`. Redaction happens before an event is queued for remote transport.

## Durable outbox

When transport is enabled, processed endpoint events are written to:

```text
<data_dir>/outbox/pending/
```

The queue is disk-backed, not an in-memory channel. Each event uses a filename derived from the SHA-256 digest of its event ID, making repeated enqueue attempts for the same event idempotent.

The delivery lifecycle is:

```text
collect
  -> normalize/detect locally
  -> redact
  -> hash-chained local journal
  -> durable outbox
  -> explicit schema map
  -> Ed25519 sign exact body
  -> mTLS POST
  -> Control Plane verifies identity/signature
  -> Control Plane ingests event
  -> HTTP 2xx
  -> Agent removes queued event
```

A queued event is removed only after a successful 2xx response.

## Retry behavior

Temporary delivery failures keep the event in the pending queue. The Agent retries with exponential backoff, capped at one minute.

Examples that remain pending for retry include:

- DNS or network errors
- TLS handshake failures
- Control Plane outage or HTTP 5xx
- authentication/authorization failures such as 401 or 403
- rate limiting or other non-permanent HTTP failures

Keeping 401/403 events pending is intentional because certificate deployment, clock, proxy, or server configuration can be repaired without losing evidence. Persistent authentication failures are visible through Agent transport error counters and logs.

## Dead-letter behavior

A payload rejected as structurally permanent is moved to:

```text
<data_dir>/outbox/dead-letter/
```

The original queued JSON is retained along with a `.reason.txt` file. Current permanent response classes are:

- HTTP 400
- HTTP 413
- HTTP 422
- corrupt local queued JSON
- queued event identity that does not match the configured Agent/Tenant transport identity

This prevents one malformed event at the front of the queue from blocking all subsequent telemetry while preserving evidence for investigation.

## Backpressure visibility

The Agent `/status` response exposes transport state including:

- transport enabled
- pending event count and bytes
- dead-letter count and bytes
- successfully sent count
- transport error count
- last successful delivery time
- backpressure state

`transport.pending_warn` controls the pending-event threshold used to report backpressure. The Agent records backpressure and recovery transitions in its local evidence journal.

## Agent configuration

After successful enrollment, enable transport in the Agent configuration:

```json
{
  "tenant_id": "demo-tenant",
  "transport": {
    "enabled": true,
    "endpoint": "https://control.example:9443/v1/agent/events",
    "cert_file": "certs/client.crt",
    "key_file": "agent-identity.key",
    "ca_file": "certs/ca.crt",
    "server_name": "control.example",
    "timeout": "15s",
    "flush_interval": "2s",
    "batch_size": 100,
    "pending_warn": 10000
  }
}
```

Relative certificate/key paths resolve under the Agent data directory. The endpoint must be an absolute HTTPS URL.

## Control Plane listener

For a direct mTLS listener:

```bash
ntshield serve \
  --host 0.0.0.0 \
  --port 9443 \
  --ssl-certfile /etc/ntshield/server.crt \
  --ssl-keyfile /etc/ntshield/server.key \
  --ssl-ca-certs ./data/pki/enrollment-ca.crt \
  --require-client-cert
```

A production reverse proxy may terminate mTLS instead, but the application-level Ed25519 body signature and enrollment registry verification should remain enabled. Do not replace the signed-body check with a proxy-added Tenant header and optimism.

## Upgrade note

The certificate registry is populated when an Agent enrolls. Agents that received a certificate before the registry feature was deployed should be enrolled again so their certificate is registered before enabling `/v1/agent/events` transport.

## Current limitations

- Certificate rotation/renewal is not automatic yet.
- Revocation is persisted in the registry, but operator-facing revocation/rotation API and UI are a later response-policy slice.
- Delivery currently sends one signed event per HTTP request. `batch_size` controls how many queued events are attempted in one flush cycle, not a single bulk envelope.
- The filesystem outbox is appropriate for endpoint durability but is not a high-volume Kafka replacement, despite humanity's recurring urge to turn every queue into Kafka.
- Remote response commands are not part of this transport. The Agent local API remains loopback-only, and telemetry cannot directly trigger endpoint mutation.

## Next transport hardening

The next production slice should add:

1. automatic certificate renewal before expiry
2. signed policy distribution with version/rollback protection
3. operator-visible Agent revocation and fleet state
4. bounded queue retention and disk-budget policy
5. signed bulk envelopes for high-EPS deployments
6. response broker separated from telemetry ingestion
