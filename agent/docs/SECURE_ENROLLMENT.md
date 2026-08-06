# Secure Enrollment and Mutual-TLS Transport

NTAgentShield endpoints generate their own ECDSA P-256 private key, request a certificate through a short-lived enrollment token, and authenticate to the evidence gateway with TLS 1.3 mutual authentication. Tenant and agent identity is carried in an issued SPIFFE URI, not trusted from request headers or certificate subjects supplied by the endpoint.

```text
administrator creates tenant-bound token
        |
        v
agent creates local key + CSR
        |
        v
HTTPS bootstrap with pinned CA + one-time token
        |
        v
gateway validates token, CSR, nonce, time and expected tenant
        |
        v
gateway issues clientAuth certificate
spiffe://ntshield.local/tenant/<tenant>/agent/<agent>
        |
        v
agent sends sequence/hash-chained evidence batches over mTLS
```

## Security properties

- The endpoint private key is generated locally and never sent to the gateway.
- Enrollment uses TLS 1.3 and a pinned bootstrap CA. Redirects and insecure certificate verification are disabled.
- Enrollment tokens contain 256 bits of randomness. The gateway persists only the SHA-256 token hash.
- Tokens are tenant-bound and can optionally be bound to one agent ID.
- A consumed token can only retry for the same agent and the same public key. The gateway returns the same certificate rather than issuing another identity.
- The gateway ignores identity claims from the CSR and constructs the certificate subject and SPIFFE URI from server-side token state.
- Evidence ingestion requires a verified client certificate. The tenant and agent in the batch must match the certificate SPIFFE identity.
- Every evidence batch contains a monotonically increasing sequence, previous-batch hash, creation time, item list and payload SHA-256.
- Identical retries receive a `duplicate` receipt. A reused sequence with different content is rejected as a fork. Gaps and incorrect previous hashes are rejected.
- Enrollment and transport endpoints impose body, header, timeout, identity, item-count and per-item limits.
- The gateway exposes no shell, command, policy mutation or response endpoint.

## Initialize a development gateway

```bash
cd agent

go run ./cmd/ntagentshield-ca init \
  --state-dir ./gateway-state \
  --dns localhost \
  --ip 127.0.0.1
```

This creates:

```text
gateway-state/
├── ca.crt.pem
├── ca.key.pem
├── gateway.crt.pem
└── gateway.key.pem
```

Existing files are never overwritten by `init`.

Start the gateway:

```bash
go run ./cmd/ntagentshield-gateway \
  --state-dir ./gateway-state \
  --listen 127.0.0.1:9443 \
  --public-url https://localhost:9443
```

## Create an enrollment token

Create a tenant-bound, agent-bound token:

```bash
go run ./cmd/ntagentshield-ca token \
  --state-dir ./gateway-state \
  --tenant tenant-01 \
  --agent server-web-01 \
  --ttl 15m
```

The plaintext token appears once in standard output. The file `enrollment-tokens.json` stores its SHA-256 hash, tenant binding, expiry and issuance result. Transfer the plaintext token through an approved secret channel.

Do not place enrollment tokens in tickets, source repositories, shell history, monitoring labels or process arguments. Humanity has already built enough accidental credential directories.

## Enroll an endpoint

The enrollment CLI reads the token from an environment variable so it does not appear in process arguments:

```bash
export NTAGENTSHIELD_ENROLLMENT_TOKEN='<one-time-token>'

go run ./cmd/ntagentshield-enroll \
  --endpoint https://localhost:9443 \
  --agent-id server-web-01 \
  --tenant tenant-01 \
  --state-dir ./endpoint-state \
  --bootstrap-ca ./gateway-state/ca.crt.pem \
  --server-name localhost
```

The command writes:

```text
endpoint-state/
├── identity.key.pem
├── identity.crt.pem
├── ca.crt.pem
└── enrollment.json
```

`enrollment.json` contains identity, certificate serial, expiry, SPIFFE URI, control-plane URL and CA fingerprint. It never contains the enrollment token or private key.

## Send a test evidence batch

```bash
go run ./cmd/ntagentshield-send \
  --state-dir ./endpoint-state \
  --endpoint https://localhost:9443 \
  --server-name localhost \
  --file ./examples/events/web-worker-shell.json \
  --type event \
  --sequence 1
```

The response contains the gateway receipt and batch hash. Use that hash as `--previous-hash` for sequence 2.

This command is a protocol and deployment diagnostic. It is not the production forwarder. The durable endpoint outbox, retry scheduler, queue quotas and journal-to-batch bridge are deliberately assigned to the next transport milestone rather than hidden behind a demo command.

## Gateway state

The gateway persists:

```text
gateway-state/
├── enrollment-tokens.json
├── gateway-sequences.json
└── accepted-evidence.jsonl
```

`gateway-sequences.json` tracks the last accepted sequence/hash for each tenant+agent and carries a payload hash. `accepted-evidence.jsonl` is append-only evidence input for the future multi-tenant control-plane ingestion service.

The append occurs before sequence-state replacement. If the process or disk fails after append but before state commit, a retry may append the same deterministic batch again. Downstream storage must deduplicate by tenant, agent, sequence and payload hash. This is explicit at-least-once delivery, not magical exactly-once marketing.

## Current limitations

### CA key protection

The development gateway stores the root CA private key in a mode-0600 PEM file. On Windows, Unix mode bits do not replace a restrictive ACL. Production deployment must apply OS-native ACLs and should use an offline root plus an online intermediate protected by a KMS, HSM or managed private CA.

### Single gateway writer

The token and sequence stores use atomic local files and in-process locks. They are suitable for one gateway process, test environments and the initial prototype. Active-active gateways require a transactional shared database with unique constraints and serializable token consumption.

### Renewal and revocation

This milestone issues short-lived client certificates but does not yet implement automatic renewal, CRL/OCSP distribution, emergency revocation or certificate rotation policy. Those belong with fleet identity lifecycle and signed policy distribution.

### Durable endpoint outbox

Enrollment and the mTLS protocol are implemented, but the agent runtime is not yet bridged to a durable transport outbox. Local evidence remains authoritative in the hash-chained journal. The next milestone will batch persisted records, enforce disk quotas, retry with backoff and acknowledge only exact gateway receipts.

### Control-plane ingestion

The gateway currently writes accepted batches to a local append-only JSONL file. It does not yet insert directly into the Python multi-tenant control plane. The later ingestion bridge must preserve the certificate-derived tenant identity and must never trust tenant headers supplied by an endpoint or reverse proxy without cryptographic binding.
