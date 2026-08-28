# Production operator security

NTAgentShield has two different trust planes. Agent endpoints authenticate machines using the
existing enrollment, certificate and signed-request protocol. Operator endpoints authenticate
people or workloads using a short-lived signed operator token with explicit roles and tenant IDs.
These identities are not interchangeable.

## Secure entry point

Use the production ASGI application:

```bash
uvicorn ntshield.production_app:app --host 127.0.0.1 --port 8080
```

The application returns `503 control_plane_locked` for protected routes until both independent
secrets are present:

```bash
export NTSHIELD_OPERATOR_SIGNING_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export NTSHIELD_AUDIT_HMAC_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
```

Do not reuse the enrollment, policy-signing, response-signing, database or AI API secrets.
Terminate public TLS at a hardened reverse proxy and keep the application listener private.

## Roles

| Role | Permission scope |
|---|---|
| `viewer` | Read findings and incidents |
| `analyst` | Read, analyze incidents and inspect fleet state |
| `ingester` | Submit operator/integration telemetry |
| `responder` | Propose typed response actions |
| `approver` | Approve an exact action proposed by another principal |
| `auditor` | Read and verify the audit ledger and metrics |
| `tenant_admin` | All tenant-scoped permissions |
| `platform_admin` | Cross-tenant platform administration |

Issue a short-lived token:

```bash
ntshield-operator-token \
  --subject analyst@example.org \
  --role analyst \
  --tenant customer-a \
  --ttl 3600
```

Use it as `Authorization: Bearer <token>`. Tokens have a maximum lifetime of 24 hours. Production
SSO may be added through an identity-aware proxy later, but it must produce the same authenticated
principal, role and tenant semantics at the NTAgentShield boundary.

## Tenant authorization

The middleware checks tenant IDs found in query parameters, telemetry bodies and object lookups.
An incident or response-action ID is resolved to its stored tenant before the request reaches the
handler. A caller cannot gain access by changing `tenant_id` in a URL or JSON document.

## Response approval

MCP exposes proposal and read tools only. The approval flow is:

1. A responder creates a proposal.
2. The API returns `action_digest`, a SHA-256 digest of every immutable action field.
3. A different authenticated approver reviews that exact digest.
4. The approver calls `POST /v1/operator/responses/{action_id}/approve` with the digest.
5. The existing response broker signs a short lease for the Agent only after approval.

Requester and approver identities come from signed tokens, not caller-supplied strings.

## Ingest boundary

Operator telemetry routes enforce:

- a maximum HTTP body size;
- strict top-level schemas and schema version checks;
- bounded nesting, collection size, key length and string length;
- recursive secret, authorization header, URI credential and private-key redaction;
- per-principal and per-tenant rate limits; and
- tenant authorization before behavioral learning.

Signed Agent telemetry remains byte-exact so its request signature can be verified.

## Audit ledger

The control plane records security decisions and state-changing requests in a separate SQLite WAL
ledger. Each record includes the previous record hash and an HMAC over canonical content. Use:

```text
GET /v1/operator/audit/verify
```

A failed audit append blocks protected responses when `NTSHIELD_AUDIT_FAIL_CLOSED=true`. Back up
the ledger independently and periodically anchor the latest hash in WORM or external storage.

## Network exposure

The supplied Compose file binds to `127.0.0.1`, drops Linux capabilities, enables a read-only root
filesystem and requires production secrets before startup. Put Nginx, Envoy or HAProxy in front of
it for TLS and route separation. Do not change the bind address to `0.0.0.0` merely because it makes
a demo convenient. Attackers also appreciate convenient demos.
