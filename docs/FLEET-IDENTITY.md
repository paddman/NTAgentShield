# Agent Certificate Renewal and Fleet Identity

NTAgentShield treats an enrolled endpoint as a persistent cryptographic identity, not as a hostname plus a reusable API key.

## Identity lifecycle

```text
bootstrap token
  -> local Ed25519 Agent identity key
  -> CSR
  -> ClientAuth certificate
  -> signed mTLS telemetry
  -> automatic same-key certificate renewal
  -> operator revocation or explicit re-enrollment
```

The Ed25519 Agent identity key does not rotate during normal certificate renewal. A renewal CSR must contain the same public key as the currently enrolled certificate. Changing the identity key requires a new enrollment flow.

## Automatic renewal

When telemetry transport is enabled, automatic renewal is enabled by default:

```json
{
  "transport": {
    "auto_renew": true,
    "renewal_endpoint": "https://control.example:9443/v1/agent/certificate/renew",
    "renew_before": "168h",
    "renew_check_interval": "1h"
  }
}
```

`renew_before=168h` means the Agent starts trying to renew seven days before certificate expiry. `renew_check_interval=1h` limits successful/not-yet-needed checks, but a failed renewal does not consume that window. Failed renewal therefore follows the transport retry/backoff path instead of sleeping until the certificate has already expired, which would be an admirably human scheduling strategy but a poor security design.

The renewal request uses:

- the current mTLS client certificate
- the current persistent Ed25519 identity key
- an Ed25519 signature over the exact renewal JSON body
- a CSR signed by the same identity key
- the enrolled Tenant ID and Agent ID

The Control Plane rejects renewal when the Agent is unknown, expired, revoked, signed by the wrong key, claims another tenant, or requests a CSR with a different public key.

On success the Agent atomically replaces `certs/client.crt` and reloads the client certificate for future TLS handshakes without restarting the daemon.

If the client certificate is already expired, automatic renewal cannot authenticate the mTLS session. The endpoint must use an approved bootstrap re-enrollment flow.

## Fleet identity state

The Control Plane registry tracks:

- Tenant ID
- Agent ID
- current client certificate
- first/latest enrollment time
- certificate update time
- certificate expiry
- last Control Plane receive time
- revocation time
- certificate rotation count

`last_seen_at` is Control Plane receive time, not endpoint event time. A delayed event delivered from the durable outbox therefore cannot make the Agent appear to move backwards in time.

Registry schema changes migrate the earlier enrollment table in place by adding lifecycle columns when necessary.

## Operator commands

Fleet identity administration is intentionally local to the Control Plane until a proper authenticated/authorized admin API exists.

List all enrolled identities:

```bash
ntshield agents
```

List one tenant:

```bash
ntshield agents --tenant demo-tenant
```

Revoke one Agent:

```bash
ntshield revoke-agent --tenant demo-tenant --agent agent_0123456789abcdef
```

The list output includes status, last seen time, certificate expiry, certificate SHA-256 fingerprint and rotation count. It does not print private keys.

A revoked Agent is rejected by application-level telemetry and certificate-renewal authorization even if a TLS terminator still trusts the issuing CA. Revocation is therefore effective at the NTAgentShield application boundary without pretending that an application database row magically becomes CRL/OCSP state inside every reverse proxy.

## Why there is no remote revoke endpoint yet

A network-accessible revocation endpoint is an administrative mutation. NTAgentShield does not expose one until tenant-aware admin authentication, authorization, audit logging and approval policy exist. Making `POST /revoke` available first and adding admin security later would be a remarkably efficient denial-of-service feature.

The current local CLI keeps the mutation behind Control Plane host access while the multi-tenant administrative plane is built.

## Recovery paths

### Renewal server temporarily unavailable

The Agent keeps telemetry in the durable outbox and retries certificate renewal using transport exponential backoff. A failed renewal does not consume the normal renewal-check interval.

### Agent certificate revoked

Telemetry and renewal are rejected. The operator must investigate and explicitly re-enroll the endpoint if it should return to service.

### Agent identity key lost or replaced

Same-key renewal cannot succeed. Re-enroll the endpoint and treat the identity transition as a security-significant event.

### Certificate expired before renewal

The expired certificate cannot authenticate a normal renewal session. Use bootstrap re-enrollment.

## Current revocation boundary

Application-level revocation is enforced by the enrollment registry. A direct mTLS listener or reverse proxy may still complete the TLS handshake for a revoked but cryptographically valid certificate until CA-level revocation support is configured. The NTAgentShield API rejects the request after handshake.

A later production slice should add:

1. admin RBAC and audited remote fleet actions
2. CRL/OCSP or short-lived-certificate policy appropriate to the TLS terminator
3. signed policy distribution and rollback protection
4. Agent health/fleet dashboard
5. re-enrollment/identity-change alerting
