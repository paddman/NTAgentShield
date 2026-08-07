# Signed Policy Distribution

NTAgentShield distributes endpoint policy as a signed, monotonic, tenant-bound document. The goal is not merely to encrypt policy transport. The Agent must be able to prove who signed a policy, whether the policy is intended for that Tenant/Agent, and whether an apparently valid update is actually an older policy being replayed.

## Trust roots

Policy signing uses its own Ed25519 key pair. It is deliberately separate from:

- the enrollment bootstrap token secret
- the enrollment certificate authority
- the Agent identity private key

Create the policy signing key once on the Control Plane:

```bash
ntshield init-policy-key
```

The private key remains on the Control Plane. The public key is returned during Agent enrollment/certificate renewal and pinned by the Agent at:

```text
<data_dir>/policy-signing.pub
```

If a different public key later appears during normal enrollment renewal, the Agent rejects it. Policy signer rotation therefore requires an explicit trust-rotation procedure instead of silently replacing the root of trust.

## Publishing a policy

Publishing is intentionally a local operator action. There is no remote policy-write endpoint yet because state-changing fleet administration requires tenant-aware admin authentication, RBAC, audit and approval controls.

Example:

```bash
ntshield publish-policy \
  --tenant demo-tenant \
  --epoch 12 \
  --policy agent/policies/default-policy.json \
  --ttl-hours 720
```

Target selected Agents instead of an entire Tenant:

```bash
ntshield publish-policy \
  --tenant demo-tenant \
  --epoch 13 \
  --policy agent/policies/default-policy.json \
  --agent agent_a \
  --agent agent_b
```

List published metadata:

```bash
ntshield policies
ntshield policies --tenant demo-tenant
```

The private signing key and raw Agent private keys are never returned by these commands.

## Signed bundle

The Control Plane signs the exact UTF-8 policy envelope bytes and transports those bytes as Base64. This avoids relying on two programming languages to serialize semantically identical JSON into byte-for-byte identical output.

The signed envelope contains:

```text
schema      = ntshield-policy/v1
epoch       = monotonic rollback counter
version     = policy document version
tenant_id   = required Tenant scope
agent_ids   = ["*"] or explicit Agent IDs
issued_at   = signed issue time
expires_at  = signed expiry time
policy      = actual deterministic Agent policy
```

The API response contains:

```text
payload_b64
signature_b64
sha256
```

The SHA-256 value is not the trust decision by itself. The Agent verifies the Ed25519 signature over the exact payload bytes using the pinned policy signing public key.

## Agent pull authentication

The Agent derives the policy endpoint from its existing telemetry Control Plane host:

```text
GET /v1/agent/policy
```

The request uses the same enrolled mTLS identity as telemetry and includes:

```text
X-NTShield-Agent-ID
X-NTShield-Tenant-ID
X-NTShield-Timestamp
X-NTShield-Signature
```

The Agent signs this exact request message:

```text
GET
/v1/agent/policy
<unix timestamp>
<tenant id>
<agent id>
```

The Control Plane rejects inactive/revoked Agents, invalid signatures and timestamps outside a five-minute window. A valid request with no applicable policy returns HTTP 204.

## Rollback protection

`epoch` is independent from the human-readable policy `version` and is the authoritative rollback counter.

The Agent accepts:

- an epoch greater than the currently applied epoch
- the same epoch only when the signed bundle digest is identical, making retry idempotent

The Agent rejects:

- any lower epoch
- the same epoch with a different digest
- an expired bundle
- a future-issued bundle outside the allowed clock skew
- another Tenant's policy
- a policy whose Agent scope does not include the local Agent
- an invalid signer or payload digest

After applying a policy the Agent stores `policy-state.json` containing the applied epoch and bundle/policy digests. That state is signed with the Agent's persistent Ed25519 identity key. On restart the Agent verifies both the state signature and the active policy digest. Editing the policy or reducing the stored epoch therefore causes updater initialization to fail rather than silently accepting a rollback.

## Last-known-good semantics

A failed fetch, bad signature, wrong scope, expired policy or rollback attempt does not replace the active policy. The previous verified policy remains in place.

Policy installation uses a temporary file and backup/restore sequence so Windows and Unix do not need identical overwrite semantics. Once a signed rollback state exists, startup fails closed if the protected policy file no longer matches that state.

## Current limits

- Policy signer key rotation is intentionally manual; there is no online root-rotation protocol yet.
- The Agent checks for policy updates every five minutes when the pinned trust root is present.
- Policy publication is local CLI only; remote fleet administration waits for proper admin RBAC/audit controls.
- This mechanism distributes deterministic policy only. It does not create a remote generic shell or allow LLM output to bypass the policy engine.
- Signed software/update distribution is a separate future trust chain and should not reuse the policy signing key by accident merely because humans enjoy reusing secrets until incident response becomes educational.
