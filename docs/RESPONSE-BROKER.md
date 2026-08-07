# Signed Response Broker

NTAgentShield response actions use a deliberately narrow control path. The response channel is not a remote shell and does not let LLM output execute commands directly.

## Trust chain

1. Agent enrollment establishes the Agent Ed25519 identity and mTLS client certificate.
2. Signed policy distribution establishes the deterministic local action policy.
3. The Response Broker has its own independent Ed25519 signing key.
4. The Agent fetches the response signing public key over its authenticated mTLS channel and pins it in `response-signing.pub`.
5. Silent response-signer replacement is rejected. Trust-root rotation is an explicit operator procedure.

Initialize the response signing root locally on the Control Plane:

```bash
ntshield init-response-key
```

Do not copy the response private key to Agents.

## Operator workflow

Create a proposal:

```bash
ntshield response-create \
  --tenant tenant-a \
  --agent agent-a \
  --tool process.terminate \
  --args '{"pid":4242}' \
  --reason 'confirmed malicious process' \
  --by soc-proposer \
  --incident inc-123
```

Approve the exact proposal:

```bash
ntshield response-approve --id rsp_xxx --by soc-approver
```

Inspect audit state:

```bash
ntshield responses --tenant tenant-a --agent agent-a
```

Write-side response operations remain local CLI operations. There is intentionally no unauthenticated or generic remote response-management API.

## Delivery and execution

The Agent polls `GET /v1/agent/responses` over mTLS and signs the GET request with its persistent Agent identity key. The Control Plane returns a short-lived Ed25519-signed lease only for an approved action scoped to that exact Tenant and Agent.

Before execution the Agent verifies:

- response signer
- payload SHA-256
- strict JSON schema
- Tenant and Agent scope
- approval metadata
- action expiry and lease expiry
- local registered tool risk
- current signed local policy

The signed lease is converted to a local `ActionRequest`. The Agent calculates the policy action digest itself and creates a local approval object only after the broker signature has been verified. The normal deterministic policy engine still has final authority.

## Replay and crash semantics

Response delivery is at-least-once, while state-changing execution is guarded against duplicate execution.

Before executing an action, the Agent persists a signed replay-ledger entry with state `started`. After execution it persists the terminal result before attempting the HTTP ACK.

This gives the following behavior:

- ACK lost after execution: the terminal result is resent; the action is not executed again.
- Agent restart after terminal result: the stored result is resent; the action is not executed again.
- Same action ID with a different local action digest: rejected as a replay conflict.
- Agent crash after `started` but before a terminal result: execution is **not retried**. The action becomes indeterminate and the Agent reports failure rather than risking duplicate containment.
- Local replay-ledger tampering: startup verification fails because the ledger is signed by the Agent identity key.

This is intentionally fail-closed. Perfect distributed exactly-once side effects do not exist merely because someone wrote the words on a diagram.

## Implemented response tool

### `process.terminate`

Current containment execution supports one exact PID:

```json
{"pid": 4242}
```

Safety constraints:

- PID must be greater than 4.
- NTAgentShield refuses to terminate its own process.
- process names, wildcard matching and shell commands are not accepted.
- the signed policy must allow the containment action and the signed lease must carry operator approval.

`host.isolate`, `file.quarantine`, and `firewall.block` remain reserved broker action names but are rejected by the Agent until dedicated typed implementations are added. They are not mapped to a shell fallback.

## Result ACK

The Agent sends the terminal result to:

```text
POST /v1/agent/responses/{action_id}/result
```

The exact JSON body is signed with the Agent Ed25519 identity key. The Control Plane verifies the Agent enrollment state, signature, Tenant/Agent identity, action ID and terminal status before recording the result.

## Operational limits

- response signer rotation is manual
- response polling currently runs every five seconds when secure transport is enabled
- current real containment tool is `process.terminate`
- host isolation, firewall block and file quarantine require separate typed platform implementations
- remote admin RBAC/audit/approval APIs are not part of this slice
