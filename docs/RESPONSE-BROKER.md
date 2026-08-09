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

Write-side response operations remain authenticated Control Plane operations. There is intentionally no unauthenticated or generic remote response-management API.

## Central MCP

Central can use the optional MCP server for the same audited workflow:

```bash
pip install -e ".[mcp]"
ntshield-mcp
```

ตัวอย่างการผูกกับ MCP host บนเครื่องเดียวกัน:

```json
{
  "mcpServers": {
    "ntagentshield-central": {
      "command": "ntshield-mcp",
      "env": {"NTSHIELD_DATABASE_PATH": "C:\\ProgramData\\NTAgentShield\\ntshield.db"}
    }
  }
}
```

The stdio MCP server exposes `firewall_port_propose`, `approve_response_action`, and
`get_response_action`. `firewall_port_propose` accepts only `open`/`close`, TCP/UDP,
inbound/outbound, and one port from 1 through 65535. It creates a `proposed` action;
it does not approve or execute the action. Central must call the approval tool after
its operator/condition workflow authorizes the exact proposal. The enrolled Agent
then verifies the signed lease and local policy before executing it.

Security boundary: this MCP transport is stdio and does not open an HTTP listener.
Run it only as the trusted Central service account and keep the MCP host behind
Central authentication/RBAC. `approved_by` is an audit identity, not proof of
authentication; the Broker also rejects self-approval, and the Agent remains the
final policy and signature enforcement point.

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

`host.isolate`, `file.quarantine`, `firewall.block`, and `firewall.port` are typed
containment actions. `firewall.port` manages only the exact Agent-owned Windows
Firewall rule recorded in its signed state; it never deletes an arbitrary rule.

## Result ACK

The Agent sends the terminal result to:

```text
POST /v1/agent/responses/{action_id}/result
```

The exact JSON body is signed with the Agent Ed25519 identity key. The Control Plane verifies the Agent enrollment state, signature, Tenant/Agent identity, action ID and terminal status before recording the result.

## Operational limits

- response signer rotation is manual
- response polling currently runs every five seconds when secure transport is enabled
- current typed containment tools include process termination, host isolation, IP blocking, file quarantine, and Windows port rules
- Linux currently rejects `firewall.port` as unsupported rather than changing an unowned firewall ruleset
- remote admin RBAC/audit/approval APIs are not part of this slice
