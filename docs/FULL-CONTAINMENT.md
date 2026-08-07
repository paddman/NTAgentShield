# Full EDR/XDR Containment

This layer extends the signed Response Broker with reversible, typed containment actions for Windows and Linux. Every state-changing action still requires the existing Control Plane proposal/approval flow, a short-lived Ed25519-signed lease, enrolled Agent mTLS identity, local signed policy evaluation, and the crash-safe replay ledger.

There is no generic shell or arbitrary command transport. Response tools reject unknown arguments instead of silently accepting command-like fields that are outside the typed action schema.

## Containment matrix

| Broker tool | Operation | Windows | Linux | Notes |
| --- | --- | --- | --- | --- |
| `process.terminate` | terminate | yes | yes | exact integer PID only; refuses PID <= 4 and Agent self-termination |
| `host.isolate` | `isolate` | Windows Firewall | nftables | preserves HTTPS Control Plane path and DNS |
| `host.isolate` | `release` | restore exported firewall policy | delete dedicated isolation table | reversible |
| `firewall.block` | `block` | Windows Firewall | nftables | one exact IPv4/IPv6 address, both directions |
| `firewall.block` | `unblock` | Windows Firewall | nftables | removes only Agent-signed NTAgentShield-owned state |
| `file.quarantine` | `quarantine` | yes | yes | allowlisted regular file only; optional expected SHA-256 |
| `file.quarantine` | `restore` | yes | yes | signed quarantine manifest; symlink-safe and no-overwrite |

The broker catalog intentionally keeps the original three action names. Reversal is expressed as a signed `operation` argument, so the Control Plane does not need a wider remote command vocabulary. Because arguments are part of the exact action digest, an approval for `isolate` cannot be replayed as `release`, and an approval for one IP/path cannot be reused for another.

## Host isolation

### Linux

Linux isolation uses a dedicated `inet ntshield_isolation` nftables table with input/output base chains. It allows:

- loopback
- established/related traffic
- the resolved Control Plane IP address(es) and HTTPS port
- DNS TCP/UDP 53 so a hostname Control Plane endpoint can reconnect
- DHCP client renewal traffic

Everything else is dropped by the dedicated isolation chains. Release deletes only the NTAgentShield isolation table and does not flush or replace the customer's existing nftables ruleset.

If the nftables table exists without a valid Agent-signed isolation state file, release fails closed rather than deleting an unknown administrator-created table.

### Windows

Before isolation the Agent exports the current Windows Firewall policy to the Agent data directory. It then creates fixed allow rules for the resolved Control Plane endpoint and DNS and changes all profiles to `blockinbound,blockoutbound`.

The backup SHA-256 and path are recorded in an Agent-signed containment state. Release verifies that signed state and the backup digest before importing the original Windows Firewall policy. A modified backup is refused. A firewall backup that exists without its signed state is also refused instead of being imported blindly.

## Firewall IP containment

`firewall.block` accepts one exact `remote_ip`. CIDR ranges, hostnames, wildcards, ports, command strings, and rule fragments are rejected.

Linux maintains a dedicated `inet ntshield_block` table with IPv4/IPv6 sets plus an Agent-signed ownership marker. If a table named `ntshield_block` already exists without that signed marker, the Agent refuses to adopt or modify it.

Windows creates a unique `NTAgentShield-Block-*` rule identity for each managed IP block and stores the exact rule name and remote IP in an Agent-signed ownership state. Reapplying a block may delete/recreate only the rule named by that verified state. Unblock with no signed ownership state is a no-op and never searches for or deletes a merely similar administrator rule.

## File quarantine

Quarantine is restricted by the existing Agent path allowlist and only accepts regular files.

The Agent:

1. opens the source file
2. copies the exact opened file into a private quarantine temporary file while calculating SHA-256
3. optionally verifies `expected_sha256`
4. verifies the source did not change during the copy
5. commits the quarantine object inside the Agent data directory
6. writes an Agent-identity-signed manifest containing original path, SHA-256, size, mode and quarantine ID
7. removes the original only after the quarantine object and signed manifest are durable

Restore requires the quarantine ID, verifies strict manifest JSON and its Agent signature, verifies the quarantined bytes against the signed size/SHA-256, resolves parent symlinks before checking the allowlist, and creates the destination with exclusive-create semantics. An existing destination is never overwritten.

## Operator examples

Create and approve host isolation:

```bash
ntshield response-create \
  --tenant demo-tenant \
  --agent agent_123 \
  --tool host.isolate \
  --args '{"operation":"isolate"}' \
  --reason 'Contain confirmed post-exploitation activity' \
  --by soc-analyst

ntshield response-approve --id rsp_xxx --by soc-lead
```

Release the host with a new approval:

```bash
ntshield response-create \
  --tenant demo-tenant \
  --agent agent_123 \
  --tool host.isolate \
  --args '{"operation":"release"}' \
  --reason 'Incident contained and host cleared for network rejoin' \
  --by soc-analyst
```

Block/unblock one IP:

```bash
--tool firewall.block --args '{"operation":"block","remote_ip":"203.0.113.8"}'
--tool firewall.block --args '{"operation":"unblock","remote_ip":"203.0.113.8"}'
```

Quarantine/restore one file:

```bash
--tool file.quarantine --args '{"operation":"quarantine","path":"/srv/app/suspicious.bin","expected_sha256":"..."}'
--tool file.quarantine --args '{"operation":"restore","quarantine_id":"q_..."}'
```

## Fail-closed behavior

- no Agent enrollment: no containment delivery
- invalid/expired lease: rejected
- wrong Tenant/Agent: rejected
- risk mismatch: rejected
- local policy denial: rejected
- unknown action arguments: rejected
- unsupported/unregistered tool: rejected
- replay with changed action digest: rejected
- crash after action start but before terminal result: no automatic re-execution
- signed containment/quarantine state tampering: rejected
- unowned nftables table or Windows Firewall rule state: not adopted or blindly removed
- host release with unverifiable Windows Firewall backup: rejected
- file restore through a changed parent symlink or onto an existing file: rejected

Operationally, Windows Firewall and Linux nftables actions require the Agent service to run with the platform privileges needed to alter firewall state. File quarantine requires filesystem permissions for the selected allowlisted path. Host isolation deliberately keeps DNS and the resolved Control Plane HTTPS path available so the Agent can receive a separately approved release action.
