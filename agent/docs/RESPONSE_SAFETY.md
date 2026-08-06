# Response Safety

## Risk classes

| Risk | Examples | Foundation behavior |
|---|---|---|
| Observe | host info, file metadata/hash, bounded file lines | may auto-allow by policy |
| Contain | isolate host, block IP, suspend process | approval required; adapters not implemented |
| Modify | change config, temporary WAF rule, disable account | approval required; adapters not implemented |
| Destructive | delete file, wipe data, irreversible kill chain | denied by foundation policy |

## Required action lifecycle

Every future state-changing tool must implement:

1. Typed input schema.
2. Canonical risk defined by the tool.
3. Resource scope and allowlist.
4. Preconditions and expected current state.
5. Dry-run output.
6. Exact-action digest.
7. Role and tenant authorization.
8. Approval or signed pre-policy.
9. Timeout and action budget.
10. Evidence snapshot before execution.
11. Idempotent execution where possible.
12. Outcome verification.
13. Audit append.
14. Rollback or explicit irreversibility notice.

## Approval binding

The foundation digest includes:

- tool name;
- full argument object;
- reason;
- canonical risk;
- trigger trust.

Changing any of these invalidates the approval. Approvals expire and require a named approver.

## Untrusted-trigger rule

Untrusted telemetry may justify a finding and a proposed plan. It cannot directly trigger a state-changing tool. An operator or signed deterministic incident policy must independently authorize the action.

## No generic shell

A generic shell cannot provide bounded scope, predictable side effects, reliable rollback, or meaningful schema validation. It is therefore excluded. New capabilities must be implemented as narrow tools such as:

```text
host.isolate(duration, reason)
process.suspend(pid, expected_hash)
file.quarantine(path, expected_hash)
firewall.block(direction, protocol, address, port, duration)
service.stop(name, expected_binary_hash)
config.apply_patch(path, expected_hash, patch, rollback_checkpoint)
```

## Automatic response

Automatic response should begin with evidence-preservation actions, not aggressive containment. Candidate low-risk actions include increasing local telemetry, capturing a process tree, hashing referenced files, and creating a forensic checkpoint. Even these require resource limits and signed policy.
