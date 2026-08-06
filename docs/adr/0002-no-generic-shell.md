# ADR 0002: Do not expose a generic shell tool

Status: Accepted

## Context

A Cline-style agent can be useful for investigation, but a security agent often runs with elevated access and consumes attacker-controlled telemetry. A generic command string cannot provide bounded scope, reliable validation, or predictable rollback.

## Decision

Do not register `shell.exec`, `cmd.exec`, or `powershell.exec`. Explicitly deny those names in policy. Add capabilities only as typed tools with canonical risk, resource scope, dry-run, approval, audit, verification, and rollback.

## Consequences

- Some tasks require more implementation work than sending a command string.
- Security review can reason about each action’s exact side effects.
- Prompt injection cannot directly become arbitrary OS execution.
- Operator workflows remain slower than unsafe automation, which is an acceptable trade.
