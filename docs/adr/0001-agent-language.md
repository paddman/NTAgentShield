# ADR 0001: Go for the foundation agent, Rust for deep sensors

Status: Accepted

## Context

The agent must run on Windows and Linux, cross-compile simply, consume modest resources, recover predictably, and remain maintainable by a small team. Deep platform telemetry may later require eBPF, ETW, or memory-safe native components.

## Decision

Use Go for the foundation service, collectors, parsers, policy, journal, API, and CLI. Keep the runtime dependency-free where practical. Use Rust selectively for future low-level sensors or sandboxed components when it materially improves memory safety or platform access.

## Consequences

- Fast cross-platform delivery and straightforward service operation.
- One static binary for the main agent.
- Strong concurrency and standard networking support.
- Some deep Windows/Linux integrations may require cgo, system APIs, or sidecar components.
- Language choice does not replace privilege separation or policy controls.
