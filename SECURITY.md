# Security policy

Report vulnerabilities privately to the repository owner. Do not place live customer logs,
credentials, exploit payloads, personal data, production indicators, certificates, signing keys,
or operator tokens in a public issue.

## Current security boundaries

- Agent enrollment, certificate renewal, policy retrieval, telemetry and response results are
  identity-bound through enrollment state, certificates and Ed25519 signatures.
- The production ASGI entry point is `ntshield.production_app:app`. It fails closed until separate
  operator-token and audit-ledger secrets are configured.
- Operator APIs use role and tenant claims. Tenant IDs supplied by a request are never treated as
  authorization by themselves.
- MCP can create typed response proposals only. Approval is deliberately absent from MCP and must
  pass through the authenticated operator API with a second principal and the exact action digest.
- Operator and response activity is recorded in an HMAC hash-chained control-plane audit ledger.
- Telemetry is untrusted input. Operator ingestion is schema-bounded, size-limited and recursively
  redacted before it reaches normalization, storage, behavioral learning or AI analysis.
- Qwen receives bounded evidence and cannot execute tools. Reports that reference nonexistent
  evidence IDs are rejected.

The development entry point `ntshield.app:app` remains available for tests and local replay. Do not
expose it as a production listener. A green CI badge is not an access-control system, despite the
industry's occasional attempts to treat it as one.
