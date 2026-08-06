# Threat model

## Protected assets

- Customer telemetry and incident data
- Agent enrollment identity
- Detection rules and allowlists
- Qwen system prompt and evidence boundary
- Response policy and approval records

## Main threats and controls

| Threat | Control in MVP | Required before production |
|---|---|---|
| Prompt injection inside logs | Evidence is marked untrusted; no tools; output evidence validation | model gateway isolation and adversarial regression suite |
| Hallucinated evidence | Unknown `event_id` rejects the report | signed evidence bundles and report provenance |
| Cross-tenant access | tenant ID on all records | authentication, authorization, RLS and tenant-scoped keys |
| Agent impersonation | none in demo | enrollment token, mTLS, key rotation and revocation |
| Rule tampering | repository review | signed rule packs and deployment approvals |
| Event flood / cost attack | request batch limits | quotas, backpressure, sampling and queue isolation |
| Destructive model action | no response tools | separate policy engine and dual approval |
| Sensitive data leakage | local model and truncated raw field | field-level redaction, retention and PDPA controls |
