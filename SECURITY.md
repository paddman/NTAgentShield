# Security policy

Report vulnerabilities privately to the repository owner. Do not place live customer logs,
credentials, exploit payloads, personal data, or production indicators in a public issue.

NTAgentShield treats telemetry as untrusted input. The Qwen analyst receives a bounded evidence
bundle, cannot execute tools, and its output is rejected if it references event IDs that do not
exist. Destructive response actions are outside this MVP and must later pass an explicit policy
engine and human approval.
