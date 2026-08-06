# Security Policy

Please do not disclose suspected vulnerabilities in a public issue when they could expose tenant data, bypass isolation, execute code, tamper with evidence, or trigger unauthorized response actions.

Provide a private report to the repository owner with:

- affected commit or release
- deployment assumptions
- reproduction steps using non-sensitive sample data
- impact and tenant-boundary implications
- suggested mitigation, if known

Do not include real credentials, customer logs, private IP inventories, malware samples containing live infrastructure, or personal data in a report.

The following are treated as high priority:

- cross-tenant data access
- authentication or enrollment bypass
- arbitrary code execution in agent, parser, API or hunt service
- prompt injection that escapes read-only tool boundaries
- unauthorized containment execution
- evidence deletion or audit tampering
- rule or model supply-chain compromise
