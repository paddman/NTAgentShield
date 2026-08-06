# Security Policy

## Supported versions

The project is in foundation development. Security fixes are applied to the latest `main` branch and the most recent tagged release.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, customer data, or a working bypass. Use GitHub private vulnerability reporting when enabled for this repository, or contact the repository owner through a private channel.

Include:

- affected version or commit;
- operating system and deployment mode;
- minimal reproduction steps;
- expected and observed security boundary;
- impact and any evidence of exploitation;
- suggested remediation when available.

Do not test against systems you do not own or have explicit authorization to assess.

## Security boundaries worth testing

Priority areas include:

- escaping typed-tool path allowlists through symlinks or path normalization;
- bypassing the untrusted-evidence action policy;
- forging or replaying an exact-action approval;
- tampering with the evidence journal without detection;
- leaking secrets through logs, findings, errors, or AI requests;
- remote exposure of the loopback API;
- prompt injection that causes an external side effect;
- parser denial-of-service or unbounded memory use;
- update or plugin signature bypasses once those features are implemented.

## Safe development

Never add a generic shell tool to the privileged agent. New state-changing tools require a threat-model update, deterministic policy, dry-run semantics, exact approval binding, bounded scope, audit records, and rollback behavior.
