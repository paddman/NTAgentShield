# Contributing

## Development setup

Use Go 1.23 or later.

```bash
gofmt -w $(find . -name '*.go' -type f)
go test ./...
go vet ./...
go build ./cmd/ntagentshield-agent ./cmd/ntagentshieldctl
```

## Pull-request requirements

- Keep the agent dependency surface small.
- Add tests for parsers, rules, policy decisions, and security boundaries.
- Do not log or commit real credentials, customer logs, malware, or personal data.
- Treat every new collector field as attacker-controlled unless cryptographically proven otherwise.
- Document false-positive expectations for new detections.
- Update schemas and docs when event or policy structures change.
- Avoid generic command execution. A narrowly typed tool is required instead.

## Detection contribution format

A detection should define:

- stable rule ID;
- title and category;
- severity and confidence;
- evidence fields used;
- likely false positives;
- safe read-only investigation steps;
- MITRE ATT&CK/ATLAS mapping when applicable;
- unit tests for positive and negative cases.

## Code style

Use standard `gofmt`. Prefer standard-library implementations when they are secure and maintainable. External dependencies require a clear operational reason and supply-chain review.
