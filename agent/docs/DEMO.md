# Demo Runbook

## 1. Verify the build

```bash
go test ./...
go vet ./...
go build ./cmd/ntagentshield-agent ./cmd/ntagentshieldctl
```

## 2. Scan IIS evidence

```bash
go run ./cmd/ntagentshieldctl scan-log --format iis_w3c --file examples/logs/iis.log
```

Expected rule categories include authentication burst, path traversal, and prompt injection embedded in a User-Agent field.

## 3. Detect an exploit behavior chain

```bash
go run ./cmd/ntagentshieldctl scan-event --file examples/events/web-worker-shell.json
```

Expected rules include `NTS-WEB-001` and `NTS-WIN-001` because an IIS worker spawned encoded PowerShell.

## 4. Scan vulnerable code

```bash
go run ./cmd/ntagentshieldctl scan-code --path examples/code
```

Expected findings include hard-coded secret, PHP dynamic evaluation chain, SQL concatenation, shell execution, unsafe deserialization, disabled TLS verification, and remote script piping.

## 5. Prove the policy boundary

```bash
go run ./cmd/ntagentshieldctl policy-check \
  --policy policies/default-policy.json \
  --tool host.isolate \
  --risk contain \
  --trust untrusted_telemetry \
  --mode auto
```

Expected result: denied because untrusted evidence cannot directly change the host.

## 6. Run the agent and verify evidence

```bash
go run ./cmd/ntagentshield-agent --config config/agent.example.json
```

Stop it with Ctrl+C, then run:

```bash
go run ./cmd/ntagentshieldctl verify-store --path data/evidence.journal.jsonl
```

## 7. Optional local AI analysis

Start a local OpenAI-compatible model endpoint, update `config/agent.local-ai.json`, then run:

```bash
go run ./cmd/ntagentshieldctl ai-analyze \
  --config config/agent.local-ai.json \
  --event examples/events/web-worker-shell.json
```

Show that the result reports `read_only: true` and `tools_exposed: false`.
