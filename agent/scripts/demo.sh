#!/usr/bin/env sh
set -eu

go run ./cmd/ntagentshieldctl scan-log --format iis_w3c --file examples/logs/iis.log
go run ./cmd/ntagentshieldctl scan-event --file examples/events/web-worker-shell.json
go run ./cmd/ntagentshieldctl scan-code --path examples/code
go run ./cmd/ntagentshieldctl policy-check --policy policies/default-policy.json --tool host.isolate --risk contain --trust untrusted_telemetry --mode auto
