$ErrorActionPreference = "Stop"
$Version = if ($env:VERSION) { $env:VERSION } else { (Get-Content VERSION -Raw).Trim() }
$Commit = if ($env:COMMIT) { $env:COMMIT } else { (git rev-parse --short HEAD 2>$null) }
if (-not $Commit) { $Commit = "unknown" }
$Date = if ($env:DATE) { $env:DATE } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
$Package = "github.com/paddman/NTAgentShield/internal/buildinfo"
$LdFlags = "-s -w -X $Package.Version=$Version -X $Package.Commit=$Commit -X $Package.Date=$Date"

New-Item -ItemType Directory -Force -Path dist | Out-Null
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -trimpath -ldflags $LdFlags -o dist/ntagentshield-agent-windows-amd64.exe ./cmd/ntagentshield-agent
go build -trimpath -ldflags $LdFlags -o dist/ntagentshieldctl-windows-amd64.exe ./cmd/ntagentshieldctl
$env:GOOS = "linux"; $env:GOARCH = "amd64"
go build -trimpath -ldflags $LdFlags -o dist/ntagentshield-agent-linux-amd64 ./cmd/ntagentshield-agent
go build -trimpath -ldflags $LdFlags -o dist/ntagentshieldctl-linux-amd64 ./cmd/ntagentshieldctl
Remove-Item Env:GOOS
Remove-Item Env:GOARCH
