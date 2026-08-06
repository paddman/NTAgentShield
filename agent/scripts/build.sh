#!/usr/bin/env sh
set -eu

VERSION="${VERSION:-$(cat VERSION)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
DATE="${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
PKG="github.com/paddman/NTAgentShield/internal/buildinfo"
LDFLAGS="-s -w -X ${PKG}.Version=${VERSION} -X ${PKG}.Commit=${COMMIT} -X ${PKG}.Date=${DATE}"

mkdir -p dist
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o dist/ntagentshield-agent-linux-amd64 ./cmd/ntagentshield-agent
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o dist/ntagentshieldctl-linux-amd64 ./cmd/ntagentshieldctl
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o dist/ntagentshield-agent-windows-amd64.exe ./cmd/ntagentshield-agent
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o dist/ntagentshieldctl-windows-amd64.exe ./cmd/ntagentshieldctl
