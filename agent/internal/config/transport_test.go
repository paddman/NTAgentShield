package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTransportRequiresHTTPS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"tenant_id":"tenant-a",
		"poll_interval":"1s",
		"api":{"enabled":false},
		"transport":{"enabled":true,"endpoint":"http://control.example/v1/agent/events"}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected plaintext telemetry transport to be rejected")
	}
}

func TestTransportDefaultsResolveInsideDataDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"tenant_id":"tenant-a",
		"data_dir":"state",
		"poll_interval":"1s",
		"api":{"enabled":false},
		"transport":{"enabled":true,"endpoint":"https://control.example/v1/agent/events"}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(dir, "state")
	if cfg.Transport.CertFile != filepath.Join(dataDir, "certs", "client.crt") {
		t.Fatalf("unexpected transport cert path: %s", cfg.Transport.CertFile)
	}
	if cfg.Transport.KeyFile != filepath.Join(dataDir, "agent-identity.key") {
		t.Fatalf("unexpected transport key path: %s", cfg.Transport.KeyFile)
	}
	if cfg.Transport.CAFile != filepath.Join(dataDir, "certs", "ca.crt") {
		t.Fatalf("unexpected transport CA path: %s", cfg.Transport.CAFile)
	}
	if cfg.Transport.BatchSize != 100 || cfg.Transport.PendingWarn != 10000 {
		t.Fatalf("transport defaults were not applied: %#v", cfg.Transport)
	}
}
