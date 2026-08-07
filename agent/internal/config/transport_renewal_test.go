package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTransportRenewalDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "renewal-config.json")
	content := `{
		"tenant_id":"tenant-a",
		"data_dir":"state",
		"poll_interval":"1s",
		"api":{"enabled":false},
		"transport":{"enabled":true,"endpoint":"https://control.example:9443/v1/agent/events"}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Transport.AutoRenew {
		t.Fatal("automatic certificate renewal should default to enabled")
	}
	if cfg.Transport.RenewalEndpoint != "https://control.example:9443/v1/agent/certificate/renew" {
		t.Fatalf("unexpected derived renewal endpoint: %s", cfg.Transport.RenewalEndpoint)
	}
	if cfg.Transport.RenewBefore != "168h" || cfg.Transport.RenewCheckInterval != "1h" {
		t.Fatalf("unexpected renewal timing defaults: %#v", cfg.Transport)
	}
}
