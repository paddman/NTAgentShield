package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsRemoteAPI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"poll_interval":"1s","api":{"enabled":true,"listen":"0.0.0.0:9477"}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected remote API address to be rejected")
	}
}

func TestLoadResolvesPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"data_dir":"state","poll_interval":"1s","api":{"enabled":false},"tools":{"policy_file":"policy.json","allowed_paths":["logs"]}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != filepath.Join(dir, "state") {
		t.Fatalf("unexpected data dir: %s", cfg.DataDir)
	}
	if cfg.Tools.AllowedPaths[0] != filepath.Join(dir, "logs") {
		t.Fatalf("unexpected allowed path: %s", cfg.Tools.AllowedPaths[0])
	}
}

func TestEnsureAgentIDPersists(t *testing.T) {
	dir := t.TempDir()
	first := Config{DataDir: dir}
	if err := EnsureAgentID(&first); err != nil {
		t.Fatal(err)
	}
	second := Config{DataDir: dir}
	if err := EnsureAgentID(&second); err != nil {
		t.Fatal(err)
	}
	if first.AgentID == "" || first.AgentID != second.AgentID {
		t.Fatalf("agent identity was not stable: %q %q", first.AgentID, second.AgentID)
	}
}
