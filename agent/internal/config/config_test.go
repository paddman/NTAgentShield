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

func TestLoadValidatesNativeSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"poll_interval":"1s",
		"api":{"enabled":false},
		"native_sources":[
			{"id":"sysmon-operational","enabled":true,"kind":"windows_eventlog","channel":"Microsoft-Windows-Sysmon/Operational","event_ids":[1,3,11,22]},
			{"id":"system-journal","enabled":true,"kind":"journald","units":["sshd.service"],"identifiers":["sudo"]},
			{"id":"linux-audit","enabled":true,"kind":"auditd","path":"logs/audit.log"}
		]
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NativeSources) != 3 {
		t.Fatalf("expected three native sources, got %d", len(cfg.NativeSources))
	}
	if cfg.NativeSources[0].MaxBatch != 256 || cfg.NativeSources[0].CommandTimeout != "15s" {
		t.Fatalf("native defaults were not applied: %#v", cfg.NativeSources[0])
	}
	if cfg.NativeSources[2].Path != filepath.Join(dir, "logs", "audit.log") {
		t.Fatalf("audit path was not resolved: %s", cfg.NativeSources[2].Path)
	}
}

func TestLoadRejectsUnsafeNativeSourceConfiguration(t *testing.T) {
	testCases := []string{
		`{"poll_interval":"1s","api":{"enabled":false},"native_sources":[{"id":"../cursor","enabled":true,"kind":"journald","units":["sshd.service"]}]}`,
		`{"poll_interval":"1s","api":{"enabled":false},"native_sources":[{"id":"security","enabled":true,"kind":"windows_eventlog","channel":"Security\n/q:*"}]}`,
		`{"poll_interval":"1s","api":{"enabled":false},"native_sources":[{"id":"journal","enabled":true,"kind":"journald","units":["sshd.service\n--output=cat"]}]}`,
	}
	for index, content := range testCases {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("case %d: expected unsafe native source configuration to be rejected", index)
		}
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
