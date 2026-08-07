package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/paddman/NTAgentShield/internal/identity"
)

func TestFileQuarantineAndRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	_, identityPath, err := identity.Ensure(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(allowed, "sample.bin")
	content := []byte("malware-sample-for-quarantine-test")
	if err := os.WriteFile(source, content, 0o640); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	expected := hex.EncodeToString(digest[:])
	quarantine, err := NewFileQuarantine([]string{allowed}, dataDir, identityPath)
	if err != nil {
		t.Fatal(err)
	}
	resultAny, err := quarantine.Execute(context.Background(), map[string]interface{}{"path": source, "expected_sha256": expected})
	if err != nil {
		t.Fatal(err)
	}
	result := resultAny.(map[string]interface{})
	quarantineID := result["quarantine_id"].(string)
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("original should be removed after quarantine, err=%v", err)
	}
	restore, err := NewFileRestore([]string{allowed}, dataDir, identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restore.Execute(context.Background(), map[string]interface{}{"quarantine_id": quarantineID}); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(content) {
		t.Fatalf("restored content mismatch: %q", restored)
	}
}

func TestFileQuarantineRejectsHashMismatchAndOutsidePath(t *testing.T) {
	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	_, identityPath, err := identity.Ensure(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(allowed, "inside.bin")
	if err := os.WriteFile(inside, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	quarantine, err := NewFileQuarantine([]string{allowed}, dataDir, identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := quarantine.Execute(context.Background(), map[string]interface{}{"path": inside, "expected_sha256": strings.Repeat("0", 64)}); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected SHA mismatch, got %v", err)
	}
	outside := filepath.Join(dir, "outside.bin")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := quarantine.Execute(context.Background(), map[string]interface{}{"path": outside}); err == nil || !strings.Contains(err.Error(), "outside allowed roots") {
		t.Fatalf("expected outside-root rejection, got %v", err)
	}
}

func TestFileRestoreRefusesExistingTargetWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	_, identityPath, err := identity.Ensure(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(allowed, "sample.bin")
	if err := os.WriteFile(source, []byte("original quarantined content"), 0o600); err != nil {
		t.Fatal(err)
	}
	quarantine, _ := NewFileQuarantine([]string{allowed}, dataDir, identityPath)
	resultAny, err := quarantine.Execute(context.Background(), map[string]interface{}{"path": source})
	if err != nil {
		t.Fatal(err)
	}
	quarantineID := resultAny.(map[string]interface{})["quarantine_id"].(string)
	if err := os.WriteFile(source, []byte("new legitimate file"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore, _ := NewFileRestore([]string{allowed}, dataDir, identityPath)
	if _, err := restore.Execute(context.Background(), map[string]interface{}{"quarantine_id": quarantineID}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected no-overwrite rejection, got %v", err)
	}
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new legitimate file" {
		t.Fatalf("existing target was modified: %q", content)
	}
}

func TestFileRestoreRejectsParentSymlinkRedirection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation requires runner privileges not guaranteed by CI")
	}
	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed")
	nested := filepath.Join(allowed, "nested")
	outside := filepath.Join(dir, "outside")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	_, identityPath, err := identity.Ensure(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(nested, "sample.bin")
	if err := os.WriteFile(source, []byte("quarantine me"), 0o600); err != nil {
		t.Fatal(err)
	}
	quarantine, _ := NewFileQuarantine([]string{allowed}, dataDir, identityPath)
	resultAny, err := quarantine.Execute(context.Background(), map[string]interface{}{"path": source})
	if err != nil {
		t.Fatal(err)
	}
	quarantineID := resultAny.(map[string]interface{})["quarantine_id"].(string)
	if err := os.Remove(nested); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, nested); err != nil {
		t.Fatal(err)
	}
	restore, _ := NewFileRestore([]string{allowed}, dataDir, identityPath)
	if _, err := restore.Execute(context.Background(), map[string]interface{}{"quarantine_id": quarantineID}); err == nil || (!strings.Contains(err.Error(), "outside allowed roots") && !strings.Contains(err.Error(), "canonical path changed")) {
		t.Fatalf("expected parent symlink redirection rejection, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "sample.bin")); !os.IsNotExist(err) {
		t.Fatalf("restore escaped allowlist through symlink, err=%v", err)
	}
}

func TestFileRestoreRejectsTamperedManifest(t *testing.T) {
	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	_, identityPath, err := identity.Ensure(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(allowed, "sample.bin")
	if err := os.WriteFile(source, []byte("signed quarantine"), 0o600); err != nil {
		t.Fatal(err)
	}
	quarantine, _ := NewFileQuarantine([]string{allowed}, dataDir, identityPath)
	resultAny, err := quarantine.Execute(context.Background(), map[string]interface{}{"path": source})
	if err != nil {
		t.Fatal(err)
	}
	quarantineID := resultAny.(map[string]interface{})["quarantine_id"].(string)
	manifestPath := filepath.Join(dataDir, "quarantine", quarantineID+".json")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest = []byte(strings.Replace(string(manifest), "\"size\": 17", "\"size\": 18", 1))
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	restore, _ := NewFileRestore([]string{allowed}, dataDir, identityPath)
	if _, err := restore.Execute(context.Background(), map[string]interface{}{"quarantine_id": quarantineID}); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("expected signed manifest tamper rejection, got %v", err)
	}
}
