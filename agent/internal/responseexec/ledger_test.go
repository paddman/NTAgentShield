package responseexec

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paddman/NTAgentShield/internal/identity"
)

func TestLedgerPersistsCompletedResultAndRejectsDigestConflict(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "response-ledger.json")
	ledger, err := OpenLedger(path, identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, replay, err := ledger.Begin("rsp-1", "digest-a"); err != nil || replay {
		t.Fatalf("unexpected begin: replay=%v err=%v", replay, err)
	}
	result := []byte(`{"status":"succeeded"}`)
	if err := ledger.Complete("rsp-1", "digest-a", result); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenLedger(path, identityPath)
	if err != nil {
		t.Fatal(err)
	}
	stored, replay, err := restarted.Begin("rsp-1", "digest-a")
	if err != nil || !replay {
		t.Fatalf("durable replay failed: replay=%v stored=%s err=%v", replay, stored, err)
	}
	assertJSONStatus(t, stored, "succeeded")
	if _, _, err := restarted.Begin("rsp-1", "digest-b"); err == nil || !strings.Contains(err.Error(), "different digest") {
		t.Fatalf("expected action digest conflict, got %v", err)
	}
}

func TestLedgerStartedStateFailsClosedAfterRestart(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "response-ledger.json")
	ledger, err := OpenLedger(path, identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Begin("rsp-crash", "digest-crash"); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenLedger(path, identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.Begin("rsp-crash", "digest-crash"); !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("expected indeterminate fail-closed state, got %v", err)
	}
	result := []byte(`{"status":"failed","error":"indeterminate"}`)
	if err := restarted.Complete("rsp-crash", "digest-crash", result); err != nil {
		t.Fatal(err)
	}
	stored, replay, err := restarted.Begin("rsp-crash", "digest-crash")
	if err != nil || !replay {
		t.Fatalf("indeterminate terminal result was not durable: replay=%v stored=%s err=%v", replay, stored, err)
	}
	assertJSONStatus(t, stored, "failed")
}

func TestLedgerDetectsLocalTampering(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "response-ledger.json")
	ledger, err := OpenLedger(path, identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Begin("rsp-tamper", "digest-original"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content = []byte(strings.Replace(string(content), "digest-original", "digest-attacker", 1))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLedger(path, identityPath); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("expected tamper rejection, got %v", err)
	}
}

func assertJSONStatus(t *testing.T, content []byte, expected string) {
	t.Helper()
	var payload map[string]interface{}
	if err := json.Unmarshal(content, &payload); err != nil {
		t.Fatalf("decode durable result: %v; content=%s", err, content)
	}
	if payload["status"] != expected {
		t.Fatalf("unexpected durable result status: got=%v want=%s content=%s", payload["status"], expected, content)
	}
}
