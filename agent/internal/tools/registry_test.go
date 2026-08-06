package tools

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
	"github.com/paddman/NTAgentShield/internal/policy"
)

func TestFileToolRejectsPathEscape(t *testing.T) {
	allowed := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	tool, err := NewFileSHA256([]string{allowed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tool.Execute(context.Background(), map[string]interface{}{"path": outsideFile}); err == nil {
		t.Fatal("expected path escape to be rejected")
	}
}

func TestRegistryUsesCanonicalToolRisk(t *testing.T) {
	allowed := t.TempDir()
	path := filepath.Join(allowed, "sample.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := policy.New(policy.Default())
	registry := NewRegistry(engine)
	tool, err := NewFileSHA256([]string{allowed})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(tool); err != nil {
		t.Fatal(err)
	}
	request := model.ActionRequest{
		Tool:         "file.sha256",
		Args:         map[string]interface{}{"path": path},
		Risk:         model.RiskDestructive,
		Mode:         model.ModeObserve,
		TriggerTrust: model.TrustUntrustedTelemetry,
		RequestedAt:  time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Minute),
	}
	result, decision, err := registry.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || result.Tool != "file.sha256" {
		t.Fatalf("safe tool should execute using canonical risk: %+v", decision)
	}
}
