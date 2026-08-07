package policyupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/identity"
	"github.com/paddman/NTAgentShield/internal/policy"
)

func TestManagerAppliesMonotonicSignedPolicyAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustPath := writeTrustRoot(t, dir, publicKey)
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "active-policy.json")
	statePath := filepath.Join(dir, "policy-state.json")
	options := ManagerOptions{
		AgentID: "agent-a", TenantID: "tenant-a", PolicyFile: policyPath,
		TrustRootFile: trustPath, IdentityKeyFile: identityPath, StateFile: statePath,
	}
	manager, err := NewManager(options)
	if err != nil {
		t.Fatal(err)
	}
	bundle := signedBundle(t, privateKey, 2, "tenant-a", []string{"*"}, "2", 300)
	result, err := manager.Apply(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied || result.Epoch != 2 || result.Version != "2" {
		t.Fatalf("unexpected apply result: %+v", result)
	}
	active, err := policy.Load(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if active.Version != "2" {
		t.Fatalf("unexpected active policy version: %s", active.Version)
	}

	restarted, err := NewManager(options)
	if err != nil {
		t.Fatal(err)
	}
	noOp, err := restarted.Apply(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if noOp.Applied || noOp.Epoch != 2 {
		t.Fatalf("same signed bundle should be idempotent: %+v", noOp)
	}
	rollback := signedBundle(t, privateKey, 1, "tenant-a", []string{"*"}, "1", 300)
	if _, err := restarted.Apply(rollback); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("expected rollback rejection, got %v", err)
	}
}

func TestManagerRejectsSameEpochConflictAndBadSignature(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	trustPath := writeTrustRoot(t, dir, publicKey)
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(ManagerOptions{
		AgentID: "agent-a", TenantID: "tenant-a",
		PolicyFile: filepath.Join(dir, "policy.json"), TrustRootFile: trustPath,
		IdentityKeyFile: identityPath, StateFile: filepath.Join(dir, "policy-state.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	first := signedBundle(t, privateKey, 5, "tenant-a", []string{"agent-a"}, "5", 300)
	if _, err := manager.Apply(first); err != nil {
		t.Fatal(err)
	}
	conflict := signedBundle(t, privateKey, 5, "tenant-a", []string{"agent-a"}, "5", 301)
	if _, err := manager.Apply(conflict); err == nil || !strings.Contains(err.Error(), "epoch conflict") {
		t.Fatalf("expected same-epoch conflict, got %v", err)
	}
	attackerPublic, attackerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	_ = attackerPublic
	bad := signedBundle(t, attackerPrivate, 6, "tenant-a", []string{"agent-a"}, "6", 300)
	if _, err := manager.Apply(bad); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected bad signature rejection, got %v", err)
	}
}

func TestManagerRejectsWrongScopeExpiryAndLocalTampering(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	trustPath := writeTrustRoot(t, dir, publicKey)
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.json")
	statePath := filepath.Join(dir, "policy-state.json")
	options := ManagerOptions{
		AgentID: "agent-a", TenantID: "tenant-a", PolicyFile: policyPath,
		TrustRootFile: trustPath, IdentityKeyFile: identityPath, StateFile: statePath,
	}
	manager, err := NewManager(options)
	if err != nil {
		t.Fatal(err)
	}
	wrongTenant := signedBundle(t, privateKey, 1, "tenant-b", []string{"agent-a"}, "1", 300)
	if _, err := manager.Apply(wrongTenant); err == nil || !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("expected tenant rejection, got %v", err)
	}
	wrongAgent := signedBundle(t, privateKey, 1, "tenant-a", []string{"agent-b"}, "1", 300)
	if _, err := manager.Apply(wrongAgent); err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("expected Agent scope rejection, got %v", err)
	}

	valid := signedBundle(t, privateKey, 3, "tenant-a", []string{"agent-a"}, "3", 300)
	if _, err := manager.Apply(valid); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(options); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected active policy tamper rejection, got %v", err)
	}

	if _, err := manager.Apply(expiredBundle(t, privateKey, 4)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired bundle rejection, got %v", err)
	}
}

func TestManagerRejectsTamperedRollbackState(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	trustPath := writeTrustRoot(t, dir, publicKey)
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "policy-state.json")
	options := ManagerOptions{
		AgentID: "agent-a", TenantID: "tenant-a", PolicyFile: filepath.Join(dir, "policy.json"),
		TrustRootFile: trustPath, IdentityKeyFile: identityPath, StateFile: statePath,
	}
	manager, err := NewManager(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(signedBundle(t, privateKey, 9, "tenant-a", []string{"*"}, "9", 300)); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	content = []byte(strings.Replace(string(content), `"epoch": 9`, `"epoch": 1`, 1))
	if err := os.WriteFile(statePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(options); err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("expected signed state tamper rejection, got %v", err)
	}
}

func writeTrustRoot(t *testing.T, dir string, publicKey ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy-signing.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func signedBundle(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	epoch uint64,
	tenant string,
	agents []string,
	version string,
	maxTTL int,
) Bundle {
	t.Helper()
	now := time.Now().UTC()
	active := policy.Default()
	active.Version = version
	active.MaxActionTTLSeconds = maxTTL
	policyBytes, err := json.Marshal(active)
	if err != nil {
		t.Fatal(err)
	}
	payload := Payload{
		Schema: policySchema, Epoch: epoch, Version: version, TenantID: tenant,
		AgentIDs: agents, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Policy: policyBytes,
	}
	return encodeBundle(t, privateKey, payload)
}

func expiredBundle(t *testing.T, privateKey ed25519.PrivateKey, epoch uint64) Bundle {
	t.Helper()
	active := policy.Default()
	active.Version = "expired"
	policyBytes, _ := json.Marshal(active)
	now := time.Now().UTC()
	return encodeBundle(t, privateKey, Payload{
		Schema: policySchema, Epoch: epoch, Version: active.Version, TenantID: "tenant-a",
		AgentIDs: []string{"agent-a"}, IssuedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour), Policy: policyBytes,
	})
}

func encodeBundle(t *testing.T, privateKey ed25519.PrivateKey, payload Payload) Bundle {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	return Bundle{
		PayloadB64:   base64.StdEncoding.EncodeToString(encoded),
		SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, encoded)),
		SHA256:       hex.EncodeToString(sum[:]),
	}
}
