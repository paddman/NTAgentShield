package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistPolicySigningKeyPinsTrustRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-signing.pub")
	first := policyPublicKeyPEM(t)
	if err := persistPolicySigningKey(path, first); err != nil {
		t.Fatal(err)
	}
	if err := persistPolicySigningKey(path, first); err != nil {
		t.Fatalf("same trust root must be idempotent: %v", err)
	}
	second := policyPublicKeyPEM(t)
	if err := persistPolicySigningKey(path, second); err == nil || !strings.Contains(err.Error(), "explicit trust rotation") {
		t.Fatalf("expected silent trust-root rotation rejection, got %v", err)
	}
}

func TestPersistPolicySigningKeyRejectsInvalidRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-signing.pub")
	if err := persistPolicySigningKey(path, "not-a-public-key"); err == nil {
		t.Fatal("expected invalid policy trust root to be rejected")
	}
}

func policyPublicKeyPEM(t *testing.T) string {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
