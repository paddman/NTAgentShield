package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenStorePersistsOnlyHashAndAllowsIdempotentRetry(t *testing.T) {
	directory := t.TempDir()
	store, err := OpenTokenStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	created, err := store.Create("tenant-01", "agent-01", 15*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(directory, "enrollment-tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), created.EnrollmentToken) {
		t.Fatal("plaintext enrollment token was persisted")
	}
	if !strings.Contains(string(content), tokenHash(created.EnrollmentToken)) {
		t.Fatal("enrollment token hash was not persisted")
	}

	issueCount := 0
	issuer := func(tenantID string) (IssuedIdentity, error) {
		issueCount++
		if tenantID != "tenant-01" {
			t.Fatalf("unexpected tenant passed to issuer: %s", tenantID)
		}
		return IssuedIdentity{CertificatePEM: "certificate", CertificateSerial: "123", ExpiresAt: now.Add(24 * time.Hour)}, nil
	}
	publicKeyHash := strings.Repeat("a", 64)
	first, err := store.Redeem(created.EnrollmentToken, "agent-01", publicKeyHash, now.Add(time.Minute), issuer)
	if err != nil {
		t.Fatal(err)
	}
	if first.Reused || first.Entry.ConsumedAt == nil {
		t.Fatalf("unexpected first redemption: %#v", first)
	}
	retry, err := store.Redeem(created.EnrollmentToken, "agent-01", publicKeyHash, now.Add(2*time.Minute), issuer)
	if err != nil {
		t.Fatal(err)
	}
	if !retry.Reused || issueCount != 1 {
		t.Fatalf("idempotent retry issued another certificate: retry=%#v count=%d", retry, issueCount)
	}
	if _, err := store.Redeem(created.EnrollmentToken, "agent-01", strings.Repeat("b", 64), now.Add(3*time.Minute), issuer); err == nil {
		t.Fatal("consumed token was accepted for another public key")
	}
	if _, err := store.Redeem(created.EnrollmentToken, "agent-02", publicKeyHash, now.Add(3*time.Minute), issuer); err == nil {
		t.Fatal("agent-bound token was accepted for another agent")
	}
}

func TestTokenStoreRejectsExpiredToken(t *testing.T) {
	store, err := OpenTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000, 0).UTC()
	created, err := store.Create("tenant-01", "", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Redeem(created.EnrollmentToken, "agent-01", strings.Repeat("c", 64), now.Add(2*time.Minute), func(string) (IssuedIdentity, error) {
		return IssuedIdentity{CertificatePEM: "certificate", CertificateSerial: "123", ExpiresAt: now.Add(time.Hour)}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token was not rejected: %v", err)
	}
}
