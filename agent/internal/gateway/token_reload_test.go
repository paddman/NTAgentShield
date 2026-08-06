package gateway

import (
	"strings"
	"testing"
	"time"
)

func TestTokenStoreReloadsTokensCreatedByAnotherProcess(t *testing.T) {
	directory := t.TempDir()
	gatewayStore, err := OpenTokenStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	adminStore, err := OpenTokenStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	created, err := adminStore.Create("tenant-live", "agent-live", 15*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := gatewayStore.Redeem(created.EnrollmentToken, "agent-live", strings.Repeat("d", 64), now.Add(time.Second), func(tenantID string) (IssuedIdentity, error) {
		return IssuedIdentity{CertificatePEM: "certificate", CertificateSerial: "999", ExpiresAt: now.Add(time.Hour)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Entry.TenantID != "tenant-live" || issued.Entry.IssuedAgentID != "agent-live" {
		t.Fatalf("live token reload returned wrong binding: %#v", issued)
	}
}
