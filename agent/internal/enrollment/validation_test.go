package enrollment

import (
	"crypto/x509"
	"net/url"
	"testing"
)

func TestValidateIdentity(t *testing.T) {
	valid := []string{"tenant-01", "agent_web.01", "A1"}
	for _, value := range valid {
		if err := ValidateIdentity("identity", value); err != nil {
			t.Fatalf("valid identity %q rejected: %v", value, err)
		}
	}
	invalid := []string{"", "../escape", "tenant/name", "has space", "-leading", string(make([]byte, 65))}
	for _, value := range invalid {
		if err := ValidateIdentity("identity", value); err == nil {
			t.Fatalf("invalid identity %q was accepted", value)
		}
	}
}

func TestSPIFFEIdentityRoundTrip(t *testing.T) {
	identityURI, err := SPIFFEURI("tenant-01", "agent.web-01")
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{URIs: []*url.URL{identityURI}}
	tenantID, agentID, err := ParseSPIFFEIdentity(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if tenantID != "tenant-01" || agentID != "agent.web-01" {
		t.Fatalf("unexpected SPIFFE identity tenant=%q agent=%q", tenantID, agentID)
	}
}

func TestParseSPIFFEIdentityRejectsWrongTrustDomain(t *testing.T) {
	identityURI, _ := url.Parse("spiffe://attacker.invalid/tenant/tenant-01/agent/agent-01")
	if _, _, err := ParseSPIFFEIdentity(&x509.Certificate{URIs: []*url.URL{identityURI}}); err == nil {
		t.Fatal("expected wrong SPIFFE trust domain to be rejected")
	}
}
