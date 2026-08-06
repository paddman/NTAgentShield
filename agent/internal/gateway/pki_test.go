package gateway

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
)

func TestInitializePKIAndIssueClientCertificate(t *testing.T) {
	directory := t.TempDir()
	now := time.Unix(1700000000, 0).UTC()
	paths, err := InitializePKI(PKIOptions{
		StateDir:   directory,
		DNSNames:   []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		Now:        now,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.RootPrivateKey, paths.ServerPrivateKey} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("private key permissions are too broad: %s %o", path, info.Mode().Perm())
		}
	}
	pkiState, err := LoadPKI(directory)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, err := x509.ParseCertificate(pkiState.ServerTLS.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(pkiState.RootCertificate)
	if _, err := serverCertificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: "localhost", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now}); err != nil {
		t.Fatalf("verify gateway certificate: %v", err)
	}

	endpointKey, _, err := enrollment.EnsurePrivateKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := enrollment.CreateCSR(endpointKey, "agent-01")
	if err != nil {
		t.Fatal(err)
	}
	block, remaining := pem.Decode(csrPEM)
	if block == nil || len(bytes.TrimSpace(remaining)) != 0 {
		t.Fatal("endpoint CSR PEM is malformed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, certificate, err := pkiState.IssueClientCertificate(csr, "tenant-01", "agent-01", 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificatePEM) == 0 {
		t.Fatal("issued certificate PEM is empty")
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		t.Fatalf("verify issued client certificate: %v", err)
	}
	tenantID, agentID, err := enrollment.ParseSPIFFEIdentity(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if tenantID != "tenant-01" || agentID != "agent-01" {
		t.Fatalf("unexpected issued identity tenant=%s agent=%s", tenantID, agentID)
	}
	if err := publicKeysEqual(certificate.PublicKey, &endpointKey.PublicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializePKI(PKIOptions{StateDir: directory, DNSNames: []string{"localhost"}, Now: now}); err == nil {
		t.Fatal("PKI initialization overwrote existing keys")
	}
}
