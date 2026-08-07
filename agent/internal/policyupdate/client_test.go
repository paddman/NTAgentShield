package policyupdate

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestClientFetchesPolicyOverMutualTLSWithSignedRequest(t *testing.T) {
	files, clientKey, serverCertificate, clientPool := policyTestPKI(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("expected verified policy client certificate")
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/v1/agent/policy" {
			http.Error(w, "unexpected route", http.StatusNotFound)
			return
		}
		agentID := r.Header.Get("X-NTShield-Agent-ID")
		tenantID := r.Header.Get("X-NTShield-Tenant-ID")
		timestamp := r.Header.Get("X-NTShield-Timestamp")
		if agentID != "agent-a" || tenantID != "tenant-a" {
			http.Error(w, "identity", http.StatusForbidden)
			return
		}
		if _, err := strconv.ParseInt(timestamp, 10, 64); err != nil {
			http.Error(w, "timestamp", http.StatusUnauthorized)
			return
		}
		signature, err := base64.StdEncoding.DecodeString(r.Header.Get("X-NTShield-Signature"))
		if err != nil || !ed25519.Verify(
			clientKey.Public().(ed25519.PublicKey),
			RequestMessage(agentID, tenantID, timestamp),
			signature,
		) {
			http.Error(w, "signature", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(Bundle{
			PayloadB64:   "e30=",
			SignatureB64: "c2ln",
			SHA256:       "policy-digest",
		})
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
	}
	server.StartTLS()
	defer server.Close()

	client, err := NewClient(ClientOptions{
		Endpoint: server.URL + "/v1/agent/policy",
		AgentID:  "agent-a",
		TenantID: "tenant-a",
		CertFile: files.clientCert,
		KeyFile:  files.clientKey,
		CAFile:   files.caCert,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := client.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bundle == nil || bundle.SHA256 != "policy-digest" || bundle.PayloadB64 != "e30=" {
		t.Fatalf("unexpected policy bundle: %+v", bundle)
	}
}

func TestClientHandlesNoPolicyAsNoUpdate(t *testing.T) {
	files, _, serverCertificate, clientPool := policyTestPKI(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
	}
	server.StartTLS()
	defer server.Close()

	client, err := NewClient(ClientOptions{
		Endpoint: server.URL + "/v1/agent/policy",
		AgentID:  "agent-a",
		TenantID: "tenant-a",
		CertFile: files.clientCert,
		KeyFile:  files.clientKey,
		CAFile:   files.caCert,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := client.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bundle != nil {
		t.Fatalf("expected no policy update, got %+v", bundle)
	}
}

type policyPKIFiles struct {
	caCert     string
	clientCert string
	clientKey  string
}

func policyTestPKI(t *testing.T) (policyPKIFiles, ed25519.PrivateKey, tls.Certificate, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().UTC()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "policy-test-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(
		rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}

	clientPublic, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject: pkix.Name{
			CommonName:         "agent-a",
			OrganizationalUnit: []string{"tenant-a"},
		},
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(
		rand.Reader, clientTemplate, caCert, clientPublic, caKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(
		clientCertPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		clientKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER}),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	clientPool := x509.NewCertPool()
	clientPool.AddCert(caCert)
	return policyPKIFiles{
		caCert:     caPath,
		clientCert: clientCertPath,
		clientKey:  clientKeyPath,
	}, clientKey, serverPair, clientPool
}
