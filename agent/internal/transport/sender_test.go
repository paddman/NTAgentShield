package transport

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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
	"github.com/paddman/NTAgentShield/internal/model"
)

func TestSenderDeliversSignedEventOverMutualTLS(t *testing.T) {
	files, clientKey, serverCertificate, clientPool, _, _ := testPKI(t)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("expected verified client certificate")
			http.Error(w, "missing client certificate", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		signature, err := base64.StdEncoding.DecodeString(r.Header.Get("X-NTShield-Signature"))
		if err != nil {
			t.Error(err)
			http.Error(w, "signature", http.StatusUnauthorized)
			return
		}
		if !ed25519.Verify(clientKey.Public().(ed25519.PublicKey), body, signature) {
			t.Error("telemetry signature did not verify")
			http.Error(w, "signature", http.StatusUnauthorized)
			return
		}
		var event ControlPlaneEvent
		if err := json.Unmarshal(body, &event); err != nil {
			t.Error(err)
			http.Error(w, "json", http.StatusBadRequest)
			return
		}
		if event.AgentID != "agent-a" || event.TenantID != "tenant-a" {
			t.Errorf("unexpected signed identity: %#v", event)
			http.Error(w, "identity", http.StatusForbidden)
			return
		}
		if r.Header.Get("X-NTShield-Agent-ID") != event.AgentID || r.Header.Get("X-NTShield-Tenant-ID") != event.TenantID {
			t.Error("authentication headers do not match signed body")
			http.Error(w, "headers", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
	}
	server.StartTLS()
	defer server.Close()

	outbox, err := OpenOutbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{
		ID:        "evt-mtls-1",
		Timestamp: time.Now().UTC(),
		AgentID:   "agent-a",
		TenantID:  "tenant-a",
		Kind:      "process.start",
		Asset:     model.Asset{Hostname: "host-a"},
		Process:   model.ProcessContext{Image: "/usr/bin/bash", ParentImage: "/usr/sbin/nginx"},
	}
	if err := outbox.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	sender, err := NewSender(outbox, SenderOptions{
		Endpoint: server.URL,
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
	result, err := sender.Flush(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if result.Sent != 1 || result.DeadLetter != 0 {
		t.Fatalf("unexpected flush result: %+v", result)
	}
	stats, err := outbox.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pending != 0 {
		t.Fatalf("event was not acknowledged after verified delivery: %+v", stats)
	}
}

func TestSenderRenewsCertificateBeforeTelemetryFlush(t *testing.T) {
	files, clientKey, serverCertificate, clientPool, caKey, caCertificate := testPKI(t)
	caPEM, err := os.ReadFile(files.caCert)
	if err != nil {
		t.Fatal(err)
	}
	var renewalSeen bool
	var eventSawRenewedCertificate bool

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/agent/certificate/renew", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].SerialNumber.Int64() != 3 {
			t.Error("renewal must authenticate with the current client certificate")
			http.Error(w, "current certificate required", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			http.Error(w, "body", http.StatusBadRequest)
			return
		}
		signature, err := base64.StdEncoding.DecodeString(r.Header.Get("X-NTShield-Signature"))
		if err != nil || !ed25519.Verify(clientKey.Public().(ed25519.PublicKey), body, signature) {
			t.Error("renewal request signature did not verify")
			http.Error(w, "signature", http.StatusUnauthorized)
			return
		}
		var request enrollment.RenewalRequest
		if err := json.Unmarshal(body, &request); err != nil {
			t.Error(err)
			http.Error(w, "json", http.StatusBadRequest)
			return
		}
		csrBlock, _ := pem.Decode([]byte(request.CSRPEM))
		if csrBlock == nil {
			t.Error("renewal CSR is missing")
			http.Error(w, "csr", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			t.Error("renewal CSR signature is invalid")
			http.Error(w, "csr", http.StatusBadRequest)
			return
		}
		requestedKey, ok := csr.PublicKey.(ed25519.PublicKey)
		if !ok || !requestedKey.Equal(clientKey.Public()) {
			t.Error("renewal CSR did not preserve the Agent identity key")
			http.Error(w, "identity", http.StatusForbidden)
			return
		}
		now := time.Now().UTC()
		newTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(4),
			Subject:      pkix.Name{CommonName: "agent-a", OrganizationalUnit: []string{"tenant-a"}},
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		newDER, err := x509.CreateCertificate(rand.Reader, newTemplate, caCertificate, requestedKey, caKey)
		if err != nil {
			t.Error(err)
			http.Error(w, "cert", http.StatusInternalServerError)
			return
		}
		response := enrollment.Response{
			AgentID:          "agent-a",
			TenantID:         "tenant-a",
			CertificatePEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newDER})),
			CACertificatePEM: string(caPEM),
			ExpiresAt:        newTemplate.NotAfter,
		}
		renewalSeen = true
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("/v1/agent/events", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("telemetry request is missing mTLS identity")
			http.Error(w, "certificate", http.StatusUnauthorized)
			return
		}
		if r.TLS.PeerCertificates[0].SerialNumber.Int64() != 4 {
			t.Errorf("telemetry should use renewed certificate; serial=%s", r.TLS.PeerCertificates[0].SerialNumber)
			http.Error(w, "old certificate", http.StatusUnauthorized)
			return
		}
		eventSawRenewedCertificate = true
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
	}
	server.StartTLS()
	defer server.Close()

	outbox, err := OpenOutbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.Enqueue(model.Event{
		ID:        "evt-after-renewal",
		Timestamp: time.Now().UTC(),
		AgentID:   "agent-a",
		TenantID:  "tenant-a",
		Kind:      "auth.success",
	}); err != nil {
		t.Fatal(err)
	}
	sender, err := NewSender(outbox, SenderOptions{
		Endpoint:           server.URL + "/v1/agent/events",
		AgentID:            "agent-a",
		TenantID:           "tenant-a",
		CertFile:           files.clientCert,
		KeyFile:            files.clientKey,
		CAFile:             files.caCert,
		Timeout:            5 * time.Second,
		AutoRenew:          true,
		RenewalEndpoint:    server.URL + "/v1/agent/certificate/renew",
		RenewBefore:        2 * time.Hour,
		RenewCheckInterval: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sender.Flush(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if !renewalSeen || !eventSawRenewedCertificate || !result.CertificateRenewed || result.Sent != 1 {
		t.Fatalf("automatic renewal path did not complete: result=%+v renewal_seen=%t event_new_cert=%t", result, renewalSeen, eventSawRenewedCertificate)
	}
	renewedContent, err := os.ReadFile(files.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	renewedBlock, _ := pem.Decode(renewedContent)
	if renewedBlock == nil {
		t.Fatal("renewed client certificate file is invalid")
	}
	renewedCertificate, err := x509.ParseCertificate(renewedBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if renewedCertificate.SerialNumber.Int64() != 4 {
		t.Fatalf("client certificate file was not rotated: serial=%s", renewedCertificate.SerialNumber)
	}
}

type testPKIFiles struct {
	caCert     string
	clientCert string
	clientKey  string
}

func testPKI(t *testing.T) (testPKIFiles, ed25519.PrivateKey, tls.Certificate, *x509.CertPool, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().UTC()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(48 * time.Hour),
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
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(48 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
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
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "agent-a", OrganizationalUnit: []string{"tenant-a"}},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, clientPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(clientCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	clientPool := x509.NewCertPool()
	clientPool.AddCert(caCert)
	return testPKIFiles{caCert: caPath, clientCert: clientCertPath, clientKey: clientKeyPath}, clientKey, serverPair, clientPool, caKey, caCert
}
