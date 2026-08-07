package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
)

func TestFailedRenewalDoesNotConsumeCheckWindow(t *testing.T) {
	files, clientKey, serverCertificate, clientPool, caKey, caCertificate := testPKI(t)
	caPEM, err := os.ReadFile(files.caCert)
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, "temporary renewal outage", http.StatusServiceUnavailable)
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
			t.Error("renewal signature did not verify")
			http.Error(w, "signature", http.StatusUnauthorized)
			return
		}
		var request enrollment.RenewalRequest
		if err := json.Unmarshal(body, &request); err != nil {
			t.Error(err)
			http.Error(w, "json", http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(request.CSRPEM))
		if block == nil {
			t.Error("missing CSR")
			http.Error(w, "csr", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			t.Error("invalid CSR")
			http.Error(w, "csr", http.StatusBadRequest)
			return
		}
		publicKey, ok := csr.PublicKey.(ed25519.PublicKey)
		if !ok || !publicKey.Equal(clientKey.Public()) {
			t.Error("CSR changed Agent identity key")
			http.Error(w, "identity", http.StatusForbidden)
			return
		}
		now := time.Now().UTC()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(9),
			Subject:      pkix.Name{CommonName: "agent-a", OrganizationalUnit: []string{"tenant-a"}},
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, publicKey, caKey)
		if err != nil {
			t.Error(err)
			http.Error(w, "certificate", http.StatusInternalServerError)
			return
		}
		response := enrollment.Response{
			AgentID:          "agent-a",
			TenantID:         "tenant-a",
			CertificatePEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			CACertificatePEM: string(caPEM),
			ExpiresAt:        template.NotAfter,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
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
		RenewCheckInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sender.Flush(context.Background(), 1); err == nil {
		t.Fatal("expected first renewal attempt to fail")
	}
	result, err := sender.Flush(context.Background(), 1)
	if err != nil {
		t.Fatalf("expected immediate retry to renew successfully: %v", err)
	}
	if attempts != 2 || !result.CertificateRenewed {
		t.Fatalf("renewal failure consumed check window: attempts=%d result=%+v", attempts, result)
	}
}
