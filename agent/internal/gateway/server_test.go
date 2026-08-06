package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
	"github.com/paddman/NTAgentShield/internal/transport"
)

func TestEnrollmentAndMutualTLSEvidenceFlow(t *testing.T) {
	serverState := t.TempDir()
	if _, err := InitializePKI(PKIOptions{
		StateDir:   serverState,
		DNSNames:   []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}); err != nil {
		t.Fatal(err)
	}
	tokenStore, err := OpenTokenStore(serverState)
	if err != nil {
		t.Fatal(err)
	}
	createdToken, err := tokenStore.Create("tenant-01", "agent-01", 15*time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{
		StateDir:            serverState,
		Listen:              "127.0.0.1:0",
		PublicURL:           "https://127.0.0.1",
		ClientCertificateTTL: 24 * time.Hour,
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	testServer := httptest.NewUnstartedServer(server.Handler())
	testServer.TLS = server.TLSConfig()
	testServer.StartTLS()
	defer testServer.Close()

	clientState := t.TempDir()
	metadata, err := enrollment.Enroll(context.Background(), enrollment.ClientOptions{
		Endpoint:         testServer.URL,
		EnrollmentToken: createdToken.EnrollmentToken,
		AgentID:          "agent-01",
		ExpectedTenantID: "tenant-01",
		StateDir:         clientState,
		BootstrapCAPath:  filepath.Join(serverState, rootCertificateFile),
		Timeout:          10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.TenantID != "tenant-01" || metadata.AgentID != "agent-01" || metadata.SPIFFEID == "" {
		t.Fatalf("unexpected enrollment metadata: %#v", metadata)
	}
	certificateBeforeRetry, err := os.ReadFile(enrollment.Paths(clientState).Certificate)
	if err != nil {
		t.Fatal(err)
	}
	retryMetadata, err := enrollment.Enroll(context.Background(), enrollment.ClientOptions{
		Endpoint:         testServer.URL,
		EnrollmentToken: createdToken.EnrollmentToken,
		AgentID:          "agent-01",
		ExpectedTenantID: "tenant-01",
		StateDir:         clientState,
		BootstrapCAPath:  filepath.Join(serverState, rootCertificateFile),
		Timeout:          10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	certificateAfterRetry, err := os.ReadFile(enrollment.Paths(clientState).Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if retryMetadata.CertificateSerial != metadata.CertificateSerial || !bytes.Equal(certificateBeforeRetry, certificateAfterRetry) {
		t.Fatal("idempotent enrollment retry changed the endpoint certificate")
	}

	transportClient, err := transport.NewClient(transport.ClientOptions{
		StateDir: clientState,
		Endpoint: testServer.URL,
		Timeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transportClient.Close()
	batch := transport.Batch{
		TenantID:  "tenant-01",
		AgentID:   "agent-01",
		Sequence:  1,
		CreatedAt: time.Now().UTC(),
		Items: []transport.EvidenceItem{{
			Type:    "event",
			ID:      "evt-01",
			Payload: json.RawMessage(`{"kind":"asset.listener_added","port":3389}`),
		}},
	}
	if err := batch.Seal(); err != nil {
		t.Fatal(err)
	}
	receipt, err := transportClient.Send(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "accepted" || receipt.PayloadSHA256 != batch.PayloadSHA256 {
		t.Fatalf("unexpected accepted receipt: %#v", receipt)
	}
	duplicate, err := transportClient.Send(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.Status != "duplicate" {
		t.Fatalf("retry was not deduplicated: %#v", duplicate)
	}
	fork := batch
	fork.Items = []transport.EvidenceItem{{Type: "event", ID: "evt-fork", Payload: json.RawMessage(`{"kind":"process.tamper"}`)}}
	fork.PayloadSHA256 = ""
	if err := fork.Seal(); err != nil {
		t.Fatal(err)
	}
	if _, err := transportClient.Send(context.Background(), fork); err == nil || !strings.Contains(err.Error(), "HTTP 409") {
		t.Fatalf("sequence fork did not return a conflict: %v", err)
	}

	withoutCertificate := trustedHTTPClient(t, filepath.Join(serverState, rootCertificateFile), nil)
	defer withoutCertificate.CloseIdleConnections()
	content, _ := json.Marshal(batch)
	request, _ := http.NewRequest(http.MethodPost, testServer.URL+"/v1/agent/events", bytes.NewReader(content))
	request.Header.Set("Content-Type", "application/json")
	response, err := withoutCertificate.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("evidence endpoint accepted a request without mTLS: HTTP %d", response.StatusCode)
	}
}

func trustedHTTPClient(t *testing.T, caPath string, certificate *tls.Certificate) *http.Transport {
	t.Helper()
	caContent, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caContent) {
		t.Fatal("test CA is invalid")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	if certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*certificate}
	}
	return &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}
}
