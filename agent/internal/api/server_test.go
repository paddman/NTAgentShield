package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paddman/NTAgentShield/internal/model"
)

func TestEnsureTokenCreatesStableSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.token")
	one, err := EnsureToken(path)
	if err != nil {
		t.Fatal(err)
	}
	two, err := EnsureToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if one != two || len(one) != 64 {
		t.Fatalf("unexpected token behavior: %q %q", one, two)
	}
}

func TestIngestForcesUntrustedNetworkProvenance(t *testing.T) {
	var received model.Event
	server := New("127.0.0.1:0", "01234567890123456789012345678901", func() interface{} { return map[string]string{"status": "ok"} }, func(_ context.Context, event model.Event) ([]model.Finding, error) {
		received = event
		return nil, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"kind":"process.start","trust":"operator","message":"test"}`))
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response := httptest.NewRecorder()
	server.auth(http.HandlerFunc(server.ingestHandler)).ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("unexpected status: %d body=%s", response.Code, response.Body.String())
	}
	if received.Trust != model.TrustUntrustedNetwork {
		t.Fatalf("remote event retained trusted provenance: %s", received.Trust)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
}
