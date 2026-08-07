package central

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/model"
)

func TestRegisterHeartbeatAndIngest(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "enrollment.token")
	if err := os.WriteFile(tokenPath, []byte("enrollment-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	apiKeyPath := filepath.Join(t.TempDir(), "central-api.key")
	var authenticated int
	var ingested ingestBatch
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agents/register" {
			var request registrationRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode registration: %v", err)
			}
			if request.EnrollmentToken != "enrollment-secret" || request.AgentID != "agent_test" {
				t.Fatalf("unexpected registration request: %#v", request)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accepted":true,"agentApiKey":"agent-api-secret"}`))
			return
		}
		if r.Header.Get("X-NTShield-Api-Key") != "agent-api-secret" {
			t.Errorf("missing Central API key")
		}
		authenticated++
		if r.URL.Path == "/api/v1/ingest" {
			if err := json.NewDecoder(r.Body).Decode(&ingested); err != nil {
				t.Fatalf("decode ingest: %v", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	defer server.Close()

	client, err := New(config.Central{
		URL:                 server.URL,
		EnrollmentTokenFile: tokenPath,
		APIKeyFile:          apiKeyPath,
		QueueSize:           10,
		MaxBatch:            10,
	}, "agent_test", "tenant_test", "host-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Register(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(apiKeyPath); err != nil || strings.TrimSpace(string(got)) != "agent-api-secret" {
		t.Fatalf("Central API key was not persisted: %q, %v", got, err)
	}
	if err := client.sendHeartbeat(context.Background(), HeartbeatStatus{Status: "running"}); err != nil {
		t.Fatal(err)
	}
	event := model.Event{
		AgentID:  "agent_test",
		Kind:     "web.request",
		Message:  "test event",
		Asset:    model.Asset{Hostname: "host-test"},
		Network:  model.NetworkContext{SourceIP: "192.0.2.10"},
		Severity: model.SeverityMedium,
	}
	event.Prepare()
	finding := model.NewFinding(event, "TEST-001", "Test finding", "Test description", "test", model.SeverityHigh, 90)
	if err := client.sendBatch(context.Background(), []queuedEvent{{event: event, findings: []model.Finding{finding}}}); err != nil {
		t.Fatal(err)
	}
	if authenticated != 2 {
		t.Fatalf("expected authenticated heartbeat and ingest requests, got %d", authenticated)
	}
	if len(ingested.SecurityEvents) != 1 || len(ingested.Alerts) != 1 {
		t.Fatalf("unexpected ingest payload: %#v", ingested)
	}
	if ingested.SecurityEvents[0].SourceIP != "192.0.2.10" || ingested.Alerts[0].Severity != 3 {
		t.Fatalf("event/finding mapping was not preserved: %#v %#v", ingested.SecurityEvents[0], ingested.Alerts[0])
	}
}
