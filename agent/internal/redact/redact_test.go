package redact

import (
	"strings"
	"testing"

	"github.com/paddman/NTAgentShield/internal/model"
)

func TestStringRedactsSecrets(t *testing.T) {
	input := "Authorization: Bearer abcdefghijklmnopqrstuvwxyz password=hunter2 AKIAABCDEFGHIJKLMNOP"
	output := String(input)
	for _, secret := range []string{"abcdefghijklmnopqrstuvwxyz", "hunter2", "AKIAABCDEFGHIJKLMNOP"} {
		if strings.Contains(output, secret) {
			t.Fatalf("secret %q was not redacted: %s", secret, output)
		}
	}
}

func TestStringRedactsCommandFlagsAndURICredentials(t *testing.T) {
	input := `worker --password "super-secret" --api-key abcdefghijkl mysql://dbuser:db-password@db.internal/app`
	output := String(input)
	for _, secret := range []string{"super-secret", "abcdefghijkl", "db-password"} {
		if strings.Contains(output, secret) {
			t.Fatalf("secret %q was not redacted: %s", secret, output)
		}
	}
}

func TestEventRedactsNestedAttributes(t *testing.T) {
	event := model.Event{Attributes: map[string]interface{}{
		"api_token": "top-secret",
		"nested":    map[string]interface{}{"password": "also-secret"},
	}}
	Event(&event)
	if event.Attributes["api_token"] != "[REDACTED]" {
		t.Fatalf("api token was not redacted")
	}
	nested := event.Attributes["nested"].(map[string]interface{})
	if nested["password"] != "[REDACTED]" {
		t.Fatalf("nested password was not redacted")
	}
}

func TestEventNormalizesAndRedactsNestedStructs(t *testing.T) {
	type process struct {
		CommandLine string `json:"command_line"`
		APIKey      string `json:"api_key"`
	}
	type snapshot struct {
		Processes []process `json:"processes"`
	}
	event := model.Event{Attributes: map[string]interface{}{
		"inventory": snapshot{Processes: []process{{
			CommandLine: "server --password nested-secret",
			APIKey:      "raw-key",
		}}},
	}}
	Event(&event)
	inventoryValue, ok := event.Attributes["inventory"].(map[string]interface{})
	if !ok {
		t.Fatalf("inventory struct was not normalized: %#v", event.Attributes["inventory"])
	}
	processes, ok := inventoryValue["processes"].([]interface{})
	if !ok || len(processes) != 1 {
		t.Fatalf("unexpected process inventory: %#v", inventoryValue["processes"])
	}
	entry := processes[0].(map[string]interface{})
	if strings.Contains(entry["command_line"].(string), "nested-secret") {
		t.Fatalf("nested command-line secret was not redacted: %#v", entry)
	}
	if entry["api_key"] != "[REDACTED]" {
		t.Fatalf("nested sensitive field was not redacted: %#v", entry)
	}
}
