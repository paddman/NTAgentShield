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
