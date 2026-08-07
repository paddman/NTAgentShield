package transport

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
)

func TestMapEventPreservesHighValueContexts(t *testing.T) {
	external := "198.51.100.8"
	event := model.Event{
		ID:        "evt-map-1",
		Timestamp: time.Now().UTC(),
		AgentID:   "agent-a",
		TenantID:  "tenant-a",
		Kind:      "process.start",
		Trust:     model.TrustUntrustedTelemetry,
		Severity:  model.SeverityHigh,
		Asset: model.Asset{
			Hostname: "web-01",
			OS:       "windows",
			IPs:      []string{"10.0.0.4"},
		},
		Actor: model.Actor{
			User:      "svc-web",
			SessionID: "session-1",
		},
		Process: model.ProcessContext{
			PID:              501,
			PPID:             500,
			Image:            `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			ParentImage:      `C:\Windows\System32\inetsrv\w3wp.exe`,
			CommandLine:      "powershell.exe -nop",
			ExecutableSHA256: "abc123",
		},
		Network: model.NetworkContext{
			DestinationIP:   external,
			DestinationPort: 443,
			Protocol:        "tcp",
		},
		HTTP: model.HTTPContext{
			Method:    "POST",
			Path:      "/upload",
			Status:    200,
			RequestID: "req-1",
		},
		File: model.FileContext{
			Path:      `C:\inetpub\wwwroot\shell.aspx`,
			Operation: "create",
			SHA256:    "def456",
		},
		Provenance: model.Provenance{
			Collector: "sysmon",
		},
		Attributes: map[string]interface{}{
			"safe_key": "safe-value",
		},
	}

	mapped := MapEvent(event)
	if mapped.Asset.ID != "agent-a" || mapped.Asset.Hostname != "web-01" {
		t.Fatalf("unexpected asset mapping: %#v", mapped.Asset)
	}
	if mapped.Process.Name != "powershell.exe" || mapped.Process.ParentName != "w3wp.exe" {
		t.Fatalf("unexpected process mapping: %#v", mapped.Process)
	}
	if mapped.Network.IsExternal == nil || !*mapped.Network.IsExternal {
		t.Fatalf("expected public destination to be external: %#v", mapped.Network)
	}
	if mapped.File.Extension != ".aspx" || mapped.Web.RequestID != "req-1" {
		t.Fatalf("unexpected file/web mapping: %#v %#v", mapped.File, mapped.Web)
	}
	if mapped.SourceType != "sysmon" || mapped.Raw["safe_key"] != "safe-value" {
		t.Fatalf("unexpected provenance/raw mapping: %#v", mapped)
	}
}

func TestOutboxEnqueueIsIdempotentAndDurable(t *testing.T) {
	outbox, err := OpenOutbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{ID: "evt-durable-1", Timestamp: time.Now().UTC(), Kind: "auth.failure"}
	if err := outbox.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	stats, err := outbox.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pending != 1 {
		t.Fatalf("expected one idempotent queued event, got %+v", stats)
	}
	items, err := outbox.Peek(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Event.ID != event.ID {
		t.Fatalf("unexpected outbox item: %+v", items)
	}
	if err := outbox.Ack(items[0]); err != nil {
		t.Fatal(err)
	}
	stats, err = outbox.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pending != 0 {
		t.Fatalf("expected empty outbox after ack: %+v", stats)
	}
}

func TestOutboxMovesCorruptPayloadToDeadLetter(t *testing.T) {
	dataDir := t.TempDir()
	outbox, err := OpenOutbox(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "outbox", "pending", "corrupt.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := outbox.Peek(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("corrupt event must not be returned for delivery: %+v", items)
	}
	stats, err := outbox.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pending != 0 || stats.DeadLetter != 1 {
		t.Fatalf("expected corrupt event in dead-letter: %+v", stats)
	}
}
