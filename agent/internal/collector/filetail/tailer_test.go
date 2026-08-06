package filetail

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/model"
)

func TestTailerReadsOnlyCompleteLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte("first\npartial"), 0o600); err != nil {
		t.Fatal(err)
	}
	tailer, err := New(config.Source{ID: "test", Path: path, Format: "raw", Trust: model.TrustUntrustedTelemetry, FromStart: true, MaxBatch: 100})
	if err != nil {
		t.Fatal(err)
	}
	events, errs := tailer.Poll()
	if len(errs) != 0 || len(events) != 1 || events[0].Message != "first" {
		t.Fatalf("unexpected first poll: events=%+v errors=%+v", events, errs)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString("-line\n")
	_ = file.Close()
	events, errs = tailer.Poll()
	if len(errs) != 0 || len(events) != 1 || events[0].Message != "partial-line" {
		t.Fatalf("unexpected second poll: events=%+v errors=%+v", events, errs)
	}
}
