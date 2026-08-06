package main

import (
	"context"
	"io"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
	"github.com/paddman/NTAgentShield/internal/outbox"
	"github.com/paddman/NTAgentShield/internal/transport"
)

func TestRunCycleBuildsAndDrainsOutbox(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "journal.jsonl")
	content := strings.Join([]string{
		`{"sequence":1,"timestamp":"2026-01-01T00:00:00Z","type":"event","payload":{"id":"evt-1"},"hash":"` + strings.Repeat("a", 64) + `"}`,
		`{"sequence":2,"timestamp":"2026-01-01T00:00:01Z","type":"finding","payload":{"id":"finding-1"},"hash":"` + strings.Repeat("b", 64) + `"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(journalPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := outbox.Open(outbox.Config{
		Directory:         filepath.Join(directory, "outbox"),
		JournalPath:       journalPath,
		MaxPendingBatches: 10,
		MaxSpoolBytes:     10 * 1024 * 1024,
		MaxBatchItems:     1,
		MaxBatchBytes:     1024 * 1024,
		BaseBackoff:       100 * time.Millisecond,
		MaxBackoff:        time.Second,
	}, enrollment.Metadata{Version: enrollment.ProtocolVersion, TenantID: "tenant-01", AgentID: "agent-01"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sender := &cycleSender{}
	if err := runCycle(context.Background(), store, sender, log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	}
	if len(sender.sequences) != 2 || sender.sequences[0] != 1 || sender.sequences[1] != 2 {
		t.Fatalf("forwarder did not deliver ordered batches: %#v", sender.sequences)
	}
	status := store.Status()
	if status.PendingBatches != 0 || status.LastAckedSequence != 2 || status.JournalCursor != 2 {
		t.Fatalf("unexpected final forwarder status: %#v", status)
	}
}

type cycleSender struct {
	sequences []uint64
}

func (s *cycleSender) Send(_ context.Context, batch transport.Batch) (transport.Receipt, error) {
	s.sequences = append(s.sequences, batch.Sequence)
	return transport.Receipt{
		Status:        "accepted",
		TenantID:      batch.TenantID,
		AgentID:       batch.AgentID,
		Sequence:      batch.Sequence,
		PayloadSHA256: batch.PayloadSHA256,
		ReceivedAt:    time.Now().UTC(),
	}, nil
}
