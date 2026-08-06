package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
	"github.com/paddman/NTAgentShield/internal/transport"
)

func TestBuildDeliverRestartAndDuplicateReceipt(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "journal.jsonl")
	writeJournal(t, journalPath, 3)
	store := openTestStore(t, directory, journalPath, 2)
	first, err := store.BuildNext(time.Unix(1000, 0).UTC())
	if err != nil || !first.Created || first.Pending.JournalFrom != 1 || first.Pending.JournalTo != 2 {
		t.Fatalf("unexpected first build result=%#v err=%v", first, err)
	}
	second, err := store.BuildNext(time.Unix(1001, 0).UTC())
	if err != nil || !second.Created || second.Pending.Sequence != 2 || second.Pending.JournalFrom != 3 {
		t.Fatalf("unexpected second build result=%#v err=%v", second, err)
	}
	if status := store.Status(); status.PendingBatches != 2 || status.JournalCursor != 3 {
		t.Fatalf("unexpected outbox status: %#v", status)
	}
	firstSpool, _, err := loadSpool(filepath.Join(directory, "outbox", "spool", first.Pending.FileName))
	if err != nil {
		t.Fatal(err)
	}
	sender := &fakeSender{status: "accepted"}
	delivery, err := store.DeliverNext(context.Background(), sender, time.Unix(1002, 0).UTC())
	if err != nil || !delivery.Delivered || delivery.Receipt.Sequence != 1 {
		t.Fatalf("unexpected delivery result=%#v err=%v", delivery, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestStore(t, directory, journalPath, 2)
	defer reopened.Close()
	if status := reopened.Status(); status.PendingBatches != 1 || status.LastAckedSequence != 1 {
		t.Fatalf("outbox state did not survive restart: %#v", status)
	}
	duplicateSender := &fakeSender{status: "duplicate"}
	delivery, err = reopened.DeliverNext(context.Background(), duplicateSender, time.Unix(1003, 0).UTC())
	if err != nil || !delivery.Delivered || !delivery.Duplicate {
		t.Fatalf("duplicate receipt was not accepted: result=%#v err=%v", delivery, err)
	}
	if status := reopened.Status(); status.PendingBatches != 0 || status.LastAckedSequence != 2 {
		t.Fatalf("unexpected final outbox status: %#v", status)
	}
	if firstSpool.Batch.PayloadSHA256 != first.Pending.PayloadSHA256 {
		t.Fatal("spool batch changed after state commit")
	}
}

func TestReconcileRecoversOrphanAndRemovesAckedFile(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "journal.jsonl")
	writeJournal(t, journalPath, 1)
	store := openTestStore(t, directory, journalPath, 1)
	metadata := testMetadata()
	batch := transport.Batch{
		TenantID:  metadata.TenantID,
		AgentID:   metadata.AgentID,
		Sequence:  1,
		CreatedAt: time.Now().UTC(),
		Items: []transport.EvidenceItem{{Type: "event", ID: "evt-1", Payload: json.RawMessage(`{"id":"evt-1"}`)}},
	}
	if err := batch.Seal(); err != nil {
		t.Fatal(err)
	}
	spool := Spool{Version: SpoolVersion, JournalFrom: 1, JournalTo: 1, Batch: batch}
	content, _ := json.Marshal(spool)
	fileName := spoolFileName(1, batch.PayloadSHA256)
	if err := atomicWrite(filepath.Join(directory, "outbox", "spool", fileName), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	recovered := openTestStore(t, directory, journalPath, 1)
	if status := recovered.Status(); status.PendingBatches != 1 || status.JournalCursor != 1 {
		t.Fatalf("orphan spool was not recovered: %#v", status)
	}
	if _, err := recovered.DeliverNext(context.Background(), &fakeSender{status: "accepted"}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(directory, "outbox", "spool", fileName), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	cleaned := openTestStore(t, directory, journalPath, 1)
	defer cleaned.Close()
	if _, err := os.Stat(filepath.Join(directory, "outbox", "spool", fileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("acknowledged orphan spool was not removed: %v", err)
	}
}

func TestDeliveryRetryAndPermanentBlock(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "journal.jsonl")
	writeJournal(t, journalPath, 1)
	store := openTestStore(t, directory, journalPath, 1)
	defer store.Close()
	if _, err := store.BuildNext(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	retryResult, err := store.DeliverNext(context.Background(), &fakeSender{err: &transport.GatewayError{StatusCode: 503, Code: "unavailable"}}, now)
	if err == nil || !retryResult.Attempted || retryResult.Blocked {
		t.Fatalf("retryable delivery was handled incorrectly: result=%#v err=%v", retryResult, err)
	}
	status := store.Status()
	if status.NextAttemptAt.IsZero() || !status.NextAttemptAt.After(now) {
		t.Fatalf("retry backoff was not persisted: %#v", status)
	}
	permanentTime := status.NextAttemptAt.Add(time.Second)
	blockResult, err := store.DeliverNext(context.Background(), &fakeSender{err: &transport.GatewayError{StatusCode: 409, Code: "batch_sequence_fork"}}, permanentTime)
	if err == nil || !blockResult.Blocked {
		t.Fatalf("permanent delivery error did not block the batch: result=%#v err=%v", blockResult, err)
	}
	if status := store.Status(); !status.Blocked {
		t.Fatalf("blocked state was not persisted: %#v", status)
	}
	if err := store.Unblock(1); err != nil {
		t.Fatal(err)
	}
	if status := store.Status(); status.Blocked {
		t.Fatalf("manual unblock failed: %#v", status)
	}
}

func TestStateTamperAndSecondWriterAreRejected(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "journal.jsonl")
	writeJournal(t, journalPath, 1)
	store := openTestStore(t, directory, journalPath, 1)
	if _, err := Open(testConfig(directory, journalPath, 1), testMetadata()); err == nil {
		t.Fatal("second active outbox writer was accepted")
	}
	if _, err := store.BuildNext(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, "outbox", "state.json")
	content, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]interface{}
	if err := json.Unmarshal(content, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["payload_sha256"] = strings.Repeat("0", 64)
	tampered, _ := json.Marshal(envelope)
	if err := os.WriteFile(statePath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(testConfig(directory, journalPath, 1), testMetadata()); err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("tampered outbox state was not quarantined: %v", err)
	}
}

type fakeSender struct {
	status string
	err    error
}

func (s *fakeSender) Send(_ context.Context, batch transport.Batch) (transport.Receipt, error) {
	if s.err != nil {
		return transport.Receipt{}, s.err
	}
	status := s.status
	if status == "" {
		status = "accepted"
	}
	return transport.Receipt{
		Status:        status,
		TenantID:      batch.TenantID,
		AgentID:       batch.AgentID,
		Sequence:      batch.Sequence,
		PayloadSHA256: batch.PayloadSHA256,
		ReceivedAt:    time.Now().UTC(),
	}, nil
}

func openTestStore(t *testing.T, directory, journalPath string, maxItems int) *Store {
	t.Helper()
	store, err := Open(testConfig(directory, journalPath, maxItems), testMetadata())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testConfig(directory, journalPath string, maxItems int) Config {
	return Config{
		Directory:         filepath.Join(directory, "outbox"),
		JournalPath:       journalPath,
		MaxPendingBatches: 10,
		MaxSpoolBytes:     10 * 1024 * 1024,
		MaxBatchItems:     maxItems,
		MaxBatchBytes:     1024 * 1024,
		BaseBackoff:       100 * time.Millisecond,
		MaxBackoff:        time.Second,
	}
}

func testMetadata() enrollment.Metadata {
	return enrollment.Metadata{Version: enrollment.ProtocolVersion, TenantID: "tenant-01", AgentID: "agent-01"}
}

func writeJournal(t *testing.T, path string, count int) {
	t.Helper()
	lines := make([]string, 0, count)
	for sequence := 1; sequence <= count; sequence++ {
		payload := `{"id":"evt-` + strings.Repeat("x", sequence) + `","kind":"test"}`
		lines = append(lines, journalLine(uint64(sequence), "event", payload, "a"))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
