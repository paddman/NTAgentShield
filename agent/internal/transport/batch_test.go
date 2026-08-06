package transport

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBatchSealAndTamperDetection(t *testing.T) {
	batch := Batch{
		TenantID:  "tenant-01",
		AgentID:   "agent-01",
		Sequence:  1,
		CreatedAt: time.Unix(1000, 0).UTC(),
		Items: []EvidenceItem{{Type: "event", ID: "evt-1", Payload: json.RawMessage(`{"kind":"process.start"}`)}},
	}
	if err := batch.Seal(); err != nil {
		t.Fatal(err)
	}
	if len(batch.PayloadSHA256) != 64 {
		t.Fatalf("unexpected batch hash %q", batch.PayloadSHA256)
	}
	originalHash := batch.PayloadSHA256
	if err := batch.Validate(); err != nil {
		t.Fatal(err)
	}
	batch.Items[0].Payload = json.RawMessage(`{"kind":"process.tamper"}`)
	if err := batch.Validate(); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tampered batch was not rejected: %v", err)
	}
	batch.Items[0].Payload = json.RawMessage(`{"kind":"process.start"}`)
	batch.PayloadSHA256 = originalHash
	if err := batch.Validate(); err != nil {
		t.Fatalf("restored batch did not validate: %v", err)
	}
}

func TestBatchSequenceAndPreviousHashRules(t *testing.T) {
	first := Batch{
		TenantID:     "tenant-01",
		AgentID:      "agent-01",
		Sequence:     1,
		PreviousHash: strings.Repeat("a", 64),
		Items:        []EvidenceItem{{Type: "event", ID: "evt-1", Payload: json.RawMessage(`{"x":1}`)}},
	}
	if err := first.Seal(); err == nil {
		t.Fatal("first batch with a previous hash was accepted")
	}
	second := Batch{
		TenantID: "tenant-01",
		AgentID:  "agent-01",
		Sequence: 2,
		Items:    []EvidenceItem{{Type: "event", ID: "evt-2", Payload: json.RawMessage(`{"x":2}`)}},
	}
	if err := second.Seal(); err == nil {
		t.Fatal("subsequent batch without a previous hash was accepted")
	}
	second.PreviousHash = strings.Repeat("b", 64)
	if err := second.Seal(); err != nil {
		t.Fatalf("valid chained batch was rejected: %v", err)
	}
}

func TestBatchRejectsUnknownEvidenceTypeAndOversizedIdentity(t *testing.T) {
	batch := Batch{
		TenantID:  "tenant-01",
		AgentID:   "agent-01",
		Sequence:  1,
		CreatedAt: time.Now().UTC(),
		Items:     []EvidenceItem{{Type: "command", ID: "run-shell", Payload: json.RawMessage(`{"command":"id"}`)}},
	}
	if err := batch.Seal(); err == nil {
		t.Fatal("unsupported evidence type was accepted")
	}
	batch.Items[0].Type = "event"
	batch.Items[0].ID = strings.Repeat("x", 257)
	if err := batch.Seal(); err == nil {
		t.Fatal("oversized evidence id was accepted")
	}
}
