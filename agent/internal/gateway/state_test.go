package gateway

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/transport"
)

func TestBatchStoreSequenceReplayAndForkProtection(t *testing.T) {
	directory := t.TempDir()
	store, err := OpenBatchStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(3000, 0).UTC()
	first := testBatch(t, 1, "", `{"kind":"process.start"}`, now)
	receipt, err := store.Accept(first, "100", now)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "accepted" || receipt.Sequence != 1 {
		t.Fatalf("unexpected first receipt: %#v", receipt)
	}
	duplicate, err := store.Accept(first, "100", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.Status != "duplicate" {
		t.Fatalf("identical retry was not deduplicated: %#v", duplicate)
	}
	fork := testBatch(t, 1, "", `{"kind":"process.tamper"}`, now)
	if _, err := store.Accept(fork, "100", now); !errors.Is(err, ErrSequenceFork) {
		t.Fatalf("sequence fork was not rejected: %v", err)
	}
	gap := testBatch(t, 3, first.PayloadSHA256, `{"kind":"network.connect"}`, now)
	if _, err := store.Accept(gap, "100", now); !errors.Is(err, ErrSequenceGap) {
		t.Fatalf("sequence gap was not rejected: %v", err)
	}
	wrongPrevious := testBatch(t, 2, fork.PayloadSHA256, `{"kind":"network.connect"}`, now)
	if _, err := store.Accept(wrongPrevious, "100", now); !errors.Is(err, ErrPreviousHash) {
		t.Fatalf("previous-hash fork was not rejected: %v", err)
	}
	second := testBatch(t, 2, first.PayloadSHA256, `{"kind":"network.connect"}`, now.Add(time.Second))
	if _, err := store.Accept(second, "100", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	reloaded, err := OpenBatchStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	reloadedDuplicate, err := reloaded.Accept(second, "100", now.Add(2*time.Second))
	if err != nil || reloadedDuplicate.Status != "duplicate" {
		t.Fatalf("persisted sequence state did not deduplicate retry: receipt=%#v err=%v", reloadedDuplicate, err)
	}
}

func testBatch(t *testing.T, sequence uint64, previousHash, payload string, createdAt time.Time) transport.Batch {
	t.Helper()
	batch := transport.Batch{
		Version:      transport.BatchProtocolVersion,
		TenantID:     "tenant-01",
		AgentID:      "agent-01",
		Sequence:     sequence,
		PreviousHash: previousHash,
		CreatedAt:    createdAt,
		Items: []transport.EvidenceItem{{
			Type:    "event",
			ID:      "evt-test",
			Payload: json.RawMessage(payload),
		}},
	}
	if err := batch.Seal(); err != nil {
		t.Fatal(err)
	}
	return batch
}
