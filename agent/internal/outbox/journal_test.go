package outbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadJournalAndConvertEvidenceItems(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	content := strings.Join([]string{
		journalLine(1, "event", `{"id":"evt-1","kind":"process.start"}`, "a"),
		journalLine(2, "finding", `{"id":"finding-1","severity":"high"}`, "b"),
		journalLine(3, "agent.start", `{"status":"started"}`, "c"),
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := ReadJournal(path, 1, 10, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Sequence != 2 || records[1].Sequence != 3 {
		t.Fatalf("unexpected exported records: %#v", records)
	}
	items, err := RecordsToItems(records)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Type != "finding" || items[0].ID != "finding-1" {
		t.Fatalf("unexpected finding item: %#v", items[0])
	}
	if items[1].Type != "audit" || !strings.HasPrefix(items[1].ID, "journal:3:") {
		t.Fatalf("unexpected audit item: %#v", items[1])
	}
}

func TestReadJournalRejectsSequenceGapAndInvalidPayload(t *testing.T) {
	directory := t.TempDir()
	gapPath := filepath.Join(directory, "gap.jsonl")
	gap := journalLine(1, "event", `{"id":"one"}`, "a") + "\n" + journalLine(3, "event", `{"id":"three"}`, "b") + "\n"
	if err := os.WriteFile(gapPath, []byte(gap), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadJournal(gapPath, 0, 10, 1024*1024); err == nil || !strings.Contains(err.Error(), "sequence discontinuity") {
		t.Fatalf("journal sequence gap was not rejected: %v", err)
	}
	invalidPath := filepath.Join(directory, "invalid.jsonl")
	invalid := `{"sequence":1,"type":"event","payload":null,"hash":"` + strings.Repeat("a", 64) + `"}`
	if err := os.WriteFile(invalidPath, []byte(invalid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadJournal(invalidPath, 0, 10, 1024*1024); err == nil {
		t.Fatal("null journal payload was accepted")
	}
}

func journalLine(sequence uint64, recordType, payload, hashCharacter string) string {
	value := map[string]interface{}{
		"sequence":  sequence,
		"timestamp": "2026-01-01T00:00:00Z",
		"type":      recordType,
		"payload":   json.RawMessage(payload),
		"hash":      strings.Repeat(hashCharacter, 64),
	}
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
