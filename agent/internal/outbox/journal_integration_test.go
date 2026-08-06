package outbox

import (
	"path/filepath"
	"testing"

	"github.com/paddman/NTAgentShield/internal/store"
)

func TestReadJournalWrittenByEvidenceStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.journal.jsonl")
	journal, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Append("event", map[string]interface{}{"id": "evt-real", "kind": "process.start"}); err != nil {
		_ = journal.Close()
		t.Fatal(err)
	}
	if _, err := journal.Append("finding", map[string]interface{}{"id": "finding-real", "severity": "high"}); err != nil {
		_ = journal.Close()
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadJournal(path, 0, 10, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Sequence != 1 || records[1].Sequence != 2 {
		t.Fatalf("unexpected records exported from evidence journal: %#v", records)
	}
	items, err := RecordsToItems(records)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Type != "event" || items[0].ID != "evt-real" || items[1].Type != "finding" || items[1].ID != "finding-real" {
		t.Fatalf("unexpected transport items: %#v", items)
	}
}
