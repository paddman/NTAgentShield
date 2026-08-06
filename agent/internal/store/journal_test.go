package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJournalAppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.journal.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Append("event", map[string]string{"message": "hello"}); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Append("finding", map[string]string{"rule": "test"}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	sequence, hash, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if sequence != 2 || hash == "" {
		t.Fatalf("unexpected verification result: sequence=%d hash=%q", sequence, hash)
	}
}

func TestJournalDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.journal.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Append("event", map[string]string{"message": "original"}); err != nil {
		t.Fatal(err)
	}
	_ = journal.Close()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content = []byte(strings.Replace(string(content), "original", "tampered", 1))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyFile(path); err == nil {
		t.Fatal("expected tampering to be detected")
	}
}
