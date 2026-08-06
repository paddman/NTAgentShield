package native

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCursorCommitAndReload(t *testing.T) {
	directory := t.TempDir()
	cursor, err := openCursor(directory, "security-log", "windows_eventlog")
	if err != nil {
		t.Fatal(err)
	}
	next := cursor.Snapshot()
	next.Initialized = true
	next.WindowsRecordID = 4242
	if err := cursor.Commit(next); err != nil {
		t.Fatal(err)
	}
	reloaded, err := openCursor(directory, "security-log", "windows_eventlog")
	if err != nil {
		t.Fatal(err)
	}
	state := reloaded.Snapshot()
	if !state.Initialized || state.WindowsRecordID != 4242 {
		t.Fatalf("unexpected cursor state: %#v", state)
	}
	info, err := os.Stat(filepath.Join(directory, "cursors", "security-log.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("cursor permissions are too broad: %o", info.Mode().Perm())
	}
}

func TestCursorRejectsCorruptionAndIdentityMismatch(t *testing.T) {
	directory := t.TempDir()
	if _, err := openCursor(directory, "../escape", "journald"); err == nil {
		t.Fatal("expected unsafe cursor source ID to be rejected")
	}
	cursorDirectory := filepath.Join(directory, "cursors")
	if err := os.MkdirAll(cursorDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cursorDirectory, "journal.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"source_id":"other","kind":"journald"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openCursor(directory, "journal", "journald"); err == nil {
		t.Fatal("expected cursor identity mismatch")
	}
	if err := os.WriteFile(path, []byte(`not-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openCursor(directory, "journal", "journald"); err == nil {
		t.Fatal("expected corrupt cursor to be rejected")
	}
}

func TestBatchAcknowledgesOnlyExplicitly(t *testing.T) {
	directory := t.TempDir()
	cursor, err := openCursor(directory, "audit", "auditd")
	if err != nil {
		t.Fatal(err)
	}
	next := cursor.Snapshot()
	next.Initialized = true
	next.FileOffset = 100
	batch := Batch{cursor: cursor, next: &next}
	if state := cursor.Snapshot(); state.FileOffset != 0 {
		t.Fatalf("cursor advanced before acknowledgement: %#v", state)
	}
	if err := batch.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	if state := cursor.Snapshot(); state.FileOffset != 100 || state.UpdatedAt.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("cursor was not acknowledged: %#v", state)
	}
}
