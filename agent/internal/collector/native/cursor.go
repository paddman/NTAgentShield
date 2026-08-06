package native

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

const cursorVersion = 1

var cursorSourceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type cursorState struct {
	Version             int       `json:"version"`
	SourceID            string    `json:"source_id"`
	Kind                string    `json:"kind"`
	Initialized         bool      `json:"initialized"`
	WindowsRecordID     uint64    `json:"windows_record_id,omitempty"`
	JournalCursor       string    `json:"journal_cursor,omitempty"`
	JournalSince        time.Time `json:"journal_since,omitempty"`
	FileOffset          int64     `json:"file_offset,omitempty"`
	FileDevice          uint64    `json:"file_device,omitempty"`
	FileInode           uint64    `json:"file_inode,omitempty"`
	FilePendingFragment string    `json:"file_pending_fragment,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type cursorFile struct {
	mu    sync.Mutex
	path  string
	state cursorState
}

func openCursor(dataDir, sourceID, kind string) (*cursorFile, error) {
	if !cursorSourceIDPattern.MatchString(sourceID) {
		return nil, fmt.Errorf("unsafe cursor source id %q", sourceID)
	}
	directory := filepath.Join(dataDir, "cursors")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create cursor directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("secure cursor directory: %w", err)
	}
	cursor := &cursorFile{
		path: filepath.Join(directory, sourceID+".json"),
		state: cursorState{
			Version:  cursorVersion,
			SourceID: sourceID,
			Kind:     kind,
		},
	}
	file, err := os.Open(cursor.path)
	if errors.Is(err, os.ErrNotExist) {
		return cursor, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open cursor %s: %w", sourceID, err)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil {
		return nil, fmt.Errorf("read cursor %s: %w", sourceID, err)
	}
	if len(content) > 64*1024 {
		return nil, fmt.Errorf("cursor %s exceeds 64 KiB", sourceID)
	}
	if err := json.Unmarshal(content, &cursor.state); err != nil {
		return nil, fmt.Errorf("decode cursor %s: %w", sourceID, err)
	}
	if cursor.state.Version != cursorVersion {
		return nil, fmt.Errorf("cursor %s has unsupported version %d", sourceID, cursor.state.Version)
	}
	if cursor.state.SourceID != sourceID || cursor.state.Kind != kind {
		return nil, fmt.Errorf("cursor %s identity mismatch", sourceID)
	}
	if err := os.Chmod(cursor.path, 0o600); err != nil {
		return nil, fmt.Errorf("secure cursor %s: %w", sourceID, err)
	}
	return cursor, nil
}

func (c *cursorFile) Snapshot() cursorState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *cursorFile) Commit(next cursorState) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if next.SourceID != "" && next.SourceID != c.state.SourceID {
		return errors.New("cursor source id cannot change")
	}
	if next.Kind != "" && next.Kind != c.state.Kind {
		return errors.New("cursor kind cannot change")
	}
	next.Version = cursorVersion
	next.SourceID = c.state.SourceID
	next.Kind = c.state.Kind
	next.UpdatedAt = time.Now().UTC()
	content, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cursor %s: %w", c.state.SourceID, err)
	}
	directory := filepath.Dir(c.path)
	temporary, err := os.CreateTemp(directory, ".cursor-*.tmp")
	if err != nil {
		return fmt.Errorf("create cursor temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure cursor temporary file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write cursor temporary file: %w", err)
	}
	if _, err := temporary.Write([]byte("\n")); err != nil {
		return fmt.Errorf("finish cursor temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync cursor temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close cursor temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, c.path); err != nil {
		if removeErr := os.Remove(c.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("replace cursor %s: rename failed: %v; remove failed: %w", c.state.SourceID, err, removeErr)
		}
		if retryErr := os.Rename(temporaryPath, c.path); retryErr != nil {
			return fmt.Errorf("replace cursor %s: %w", c.state.SourceID, retryErr)
		}
	}
	removeTemporary = false
	if err := os.Chmod(c.path, 0o600); err != nil {
		return fmt.Errorf("secure cursor %s: %w", c.state.SourceID, err)
	}
	c.state = next
	return nil
}
