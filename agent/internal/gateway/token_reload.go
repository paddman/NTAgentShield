package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func (s *TokenStore) reloadLocked() error {
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.entries = nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("open enrollment token store: %w", err)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxTokenStoreBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return fmt.Errorf("read enrollment token store: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close enrollment token store: %w", closeErr)
	}
	if len(content) > maxTokenStoreBytes {
		return fmt.Errorf("enrollment token store exceeds %d bytes", maxTokenStoreBytes)
	}
	var envelope tokenEnvelope
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return fmt.Errorf("decode enrollment token store: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("enrollment token store contains multiple JSON values")
		}
		return fmt.Errorf("decode enrollment token store trailer: %w", err)
	}
	if envelope.Version != tokenStoreVersion || len(envelope.Entries) > maxTokenEntries {
		return errors.New("enrollment token store version or entry count is invalid")
	}
	expected, err := tokenPayloadHash(envelope.Entries)
	if err != nil {
		return err
	}
	if !constantEqual(expected, envelope.PayloadSHA256) {
		return errors.New("enrollment token store integrity hash mismatch")
	}
	for _, entry := range envelope.Entries {
		if err := validateTokenEntry(entry); err != nil {
			return err
		}
	}
	s.entries = append([]TokenEntry(nil), envelope.Entries...)
	if err := os.Chmod(s.path, 0o600); err != nil {
		return fmt.Errorf("secure enrollment token store: %w", err)
	}
	return nil
}

func acquireTokenFileLock(storePath string, timeout time.Duration) (func(), error) {
	lockPath := storePath + ".lock"
	deadline := time.Now().Add(timeout)
	for {
		err := os.Mkdir(lockPath, 0o700)
		if err == nil {
			owner := []byte(fmt.Sprintf("pid=%d created_at=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano)))
			_ = os.WriteFile(filepath.Join(lockPath, "owner"), owner, 0o600)
			return func() { _ = os.RemoveAll(lockPath) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("acquire enrollment token store lock: %w", err)
		}
		info, statErr := os.Stat(lockPath)
		if statErr == nil && time.Since(info.ModTime()) > 2*time.Minute {
			_ = os.RemoveAll(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timed out acquiring enrollment token store lock")
		}
		time.Sleep(25 * time.Millisecond)
	}
}
