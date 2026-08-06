package outbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
)

type Store struct {
	mu        sync.Mutex
	config    Config
	statePath string
	spoolDir  string
	state     State
	lock      *processLock
	closed    bool
}

func Open(config Config, metadata enrollment.Metadata) (*Store, error) {
	if err := validateConfig(&config); err != nil {
		return nil, err
	}
	if metadata.Version != enrollment.ProtocolVersion {
		return nil, fmt.Errorf("unsupported enrollment metadata version %d", metadata.Version)
	}
	if err := enrollment.ValidateIdentity("tenant_id", metadata.TenantID); err != nil {
		return nil, err
	}
	if err := enrollment.ValidateIdentity("agent_id", metadata.AgentID); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(config.Directory, 0o700); err != nil {
		return nil, fmt.Errorf("create outbox directory: %w", err)
	}
	if err := os.Chmod(config.Directory, 0o700); err != nil {
		return nil, fmt.Errorf("secure outbox directory: %w", err)
	}
	spoolDir := filepath.Join(config.Directory, "spool")
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		return nil, fmt.Errorf("create outbox spool directory: %w", err)
	}
	if err := os.Chmod(spoolDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure outbox spool directory: %w", err)
	}
	lock, err := acquireProcessLock(config.Directory)
	if err != nil {
		return nil, err
	}
	store := &Store{
		config:    config,
		statePath: filepath.Join(config.Directory, "state.json"),
		spoolDir:  spoolDir,
		lock:      lock,
	}
	state, err := loadState(store.statePath, metadata)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	store.state = state
	if err := store.reconcile(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return store, nil
}

func validateConfig(config *Config) error {
	if config == nil {
		return errors.New("outbox config is required")
	}
	config.Directory = filepath.Clean(strings.TrimSpace(config.Directory))
	config.JournalPath = filepath.Clean(strings.TrimSpace(config.JournalPath))
	if config.Directory == "." || config.JournalPath == "." {
		return errors.New("outbox directory and journal path are required")
	}
	if config.MaxPendingBatches == 0 {
		config.MaxPendingBatches = 1024
	}
	if config.MaxSpoolBytes == 0 {
		config.MaxSpoolBytes = 1024 * 1024 * 1024
	}
	if config.MaxBatchItems == 0 {
		config.MaxBatchItems = 256
	}
	if config.MaxBatchBytes == 0 {
		config.MaxBatchBytes = 4 * 1024 * 1024
	}
	if config.BaseBackoff == 0 {
		config.BaseBackoff = 2 * time.Second
	}
	if config.MaxBackoff == 0 {
		config.MaxBackoff = 5 * time.Minute
	}
	if config.MaxPendingBatches < 1 || config.MaxPendingBatches > 10000 {
		return errors.New("max pending batches must be between 1 and 10000")
	}
	if config.MaxSpoolBytes < 1024*1024 || config.MaxSpoolBytes > 1024*1024*1024*1024 {
		return errors.New("max spool bytes must be between 1 MiB and 1 TiB")
	}
	if config.MaxBatchItems < 1 || config.MaxBatchItems > 1000 {
		return errors.New("max batch items must be between 1 and 1000")
	}
	if config.MaxBatchBytes < 1024 || config.MaxBatchBytes > maxSpoolFileBytes {
		return fmt.Errorf("max batch bytes must be between 1024 and %d", maxSpoolFileBytes)
	}
	if config.BaseBackoff < 100*time.Millisecond || config.BaseBackoff > time.Minute {
		return errors.New("base backoff must be between 100ms and 1m")
	}
	if config.MaxBackoff < config.BaseBackoff || config.MaxBackoff > time.Hour {
		return errors.New("max backoff must be at least base backoff and no more than 1h")
	}
	return nil
}

func loadState(path string, metadata enrollment.Metadata) (State, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return State{
			Version:           StateVersion,
			TenantID:          metadata.TenantID,
			AgentID:           metadata.AgentID,
			NextBatchSequence: 1,
			UpdatedAt:         time.Now().UTC(),
		}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("open outbox state: %w", err)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return State{}, fmt.Errorf("read outbox state: %w", readErr)
	}
	if closeErr != nil {
		return State{}, fmt.Errorf("close outbox state: %w", closeErr)
	}
	if len(content) > maxStateBytes {
		return State{}, fmt.Errorf("outbox state exceeds %d bytes", maxStateBytes)
	}
	var envelope stateEnvelope
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return State{}, quarantineState(path, fmt.Errorf("decode outbox state: %w", err))
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return State{}, quarantineState(path, errors.New("outbox state contains multiple JSON values"))
		}
		return State{}, quarantineState(path, fmt.Errorf("decode outbox state trailer: %w", err))
	}
	if envelope.Version != StateVersion || envelope.State.Version != StateVersion {
		return State{}, quarantineState(path, errors.New("outbox state version is unsupported"))
	}
	expected, err := stateHash(envelope.State)
	if err != nil {
		return State{}, err
	}
	if !constantEqual(expected, envelope.PayloadSHA256) {
		return State{}, quarantineState(path, errors.New("outbox state integrity hash mismatch"))
	}
	if err := validateState(envelope.State, metadata); err != nil {
		return State{}, quarantineState(path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return State{}, fmt.Errorf("secure outbox state: %w", err)
	}
	return cloneState(envelope.State), nil
}

func validateState(state State, metadata enrollment.Metadata) error {
	if state.TenantID != metadata.TenantID || state.AgentID != metadata.AgentID {
		return errors.New("outbox state identity does not match endpoint enrollment")
	}
	if state.NextBatchSequence == 0 {
		return errors.New("outbox next batch sequence is invalid")
	}
	if state.LastAckedSequence >= state.NextBatchSequence {
		return errors.New("outbox acknowledgement sequence is ahead of generated batches")
	}
	if state.LastGeneratedHash != "" && !validHash(state.LastGeneratedHash) {
		return errors.New("outbox last generated hash is invalid")
	}
	if state.LastAckedHash != "" && !validHash(state.LastAckedHash) {
		return errors.New("outbox last acknowledged hash is invalid")
	}
	previousSequence := state.LastAckedSequence
	seenFiles := map[string]struct{}{}
	for _, pending := range state.Pending {
		if pending.Sequence <= previousSequence || pending.Sequence >= state.NextBatchSequence {
			return errors.New("outbox pending sequence is invalid")
		}
		if !validHash(pending.PayloadSHA256) || pending.FileName != spoolFileName(pending.Sequence, pending.PayloadSHA256) {
			return errors.New("outbox pending hash or filename is invalid")
		}
		if pending.JournalFrom == 0 || pending.JournalTo < pending.JournalFrom || pending.ItemCount < 1 || pending.SizeBytes < 1 {
			return errors.New("outbox pending journal range or size is invalid")
		}
		if _, exists := seenFiles[pending.FileName]; exists {
			return errors.New("outbox state contains duplicate spool files")
		}
		seenFiles[pending.FileName] = struct{}{}
		previousSequence = pending.Sequence
	}
	return nil
}

func (s *Store) saveState(candidate State) error {
	candidate.Version = StateVersion
	candidate.UpdatedAt = time.Now().UTC()
	sort.Slice(candidate.Pending, func(i, j int) bool { return candidate.Pending[i].Sequence < candidate.Pending[j].Sequence })
	payloadHash, err := stateHash(candidate)
	if err != nil {
		return err
	}
	envelope := stateEnvelope{Version: StateVersion, State: candidate, PayloadSHA256: payloadHash}
	content, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("encode outbox state: %w", err)
	}
	if len(content) > maxStateBytes {
		return fmt.Errorf("outbox state exceeds %d bytes", maxStateBytes)
	}
	if err := atomicWrite(s.statePath, append(content, '\n'), 0o600); err != nil {
		return err
	}
	s.state = cloneState(candidate)
	return nil
}

func stateHash(state State) (string, error) {
	content, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("encode outbox state payload: %w", err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func quarantineState(path string, reason error) error {
	quarantinePath := fmt.Sprintf("%s.corrupt-%d", path, time.Now().UTC().UnixNano())
	if err := os.Rename(path, quarantinePath); err != nil {
		return fmt.Errorf("outbox state invalid (%v) and quarantine failed: %w", reason, err)
	}
	return fmt.Errorf("outbox state invalid and quarantined as %s: %w", filepath.Base(quarantinePath), reason)
}

func (s *Store) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := Status{
		TenantID:          s.state.TenantID,
		AgentID:           s.state.AgentID,
		JournalCursor:     s.state.JournalCursor,
		LastAckedSequence: s.state.LastAckedSequence,
		PendingBatches:    len(s.state.Pending),
	}
	for _, pending := range s.state.Pending {
		status.PendingBytes += pending.SizeBytes
		if pending.Blocked {
			status.Blocked = true
		}
		if status.NextAttemptAt.IsZero() || (!pending.NextAttemptAt.IsZero() && pending.NextAttemptAt.Before(status.NextAttemptAt)) {
			status.NextAttemptAt = pending.NextAttemptAt
		}
	}
	status.Backpressured = len(s.state.Pending) >= s.config.MaxPendingBatches || status.PendingBytes >= s.config.MaxSpoolBytes
	return status
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	lock := s.lock
	s.mu.Unlock()
	return lock.Close()
}

func (s *Store) ensureOpen() error {
	if s == nil || s.closed {
		return errors.New("outbox store is closed")
	}
	return nil
}

func cloneState(state State) State {
	copy := state
	copy.Pending = append([]Pending(nil), state.Pending...)
	return copy
}

func constantEqual(left, right string) bool {
	if len(left) != len(right) || len(left) == 0 {
		return false
	}
	var difference byte
	for index := 0; index < len(left); index++ {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".outbox-*.tmp")
	if err != nil {
		return fmt.Errorf("create outbox temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return fmt.Errorf("secure outbox temporary file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write outbox temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync outbox temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close outbox temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("replace outbox file: rename failed: %v; remove failed: %w", err, removeErr)
		}
		if retryErr := os.Rename(temporaryPath, path); retryErr != nil {
			return fmt.Errorf("replace outbox file: %w", retryErr)
		}
	}
	removeTemporary = false
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("secure outbox file: %w", err)
	}
	return nil
}
