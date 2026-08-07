package responseexec

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/paddman/NTAgentShield/internal/identity"
)

const maxLedgerEntries = 4096

var ErrIndeterminate = errors.New("response action was started before restart; refusing to execute it again")

type LedgerEntry struct {
	ActionDigest string          `json:"action_digest"`
	Status       string          `json:"status"`
	StartedAt    time.Time       `json:"started_at"`
	CompletedAt  time.Time       `json:"completed_at,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
}

type ledgerState struct {
	Entries   map[string]LedgerEntry `json:"entries"`
	Signature string                 `json:"signature"`
}

type Ledger struct {
	mu          sync.Mutex
	path        string
	identityKey ed25519.PrivateKey
	entries     map[string]LedgerEntry
}

func OpenLedger(path, identityKeyFile string) (*Ledger, error) {
	privateKey, err := identity.Load(identityKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load response ledger signing identity: %w", err)
	}
	ledger := &Ledger{path: path, identityKey: privateKey, entries: map[string]LedgerEntry{}}
	if err := ledger.load(); err != nil {
		return nil, err
	}
	return ledger, nil
}

// Begin persists the non-repeatable intent before execution. If a crash happens
// after Begin but before Complete, the action becomes indeterminate and is not
// executed again on restart.
func (l *Ledger) Begin(actionID, actionDigest string) ([]byte, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if strings.TrimSpace(actionID) == "" || strings.TrimSpace(actionDigest) == "" {
		return nil, false, errors.New("response ledger requires action ID and digest")
	}
	if existing, ok := l.entries[actionID]; ok {
		if existing.ActionDigest != actionDigest {
			return nil, false, errors.New("response replay conflict: action ID was already bound to a different digest")
		}
		if existing.Status == "completed" && len(existing.Result) > 0 {
			return append([]byte(nil), existing.Result...), true, nil
		}
		return nil, false, ErrIndeterminate
	}
	l.entries[actionID] = LedgerEntry{
		ActionDigest: actionDigest,
		Status:       "started",
		StartedAt:    time.Now().UTC(),
	}
	l.pruneLocked()
	if err := l.saveLocked(); err != nil {
		delete(l.entries, actionID)
		return nil, false, err
	}
	return nil, false, nil
}

func (l *Ledger) Complete(actionID, actionDigest string, result []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[actionID]
	if !ok {
		return errors.New("response action was not started in replay ledger")
	}
	if entry.ActionDigest != actionDigest {
		return errors.New("response replay conflict while completing action")
	}
	if entry.Status == "completed" {
		if string(entry.Result) != string(result) {
			return errors.New("response action already has a different terminal result")
		}
		return nil
	}
	if !json.Valid(result) {
		return errors.New("response result is not valid JSON")
	}
	entry.Status = "completed"
	entry.CompletedAt = time.Now().UTC()
	entry.Result = append(json.RawMessage(nil), result...)
	l.entries[actionID] = entry
	return l.saveLocked()
}

func (l *Ledger) load() error {
	content, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read response replay ledger: %w", err)
	}
	var state ledgerState
	if err := json.Unmarshal(content, &state); err != nil {
		return fmt.Errorf("decode response replay ledger: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(state.Signature)
	if err != nil {
		return errors.New("decode response replay ledger signature")
	}
	state.Signature = ""
	unsigned, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if !ed25519.Verify(l.identityKey.Public().(ed25519.PublicKey), unsigned, signature) {
		return errors.New("response replay ledger signature verification failed")
	}
	if state.Entries == nil {
		state.Entries = map[string]LedgerEntry{}
	}
	for actionID, entry := range state.Entries {
		if entry.ActionDigest == "" || (entry.Status != "started" && entry.Status != "completed") {
			return fmt.Errorf("response replay ledger contains invalid entry %q", actionID)
		}
		if entry.Status == "completed" && !json.Valid(entry.Result) {
			return fmt.Errorf("response replay ledger contains invalid result for %q", actionID)
		}
	}
	l.entries = state.Entries
	return nil
}

func (l *Ledger) saveLocked() error {
	state := ledgerState{Entries: l.entries}
	unsigned, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode response replay ledger: %w", err)
	}
	state.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(l.identityKey, unsigned))
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode signed response replay ledger: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := replaceLedgerFile(l.path, encoded, 0o600); err != nil {
		return fmt.Errorf("persist response replay ledger: %w", err)
	}
	return nil
}

func (l *Ledger) pruneLocked() {
	if len(l.entries) <= maxLedgerEntries {
		return
	}
	type candidate struct {
		id   string
		time time.Time
	}
	completed := make([]candidate, 0, len(l.entries))
	for id, entry := range l.entries {
		if entry.Status == "completed" {
			when := entry.CompletedAt
			if when.IsZero() {
				when = entry.StartedAt
			}
			completed = append(completed, candidate{id: id, time: when})
		}
	}
	sort.Slice(completed, func(i, j int) bool { return completed[i].time.Before(completed[j].time) })
	for _, item := range completed {
		if len(l.entries) <= maxLedgerEntries {
			break
		}
		delete(l.entries, item.id)
	}
}

func replaceLedgerFile(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".new"
	backup := path + ".bak"
	if err := os.WriteFile(temporary, content, mode); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	_ = os.Remove(backup)
	hadExisting := false
	if _, err := os.Stat(path); err == nil {
		hadExisting = true
		if err := os.Rename(path, backup); err != nil {
			_ = os.Remove(temporary)
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		if hadExisting {
			_ = os.Rename(backup, path)
		}
		_ = os.Remove(temporary)
		return err
	}
	if hadExisting {
		_ = os.Remove(backup)
	}
	return os.Chmod(path, mode)
}
