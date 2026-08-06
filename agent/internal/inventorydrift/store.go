package inventorydrift

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
	"sync"
	"time"

	"github.com/paddman/NTAgentShield/internal/inventory"
)

type Store struct {
	mu              sync.Mutex
	path            string
	current         *Baseline
	warning         error
	quarantinedPath string
}

func Open(dataDir string) (*Store, error) {
	directory := filepath.Clean(dataDir)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create inventory baseline directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("secure inventory baseline directory: %w", err)
	}
	store := &Store{path: filepath.Join(directory, "inventory-baseline.json")}
	file, err := os.Open(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open inventory baseline: %w", err)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxBaselineBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read inventory baseline: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close inventory baseline: %w", closeErr)
	}
	if len(content) > maxBaselineBytes {
		return store.quarantine(fmt.Errorf("inventory baseline exceeds %d bytes", maxBaselineBytes))
	}
	var stored envelope
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return store.quarantine(fmt.Errorf("decode inventory baseline: %w", err))
	}
	if stored.Version != SchemaVersion || stored.Baseline.SchemaVersion != SchemaVersion {
		return store.quarantine(fmt.Errorf("unsupported inventory baseline version envelope=%d payload=%d", stored.Version, stored.Baseline.SchemaVersion))
	}
	hash, err := baselineHash(stored.Baseline)
	if err != nil {
		return nil, err
	}
	if !secureEqual(hash, stored.PayloadSHA256) {
		return store.quarantine(errors.New("inventory baseline integrity hash mismatch"))
	}
	if err := validateBaseline(stored.Baseline); err != nil {
		return store.quarantine(err)
	}
	copy := cloneBaseline(stored.Baseline)
	store.current = &copy
	if err := os.Chmod(store.path, 0o600); err != nil {
		return nil, fmt.Errorf("secure inventory baseline: %w", err)
	}
	return store, nil
}

func (s *Store) Warning() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.warning
}

func (s *Store) QuarantinedPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.quarantinedPath
}

func (s *Store) Plan(snapshot inventory.Snapshot, maxEvents int) (Plan, error) {
	if maxEvents < 1 || maxEvents > 5000 {
		return Plan{}, errors.New("inventory drift max events must be between 1 and 5000")
	}
	s.mu.Lock()
	var previous *Baseline
	if s.current != nil {
		copy := cloneBaseline(*s.current)
		previous = &copy
	}
	s.mu.Unlock()

	next := project(snapshot, previous)
	currentHash, err := baselineHash(next)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{Initial: previous == nil, Next: next, CurrentHash: currentHash}
	if previous == nil {
		return plan, nil
	}
	plan.PreviousHash, err = baselineHash(*previous)
	if err != nil {
		return Plan{}, err
	}
	changes := compare(*previous, next, snapshot.CollectedAt.UTC(), plan.PreviousHash, plan.CurrentHash)
	plan.TotalChanges = len(changes)
	if len(changes) <= maxEvents {
		plan.Events = changes.events()
		return plan, nil
	}
	plan.Truncated = true
	summary := summaryChange(snapshot, *previous, next, len(changes), plan.PreviousHash, plan.CurrentHash)
	if maxEvents == 1 {
		plan.Events = inventoryEvents{summary}.events()
		return plan, nil
	}
	selected := append(inventoryEvents(nil), changes[:maxEvents-1]...)
	selected = append(selected, summary)
	plan.Events = selected.events()
	return plan, nil
}

func (s *Store) Commit(plan Plan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	currentHash := ""
	if s.current != nil {
		var err error
		currentHash, err = baselineHash(*s.current)
		if err != nil {
			return err
		}
	}
	if currentHash != plan.PreviousHash {
		return errors.New("inventory baseline changed after drift plan was created")
	}
	if plan.Next.SchemaVersion != SchemaVersion {
		return errors.New("cannot commit an unsupported inventory baseline")
	}
	payloadHash, err := baselineHash(plan.Next)
	if err != nil {
		return err
	}
	if plan.CurrentHash != "" && payloadHash != plan.CurrentHash {
		return errors.New("inventory drift plan baseline hash changed before commit")
	}
	stored := envelope{Version: SchemaVersion, Baseline: plan.Next, PayloadSHA256: payloadHash}
	content, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("encode inventory baseline: %w", err)
	}
	if len(content) > maxBaselineBytes {
		return fmt.Errorf("inventory baseline exceeds %d bytes", maxBaselineBytes)
	}
	if err := atomicWrite(s.path, append(content, '\n')); err != nil {
		return err
	}
	copy := cloneBaseline(plan.Next)
	s.current = &copy
	return nil
}

func (s *Store) quarantine(reason error) (*Store, error) {
	quarantinePath := fmt.Sprintf("%s.corrupt-%d", s.path, time.Now().UTC().UnixNano())
	if err := os.Rename(s.path, quarantinePath); err != nil {
		return nil, fmt.Errorf("quarantine corrupt inventory baseline: %w", err)
	}
	s.warning = reason
	s.quarantinedPath = quarantinePath
	return s, nil
}

func baselineHash(baseline Baseline) (string, error) {
	content, err := json.Marshal(baseline)
	if err != nil {
		return "", fmt.Errorf("encode inventory baseline payload: %w", err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func validateBaseline(baseline Baseline) error {
	if baseline.SchemaVersion != SchemaVersion {
		return errors.New("inventory baseline payload version is invalid")
	}
	if baseline.CapturedAt.IsZero() {
		return errors.New("inventory baseline capture timestamp is missing")
	}
	if len(baseline.Services) > 10000 || len(baseline.Listeners) > 10000 || len(baseline.Software) > 10000 || len(baseline.Interfaces) > 10000 || len(baseline.ProcessImages) > 10000 {
		return errors.New("inventory baseline category exceeds safety limit")
	}
	return nil
}

func secureEqual(left, right string) bool {
	if len(left) != len(right) || len(left) == 0 {
		return false
	}
	var difference byte
	for index := 0; index < len(left); index++ {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func atomicWrite(path string, content []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".inventory-baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("create inventory baseline temporary file: %w", err)
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
		return fmt.Errorf("secure inventory baseline temporary file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write inventory baseline temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync inventory baseline temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close inventory baseline temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("replace inventory baseline: rename failed: %v; remove failed: %w", err, removeErr)
		}
		if retryErr := os.Rename(temporaryPath, path); retryErr != nil {
			return fmt.Errorf("replace inventory baseline: %w", retryErr)
		}
	}
	removeTemporary = false
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure inventory baseline: %w", err)
	}
	return nil
}

func cloneBaseline(value Baseline) Baseline {
	copy := value
	copy.Services = cloneServices(value.Services)
	copy.Listeners = cloneListeners(value.Listeners)
	copy.Software = cloneSoftware(value.Software)
	copy.Interfaces = cloneInterfaces(value.Interfaces)
	copy.ProcessImages = cloneProcessImages(value.ProcessImages)
	return copy
}

func cloneInterfaces(values []InterfaceState) []InterfaceState {
	result := make([]InterfaceState, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Addresses = append([]string(nil), value.Addresses...)
	}
	return result
}
