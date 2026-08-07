package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
)

type Outbox struct {
	mu         sync.Mutex
	pendingDir string
	deadDir    string
}

type Item struct {
	Path  string
	Event model.Event
	Size  int64
}

type OutboxStats struct {
	Pending       int   `json:"pending"`
	PendingBytes  int64 `json:"pending_bytes"`
	DeadLetter    int   `json:"dead_letter"`
	DeadLetterBty int64 `json:"dead_letter_bytes"`
}

func OpenOutbox(dataDir string) (*Outbox, error) {
	root := filepath.Join(dataDir, "outbox")
	pending := filepath.Join(root, "pending")
	dead := filepath.Join(root, "dead-letter")
	for _, path := range []string{root, pending, dead} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("create transport outbox directory: %w", err)
		}
	}
	return &Outbox{pendingDir: pending, deadDir: dead}, nil
}

func (o *Outbox) Enqueue(event model.Event) error {
	if strings.TrimSpace(event.ID) == "" {
		return errors.New("cannot enqueue telemetry without event ID")
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode telemetry outbox event: %w", err)
	}
	encoded = append(encoded, '\n')
	name := eventFilename(event.ID)
	finalPath := filepath.Join(o.pendingDir, name)

	o.mu.Lock()
	defer o.mu.Unlock()
	if _, err := os.Stat(finalPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check telemetry outbox event: %w", err)
	}
	temporary := filepath.Join(o.pendingDir, fmt.Sprintf(".%s.%d.tmp", name, time.Now().UnixNano()))
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return fmt.Errorf("write telemetry outbox event: %w", err)
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("protect telemetry outbox event: %w", err)
	}
	if err := os.Rename(temporary, finalPath); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("install telemetry outbox event: %w", err)
	}
	return nil
}

func (o *Outbox) Peek(limit int) ([]Item, error) {
	if limit <= 0 {
		return nil, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	entries, err := os.ReadDir(o.pendingDir)
	if err != nil {
		return nil, fmt.Errorf("read telemetry outbox: %w", err)
	}
	type candidate struct {
		path    string
		name    string
		modTime time.Time
		size    int64
	}
	candidates := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("stat telemetry outbox event: %w", err)
		}
		candidates = append(candidates, candidate{
			path:    filepath.Join(o.pendingDir, entry.Name()),
			name:    entry.Name(),
			modTime: info.ModTime(),
			size:    info.Size(),
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].modTime.Equal(candidates[j].modTime) {
			return candidates[i].name < candidates[j].name
		}
		return candidates[i].modTime.Before(candidates[j].modTime)
	})

	items := make([]Item, 0, min(limit, len(candidates)))
	for _, candidate := range candidates {
		if len(items) >= limit {
			break
		}
		content, err := os.ReadFile(candidate.path)
		if err != nil {
			return items, fmt.Errorf("read telemetry outbox event: %w", err)
		}
		var event model.Event
		if err := json.Unmarshal(content, &event); err != nil {
			if deadErr := o.deadLetterLocked(candidate.path, "invalid queued event: "+err.Error()); deadErr != nil {
				return items, deadErr
			}
			continue
		}
		items = append(items, Item{Path: candidate.path, Event: event, Size: candidate.size})
	}
	return items, nil
}

func (o *Outbox) Ack(item Item) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := os.Remove(item.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ack telemetry outbox event: %w", err)
	}
	return nil
}

func (o *Outbox) DeadLetter(item Item, reason string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.deadLetterLocked(item.Path, reason)
}

func (o *Outbox) deadLetterLocked(path, reason string) error {
	name := filepath.Base(path)
	destination := filepath.Join(o.deadDir, name)
	if _, err := os.Stat(destination); err == nil {
		destination = filepath.Join(o.deadDir, fmt.Sprintf("%d-%s", time.Now().UnixNano(), name))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check telemetry dead-letter target: %w", err)
	}
	if err := os.Rename(path, destination); err != nil {
		return fmt.Errorf("move telemetry event to dead-letter: %w", err)
	}
	reasonPath := destination + ".reason.txt"
	if err := os.WriteFile(reasonPath, []byte(strings.TrimSpace(reason)+"\n"), 0o600); err != nil {
		return fmt.Errorf("write telemetry dead-letter reason: %w", err)
	}
	return nil
}

func (o *Outbox) Stats() (OutboxStats, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	pending, pendingBytes, err := directoryStats(o.pendingDir, ".json")
	if err != nil {
		return OutboxStats{}, err
	}
	dead, deadBytes, err := directoryStats(o.deadDir, ".json")
	if err != nil {
		return OutboxStats{}, err
	}
	return OutboxStats{
		Pending:       pending,
		PendingBytes:  pendingBytes,
		DeadLetter:    dead,
		DeadLetterBty: deadBytes,
	}, nil
}

func directoryStats(path, suffix string) (int, int64, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0, 0, fmt.Errorf("read outbox stats: %w", err)
	}
	count := 0
	var bytes int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), suffix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return 0, 0, fmt.Errorf("stat outbox entry: %w", err)
		}
		count++
		bytes += info.Size()
	}
	return count, bytes, nil
}

func eventFilename(eventID string) string {
	digest := sha256.Sum256([]byte(eventID))
	return hex.EncodeToString(digest[:]) + ".json"
}
