package outbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/transport"
)

func (s *Store) BuildNext(now time.Time) (BuildResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return BuildResult{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	pendingBytes := int64(0)
	for _, pending := range s.state.Pending {
		pendingBytes += pending.SizeBytes
		if pending.Blocked {
			return BuildResult{Backpressured: true}, nil
		}
	}
	if len(s.state.Pending) >= s.config.MaxPendingBatches || pendingBytes >= s.config.MaxSpoolBytes {
		return BuildResult{Backpressured: true}, nil
	}
	records, err := ReadJournal(s.config.JournalPath, s.state.JournalCursor, s.config.MaxBatchItems, s.config.MaxBatchBytes)
	if err != nil {
		return BuildResult{}, err
	}
	if len(records) == 0 {
		return BuildResult{}, nil
	}
	if records[0].Sequence != s.state.JournalCursor+1 {
		return BuildResult{}, fmt.Errorf("journal cursor gap: expected=%d current=%d", s.state.JournalCursor+1, records[0].Sequence)
	}
	items, err := RecordsToItems(records)
	if err != nil {
		return BuildResult{}, err
	}
	batch := transport.Batch{
		Version:      transport.BatchProtocolVersion,
		TenantID:     s.state.TenantID,
		AgentID:      s.state.AgentID,
		Sequence:     s.state.NextBatchSequence,
		PreviousHash: s.state.LastGeneratedHash,
		CreatedAt:    now,
		Items:        items,
	}
	if err := batch.Seal(); err != nil {
		return BuildResult{}, err
	}
	spool := Spool{
		Version:     SpoolVersion,
		JournalFrom: records[0].Sequence,
		JournalTo:   records[len(records)-1].Sequence,
		Batch:       batch,
	}
	content, err := json.MarshalIndent(spool, "", "  ")
	if err != nil {
		return BuildResult{}, fmt.Errorf("encode outbox spool batch: %w", err)
	}
	if int64(len(content)) > s.config.MaxBatchBytes || len(content) > maxSpoolFileBytes {
		return BuildResult{}, errors.New("encoded spool batch exceeds configured size limit")
	}
	if pendingBytes+int64(len(content)) > s.config.MaxSpoolBytes {
		return BuildResult{Backpressured: true}, nil
	}
	fileName := spoolFileName(batch.Sequence, batch.PayloadSHA256)
	path := filepath.Join(s.spoolDir, fileName)
	if _, err := os.Lstat(path); err == nil {
		return BuildResult{}, errors.New("deterministic spool file already exists before state commit")
	} else if !errors.Is(err, os.ErrNotExist) {
		return BuildResult{}, fmt.Errorf("inspect spool path: %w", err)
	}
	if err := atomicWrite(path, append(content, '\n'), 0o600); err != nil {
		return BuildResult{}, err
	}
	pending := Pending{
		Sequence:      batch.Sequence,
		PayloadSHA256: batch.PayloadSHA256,
		FileName:      fileName,
		JournalFrom:   spool.JournalFrom,
		JournalTo:     spool.JournalTo,
		ItemCount:     len(items),
		SizeBytes:     int64(len(content) + 1),
		CreatedAt:     now,
	}
	candidate := cloneState(s.state)
	candidate.JournalCursor = spool.JournalTo
	candidate.NextBatchSequence = batch.Sequence + 1
	candidate.LastGeneratedHash = batch.PayloadSHA256
	candidate.Pending = append(candidate.Pending, pending)
	if err := s.saveState(candidate); err != nil {
		return BuildResult{}, fmt.Errorf("commit outbox state after spool write: %w", err)
	}
	return BuildResult{Created: true, Pending: pending}, nil
}

func (s *Store) reconcile() error {
	entries, err := os.ReadDir(s.spoolDir)
	if err != nil {
		return fmt.Errorf("read outbox spool directory: %w", err)
	}
	type diskSpool struct {
		fileName string
		size     int64
		spool    Spool
	}
	disk := make([]diskSpool, 0)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "batch-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return fmt.Errorf("outbox spool contains unsafe entry %s", entry.Name())
		}
		path := filepath.Join(s.spoolDir, entry.Name())
		spool, size, err := loadSpool(path)
		if err != nil {
			return err
		}
		if spool.Batch.TenantID != s.state.TenantID || spool.Batch.AgentID != s.state.AgentID {
			return fmt.Errorf("spool file %s identity does not match enrolled endpoint", entry.Name())
		}
		expectedName := spoolFileName(spool.Batch.Sequence, spool.Batch.PayloadSHA256)
		if entry.Name() != expectedName {
			return fmt.Errorf("spool file %s does not match batch identity %s", entry.Name(), expectedName)
		}
		disk = append(disk, diskSpool{fileName: entry.Name(), size: size, spool: spool})
	}
	sort.Slice(disk, func(i, j int) bool { return disk[i].spool.Batch.Sequence < disk[j].spool.Batch.Sequence })
	pendingByFile := make(map[string]Pending, len(s.state.Pending))
	for _, pending := range s.state.Pending {
		pendingByFile[pending.FileName] = pending
	}
	seen := map[string]struct{}{}
	candidate := cloneState(s.state)
	changed := false
	for _, item := range disk {
		sequence := item.spool.Batch.Sequence
		if sequence <= candidate.LastAckedSequence {
			if err := os.Remove(filepath.Join(s.spoolDir, item.fileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove acknowledged orphan spool file: %w", err)
			}
			changed = true
			continue
		}
		if pending, exists := pendingByFile[item.fileName]; exists {
			if pending.Sequence != sequence || pending.PayloadSHA256 != item.spool.Batch.PayloadSHA256 || pending.JournalFrom != item.spool.JournalFrom || pending.JournalTo != item.spool.JournalTo {
				return fmt.Errorf("spool file %s does not match persisted pending state", item.fileName)
			}
			seen[item.fileName] = struct{}{}
			continue
		}
		if sequence != candidate.NextBatchSequence || item.spool.Batch.PreviousHash != candidate.LastGeneratedHash || item.spool.JournalFrom != candidate.JournalCursor+1 {
			return fmt.Errorf("untracked spool file %s would fork outbox state", item.fileName)
		}
		pending := Pending{
			Sequence:      sequence,
			PayloadSHA256: item.spool.Batch.PayloadSHA256,
			FileName:      item.fileName,
			JournalFrom:   item.spool.JournalFrom,
			JournalTo:     item.spool.JournalTo,
			ItemCount:     len(item.spool.Batch.Items),
			SizeBytes:     item.size,
			CreatedAt:     item.spool.Batch.CreatedAt,
		}
		candidate.Pending = append(candidate.Pending, pending)
		candidate.JournalCursor = item.spool.JournalTo
		candidate.NextBatchSequence = sequence + 1
		candidate.LastGeneratedHash = item.spool.Batch.PayloadSHA256
		seen[item.fileName] = struct{}{}
		changed = true
	}
	for _, pending := range candidate.Pending {
		if _, exists := seen[pending.FileName]; !exists {
			return fmt.Errorf("outbox state references missing spool file %s", pending.FileName)
		}
	}
	if changed {
		return s.saveState(candidate)
	}
	return nil
}

func loadSpool(path string) (Spool, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Spool{}, 0, fmt.Errorf("inspect spool file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxSpoolFileBytes {
		return Spool{}, 0, fmt.Errorf("spool file %s type or size is invalid", filepath.Base(path))
	}
	file, err := os.Open(path)
	if err != nil {
		return Spool{}, 0, fmt.Errorf("open spool file: %w", err)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxSpoolFileBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return Spool{}, 0, fmt.Errorf("read spool file: %w", readErr)
	}
	if closeErr != nil {
		return Spool{}, 0, fmt.Errorf("close spool file: %w", closeErr)
	}
	var spool Spool
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spool); err != nil {
		return Spool{}, 0, fmt.Errorf("decode spool file %s: %w", filepath.Base(path), err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Spool{}, 0, errors.New("spool file contains multiple JSON values")
		}
		return Spool{}, 0, err
	}
	if spool.Version != SpoolVersion || spool.JournalFrom == 0 || spool.JournalTo < spool.JournalFrom {
		return Spool{}, 0, fmt.Errorf("spool file %s metadata is invalid", filepath.Base(path))
	}
	if len(spool.Batch.Items) != int(spool.JournalTo-spool.JournalFrom+1) {
		return Spool{}, 0, fmt.Errorf("spool file %s journal range does not match item count", filepath.Base(path))
	}
	if err := spool.Batch.Validate(); err != nil {
		return Spool{}, 0, fmt.Errorf("validate spool batch %s: %w", filepath.Base(path), err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return Spool{}, 0, fmt.Errorf("secure spool file: %w", err)
	}
	return spool, info.Size(), nil
}

func spoolFileName(sequence uint64, hash string) string {
	return fmt.Sprintf("batch-%020d-%s.json", sequence, strings.ToLower(hash))
}
