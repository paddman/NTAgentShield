package store

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Record struct {
	Sequence     uint64          `json:"sequence"`
	RecordedAt   time.Time       `json:"recorded_at"`
	Kind         string          `json:"kind"`
	PreviousHash string          `json:"previous_hash"`
	PayloadHash  string          `json:"payload_hash"`
	RecordHash   string          `json:"record_hash"`
	Payload      json.RawMessage `json:"payload"`
}

type Journal struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	sequence uint64
	lastHash string
}

func Open(path string) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create journal directory: %w", err)
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return nil, fmt.Errorf("create journal: %w", err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("secure journal permissions: %w", err)
	}
	sequence, lastHash, err := VerifyFile(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open journal: %w", err)
	}
	return &Journal{path: path, file: file, sequence: sequence, lastHash: lastHash}, nil
}

func (j *Journal) Append(kind string, payload interface{}) (Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return Record{}, errors.New("journal is closed")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Record{}, fmt.Errorf("encode journal payload: %w", err)
	}
	payloadHash := hash(encoded)
	record := Record{
		Sequence:     j.sequence + 1,
		RecordedAt:   time.Now().UTC(),
		Kind:         kind,
		PreviousHash: j.lastHash,
		PayloadHash:  payloadHash,
		Payload:      encoded,
	}
	record.RecordHash = calculateRecordHash(record)
	line, err := json.Marshal(record)
	if err != nil {
		return Record{}, fmt.Errorf("encode journal record: %w", err)
	}
	line = append(line, '\n')
	if _, err := j.file.Write(line); err != nil {
		return Record{}, fmt.Errorf("append journal: %w", err)
	}
	if err := j.file.Sync(); err != nil {
		return Record{}, fmt.Errorf("sync journal: %w", err)
	}
	j.sequence = record.Sequence
	j.lastHash = record.RecordHash
	return record, nil
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	return err
}

func VerifyFile(path string) (uint64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", fmt.Errorf("open journal for verification: %w", err)
	}
	defer file.Close()

	var sequence uint64
	var previous string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return sequence, previous, fmt.Errorf("decode journal line %d: %w", lineNumber, err)
		}
		if record.Sequence != sequence+1 {
			return sequence, previous, fmt.Errorf("journal sequence mismatch at line %d", lineNumber)
		}
		if record.PreviousHash != previous {
			return sequence, previous, fmt.Errorf("journal previous hash mismatch at line %d", lineNumber)
		}
		if hash(record.Payload) != record.PayloadHash {
			return sequence, previous, fmt.Errorf("journal payload hash mismatch at line %d", lineNumber)
		}
		if calculateRecordHash(record) != record.RecordHash {
			return sequence, previous, fmt.Errorf("journal record hash mismatch at line %d", lineNumber)
		}
		sequence = record.Sequence
		previous = record.RecordHash
	}
	if err := scanner.Err(); err != nil {
		return sequence, previous, fmt.Errorf("scan journal: %w", err)
	}
	return sequence, previous, nil
}

func calculateRecordHash(record Record) string {
	parts := []string{
		strconv.FormatUint(record.Sequence, 10),
		record.RecordedAt.UTC().Format(time.RFC3339Nano),
		record.Kind,
		record.PreviousHash,
		record.PayloadHash,
	}
	return hash([]byte(strings.Join(parts, "\x00")))
}

func hash(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
