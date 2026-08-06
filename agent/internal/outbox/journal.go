package outbox

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/transport"
)

type JournalRecord struct {
	Sequence   uint64
	RecordType string
	Timestamp  time.Time
	Payload    json.RawMessage
	RecordHash string
}

func ReadJournal(path string, afterSequence uint64, maxItems int, maxPayloadBytes int64) ([]JournalRecord, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("journal path is required")
	}
	if maxItems < 1 || maxItems > transport.MaxBatchItems {
		return nil, fmt.Errorf("journal read max items must be between 1 and %d", transport.MaxBatchItems)
	}
	if maxPayloadBytes < 1024 || maxPayloadBytes > maxSpoolFileBytes {
		return nil, fmt.Errorf("journal read max payload bytes must be between 1024 and %d", maxSpoolFileBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open evidence journal: %w", err)
	}
	defer file.Close()

	reader := bufio.NewReaderSize(file, 64*1024)
	records := make([]JournalRecord, 0, maxItems)
	var previousSequence uint64
	var selectedBytes int64
	lineNumber := 0
	for {
		line, readErr := readBoundedLine(reader, maxJournalLineBytes)
		if len(line) > 0 {
			lineNumber++
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 {
				record, parseErr := parseJournalRecord(trimmed)
				if parseErr != nil {
					return nil, fmt.Errorf("parse evidence journal line %d: %w", lineNumber, parseErr)
				}
				if previousSequence != 0 && record.Sequence != previousSequence+1 {
					return nil, fmt.Errorf("evidence journal sequence discontinuity at line %d: previous=%d current=%d", lineNumber, previousSequence, record.Sequence)
				}
				previousSequence = record.Sequence
				if record.Sequence > afterSequence {
					payloadBytes := int64(len(record.Payload))
					if payloadBytes > transport.MaxItemBytes {
						return nil, fmt.Errorf("journal record %d payload exceeds transport item limit", record.Sequence)
					}
					if len(records) > 0 && (len(records) >= maxItems || selectedBytes+payloadBytes > maxPayloadBytes) {
						return records, nil
					}
					if len(records) == 0 && payloadBytes > maxPayloadBytes {
						return nil, fmt.Errorf("journal record %d exceeds configured batch payload limit", record.Sequence)
					}
					records = append(records, record)
					selectedBytes += payloadBytes
					if len(records) >= maxItems {
						return records, nil
					}
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read evidence journal: %w", readErr)
		}
	}
	return records, nil
}

func RecordsToItems(records []JournalRecord) ([]transport.EvidenceItem, error) {
	items := make([]transport.EvidenceItem, 0, len(records))
	for _, record := range records {
		itemType := transportItemType(record.RecordType)
		identifier := payloadIdentifier(record.Payload)
		if identifier == "" {
			identifier = fmt.Sprintf("journal:%d:%s", record.Sequence, record.RecordHash)
		}
		item := transport.EvidenceItem{
			Type:    itemType,
			ID:      identifier,
			Payload: append(json.RawMessage(nil), record.Payload...),
		}
		items = append(items, item)
	}
	return items, nil
}

func parseJournalRecord(line []byte) (JournalRecord, error) {
	var raw map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	if err := decoder.Decode(&raw); err != nil {
		return JournalRecord{}, err
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return JournalRecord{}, errors.New("journal line contains multiple JSON values")
		}
		return JournalRecord{}, err
	}
	sequence, err := rawUint64(raw, "sequence", "seq")
	if err != nil || sequence == 0 {
		return JournalRecord{}, errors.New("journal record sequence is missing or invalid")
	}
	recordType, err := rawString(raw, "type", "record_type", "kind")
	if err != nil || strings.TrimSpace(recordType) == "" {
		return JournalRecord{}, errors.New("journal record type is missing or invalid")
	}
	recordHash, err := rawString(raw, "hash", "record_hash")
	if err != nil || !validHash(recordHash) {
		return JournalRecord{}, errors.New("journal record hash is missing or invalid")
	}
	payload, exists := firstRaw(raw, "payload")
	if !exists || len(bytes.TrimSpace(payload)) == 0 || !json.Valid(payload) {
		return JournalRecord{}, errors.New("journal record payload is missing or invalid")
	}
	timestamp := time.Time{}
	if timestampRaw, exists := firstRaw(raw, "timestamp", "created_at"); exists {
		_ = json.Unmarshal(timestampRaw, &timestamp)
	}
	return JournalRecord{
		Sequence:   sequence,
		RecordType: strings.TrimSpace(recordType),
		Timestamp:  timestamp.UTC(),
		Payload:    append(json.RawMessage(nil), payload...),
		RecordHash: strings.ToLower(recordHash),
	}, nil
}

func readBoundedLine(reader *bufio.Reader, maximum int) ([]byte, error) {
	var result []byte
	for {
		fragment, isPrefix, err := reader.ReadLine()
		if len(result)+len(fragment) > maximum {
			return nil, fmt.Errorf("journal line exceeds %d bytes", maximum)
		}
		result = append(result, fragment...)
		if !isPrefix {
			return result, err
		}
	}
}

func rawUint64(values map[string]json.RawMessage, keys ...string) (uint64, error) {
	raw, exists := firstRaw(values, keys...)
	if !exists {
		return 0, errors.New("value is missing")
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err == nil {
		return strconv.ParseUint(number.String(), 10, 64)
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(text), 10, 64)
}

func rawString(values map[string]json.RawMessage, keys ...string) (string, error) {
	raw, exists := firstRaw(values, keys...)
	if !exists {
		return "", errors.New("value is missing")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return value, nil
}

func firstRaw(values map[string]json.RawMessage, keys ...string) (json.RawMessage, bool) {
	for _, key := range keys {
		if value, exists := values[key]; exists {
			return value, true
		}
	}
	return nil, false
}

func transportItemType(recordType string) string {
	normalized := strings.ToLower(strings.TrimSpace(recordType))
	switch {
	case normalized == "event", strings.HasPrefix(normalized, "event."):
		return "event"
	case normalized == "finding", strings.HasPrefix(normalized, "finding."):
		return "finding"
	default:
		return "audit"
	}
}

func payloadIdentifier(payload json.RawMessage) string {
	var header struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return ""
	}
	identifier := strings.TrimSpace(header.ID)
	if len(identifier) > 256 {
		return ""
	}
	return identifier
}

func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
