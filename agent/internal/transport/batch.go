package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
)

const (
	BatchProtocolVersion = 1
	MaxBatchItems         = 1000
	MaxItemBytes          = 1024 * 1024
)

type EvidenceItem struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
}

type Batch struct {
	Version       int            `json:"version"`
	TenantID      string         `json:"tenant_id"`
	AgentID       string         `json:"agent_id"`
	Sequence      uint64         `json:"sequence"`
	PreviousHash  string         `json:"previous_hash,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	Items         []EvidenceItem `json:"items"`
	PayloadSHA256 string         `json:"payload_sha256"`
}

type Receipt struct {
	Status        string    `json:"status"`
	TenantID      string    `json:"tenant_id"`
	AgentID       string    `json:"agent_id"`
	Sequence      uint64    `json:"sequence"`
	PayloadSHA256 string    `json:"payload_sha256"`
	ReceivedAt    time.Time `json:"received_at"`
}

func (b *Batch) Seal() error {
	if b.Version == 0 {
		b.Version = BatchProtocolVersion
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	} else {
		b.CreatedAt = b.CreatedAt.UTC()
	}
	hash, err := b.computedHash()
	if err != nil {
		return err
	}
	b.PayloadSHA256 = hash
	return b.Validate()
}

func (b Batch) Validate() error {
	if b.Version != BatchProtocolVersion {
		return fmt.Errorf("unsupported batch version %d", b.Version)
	}
	if err := enrollment.ValidateIdentity("tenant_id", b.TenantID); err != nil {
		return err
	}
	if err := enrollment.ValidateIdentity("agent_id", b.AgentID); err != nil {
		return err
	}
	if b.Sequence == 0 {
		return errors.New("batch sequence must start at one")
	}
	if b.Sequence == 1 && b.PreviousHash != "" {
		return errors.New("first batch must not declare a previous hash")
	}
	if b.Sequence > 1 && !validSHA256(b.PreviousHash) {
		return errors.New("subsequent batch requires a valid previous hash")
	}
	if b.CreatedAt.IsZero() {
		return errors.New("batch creation timestamp is required")
	}
	if len(b.Items) == 0 || len(b.Items) > MaxBatchItems {
		return fmt.Errorf("batch must contain between 1 and %d items", MaxBatchItems)
	}
	for index, item := range b.Items {
		if item.Type != "event" && item.Type != "finding" && item.Type != "audit" {
			return fmt.Errorf("batch item %d has unsupported type %q", index, item.Type)
		}
		if strings.TrimSpace(item.ID) == "" || len(item.ID) > 256 {
			return fmt.Errorf("batch item %d has invalid id", index)
		}
		if len(item.Payload) == 0 || len(item.Payload) > MaxItemBytes || !json.Valid(item.Payload) {
			return fmt.Errorf("batch item %d has invalid payload", index)
		}
	}
	if !validSHA256(b.PayloadSHA256) {
		return errors.New("batch payload hash is invalid")
	}
	expected, err := b.computedHash()
	if err != nil {
		return err
	}
	if !constantStringEqual(expected, strings.ToLower(b.PayloadSHA256)) {
		return errors.New("batch payload hash mismatch")
	}
	return nil
}

func (b Batch) computedHash() (string, error) {
	copy := b
	copy.PayloadSHA256 = ""
	content, err := json.Marshal(copy)
	if err != nil {
		return "", fmt.Errorf("encode evidence batch: %w", err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func constantStringEqual(left, right string) bool {
	if len(left) != len(right) || len(left) == 0 {
		return false
	}
	var difference byte
	for index := 0; index < len(left); index++ {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
