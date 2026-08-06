package outbox

import (
	"time"

	"github.com/paddman/NTAgentShield/internal/transport"
)

const (
	StateVersion       = 1
	SpoolVersion       = 1
	maxStateBytes      = 16 * 1024 * 1024
	maxSpoolFileBytes  = 16 * 1024 * 1024
	maxJournalLineBytes = 8 * 1024 * 1024
)

type Config struct {
	Directory         string
	JournalPath       string
	MaxPendingBatches int
	MaxSpoolBytes     int64
	MaxBatchItems     int
	MaxBatchBytes     int64
	BaseBackoff       time.Duration
	MaxBackoff        time.Duration
}

type Pending struct {
	Sequence      uint64    `json:"sequence"`
	PayloadSHA256 string    `json:"payload_sha256"`
	FileName      string    `json:"file_name"`
	JournalFrom   uint64    `json:"journal_from"`
	JournalTo     uint64    `json:"journal_to"`
	ItemCount     int       `json:"item_count"`
	SizeBytes     int64     `json:"size_bytes"`
	CreatedAt     time.Time `json:"created_at"`
	Attempts      uint32    `json:"attempts"`
	LastAttemptAt time.Time `json:"last_attempt_at,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`
	LastErrorCode string    `json:"last_error_code,omitempty"`
	Blocked       bool      `json:"blocked"`
}

type State struct {
	Version            int       `json:"version"`
	TenantID           string    `json:"tenant_id"`
	AgentID            string    `json:"agent_id"`
	JournalCursor      uint64    `json:"journal_cursor"`
	NextBatchSequence  uint64    `json:"next_batch_sequence"`
	LastGeneratedHash  string    `json:"last_generated_hash,omitempty"`
	LastAckedSequence  uint64    `json:"last_acked_sequence"`
	LastAckedHash      string    `json:"last_acked_hash,omitempty"`
	Pending            []Pending `json:"pending,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type stateEnvelope struct {
	Version       int    `json:"version"`
	State         State  `json:"state"`
	PayloadSHA256 string `json:"payload_sha256"`
}

type Spool struct {
	Version     int             `json:"version"`
	JournalFrom uint64          `json:"journal_from"`
	JournalTo   uint64          `json:"journal_to"`
	Batch       transport.Batch `json:"batch"`
}

type Status struct {
	TenantID          string    `json:"tenant_id"`
	AgentID           string    `json:"agent_id"`
	JournalCursor     uint64    `json:"journal_cursor"`
	LastAckedSequence uint64    `json:"last_acked_sequence"`
	PendingBatches    int       `json:"pending_batches"`
	PendingBytes      int64     `json:"pending_bytes"`
	Blocked           bool      `json:"blocked"`
	Backpressured     bool      `json:"backpressured"`
	NextAttemptAt     time.Time `json:"next_attempt_at,omitempty"`
}

type BuildResult struct {
	Created       bool
	Backpressured bool
	Pending       Pending
}

type DeliveryResult struct {
	Attempted bool
	Delivered bool
	Duplicate bool
	Blocked   bool
	Receipt   transport.Receipt
}
