package gateway

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

	"github.com/paddman/NTAgentShield/internal/transport"
)

const (
	gatewayStateVersion = 1
	maxGatewayStateBytes = 64 * 1024 * 1024
	maxGatewayAgents     = 100000
)

var (
	ErrSequenceGap  = errors.New("evidence batch sequence gap")
	ErrSequenceFork = errors.New("evidence batch sequence fork")
	ErrPreviousHash = errors.New("evidence batch previous hash mismatch")
)

type AgentState struct {
	TenantID     string    `json:"tenant_id"`
	AgentID      string    `json:"agent_id"`
	Sequence     uint64    `json:"sequence"`
	LastHash     string    `json:"last_hash"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type gatewayStateEnvelope struct {
	Version       int          `json:"version"`
	Agents        []AgentState `json:"agents"`
	PayloadSHA256 string       `json:"payload_sha256"`
}

type acceptedRecord struct {
	ReceivedAt        time.Time       `json:"received_at"`
	ClientCertSerial  string          `json:"client_cert_serial"`
	Batch             transport.Batch `json:"batch"`
}

type BatchStore struct {
	mu        sync.Mutex
	statePath string
	logPath   string
	agents    map[string]AgentState
}

func OpenBatchStore(stateDir string) (*BatchStore, error) {
	directory := filepath.Clean(stateDir)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create gateway state directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("secure gateway state directory: %w", err)
	}
	store := &BatchStore{
		statePath: filepath.Join(directory, "gateway-sequences.json"),
		logPath:   filepath.Join(directory, "accepted-evidence.jsonl"),
		agents:    map[string]AgentState{},
	}
	file, err := os.Open(store.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open gateway sequence state: %w", err)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxGatewayStateBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read gateway sequence state: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close gateway sequence state: %w", closeErr)
	}
	if len(content) > maxGatewayStateBytes {
		return nil, fmt.Errorf("gateway sequence state exceeds %d bytes", maxGatewayStateBytes)
	}
	var envelope gatewayStateEnvelope
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode gateway sequence state: %w", err)
	}
	if envelope.Version != gatewayStateVersion || len(envelope.Agents) > maxGatewayAgents {
		return nil, errors.New("gateway sequence state version or agent count is invalid")
	}
	expected, err := gatewayStateHash(envelope.Agents)
	if err != nil {
		return nil, err
	}
	if !constantEqual(expected, envelope.PayloadSHA256) {
		return nil, errors.New("gateway sequence state integrity hash mismatch")
	}
	for _, agent := range envelope.Agents {
		if agent.TenantID == "" || agent.AgentID == "" || agent.Sequence == 0 || len(agent.LastHash) != 64 {
			return nil, errors.New("gateway sequence state contains an invalid agent cursor")
		}
		key := identityKey(agent.TenantID, agent.AgentID)
		if _, exists := store.agents[key]; exists {
			return nil, errors.New("gateway sequence state contains a duplicate agent identity")
		}
		store.agents[key] = agent
	}
	if err := os.Chmod(store.statePath, 0o600); err != nil {
		return nil, fmt.Errorf("secure gateway sequence state: %w", err)
	}
	return store, nil
}

func (s *BatchStore) Accept(batch transport.Batch, clientCertSerial string, now time.Time) (transport.Receipt, error) {
	if s == nil {
		return transport.Receipt{}, errors.New("batch store is not initialized")
	}
	if err := batch.Validate(); err != nil {
		return transport.Receipt{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	key := identityKey(batch.TenantID, batch.AgentID)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.agents[key]
	if exists && batch.Sequence == current.Sequence {
		if constantEqual(batch.PayloadSHA256, current.LastHash) {
			return transport.Receipt{Status: "duplicate", TenantID: batch.TenantID, AgentID: batch.AgentID, Sequence: batch.Sequence, PayloadSHA256: batch.PayloadSHA256, ReceivedAt: now}, nil
		}
		return transport.Receipt{}, ErrSequenceFork
	}
	expectedSequence := uint64(1)
	expectedPreviousHash := ""
	if exists {
		expectedSequence = current.Sequence + 1
		expectedPreviousHash = current.LastHash
	}
	if batch.Sequence != expectedSequence {
		if batch.Sequence < expectedSequence {
			return transport.Receipt{}, ErrSequenceFork
		}
		return transport.Receipt{}, ErrSequenceGap
	}
	if batch.PreviousHash != expectedPreviousHash {
		return transport.Receipt{}, ErrPreviousHash
	}
	record := acceptedRecord{ReceivedAt: now, ClientCertSerial: clientCertSerial, Batch: batch}
	if err := s.appendRecord(record); err != nil {
		return transport.Receipt{}, err
	}
	next := AgentState{TenantID: batch.TenantID, AgentID: batch.AgentID, Sequence: batch.Sequence, LastHash: batch.PayloadSHA256, UpdatedAt: now}
	candidate := make(map[string]AgentState, len(s.agents)+1)
	for existingKey, value := range s.agents {
		candidate[existingKey] = value
	}
	candidate[key] = next
	if len(candidate) > maxGatewayAgents {
		return transport.Receipt{}, errors.New("gateway sequence state reached its agent limit")
	}
	if err := s.save(candidate); err != nil {
		return transport.Receipt{}, err
	}
	s.agents = candidate
	return transport.Receipt{Status: "accepted", TenantID: batch.TenantID, AgentID: batch.AgentID, Sequence: batch.Sequence, PayloadSHA256: batch.PayloadSHA256, ReceivedAt: now}, nil
}

func (s *BatchStore) appendRecord(record acceptedRecord) error {
	content, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode accepted evidence record: %w", err)
	}
	file, err := os.OpenFile(s.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open accepted evidence log: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure accepted evidence log: %w", err)
	}
	if _, err := file.Write(append(content, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("append accepted evidence log: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync accepted evidence log: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close accepted evidence log: %w", err)
	}
	return nil
}

func (s *BatchStore) save(agents map[string]AgentState) error {
	values := make([]AgentState, 0, len(agents))
	for _, agent := range agents {
		values = append(values, agent)
	}
	sortAgentStates(values)
	payloadHash, err := gatewayStateHash(values)
	if err != nil {
		return err
	}
	envelope := gatewayStateEnvelope{Version: gatewayStateVersion, Agents: values, PayloadSHA256: payloadHash}
	content, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("encode gateway sequence state: %w", err)
	}
	if len(content) > maxGatewayStateBytes {
		return errors.New("gateway sequence state exceeds size limit")
	}
	return atomicPrivateWrite(s.statePath, append(content, '\n'))
}

func gatewayStateHash(values []AgentState) (string, error) {
	content, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("encode gateway state payload: %w", err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func identityKey(tenantID, agentID string) string {
	return tenantID + "\x00" + agentID
}

func sortAgentStates(values []AgentState) {
	for index := 1; index < len(values); index++ {
		current := values[index]
		position := index - 1
		for position >= 0 && identityKey(values[position].TenantID, values[position].AgentID) > identityKey(current.TenantID, current.AgentID) {
			values[position+1] = values[position]
			position--
		}
		values[position+1] = current
	}
}
