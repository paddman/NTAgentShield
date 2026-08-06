package outbox

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/paddman/NTAgentShield/internal/transport"
)

type Sender interface {
	Send(context.Context, transport.Batch) (transport.Receipt, error)
}

func (s *Store) DeliverNext(ctx context.Context, sender Sender, now time.Time) (DeliveryResult, error) {
	if sender == nil {
		return DeliveryResult{}, errors.New("evidence sender is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return DeliveryResult{}, err
	}
	if len(s.state.Pending) == 0 {
		return DeliveryResult{}, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	pending := s.state.Pending[0]
	if pending.Blocked {
		return DeliveryResult{Blocked: true}, nil
	}
	if !pending.NextAttemptAt.IsZero() && now.Before(pending.NextAttemptAt) {
		return DeliveryResult{}, nil
	}
	spool, _, err := loadSpool(filepath.Join(s.spoolDir, pending.FileName))
	if err != nil {
		return DeliveryResult{}, err
	}
	if spool.Batch.Sequence != pending.Sequence || spool.Batch.PayloadSHA256 != pending.PayloadSHA256 {
		return DeliveryResult{}, errors.New("pending state does not match spool batch")
	}
	receipt, sendErr := sender.Send(ctx, spool.Batch)
	if sendErr != nil {
		candidate := cloneState(s.state)
		candidatePending := candidate.Pending[0]
		candidatePending.Attempts++
		candidatePending.LastAttemptAt = now
		candidatePending.LastErrorCode = deliveryErrorCode(sendErr)
		candidatePending.Blocked = !retryableDeliveryError(sendErr)
		if !candidatePending.Blocked {
			candidatePending.NextAttemptAt = now.Add(s.retryDelay(candidatePending))
		} else {
			candidatePending.NextAttemptAt = time.Time{}
		}
		candidate.Pending[0] = candidatePending
		if err := s.saveState(candidate); err != nil {
			return DeliveryResult{Attempted: true, Blocked: candidatePending.Blocked}, fmt.Errorf("persist outbox delivery failure: %w", err)
		}
		return DeliveryResult{Attempted: true, Blocked: candidatePending.Blocked}, sendErr
	}
	if receipt.TenantID != s.state.TenantID || receipt.AgentID != s.state.AgentID || receipt.Sequence != pending.Sequence || receipt.PayloadSHA256 != pending.PayloadSHA256 {
		return DeliveryResult{Attempted: true}, errors.New("gateway receipt does not match pending outbox batch")
	}
	if receipt.Status != "accepted" && receipt.Status != "duplicate" {
		return DeliveryResult{Attempted: true}, fmt.Errorf("gateway returned unsupported receipt status %q", receipt.Status)
	}
	candidate := cloneState(s.state)
	candidate.LastAckedSequence = pending.Sequence
	candidate.LastAckedHash = pending.PayloadSHA256
	candidate.Pending = append([]Pending(nil), candidate.Pending[1:]...)
	if err := s.saveState(candidate); err != nil {
		return DeliveryResult{Attempted: true}, fmt.Errorf("persist outbox acknowledgement: %w", err)
	}
	removeErr := os.Remove(filepath.Join(s.spoolDir, pending.FileName))
	result := DeliveryResult{
		Attempted: true,
		Delivered: true,
		Duplicate: receipt.Status == "duplicate",
		Receipt:   receipt,
	}
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return result, fmt.Errorf("remove acknowledged spool file: %w", removeErr)
	}
	return result, nil
}

func (s *Store) Unblock(sequence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return err
	}
	candidate := cloneState(s.state)
	for index := range candidate.Pending {
		if candidate.Pending[index].Sequence != sequence {
			continue
		}
		candidate.Pending[index].Blocked = false
		candidate.Pending[index].NextAttemptAt = time.Time{}
		candidate.Pending[index].LastErrorCode = ""
		return s.saveState(candidate)
	}
	return fmt.Errorf("pending outbox sequence %d was not found", sequence)
}

func retryableDeliveryError(err error) bool {
	var gatewayError *transport.GatewayError
	if errors.As(err, &gatewayError) {
		return gatewayError.Retryable()
	}
	return true
}

func deliveryErrorCode(err error) string {
	var gatewayError *transport.GatewayError
	if errors.As(err, &gatewayError) {
		if gatewayError.Code != "" {
			return gatewayError.Code
		}
		return fmt.Sprintf("http_%d", gatewayError.StatusCode)
	}
	return "transport_error"
}

func (s *Store) retryDelay(pending Pending) time.Duration {
	attempt := pending.Attempts
	if attempt == 0 {
		attempt = 1
	}
	delay := s.config.BaseBackoff
	for count := uint32(1); count < attempt && delay < s.config.MaxBackoff; count++ {
		if delay > s.config.MaxBackoff/2 {
			delay = s.config.MaxBackoff
			break
		}
		delay *= 2
	}
	if delay > s.config.MaxBackoff {
		delay = s.config.MaxBackoff
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", pending.PayloadSHA256, pending.Attempts)))
	jitterRange := delay / 5
	if jitterRange <= 0 {
		return delay
	}
	jitter := time.Duration(binary.BigEndian.Uint64(digest[:8]) % uint64(jitterRange+1))
	if delay+jitter > s.config.MaxBackoff {
		return s.config.MaxBackoff
	}
	return delay + jitter
}
