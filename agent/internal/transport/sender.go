package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
	"github.com/paddman/NTAgentShield/internal/identity"
)

const maxTransportResponseBytes = 1 << 20

type SenderOptions struct {
	Endpoint   string
	AgentID    string
	TenantID   string
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
	Timeout    time.Duration
}

type Sender struct {
	options    SenderOptions
	outbox     *Outbox
	privateKey ed25519.PrivateKey
	client     *http.Client
}

type FlushResult struct {
	Sent       int `json:"sent"`
	DeadLetter int `json:"dead_letter"`
	Attempted  int `json:"attempted"`
}

func NewSender(outbox *Outbox, options SenderOptions) (*Sender, error) {
	if outbox == nil {
		return nil, errors.New("telemetry sender requires an outbox")
	}
	if strings.TrimSpace(options.Endpoint) == "" || strings.TrimSpace(options.AgentID) == "" || strings.TrimSpace(options.TenantID) == "" {
		return nil, errors.New("telemetry sender requires endpoint, agent_id, and tenant_id")
	}
	if options.Timeout < time.Second || options.Timeout > 2*time.Minute {
		return nil, errors.New("telemetry sender timeout must be between 1s and 2m")
	}
	privateKey, err := identity.Load(options.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load telemetry signing key: %w", err)
	}
	tlsConfig, err := enrollment.ClientTLSConfig(options.CertFile, options.KeyFile, options.CAFile, options.ServerName)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   min(10*time.Second, options.Timeout),
		ResponseHeaderTimeout: options.Timeout,
	}
	return &Sender{
		options:    options,
		outbox:     outbox,
		privateKey: privateKey,
		client:     &http.Client{Timeout: options.Timeout, Transport: transport},
	}, nil
}

func (s *Sender) Flush(ctx context.Context, limit int) (FlushResult, error) {
	items, err := s.outbox.Peek(limit)
	if err != nil {
		return FlushResult{}, err
	}
	result := FlushResult{}
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		result.Attempted++
		mapped := MapEvent(item.Event)
		if mapped.AgentID != s.options.AgentID || mapped.TenantID != s.options.TenantID {
			reason := fmt.Sprintf("queued event identity %q/%q does not match transport identity %q/%q", mapped.TenantID, mapped.AgentID, s.options.TenantID, s.options.AgentID)
			if err := s.outbox.DeadLetter(item, reason); err != nil {
				return result, err
			}
			result.DeadLetter++
			continue
		}
		body, err := json.Marshal(mapped)
		if err != nil {
			if deadErr := s.outbox.DeadLetter(item, "map event payload: "+err.Error()); deadErr != nil {
				return result, deadErr
			}
			result.DeadLetter++
			continue
		}
		signature := base64.StdEncoding.EncodeToString(ed25519.Sign(s.privateKey, body))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.options.Endpoint, bytes.NewReader(body))
		if err != nil {
			return result, fmt.Errorf("create telemetry request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-NTShield-Agent-ID", s.options.AgentID)
		req.Header.Set("X-NTShield-Tenant-ID", s.options.TenantID)
		req.Header.Set("X-NTShield-Signature", signature)
		resp, err := s.client.Do(req)
		if err != nil {
			return result, fmt.Errorf("send telemetry: %w", err)
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxTransportResponseBytes))
		closeErr := resp.Body.Close()
		if readErr != nil {
			return result, fmt.Errorf("read telemetry response: %w", readErr)
		}
		if closeErr != nil {
			return result, fmt.Errorf("close telemetry response: %w", closeErr)
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if err := s.outbox.Ack(item); err != nil {
				return result, err
			}
			result.Sent++
			continue
		}
		responseText := strings.TrimSpace(string(responseBody))
		if permanentPayloadFailure(resp.StatusCode) {
			reason := fmt.Sprintf("Control Plane rejected event with HTTP %d: %s", resp.StatusCode, responseText)
			if err := s.outbox.DeadLetter(item, reason); err != nil {
				return result, err
			}
			result.DeadLetter++
			continue
		}
		return result, fmt.Errorf("Control Plane transport HTTP %d: %s", resp.StatusCode, responseText)
	}
	return result, nil
}

func permanentPayloadFailure(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
