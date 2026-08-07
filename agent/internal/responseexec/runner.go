package responseexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
	"github.com/paddman/NTAgentShield/internal/tools"
)

type RunnerOptions struct {
	DataDir           string
	AgentID           string
	TenantID          string
	PolicyFile        string
	AllowedPaths      []string
	TransportEndpoint string
	CertFile          string
	KeyFile           string
	CAFile            string
	ServerName        string
	Timeout           time.Duration
	Interval          time.Duration
}

type Runner struct {
	options RunnerOptions
	client  *Client
	ledger  *Ledger
}

type ResultPayload struct {
	ActionID       string                 `json:"action_id"`
	TenantID       string                 `json:"tenant_id"`
	AgentID        string                 `json:"agent_id"`
	Tool           string                 `json:"tool"`
	Status         string                 `json:"status"`
	DecisionReason string                 `json:"decision_reason"`
	Error          *string                `json:"error"`
	ExecutedAt     time.Time              `json:"executed_at"`
	Data           map[string]interface{} `json:"data"`
}

func NewRunner(options RunnerOptions) (*Runner, error) {
	if options.Interval <= 0 {
		options.Interval = 5 * time.Second
	}
	trustRoot := filepath.Join(options.DataDir, "response-signing.pub")
	client, err := NewClient(ClientOptions{
		TransportEndpoint: options.TransportEndpoint,
		AgentID:           options.AgentID,
		TenantID:          options.TenantID,
		CertFile:          options.CertFile,
		KeyFile:           options.KeyFile,
		CAFile:            options.CAFile,
		ServerName:        options.ServerName,
		TrustRootFile:     trustRoot,
		Timeout:           options.Timeout,
	})
	if err != nil {
		return nil, err
	}
	ledger, err := OpenLedger(filepath.Join(options.DataDir, "response-ledger.json"), options.KeyFile)
	if err != nil {
		return nil, err
	}
	return &Runner{options: options, client: client, ledger: ledger}, nil
}

func (r *Runner) Run(ctx context.Context, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	if err := r.client.EnsureTrustRoot(ctx); err != nil {
		logger.Printf("response broker trust bootstrap unavailable: %v", err)
	}
	r.sync(ctx, logger)
	ticker := time.NewTicker(r.options.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sync(ctx, logger)
		}
	}
}

func (r *Runner) sync(ctx context.Context, logger *log.Logger) {
	if err := r.client.EnsureTrustRoot(ctx); err != nil {
		logger.Printf("response broker trust check rejected/error: %v", err)
		return
	}
	bundle, err := r.client.Fetch(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			logger.Printf("response broker fetch error: %v", err)
		}
		return
	}
	if bundle == nil {
		return
	}
	lease, err := VerifyLease(
		*bundle,
		filepath.Join(r.options.DataDir, "response-signing.pub"),
		r.options.TenantID,
		r.options.AgentID,
		time.Now().UTC(),
	)
	if err != nil {
		logger.Printf("response lease rejected: %v", err)
		return
	}
	request, digest, err := lease.ActionRequest()
	if err != nil {
		logger.Printf("response action rejected: %v", err)
		return
	}

	stored, replay, beginErr := r.ledger.Begin(lease.ActionID, digest)
	if beginErr == nil && replay {
		if err := r.client.PostResult(ctx, lease.ActionID, stored); err != nil {
			logger.Printf("response result replay ACK failed action=%s: %v", lease.ActionID, err)
		}
		return
	}
	if errors.Is(beginErr, ErrIndeterminate) {
		result := resultJSON(lease, "failed", "action state is indeterminate after restart; duplicate execution refused", ErrIndeterminate, nil)
		if err := r.ledger.Complete(lease.ActionID, digest, result); err != nil {
			logger.Printf("response indeterminate result persistence failed action=%s: %v", lease.ActionID, err)
			return
		}
		if err := r.client.PostResult(ctx, lease.ActionID, result); err != nil {
			logger.Printf("response indeterminate ACK failed action=%s: %v", lease.ActionID, err)
		}
		return
	}
	if beginErr != nil {
		logger.Printf("response replay ledger rejected action=%s: %v", lease.ActionID, beginErr)
		return
	}

	result := r.execute(ctx, lease, request)
	if err := r.ledger.Complete(lease.ActionID, digest, result); err != nil {
		logger.Printf("response result persistence failed action=%s; action will not be re-executed: %v", lease.ActionID, err)
		return
	}
	if err := r.client.PostResult(ctx, lease.ActionID, result); err != nil {
		logger.Printf("response result ACK failed action=%s; durable result will be retried: %v", lease.ActionID, err)
		return
	}
	logger.Printf("response action terminal action=%s tool=%s", lease.ActionID, lease.Tool)
}

func (r *Runner) execute(ctx context.Context, lease Lease, request model.ActionRequest) []byte {
	registry, err := tools.NewFoundationRegistry(r.options.PolicyFile, r.options.AllowedPaths)
	if err != nil {
		return resultJSON(lease, "failed", "unable to load active local policy/tool registry", err, nil)
	}
	var declaredRisk model.ActionRisk
	found := false
	for _, spec := range registry.Specs() {
		if spec.Name == lease.Tool {
			declaredRisk = spec.Risk
			found = true
			break
		}
	}
	if !found {
		return resultJSON(lease, "rejected", "response tool is not registered on this Agent", nil, nil)
	}
	if declaredRisk != lease.Risk {
		return resultJSON(lease, "rejected", "signed response risk does not match local tool risk", nil, nil)
	}
	result, decision, execErr := registry.Execute(ctx, request)
	if !decision.Allowed {
		return resultJSON(lease, "rejected", decision.Reason, nil, nil)
	}
	if execErr != nil {
		return resultJSON(lease, "failed", decision.Reason, execErr, nil)
	}
	data := map[string]interface{}{}
	if result.Data != nil {
		if mapped, ok := result.Data.(map[string]interface{}); ok {
			data = mapped
		} else {
			data["value"] = result.Data
		}
	}
	return resultJSON(lease, "succeeded", decision.Reason, nil, data)
}

func resultJSON(lease Lease, status, reason string, err error, data map[string]interface{}) []byte {
	if data == nil {
		data = map[string]interface{}{}
	}
	var errorText *string
	if err != nil {
		text := err.Error()
		errorText = &text
	}
	payload := ResultPayload{
		ActionID:       lease.ActionID,
		TenantID:       lease.TenantID,
		AgentID:        lease.AgentID,
		Tool:           lease.Tool,
		Status:         status,
		DecisionReason: reason,
		Error:          errorText,
		ExecutedAt:     time.Now().UTC(),
		Data:           data,
	}
	encoded, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		return []byte(fmt.Sprintf(`{"action_id":%q,"tenant_id":%q,"agent_id":%q,"tool":%q,"status":"failed","decision_reason":"result encoding failed","error":%q,"executed_at":%q,"data":{}}`, lease.ActionID, lease.TenantID, lease.AgentID, lease.Tool, marshalErr.Error(), time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return encoded
}
