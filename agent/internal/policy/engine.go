package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
)

type Policy struct {
	Version                 string   `json:"version"`
	DenyTools               []string `json:"deny_tools"`
	AutoAllowTools          []string `json:"auto_allow_tools"`
	ApprovalRequiredTools   []string `json:"approval_required_tools"`
	NeverAllowDestructive   bool     `json:"never_allow_destructive"`
	DenyUntrustedStateWrite bool     `json:"deny_untrusted_state_write"`
	MaxActionTTLSeconds     int      `json:"max_action_ttl_seconds"`
}

func Default() Policy {
	return Policy{
		Version:                 "1",
		DenyTools:               []string{"shell.exec", "powershell.exec", "cmd.exec"},
		AutoAllowTools:          []string{"host.info", "file.stat", "file.sha256", "file.read_lines"},
		ApprovalRequiredTools:   []string{"host.isolate", "process.terminate", "file.quarantine", "firewall.block"},
		NeverAllowDestructive:   true,
		DenyUntrustedStateWrite: true,
		MaxActionTTLSeconds:     300,
	}
}

func Load(path string) (Policy, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	policy := Default()
	if err := json.Unmarshal(content, &policy); err != nil {
		return Policy{}, fmt.Errorf("decode policy: %w", err)
	}
	if policy.Version == "" {
		return Policy{}, errors.New("policy version is required")
	}
	if policy.MaxActionTTLSeconds <= 0 {
		policy.MaxActionTTLSeconds = 300
	}
	return policy, nil
}

type Engine struct {
	policy Policy
}

func New(policy Policy) *Engine {
	return &Engine{policy: policy}
}

func (e *Engine) Evaluate(request model.ActionRequest) model.Decision {
	request.Prepare()
	now := time.Now().UTC()
	decision := model.Decision{EvaluatedAt: now, Risk: request.Risk}

	if slices.Contains(e.policy.DenyTools, request.Tool) {
		decision.Reason = "tool is explicitly denied by policy"
		return decision
	}
	if request.ExpiresAt.IsZero() {
		request.ExpiresAt = request.RequestedAt.Add(time.Duration(e.policy.MaxActionTTLSeconds) * time.Second)
	}
	if request.ExpiresAt.Before(now) {
		decision.Reason = "action request expired"
		return decision
	}
	maxExpiry := request.RequestedAt.Add(time.Duration(e.policy.MaxActionTTLSeconds) * time.Second)
	if request.ExpiresAt.After(maxExpiry) {
		decision.Reason = "action request exceeds maximum TTL"
		return decision
	}
	if e.policy.NeverAllowDestructive && request.Risk == model.RiskDestructive {
		decision.Reason = "destructive actions are disabled in the foundation policy"
		return decision
	}
	if e.policy.DenyUntrustedStateWrite && request.TriggerTrust.IsUntrusted() && request.Risk != model.RiskObserve {
		decision.Reason = "untrusted evidence cannot directly trigger a state-changing action"
		return decision
	}
	if request.Risk == model.RiskObserve && slices.Contains(e.policy.AutoAllowTools, request.Tool) {
		decision.Allowed = true
		decision.Reason = "read-only tool is auto-allowed"
		return decision
	}
	if request.Risk == model.RiskObserve && request.Mode == model.ModeObserve {
		decision.Allowed = true
		decision.Reason = "read-only action allowed in observe mode"
		return decision
	}

	requiresApproval := request.Risk == model.RiskContain || request.Risk == model.RiskModify || slices.Contains(e.policy.ApprovalRequiredTools, request.Tool)
	if requiresApproval {
		decision.RequiresApproval = true
		if request.Approval == nil {
			decision.Reason = "operator approval is required"
			return decision
		}
		digest, err := ActionDigest(request)
		if err != nil {
			decision.Reason = "unable to calculate action digest"
			return decision
		}
		if request.Approval.ActionDigest != digest || request.Approval.ExpiresAt.Before(now) || request.Approval.ApprovedBy == "" {
			decision.Reason = "approval does not match this exact action or has expired"
			return decision
		}
		decision.Allowed = true
		decision.Reason = "exact action approved by operator"
		return decision
	}
	decision.Reason = "tool is not allowed by the active policy"
	return decision
}

func ActionDigest(request model.ActionRequest) (string, error) {
	canonical := struct {
		Tool         string                 `json:"tool"`
		Args         map[string]interface{} `json:"args"`
		Reason       string                 `json:"reason"`
		Risk         model.ActionRisk       `json:"risk"`
		TriggerTrust model.TrustLevel       `json:"trigger_trust"`
	}{
		Tool:         request.Tool,
		Args:         request.Args,
		Reason:       request.Reason,
		Risk:         request.Risk,
		TriggerTrust: request.TriggerTrust,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
