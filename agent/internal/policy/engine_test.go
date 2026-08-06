package policy

import (
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
)

func TestDenyUntrustedStateChange(t *testing.T) {
	engine := New(Default())
	request := model.ActionRequest{
		Tool:         "host.isolate",
		Risk:         model.RiskContain,
		Mode:         model.ModeAuto,
		TriggerTrust: model.TrustUntrustedTelemetry,
		RequestedAt:  time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Minute),
	}
	decision := engine.Evaluate(request)
	if decision.Allowed {
		t.Fatal("untrusted telemetry must not directly trigger containment")
	}
}

func TestAllowReadOnlyTool(t *testing.T) {
	engine := New(Default())
	request := model.ActionRequest{
		Tool:         "file.sha256",
		Risk:         model.RiskObserve,
		Mode:         model.ModeObserve,
		TriggerTrust: model.TrustUntrustedTelemetry,
		RequestedAt:  time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Minute),
	}
	decision := engine.Evaluate(request)
	if !decision.Allowed {
		t.Fatalf("read-only tool should be allowed: %s", decision.Reason)
	}
}

func TestApprovalBoundToExactAction(t *testing.T) {
	engine := New(Default())
	request := model.ActionRequest{
		Tool:         "host.isolate",
		Args:         map[string]interface{}{"duration_seconds": 300},
		Reason:       "confirmed incident",
		Risk:         model.RiskContain,
		Mode:         model.ModeAct,
		TriggerTrust: model.TrustOperator,
		RequestedAt:  time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Minute),
	}
	digest, err := ActionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Approval = &model.Approval{
		ID:           "approval-1",
		ActionDigest: digest,
		ApprovedBy:   "analyst@example.com",
		ApprovedAt:   time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Minute),
	}
	if decision := engine.Evaluate(request); !decision.Allowed {
		t.Fatalf("approved exact action should be allowed: %s", decision.Reason)
	}
	request.Args["duration_seconds"] = 600
	if decision := engine.Evaluate(request); decision.Allowed {
		t.Fatal("modified action must invalidate approval")
	}
}
