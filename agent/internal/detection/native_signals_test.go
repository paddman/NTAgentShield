package detection

import (
	"testing"

	"github.com/paddman/NTAgentShield/internal/model"
)

func TestNativeHighSignalRule(t *testing.T) {
	rule := nativeHighSignalRule{}
	testCases := []struct {
		kind       string
		message    string
		ruleID     string
		severity   model.Severity
		shouldFind bool
	}{
		{"security.log_clear", "The audit log was cleared", "NTS-NATIVE-001", model.SeverityCritical, true},
		{"process.tamper", "Process image changed", "NTS-NATIVE-002", model.SeverityCritical, true},
		{"process.remote_thread", "CreateRemoteThread", "NTS-NATIVE-003", model.SeverityHigh, true},
		{"persistence.scheduled_task", "Task created", "NTS-NATIVE-004", model.SeverityHigh, true},
		{"service.create", "Service installed", "NTS-NATIVE-005", model.SeverityHigh, true},
		{"identity.account_create", "User created", "NTS-NATIVE-006", model.SeverityHigh, true},
		{"security.audit_config", "audit_enabled=0", "NTS-NATIVE-007", model.SeverityCritical, true},
		{"security.audit_config", "audit rule added", "", "", false},
	}
	for _, testCase := range testCases {
		event := model.Event{Kind: testCase.kind, Message: testCase.message, Trust: model.TrustUntrustedTelemetry}
		event.Prepare()
		findings := rule.Evaluate(event)
		if !testCase.shouldFind {
			if len(findings) != 0 {
				t.Fatalf("kind %s unexpectedly produced findings: %#v", testCase.kind, findings)
			}
			continue
		}
		if len(findings) != 1 {
			t.Fatalf("kind %s expected one finding, got %d", testCase.kind, len(findings))
		}
		if findings[0].RuleID != testCase.ruleID || findings[0].Severity != testCase.severity {
			t.Fatalf("kind %s produced unexpected finding: %#v", testCase.kind, findings[0])
		}
	}
}

func TestDetectionEngineIncludesNativeHighSignalRule(t *testing.T) {
	engine := New()
	event := model.Event{Kind: "security.log_clear", Message: "Security log cleared", Trust: model.TrustUntrustedTelemetry}
	event.Prepare()
	findings := engine.Inspect(event)
	found := false
	for _, finding := range findings {
		if finding.RuleID == "NTS-NATIVE-001" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("native high-signal rule is not registered in the detection engine")
	}
}
