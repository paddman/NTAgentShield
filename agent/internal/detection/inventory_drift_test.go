package detection

import (
	"testing"

	"github.com/paddman/NTAgentShield/internal/model"
)

func TestInventoryDriftRule(t *testing.T) {
	rule := inventoryDriftRule{}
	testCases := []struct {
		kind     string
		severity model.Severity
		port     int
		ruleID   string
		find     bool
	}{
		{"security.inventory_baseline_integrity", model.SeverityCritical, 0, "NTS-DRIFT-001", true},
		{"security.control_disabled", model.SeverityCritical, 0, "NTS-DRIFT-002", true},
		{"asset.listener_added", model.SeverityHigh, 3389, "NTS-DRIFT-003", true},
		{"asset.listener_added", model.SeverityLow, 8080, "", false},
		{"asset.process_image_added", model.SeverityHigh, 0, "NTS-DRIFT-004", true},
		{"asset.service_added", model.SeverityMedium, 0, "NTS-DRIFT-005", true},
		{"asset.service_added", model.SeverityLow, 0, "", false},
		{"asset.inventory_delta_truncated", model.SeverityMedium, 0, "NTS-DRIFT-006", true},
	}
	for _, testCase := range testCases {
		event := model.Event{
			Kind:     testCase.kind,
			Severity: testCase.severity,
			Trust:    model.TrustUntrustedTelemetry,
			Network:  model.NetworkContext{DestinationPort: testCase.port},
		}
		event.Prepare()
		findings := rule.Evaluate(event)
		if !testCase.find {
			if len(findings) != 0 {
				t.Fatalf("kind %s unexpectedly produced findings: %#v", testCase.kind, findings)
			}
			continue
		}
		if len(findings) != 1 || findings[0].RuleID != testCase.ruleID {
			t.Fatalf("kind %s produced unexpected finding: %#v", testCase.kind, findings)
		}
	}
}

func TestDetectionEngineIncludesInventoryDriftRule(t *testing.T) {
	engine := New()
	event := model.Event{Kind: "security.control_removed", Severity: model.SeverityCritical, Trust: model.TrustUntrustedTelemetry}
	event.Prepare()
	findings := engine.Inspect(event)
	for _, finding := range findings {
		if finding.RuleID == "NTS-DRIFT-002" {
			return
		}
	}
	t.Fatal("inventory drift rule is not registered in the detection engine")
}
