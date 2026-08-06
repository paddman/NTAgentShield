package detection

import (
	"fmt"

	"github.com/paddman/NTAgentShield/internal/model"
)

type inventoryDriftRule struct{}

func (inventoryDriftRule) ID() string { return "NTS-DRIFT-001" }

func (r inventoryDriftRule) Evaluate(event model.Event) []model.Finding {
	switch event.Kind {
	case "security.inventory_baseline_integrity":
		finding := model.NewFinding(event, r.ID(), "Inventory baseline integrity failure", "The local inventory baseline failed integrity validation and was quarantined. This can be accidental corruption or an attempt to hide host drift.", "defense_evasion.local_state_tamper", model.SeverityCritical, 97)
		finding.MITRETactics = []string{"Defense Evasion"}
		finding.MITRETechniques = []string{"T1562.001"}
		finding.RecommendedSteps = []string{"Preserve the quarantined baseline and hash-chained evidence journal", "Inspect local file ownership, ACLs, and recent administrative activity", "Allow the agent to establish a fresh baseline only after the integrity alert is reviewed"}
		return []model.Finding{finding}
	case "security.control_removed", "security.control_disabled":
		finding := model.NewFinding(event, "NTS-DRIFT-002", "Security control was removed or disabled", "Inventory drift indicates that a security-related service or software component disappeared, stopped, or became disabled.", "defense_evasion.security_control_drift", model.SeverityCritical, 94)
		finding.MITRETactics = []string{"Defense Evasion"}
		finding.MITRETechniques = []string{"T1562.001"}
		finding.RecommendedSteps = []string{"Identify the service or software change and the responsible account", "Correlate the drift timestamp with process, audit, and authentication telemetry", "Restore protection only through an approved response policy"}
		return []model.Finding{finding}
	case "asset.listener_added", "asset.listener_owner_changed":
		if event.Severity != model.SeverityHigh && event.Severity != model.SeverityCritical {
			return nil
		}
		title := fmt.Sprintf("New or changed exposed listener on port %d", event.Network.DestinationPort)
		finding := model.NewFinding(event, "NTS-DRIFT-003", title, "A new externally reachable or security-sensitive listening socket appeared, or its owning process image changed.", "exposure.listener_drift", event.Severity, 88)
		finding.MITRETactics = []string{"Persistence", "Command and Control"}
		finding.RecommendedSteps = []string{"Identify the owning process and executable signature", "Verify the port against the approved service topology", "Correlate service creation, process start, and inbound connection telemetry"}
		return []model.Finding{finding}
	case "asset.process_image_added":
		finding := model.NewFinding(event, "NTS-DRIFT-004", "New process image from a writable location", "A previously unseen process image is running from a temporary or user-writable path. This is common in software deployment but also in exploitation and persistence.", "execution.writable_path_image", model.SeverityHigh, 84)
		finding.MITRETactics = []string{"Execution", "Persistence"}
		finding.RecommendedSteps = []string{"Hash and inspect the executable", "Review signer, owner, creation time, and parent process", "Correlate new listeners and outbound connections from the same asset"}
		return []model.Finding{finding}
	case "asset.service_added":
		if event.Severity == model.SeverityInfo || event.Severity == model.SeverityLow {
			return nil
		}
		finding := model.NewFinding(event, "NTS-DRIFT-005", "New active or automatic service detected", "A service appeared in inventory already running or configured for automatic start.", "persistence.service_inventory_drift", model.SeverityMedium, 76)
		finding.MITRETactics = []string{"Persistence", "Privilege Escalation"}
		finding.MITRETechniques = []string{"T1543.003"}
		finding.RecommendedSteps = []string{"Compare the service against the approved asset baseline", "Inspect the binary path and signer", "Correlate service installation and process telemetry"}
		return []model.Finding{finding}
	case "asset.inventory_delta_truncated":
		finding := model.NewFinding(event, "NTS-DRIFT-006", "Inventory changed beyond the configured event cap", "The number of inventory changes exceeded the per-scan drift event cap. A large deployment may be legitimate; mass tampering or data-quality failure must also be considered.", "inventory.mass_change", model.SeverityMedium, 72)
		finding.RecommendedSteps = []string{"Review the complete inventory snapshot and deployment window", "Check whether collection was truncated or asset identity changed", "Increase the cap only after validating expected change volume"}
		return []model.Finding{finding}
	default:
		return nil
	}
}
