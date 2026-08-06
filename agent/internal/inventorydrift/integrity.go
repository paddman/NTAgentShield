package inventorydrift

import (
	"path/filepath"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
)

func IntegrityEvent(hostname, osName string, warning error, quarantinedPath string) model.Event {
	reason := "inventory baseline failed integrity validation"
	if warning != nil {
		reason = warning.Error()
	}
	quarantined := filepath.Base(quarantinedPath)
	event := model.Event{
		ID:        driftEventID("security.inventory_baseline_integrity", hostname, quarantined, reason),
		Timestamp: time.Now().UTC(),
		Kind:      "security.inventory_baseline_integrity",
		Severity:  model.SeverityCritical,
		Trust:     model.TrustSystem,
		Asset:     model.Asset{Hostname: hostname, OS: osName},
		Message:   "Inventory baseline failed integrity validation and was quarantined",
		Attributes: map[string]interface{}{
			"local_state": map[string]interface{}{
				"component":        "inventory-drift",
				"reason":           reason,
				"quarantined_file": quarantined,
			},
		},
		Provenance: model.Provenance{Source: "local-state", Collector: "inventory-drift"},
	}
	event.Prepare()
	return event
}
