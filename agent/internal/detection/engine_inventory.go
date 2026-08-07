package detection

import "github.com/paddman/NTAgentShield/internal/inventory"

func (e *Engine) SeedInventoryBaseline(snapshot inventory.Snapshot) bool {
	for _, rule := range e.rules {
		tracker, ok := rule.(*inventoryDriftRule)
		if !ok {
			continue
		}
		tracker.seed(snapshot)
		return true
	}
	return false
}

func (r *inventoryDriftRule) seed(snapshot inventory.Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.previous = snapshot
	r.initialized = true
}
