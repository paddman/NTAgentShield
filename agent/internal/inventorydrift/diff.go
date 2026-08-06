package inventorydrift

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/inventory"
	"github.com/paddman/NTAgentShield/internal/model"
)

type inventoryEvent struct {
	sortKey string
	event   model.Event
}

type inventoryEvents []inventoryEvent

func (values inventoryEvents) events() []model.Event {
	result := make([]model.Event, 0, len(values))
	for _, value := range values {
		result = append(result, value.event)
	}
	return result
}

func compare(previous, current Baseline, timestamp time.Time, previousHash, currentHash string) inventoryEvents {
	changes := make(inventoryEvents, 0)
	if previous.Complete.Services && current.Complete.Services {
		changes = append(changes, compareServices(previous, current, timestamp, previousHash, currentHash)...)
	}
	if previous.Complete.Listeners && current.Complete.Listeners {
		changes = append(changes, compareListeners(previous, current, timestamp, previousHash, currentHash)...)
	}
	if previous.Complete.Software && current.Complete.Software {
		changes = append(changes, compareSoftware(previous, current, timestamp, previousHash, currentHash)...)
	}
	if previous.Complete.Interfaces && current.Complete.Interfaces {
		changes = append(changes, compareInterfaces(previous, current, timestamp, previousHash, currentHash)...)
	}
	if previous.Complete.ProcessImages && current.Complete.ProcessImages {
		changes = append(changes, compareProcessImages(previous, current, timestamp, previousHash, currentHash)...)
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].sortKey < changes[j].sortKey })
	return changes
}

func compareServices(previous, current Baseline, timestamp time.Time, previousHash, currentHash string) inventoryEvents {
	before := serviceMap(previous.Services)
	after := serviceMap(current.Services)
	changes := make(inventoryEvents, 0)
	for key, service := range after {
		old, exists := before[key]
		if !exists {
			severity := model.SeverityLow
			if serviceRunning(service) || serviceAutomatic(service) {
				severity = model.SeverityMedium
			}
			changes = append(changes, newDriftEvent("asset.service_added", severity, timestamp, current, key, nil, service, previousHash, currentHash, "A system service appeared in the host inventory"))
			continue
		}
		if old.State == service.State && old.StartMode == service.StartMode && old.DisplayName == service.DisplayName {
			continue
		}
		kind := "asset.service_changed"
		severity := model.SeverityInfo
		message := "A system service changed state or start mode"
		if isSecurityProduct(service.Name+" "+service.DisplayName) && serviceStopped(service) {
			kind = "security.control_disabled"
			severity = model.SeverityCritical
			message = "A security-related service stopped or became disabled"
		} else if serviceStopped(service) || serviceAutomatic(service) != serviceAutomatic(old) {
			severity = model.SeverityMedium
		}
		changes = append(changes, newDriftEvent(kind, severity, timestamp, current, key, old, service, previousHash, currentHash, message))
	}
	for key, service := range before {
		if _, exists := after[key]; exists {
			continue
		}
		kind := "asset.service_removed"
		severity := model.SeverityLow
		message := "A system service disappeared from the host inventory"
		if isSecurityProduct(service.Name + " " + service.DisplayName) {
			kind = "security.control_removed"
			severity = model.SeverityCritical
			message = "A security-related service disappeared from the host inventory"
		}
		changes = append(changes, newDriftEvent(kind, severity, timestamp, current, key, service, nil, previousHash, currentHash, message))
	}
	return changes
}

func compareListeners(previous, current Baseline, timestamp time.Time, previousHash, currentHash string) inventoryEvents {
	before := listenerMap(previous.Listeners)
	after := listenerMap(current.Listeners)
	changes := make(inventoryEvents, 0)
	for key, listener := range after {
		old, exists := before[key]
		if exists {
			if old.ProcessImage != listener.ProcessImage && listener.ProcessImage != "" {
				severity := model.SeverityMedium
				if listener.Exposed && suspiciousExecutablePath(current.OS, listener.ProcessImage) {
					severity = model.SeverityHigh
				}
				change := newDriftEvent("asset.listener_owner_changed", severity, timestamp, current, key, old, listener, previousHash, currentHash, "The process image owning a listening socket changed")
				change.event.Network = listenerNetwork(listener)
				change.event.Process.Image = listener.ProcessImage
				changes = append(changes, change)
			}
			continue
		}
		severity := model.SeverityLow
		if listener.Exposed {
			severity = model.SeverityMedium
		}
		if listener.Exposed && (listener.Sensitive || suspiciousExecutablePath(current.OS, listener.ProcessImage)) {
			severity = model.SeverityHigh
		}
		change := newDriftEvent("asset.listener_added", severity, timestamp, current, key, nil, listener, previousHash, currentHash, "A new listening socket appeared in the host inventory")
		change.event.Network = listenerNetwork(listener)
		change.event.Process.Image = listener.ProcessImage
		changes = append(changes, change)
	}
	for key, listener := range before {
		if _, exists := after[key]; exists {
			continue
		}
		change := newDriftEvent("asset.listener_removed", model.SeverityInfo, timestamp, current, key, listener, nil, previousHash, currentHash, "A listening socket disappeared from the host inventory")
		change.event.Network = listenerNetwork(listener)
		change.event.Process.Image = listener.ProcessImage
		changes = append(changes, change)
	}
	return changes
}

func compareSoftware(previous, current Baseline, timestamp time.Time, previousHash, currentHash string) inventoryEvents {
	before := softwareMap(previous.Software)
	after := softwareMap(current.Software)
	changes := make(inventoryEvents, 0)
	for key, software := range after {
		old, exists := before[key]
		if !exists {
			changes = append(changes, newDriftEvent("asset.software_added", model.SeverityInfo, timestamp, current, key, nil, software, previousHash, currentHash, "Software was added to the host inventory"))
			continue
		}
		if old.Version != software.Version || old.Publisher != software.Publisher {
			changes = append(changes, newDriftEvent("asset.software_version_changed", model.SeverityInfo, timestamp, current, key, old, software, previousHash, currentHash, "Installed software version or publisher changed"))
		}
	}
	for key, software := range before {
		if _, exists := after[key]; exists {
			continue
		}
		kind := "asset.software_removed"
		severity := model.SeverityLow
		message := "Software disappeared from the host inventory"
		if isSecurityProduct(software.Name + " " + software.Publisher) {
			kind = "security.control_removed"
			severity = model.SeverityHigh
			message = "Security-related software disappeared from the host inventory"
		}
		changes = append(changes, newDriftEvent(kind, severity, timestamp, current, key, software, nil, previousHash, currentHash, message))
	}
	return changes
}

func compareInterfaces(previous, current Baseline, timestamp time.Time, previousHash, currentHash string) inventoryEvents {
	before := interfaceMap(previous.Interfaces)
	after := interfaceMap(current.Interfaces)
	changes := make(inventoryEvents, 0)
	for key, networkInterface := range after {
		old, exists := before[key]
		if !exists {
			changes = append(changes, newDriftEvent("asset.interface_added", model.SeverityLow, timestamp, current, key, nil, networkInterface, previousHash, currentHash, "A network interface appeared in the host inventory"))
			continue
		}
		if old.IsUp != networkInterface.IsUp || old.MACHash != networkInterface.MACHash || !reflect.DeepEqual(old.Addresses, networkInterface.Addresses) {
			changes = append(changes, newDriftEvent("asset.interface_changed", model.SeverityLow, timestamp, current, key, old, networkInterface, previousHash, currentHash, "A network interface address or state changed"))
		}
	}
	for key, networkInterface := range before {
		if _, exists := after[key]; exists {
			continue
		}
		changes = append(changes, newDriftEvent("asset.interface_removed", model.SeverityLow, timestamp, current, key, networkInterface, nil, previousHash, currentHash, "A network interface disappeared from the host inventory"))
	}
	return changes
}

func compareProcessImages(previous, current Baseline, timestamp time.Time, previousHash, currentHash string) inventoryEvents {
	before := processImageMap(previous.ProcessImages)
	changes := make(inventoryEvents, 0)
	for key, process := range processImageMap(current.ProcessImages) {
		if _, exists := before[key]; exists || !process.Suspicious {
			continue
		}
		change := newDriftEvent("asset.process_image_added", model.SeverityHigh, timestamp, current, key, nil, process, previousHash, currentHash, "A previously unseen process image is running from a user-writable or temporary location")
		change.event.Process.Image = firstNonEmpty(process.Executable, process.Name)
		changes = append(changes, change)
	}
	return changes
}

func newDriftEvent(kind string, severity model.Severity, timestamp time.Time, baseline Baseline, key string, before, after interface{}, previousHash, currentHash, message string) inventoryEvent {
	event := model.Event{
		ID:        driftEventID(kind, baseline.Hostname, key, previousHash, currentHash),
		Timestamp: timestamp,
		Kind:      kind,
		Severity:  severity,
		Trust:     model.TrustUntrustedTelemetry,
		Asset: model.Asset{
			Hostname: baseline.Hostname,
			OS:       baseline.OS,
		},
		Message: message,
		Attributes: map[string]interface{}{
			"drift": map[string]interface{}{
				"key":                    key,
				"before":                 before,
				"after":                  after,
				"previous_baseline_hash": previousHash,
				"current_baseline_hash":  currentHash,
			},
		},
		Provenance: model.Provenance{Source: "native-inventory", Collector: "inventory-drift"},
	}
	event.Prepare()
	return inventoryEvent{sortKey: kind + "|" + key, event: event}
}

func summaryChange(snapshot inventory.Snapshot, previous, current Baseline, total int, previousHash, currentHash string) inventoryEvent {
	return newDriftEvent("asset.inventory_delta_truncated", model.SeverityMedium, snapshot.CollectedAt.UTC(), current, fmt.Sprintf("%d", total), nil, map[string]interface{}{
		"total_changes": total,
	}, previousHash, currentHash, "Inventory drift changes exceeded the configured event cap")
}

func listenerNetwork(listener ListenerState) model.NetworkContext {
	return model.NetworkContext{
		DestinationIP:   listener.Address,
		DestinationPort: listener.Port,
		Protocol:        listener.Protocol,
		Direction:       "inbound",
	}
}

func driftEventID(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(part))
	}
	return "evt_" + hex.EncodeToString(hash.Sum(nil))
}

func serviceMap(values []ServiceState) map[string]ServiceState {
	result := make(map[string]ServiceState, len(values))
	for _, value := range values { result[value.Key] = value }
	return result
}

func listenerMap(values []ListenerState) map[string]ListenerState {
	result := make(map[string]ListenerState, len(values))
	for _, value := range values { result[value.Key] = value }
	return result
}

func softwareMap(values []SoftwareState) map[string]SoftwareState {
	result := make(map[string]SoftwareState, len(values))
	for _, value := range values { result[value.Key] = value }
	return result
}

func interfaceMap(values []InterfaceState) map[string]InterfaceState {
	result := make(map[string]InterfaceState, len(values))
	for _, value := range values { result[value.Key] = value }
	return result
}

func processImageMap(values []ProcessImage) map[string]ProcessImage {
	result := make(map[string]ProcessImage, len(values))
	for _, value := range values { result[value.Key] = value }
	return result
}

func serviceRunning(service ServiceState) bool {
	state := strings.ToLower(service.State)
	return state == "running" || state == "active"
}

func serviceStopped(service ServiceState) bool {
	state := strings.ToLower(service.State)
	mode := strings.ToLower(service.StartMode)
	return state == "stopped" || state == "inactive" || state == "failed" || mode == "disabled"
}

func serviceAutomatic(service ServiceState) bool {
	mode := strings.ToLower(service.StartMode)
	return strings.Contains(mode, "auto") || mode == "enabled"
}

func isSecurityProduct(value string) bool {
	value = strings.ToLower(value)
	for _, fragment := range []string{
		"ntagentshield", "nt shield", "windows defender", "microsoft defender", "sysmon", "wazuh", "crowdstrike", "falcon sensor", "sentinelone", "sophos", "trend micro", "carbon black", "elastic agent", "auditd", "suricata", "osquery", "clamav", "security agent", "endpoint protection", "antivirus", "edr",
	} {
		if strings.Contains(value, fragment) { return true }
	}
	return false
}
