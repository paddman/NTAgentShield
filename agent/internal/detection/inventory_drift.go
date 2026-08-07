package detection

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/paddman/NTAgentShield/internal/inventory"
	"github.com/paddman/NTAgentShield/internal/model"
)

const maxInventoryDeltaFindings = 10

type inventoryDriftRule struct {
	mu          sync.Mutex
	initialized bool
	previous    inventory.Snapshot
}

func newInventoryDriftRule() *inventoryDriftRule {
	return &inventoryDriftRule{}
}

func (*inventoryDriftRule) ID() string { return "NTS-INV" }

func (r *inventoryDriftRule) Evaluate(event model.Event) []model.Finding {
	if event.Kind != "asset.inventory" {
		return nil
	}
	snapshot, ok := decodeInventorySnapshot(event.Attributes["inventory"])
	if !ok {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	findings := detectNewSuspiciousAncestry(event, r.previous, snapshot, r.initialized)
	if r.initialized {
		findings = append(findings, detectServiceDrift(event, r.previous, snapshot)...)
		findings = append(findings, detectListenerDrift(event, r.previous, snapshot)...)
		findings = append(findings, detectSoftwareDrift(event, r.previous, snapshot)...)
	}

	r.previous = snapshot
	r.initialized = true
	return findings
}

func decodeInventorySnapshot(value interface{}) (inventory.Snapshot, bool) {
	if value == nil {
		return inventory.Snapshot{}, false
	}
	if snapshot, ok := value.(inventory.Snapshot); ok {
		return snapshot, true
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return inventory.Snapshot{}, false
	}
	var snapshot inventory.Snapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return inventory.Snapshot{}, false
	}
	return snapshot, true
}

func detectServiceDrift(event model.Event, previous, current inventory.Snapshot) []model.Finding {
	if inventoryTruncated(previous, "services") || inventoryTruncated(current, "services") {
		return nil
	}
	previousServices := make(map[string]inventory.Service, len(previous.Services))
	for _, service := range previous.Services {
		previousServices[serviceKey(service)] = service
	}

	findings := make([]model.Finding, 0)
	for _, service := range current.Services {
		before, existed := previousServices[serviceKey(service)]
		if !existed {
			severity := model.SeverityMedium
			confidence := 76
			if serviceRunsAutomatically(service) || serviceIsRunning(service) {
				severity = model.SeverityHigh
				confidence = 84
			}
			finding := model.NewFinding(event, "NTS-INV-001", "New system service appeared after baseline", fmt.Sprintf("Service %q was not present in the previous inventory snapshot. New services can be legitimate deployment activity or persistence and should be correlated with native service-creation telemetry.", service.Name), "persistence.service_drift", severity, confidence)
			finding.MITRETactics = []string{"Persistence", "Privilege Escalation"}
			finding.MITRETechniques = []string{"T1543"}
			finding.Attributes["change_type"] = "new_service"
			finding.Attributes["service_name"] = service.Name
			finding.Attributes["display_name"] = service.DisplayName
			finding.Attributes["state"] = service.State
			finding.Attributes["start_mode"] = service.StartMode
			finding.RecommendedSteps = []string{"Verify the service against an approved deployment window", "Inspect the service binary, account, and signer", "Correlate process, file-write, and network telemetry around the first appearance"}
			findings = append(findings, finding)
		} else if !serviceRunsAutomatically(before) && serviceRunsAutomatically(service) {
			finding := model.NewFinding(event, "NTS-INV-001", "Service changed to automatic startup", fmt.Sprintf("Service %q changed startup mode from %q to %q between inventory snapshots.", service.Name, before.StartMode, service.StartMode), "persistence.service_drift", model.SeverityHigh, 86)
			finding.MITRETactics = []string{"Persistence", "Privilege Escalation"}
			finding.MITRETechniques = []string{"T1543"}
			finding.Attributes["change_type"] = "start_mode_change"
			finding.Attributes["service_name"] = service.Name
			finding.Attributes["previous_start_mode"] = before.StartMode
			finding.Attributes["current_start_mode"] = service.StartMode
			finding.RecommendedSteps = []string{"Identify the account or deployment that changed the startup mode", "Inspect the service executable and signature", "Compare the change with approved configuration management activity"}
			findings = append(findings, finding)
		}
		if len(findings) >= maxInventoryDeltaFindings {
			break
		}
	}
	return findings
}

func detectListenerDrift(event model.Event, previous, current inventory.Snapshot) []model.Finding {
	if inventoryTruncated(previous, "listeners") || inventoryTruncated(current, "listeners") {
		return nil
	}
	previousListeners := make(map[string]struct{}, len(previous.Listeners))
	for _, listener := range previous.Listeners {
		previousListeners[listenerKey(listener)] = struct{}{}
	}

	findings := make([]model.Finding, 0)
	for _, listener := range current.Listeners {
		if _, existed := previousListeners[listenerKey(listener)]; existed || !listenerExternallyReachable(listener.Address) {
			continue
		}
		severity := model.SeverityMedium
		confidence := 78
		if sensitiveListenerPort(listener.Port) {
			severity = model.SeverityHigh
			confidence = 86
		}
		finding := model.NewFinding(event, "NTS-INV-002", "New externally reachable listening socket", fmt.Sprintf("A new %s listener appeared on %s:%d after the previous inventory baseline.", strings.ToUpper(listener.Protocol), listener.Address, listener.Port), "exposure.listener_drift", severity, confidence)
		finding.MITRETactics = []string{"Persistence", "Command and Control"}
		finding.Attributes["protocol"] = listener.Protocol
		finding.Attributes["address"] = listener.Address
		finding.Attributes["port"] = listener.Port
		finding.Attributes["pid"] = listener.PID
		finding.Attributes["sensitive_port"] = sensitiveListenerPort(listener.Port)
		finding.RecommendedSteps = []string{"Resolve the owning process and executable signer", "Confirm the listener is expected for this asset role", "Review inbound connections and recent service or software changes"}
		findings = append(findings, finding)
		if len(findings) >= maxInventoryDeltaFindings {
			break
		}
	}
	return findings
}

func detectSoftwareDrift(event model.Event, previous, current inventory.Snapshot) []model.Finding {
	if inventoryTruncated(previous, "software") || inventoryTruncated(current, "software") {
		return nil
	}
	previousSoftware := make(map[string]struct{}, len(previous.Software))
	for _, software := range previous.Software {
		previousSoftware[softwareKey(software)] = struct{}{}
	}
	added := make([]string, 0)
	for _, software := range current.Software {
		if _, existed := previousSoftware[softwareKey(software)]; existed {
			continue
		}
		label := strings.TrimSpace(software.Name)
		if software.Version != "" {
			label += " " + strings.TrimSpace(software.Version)
		}
		added = append(added, strings.TrimSpace(label))
	}
	if len(added) == 0 {
		return nil
	}
	sort.Strings(added)
	total := len(added)
	if len(added) > 20 {
		added = added[:20]
	}
	finding := model.NewFinding(event, "NTS-INV-003", "Installed software changed after baseline", fmt.Sprintf("%d previously unseen software package(s) appeared in the latest host inventory.", total), "asset.software_drift", model.SeverityLow, 72)
	finding.Attributes["added_count"] = total
	finding.Attributes["added_software"] = added
	finding.RecommendedSteps = []string{"Compare the additions with approved package-management or deployment activity", "Inspect unsigned or unexpected binaries before raising severity", "Correlate new software with new services, listeners, and process execution"}
	return []model.Finding{finding}
}

func detectNewSuspiciousAncestry(event model.Event, previous, current inventory.Snapshot, hasPrevious bool) []model.Finding {
	currentRelations := suspiciousAncestryRelations(current)
	if len(currentRelations) == 0 {
		return nil
	}
	previousRelations := map[string]ancestryRelation{}
	if hasPrevious {
		previousRelations = suspiciousAncestryRelations(previous)
	}

	keys := make([]string, 0, len(currentRelations))
	for key := range currentRelations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	findings := make([]model.Finding, 0)
	for _, key := range keys {
		if _, existed := previousRelations[key]; existed {
			continue
		}
		relation := currentRelations[key]
		finding := model.NewFinding(event, "NTS-PROC-001", "Suspicious process ancestry found in host inventory", fmt.Sprintf("Process %s (PID %d) is running under %s (PID %d): %s.", relation.Child.Name, relation.Child.PID, relation.Parent.Name, relation.Parent.PID, relation.Reason), "execution.process_ancestry", relation.Severity, relation.Confidence)
		finding.MITRETactics = relation.MITRETactics
		finding.MITRETechniques = relation.MITRETechniques
		finding.Attributes["parent_pid"] = relation.Parent.PID
		finding.Attributes["parent_name"] = relation.Parent.Name
		finding.Attributes["parent_executable"] = relation.Parent.Executable
		finding.Attributes["child_pid"] = relation.Child.PID
		finding.Attributes["child_name"] = relation.Child.Name
		finding.Attributes["child_executable"] = relation.Child.Executable
		finding.Attributes["reason"] = relation.Reason
		finding.RecommendedSteps = []string{"Capture the full command line and executable hashes", "Correlate the process pair with native process-start and network telemetry", "Review the triggering web, database, document, or remote-management activity before containment"}
		findings = append(findings, finding)
		if len(findings) >= maxInventoryDeltaFindings {
			break
		}
	}
	return findings
}

type ancestryRelation struct {
	Parent          inventory.Process
	Child           inventory.Process
	Reason          string
	Severity        model.Severity
	Confidence      int
	MITRETactics    []string
	MITRETechniques []string
}

func suspiciousAncestryRelations(snapshot inventory.Snapshot) map[string]ancestryRelation {
	byPID := make(map[int]inventory.Process, len(snapshot.Processes))
	for _, process := range snapshot.Processes {
		if process.PID > 0 {
			byPID[process.PID] = process
		}
	}
	result := make(map[string]ancestryRelation)
	for _, child := range snapshot.Processes {
		if child.PPID <= 0 {
			continue
		}
		parent, ok := byPID[child.PPID]
		if !ok {
			continue
		}
		relation, suspicious := classifyAncestry(parent, child)
		if !suspicious {
			continue
		}
		result[ancestryKey(parent, child)] = relation
	}
	return result
}

func classifyAncestry(parent, child inventory.Process) (ancestryRelation, bool) {
	parentName := processBase(parent)
	childName := processBase(child)
	webParents := stringSet("w3wp.exe", "nginx", "httpd", "apache2", "php-fpm", "php-cgi", "tomcat", "java")
	databaseParents := stringSet("mysqld", "mariadbd", "postgres", "sqlservr.exe", "oracle", "oracle.exe")
	officeParents := stringSet("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe")
	shellOrDownloader := stringSet("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "dash", "zsh", "curl", "wget", "nc", "ncat", "certutil.exe", "bitsadmin.exe")
	officeChildren := stringSet("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")

	relation := ancestryRelation{Parent: parent, Child: child}
	switch {
	case webParents[parentName] && shellOrDownloader[childName]:
		relation.Reason = "web-serving process spawned a shell, interpreter, or download utility"
		relation.Severity = model.SeverityCritical
		relation.Confidence = 95
		relation.MITRETactics = []string{"Initial Access", "Execution"}
		relation.MITRETechniques = []string{"T1190", "T1059"}
		return relation, true
	case databaseParents[parentName] && shellOrDownloader[childName]:
		relation.Reason = "database server process spawned a shell, interpreter, or download utility"
		relation.Severity = model.SeverityCritical
		relation.Confidence = 94
		relation.MITRETactics = []string{"Execution", "Privilege Escalation"}
		relation.MITRETechniques = []string{"T1059"}
		return relation, true
	case officeParents[parentName] && officeChildren[childName]:
		relation.Reason = "Office application spawned a script host or living-off-the-land execution utility"
		relation.Severity = model.SeverityHigh
		relation.Confidence = 91
		relation.MITRETactics = []string{"Execution"}
		relation.MITRETechniques = []string{"T1204", "T1059"}
		return relation, true
	default:
		return ancestryRelation{}, false
	}
}

func inventoryTruncated(snapshot inventory.Snapshot, key string) bool {
	return snapshot.Truncated != nil && snapshot.Truncated[key]
}

func serviceKey(service inventory.Service) string {
	return strings.ToLower(strings.TrimSpace(service.Name))
}

func softwareKey(software inventory.Software) string {
	return strings.ToLower(strings.TrimSpace(software.Name))
}

func listenerKey(listener inventory.Listener) string {
	return strings.ToLower(strings.TrimSpace(listener.Protocol)) + "|" + normalizeListenerAddress(listener.Address) + "|" + strconv.Itoa(listener.Port)
}

func ancestryKey(parent, child inventory.Process) string {
	return strconv.Itoa(parent.PID) + "|" + strconv.Itoa(child.PID) + "|" + processBase(parent) + "|" + processBase(child)
}

func processBase(process inventory.Process) string {
	value := process.Executable
	if strings.TrimSpace(value) == "" {
		value = process.Name
	}
	value = strings.ReplaceAll(value, "\\", "/")
	return strings.ToLower(filepath.Base(value))
}

func stringSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[strings.ToLower(value)] = true
	}
	return result
}

func serviceRunsAutomatically(service inventory.Service) bool {
	mode := strings.ToLower(strings.TrimSpace(service.StartMode))
	return mode == "auto" || mode == "automatic" || mode == "enabled" || strings.HasPrefix(mode, "auto ")
}

func serviceIsRunning(service inventory.Service) bool {
	state := strings.ToLower(strings.TrimSpace(service.State))
	return state == "running" || state == "active"
}

func normalizeListenerAddress(address string) string {
	value := strings.ToLower(strings.TrimSpace(address))
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	return value
}

func listenerExternallyReachable(address string) bool {
	value := normalizeListenerAddress(address)
	if value == "" || value == "*" || value == "0.0.0.0" || value == "::" || value == "0:0:0:0:0:0:0:0" {
		return true
	}
	if value == "localhost" {
		return false
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return true
	}
	return !ip.IsLoopback()
}

func sensitiveListenerPort(port int) bool {
	switch port {
	case 22, 23, 445, 1433, 2375, 2376, 3306, 3389, 5432, 5985, 5986, 6379, 9200, 11211, 27017:
		return true
	default:
		return false
	}
}
