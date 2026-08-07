package detection

import (
	"testing"

	"github.com/paddman/NTAgentShield/internal/inventory"
	"github.com/paddman/NTAgentShield/internal/model"
)

func TestInventoryFirstSnapshotEstablishesDriftBaseline(t *testing.T) {
	engine := New()
	baseline := inventory.Snapshot{
		Services:  []inventory.Service{{Name: "baseline-agent", State: "running", StartMode: "automatic"}},
		Listeners: []inventory.Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 8443, PID: 20}},
		Software:  []inventory.Software{{Name: "baseline-package", Version: "1.0"}},
	}

	findings := engine.Inspect(inventoryEvent(baseline))
	if containsRule(findings, "NTS-INV-001") || containsRule(findings, "NTS-INV-002") || containsRule(findings, "NTS-INV-003") {
		t.Fatalf("first inventory must establish baseline without drift findings: %+v", findings)
	}
}

func TestInventoryDetectsServiceListenerAndSoftwareDrift(t *testing.T) {
	engine := New()
	engine.Inspect(inventoryEvent(inventory.Snapshot{}))

	current := inventory.Snapshot{
		Services: []inventory.Service{{Name: "shadow-service", State: "running", StartMode: "automatic"}},
		Listeners: []inventory.Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 6379, PID: 440}},
		Software: []inventory.Software{{Name: "remote-helper", Version: "2.4"}},
	}
	findings := engine.Inspect(inventoryEvent(current))

	for _, ruleID := range []string{"NTS-INV-001", "NTS-INV-002", "NTS-INV-003"} {
		if !containsRule(findings, ruleID) {
			t.Fatalf("expected %s finding: %+v", ruleID, findings)
		}
	}
}

func TestInventoryIgnoresNewLoopbackListener(t *testing.T) {
	engine := New()
	engine.Inspect(inventoryEvent(inventory.Snapshot{}))

	findings := engine.Inspect(inventoryEvent(inventory.Snapshot{
		Listeners: []inventory.Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: 9000, PID: 7}},
	}))
	if containsRule(findings, "NTS-INV-002") {
		t.Fatalf("loopback listener should not be treated as new network exposure: %+v", findings)
	}
}

func TestInventoryDetectsSuspiciousProcessAncestryOnFirstSnapshot(t *testing.T) {
	engine := New()
	snapshot := inventory.Snapshot{Processes: []inventory.Process{
		{PID: 100, Name: "w3wp.exe", Executable: `C:\Windows\System32\inetsrv\w3wp.exe`},
		{PID: 101, PPID: 100, Name: "powershell.exe", Executable: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, CommandLine: "powershell.exe -nop"},
	}}
	findings := engine.Inspect(inventoryEvent(snapshot))
	if !containsRule(findings, "NTS-PROC-001") {
		t.Fatalf("expected suspicious process ancestry finding: %+v", findings)
	}
}

func TestInventoryDoesNotRepeatSameSuspiciousProcessPair(t *testing.T) {
	engine := New()
	snapshot := inventory.Snapshot{Processes: []inventory.Process{
		{PID: 500, Name: "postgres", Executable: "/usr/lib/postgresql/postgres"},
		{PID: 501, PPID: 500, Name: "bash", Executable: "/usr/bin/bash"},
	}}
	first := engine.Inspect(inventoryEvent(snapshot))
	if !containsRule(first, "NTS-PROC-001") {
		t.Fatalf("expected first ancestry finding: %+v", first)
	}
	second := engine.Inspect(inventoryEvent(snapshot))
	if containsRule(second, "NTS-PROC-001") {
		t.Fatalf("unchanged process pair should not repeat finding: %+v", second)
	}
}

func TestInventorySkipsDriftWhenCollectionWasTruncated(t *testing.T) {
	engine := New()
	engine.Inspect(inventoryEvent(inventory.Snapshot{Truncated: map[string]bool{"services": true, "listeners": true, "software": true}}))
	findings := engine.Inspect(inventoryEvent(inventory.Snapshot{
		Services:  []inventory.Service{{Name: "possibly-missed", State: "running", StartMode: "automatic"}},
		Listeners: []inventory.Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 3389}},
		Software:  []inventory.Software{{Name: "possibly-missed-package"}},
	}))
	for _, ruleID := range []string{"NTS-INV-001", "NTS-INV-002", "NTS-INV-003"} {
		if containsRule(findings, ruleID) {
			t.Fatalf("truncated prior inventory must suppress %s drift: %+v", ruleID, findings)
		}
	}
}

func inventoryEvent(snapshot inventory.Snapshot) model.Event {
	event := model.Event{
		Kind:  "asset.inventory",
		Trust: model.TrustUntrustedTelemetry,
		Attributes: map[string]interface{}{
			"inventory": snapshot,
		},
	}
	event.Prepare()
	return event
}
