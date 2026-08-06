package inventorydrift

import (
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/inventory"
	"github.com/paddman/NTAgentShield/internal/model"
)

func TestCompareRaisesExposureAndSecurityControlDrift(t *testing.T) {
	captured := time.Now().UTC()
	previousSnapshot := inventory.Snapshot{
		SchemaVersion: inventory.SchemaVersion,
		CollectedAt:   captured.Add(-time.Minute),
		Hostname:      "win01",
		OS:            "windows",
		Services: []inventory.Service{
			{Name: "Sense", DisplayName: "Microsoft Defender for Endpoint", State: "Running", StartMode: "Auto"},
		},
		Listeners:  []inventory.Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: 8080, PID: 10}},
		Software:   []inventory.Software{{Name: "CrowdStrike Falcon Sensor", Version: "7.0", Publisher: "CrowdStrike", Source: "registry"}},
		Interfaces: []inventory.NetworkInterface{{Name: "Ethernet", MAC: "00:11:22:33:44:55", Addresses: []string{"10.0.0.10/24"}, IsUp: true}},
		Processes:  []inventory.Process{{PID: 10, Name: "system.exe", Executable: `C:\Windows\System32\system.exe`}},
	}
	currentSnapshot := inventory.Snapshot{
		SchemaVersion: inventory.SchemaVersion,
		CollectedAt:   captured,
		Hostname:      "win01",
		OS:            "windows",
		Services: []inventory.Service{
			{Name: "Sense", DisplayName: "Microsoft Defender for Endpoint", State: "Stopped", StartMode: "Disabled"},
		},
		Listeners: []inventory.Listener{
			{Protocol: "tcp", Address: "127.0.0.1", Port: 8080, PID: 10},
			{Protocol: "tcp", Address: "0.0.0.0", Port: 3389, PID: 9001},
		},
		Interfaces: []inventory.NetworkInterface{{Name: "Ethernet", MAC: "00:11:22:33:44:55", Addresses: []string{"10.0.0.10/24"}, IsUp: true}},
		Processes: []inventory.Process{
			{PID: 10, Name: "system.exe", Executable: `C:\Windows\System32\system.exe`},
			{PID: 9001, Name: "server.exe", Executable: `C:\Users\Public\server.exe`, CommandLine: `server.exe --token drift-secret`},
		},
	}
	previous := project(previousSnapshot, nil)
	current := project(currentSnapshot, &previous)
	previousHash, _ := baselineHash(previous)
	currentHash, _ := baselineHash(current)
	changes := compare(previous, current, captured, previousHash, currentHash)
	kinds := map[string]model.Event{}
	for _, change := range changes {
		kinds[change.event.Kind] = change.event
	}
	for _, expected := range []string{"security.control_disabled", "security.control_removed", "asset.listener_added", "asset.process_image_added"} {
		if _, exists := kinds[expected]; !exists {
			t.Fatalf("expected drift event %s, got %#v", expected, kinds)
		}
	}
	listener := kinds["asset.listener_added"]
	if listener.Severity != model.SeverityHigh || listener.Network.DestinationPort != 3389 || listener.Process.Image != `C:\Users\Public\server.exe` {
		t.Fatalf("unexpected exposed-listener event: %#v", listener)
	}
}

func TestPlanCapsEventsAndEmitsSummary(t *testing.T) {
	directory := t.TempDir()
	store, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	first := inventory.Snapshot{
		SchemaVersion: inventory.SchemaVersion,
		CollectedAt:   time.Now().Add(-time.Minute).UTC(),
		Hostname:      "host01",
		OS:            "linux",
		Services:      []inventory.Service{{Name: "base.service", State: "active"}},
	}
	initial, err := store.Plan(first, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(initial); err != nil {
		t.Fatal(err)
	}
	second := first
	second.CollectedAt = time.Now().UTC()
	second.Services = []inventory.Service{
		{Name: "base.service", State: "active"},
		{Name: "one.service", State: "active"},
		{Name: "two.service", State: "active"},
		{Name: "three.service", State: "active"},
	}
	plan, err := store.Plan(second, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Truncated || plan.TotalChanges != 3 || len(plan.Events) != 2 {
		t.Fatalf("unexpected capped drift plan: %#v", plan)
	}
	if plan.Events[1].Kind != "asset.inventory_delta_truncated" {
		t.Fatalf("summary event was not appended: %#v", plan.Events)
	}
}

func TestIntegrityEventDoesNotExposeFullQuarantinePath(t *testing.T) {
	event := IntegrityEvent("host01", "linux", errTest("hash mismatch"), `/var/lib/ntagentshield/inventory-baseline.json.corrupt-1`)
	if event.Kind != "security.inventory_baseline_integrity" || event.Severity != model.SeverityCritical {
		t.Fatalf("unexpected integrity event: %#v", event)
	}
	state := event.Attributes["local_state"].(map[string]interface{})
	if state["quarantined_file"] != "inventory-baseline.json.corrupt-1" {
		t.Fatalf("full quarantine path leaked: %#v", state)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
