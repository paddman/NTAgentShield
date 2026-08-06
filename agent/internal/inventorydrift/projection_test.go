package inventorydrift

import (
	"strings"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/inventory"
)

func TestProjectionExcludesCommandLinesAndHashesMAC(t *testing.T) {
	snapshot := inventory.Snapshot{
		SchemaVersion: inventory.SchemaVersion,
		CollectedAt:   time.Now().UTC(),
		Hostname:      "web01",
		OS:            "linux",
		Services:      []inventory.Service{{Name: "nginx.service", State: "active", StartMode: "enabled"}},
		Listeners:     []inventory.Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 443, PID: 42, State: "LISTEN"}},
		Software:      []inventory.Software{{Name: "nginx", Version: "1.24", Source: "dpkg"}},
		Interfaces:    []inventory.NetworkInterface{{Name: "eth0", MAC: "00:11:22:33:44:55", Addresses: []string{"10.0.0.10/24"}, IsUp: true}},
		Processes:     []inventory.Process{{PID: 42, Name: "nginx", Executable: "/usr/sbin/nginx", CommandLine: "nginx --password baseline-secret"}},
	}
	baseline := project(snapshot, nil)
	if len(baseline.Interfaces) != 1 || baseline.Interfaces[0].MACHash == "" {
		t.Fatalf("MAC hash was not projected: %#v", baseline.Interfaces)
	}
	if baseline.Interfaces[0].MACHash == "00:11:22:33:44:55" {
		t.Fatal("raw MAC address leaked into the baseline")
	}
	encoded, err := baselineHash(baseline)
	if err != nil || len(encoded) != 64 {
		t.Fatalf("unexpected baseline hash %q err=%v", encoded, err)
	}
	for _, process := range baseline.ProcessImages {
		if strings.Contains(process.Executable, "baseline-secret") {
			t.Fatalf("command line leaked into process projection: %#v", process)
		}
	}
	if baseline.Listeners[0].ProcessImage != "/usr/sbin/nginx" || !baseline.Listeners[0].Exposed || !baseline.Listeners[0].Sensitive {
		t.Fatalf("listener context was not projected: %#v", baseline.Listeners[0])
	}
}

func TestProjectionRetainsCompleteCategoryWhenCurrentSnapshotIsTruncated(t *testing.T) {
	previous := Baseline{
		SchemaVersion: SchemaVersion,
		CapturedAt:    time.Now().Add(-time.Minute).UTC(),
		Hostname:      "db01",
		OS:            "linux",
		Complete:      Completeness{Services: true, Listeners: true, Software: true, Interfaces: true, ProcessImages: true},
		Services:      []ServiceState{{Key: "mysql.service", Name: "mysql.service", State: "active"}},
	}
	snapshot := inventory.Snapshot{
		SchemaVersion: inventory.SchemaVersion,
		CollectedAt:   time.Now().UTC(),
		Hostname:      "db01",
		OS:            "linux",
		Services:      []inventory.Service{{Name: "only-first-service", State: "active"}},
		Truncated:     map[string]bool{"services": true},
	}
	next := project(snapshot, &previous)
	if !next.Complete.Services || len(next.Services) != 1 || next.Services[0].Name != "mysql.service" {
		t.Fatalf("truncated service inventory replaced a complete baseline: %#v", next)
	}
}

func TestSuspiciousExecutablePath(t *testing.T) {
	testCases := []struct {
		osName string
		path   string
		want   bool
	}{
		{"linux", "/tmp/update", true},
		{"linux", "/usr/bin/ssh", false},
		{"windows", `C:\Users\Public\agent.exe`, true},
		{"windows", `C:\Windows\System32\svchost.exe`, false},
	}
	for _, testCase := range testCases {
		if got := suspiciousExecutablePath(testCase.osName, testCase.path); got != testCase.want {
			t.Fatalf("suspicious path %s %q: got %t want %t", testCase.osName, testCase.path, got, testCase.want)
		}
	}
}
