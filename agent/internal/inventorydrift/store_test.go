package inventorydrift

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/inventory"
)

func TestStoreCommitReloadAndDetectTampering(t *testing.T) {
	directory := t.TempDir()
	store, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	first := inventory.Snapshot{
		SchemaVersion: inventory.SchemaVersion,
		CollectedAt:   time.Now().UTC(),
		Hostname:      "web01",
		OS:            "linux",
		Services:      []inventory.Service{{Name: "nginx.service", State: "active", StartMode: "enabled"}},
	}
	plan, err := store.Plan(first, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Initial || len(plan.Events) != 0 {
		t.Fatalf("first baseline should initialize without drift: %#v", plan)
	}
	if err := store.Commit(plan); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(directory, "inventory-baseline.json")
	info, err := os.Stat(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("baseline permissions are too broad: %o", info.Mode().Perm())
	}

	reloaded, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.CollectedAt = first.CollectedAt.Add(time.Minute)
	second.Services = append(second.Services, inventory.Service{Name: "backdoor.service", State: "active", StartMode: "enabled"})
	changePlan, err := reloaded.Plan(second, 64)
	if err != nil {
		t.Fatal(err)
	}
	if changePlan.Initial || len(changePlan.Events) != 1 || changePlan.Events[0].Kind != "asset.service_added" {
		t.Fatalf("unexpected drift plan: %#v", changePlan)
	}

	content, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]interface{}
	if err := json.Unmarshal(content, &stored); err != nil {
		t.Fatal(err)
	}
	stored["payload_sha256"] = strings.Repeat("0", 64)
	tampered, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	quarantiningStore, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	if quarantiningStore.Warning() == nil || quarantiningStore.QuarantinedPath() == "" {
		t.Fatal("tampered baseline was not quarantined")
	}
	if _, err := os.Stat(baselinePath); !os.IsNotExist(err) {
		t.Fatalf("tampered baseline remains active: %v", err)
	}
	if _, err := os.Stat(quarantiningStore.QuarantinedPath()); err != nil {
		t.Fatalf("quarantined baseline is missing: %v", err)
	}
}

func TestStoreRejectsStalePlan(t *testing.T) {
	directory := t.TempDir()
	store, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := inventory.Snapshot{SchemaVersion: inventory.SchemaVersion, CollectedAt: time.Now().UTC(), Hostname: "host", OS: "linux"}
	firstPlan, err := store.Plan(snapshot, 16)
	if err != nil {
		t.Fatal(err)
	}
	stalePlan := firstPlan
	if err := store.Commit(firstPlan); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(stalePlan); err == nil {
		t.Fatal("expected a stale drift plan to be rejected")
	}
}
