package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/paddman/NTAgentShield/internal/inventory"
	"github.com/paddman/NTAgentShield/internal/model"
)

func TestStoreRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	store, err := New(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := inventory.Snapshot{
		Hostname: "host-a",
		Services: []inventory.Service{{Name: "sshd", State: "running"}},
	}
	if err := store.Save(snapshot); err != nil {
		t.Fatal(err)
	}
	loaded, ok, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || loaded.Hostname != "host-a" || len(loaded.Services) != 1 {
		t.Fatalf("unexpected baseline: ok=%t snapshot=%+v", ok, loaded)
	}
}

func TestStoreRejectsTampering(t *testing.T) {
	dataDir := t.TempDir()
	store, err := New(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(inventory.Snapshot{Hostname: "host-a"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, baselineFilename)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)/2] ^= 1
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(); err == nil {
		t.Fatal("expected tampered baseline to fail verification")
	}
}

func TestSnapshotFromEventAcceptsNormalizedMap(t *testing.T) {
	event := model.Event{
		Kind: "asset.inventory",
		Attributes: map[string]interface{}{
			"inventory": map[string]interface{}{
				"hostname": "host-b",
				"services": []interface{}{map[string]interface{}{"name": "nginx"}},
			},
		},
	}
	snapshot, err := SnapshotFromEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Hostname != "host-b" || len(snapshot.Services) != 1 || snapshot.Services[0].Name != "nginx" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}
