//go:build windows

package tools

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paddman/NTAgentShield/internal/identity"
)

type windowsFakeRunner struct {
	calls []string
}

func (f *windowsFakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if name == "netsh" && len(args) >= 3 && args[0] == "advfirewall" && args[1] == "export" {
		if err := os.WriteFile(args[2], []byte("fake-windows-firewall-policy"), 0o600); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (f *windowsFakeRunner) RunInput(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return nil, nil
}

func TestWindowsHostIsolationExportsAndRestoresFirewallPolicy(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &windowsFakeRunner{}
	backend := &windowsNetworkBackend{runner: fake, dataDir: dir, identityKeyFile: identityPath, controlEndpoint: "https://203.0.113.20:9443/v1/agent/events"}
	if _, err := backend.Isolate(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(fake.calls, "\n")
	for _, expected := range []string{
		"netsh advfirewall export",
		"remoteip=203.0.113.20 remoteport=9443",
		"protocol=UDP remoteport=53",
		"netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("Windows isolation command set missing %q:\n%s", expected, joined)
		}
	}
	statePath := filepath.Join(dir, "containment", "host-isolation.json")
	if _, err := loadSignedContainmentState(statePath, identityPath, "host-isolation-windows-firewall"); err != nil {
		t.Fatalf("signed isolation state invalid: %v", err)
	}
	if _, err := backend.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(fake.calls, "\n")
	if !strings.Contains(joined, "netsh advfirewall import") {
		t.Fatalf("release should import prior firewall policy:\n%s", joined)
	}
}

func TestWindowsIsolationRefusesBackupWithoutSignedState(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	backend := &windowsNetworkBackend{runner: &windowsFakeRunner{}, dataDir: dir, identityKeyFile: identityPath}
	if err := os.MkdirAll(backend.isolationDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backend.firewallBackupPath(), []byte("unverifiable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Release(context.Background()); err == nil || !strings.Contains(err.Error(), "without signed state") {
		t.Fatalf("expected unverifiable backup rejection, got %v", err)
	}
}

func TestWindowsFirewallBlockUsesSignedUniqueOwnedRule(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &windowsFakeRunner{}
	backend := &windowsNetworkBackend{runner: fake, dataDir: dir, identityKeyFile: identityPath}
	address := netip.MustParseAddr("198.51.100.22")
	if _, err := backend.Block(context.Background(), address); err != nil {
		t.Fatal(err)
	}
	state, err := loadSignedContainmentState(backend.blockStatePath(address), identityPath, "firewall-block-windows")
	if err != nil {
		t.Fatalf("signed Windows block state invalid: %v", err)
	}
	name, ok := state.Data["rule"].(string)
	if !ok || !strings.HasPrefix(name, windowsBlockRulePrefix(address)+"-") {
		t.Fatalf("unexpected owned rule identity: %#v", state.Data["rule"])
	}
	joined := strings.Join(fake.calls, "\n")
	for _, expected := range []string{"name=" + name + " dir=in action=block remoteip=198.51.100.22", "name=" + name + " dir=out action=block remoteip=198.51.100.22"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("Windows block command missing %q:\n%s", expected, joined)
		}
	}
	if _, err := backend.Unblock(context.Background(), address); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backend.blockStatePath(address)); !os.IsNotExist(err) {
		t.Fatalf("block ownership state should be removed after unblock, err=%v", err)
	}
}

func TestWindowsFirewallPortUsesSignedOwnedRule(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &windowsFakeRunner{}
	backend := &windowsNetworkBackend{runner: fake, dataDir: dir, identityKeyFile: identityPath}
	rule := PortRule{Protocol: "TCP", Direction: "inbound", Port: 8443}
	if _, err := backend.OpenPort(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	state, err := loadSignedContainmentState(backend.portStatePath(rule), identityPath, "firewall-port-windows")
	if err != nil {
		t.Fatalf("signed Windows port state invalid: %v", err)
	}
	name, ok := state.Data["rule"].(string)
	if !ok || !strings.HasPrefix(name, windowsPortRulePrefix(rule)+"-") {
		t.Fatalf("unexpected owned rule identity: %#v", state.Data["rule"])
	}
	joined := strings.Join(fake.calls, "\n")
	if !strings.Contains(joined, "name="+name+" dir=in action=allow protocol=TCP localport=8443") {
		t.Fatalf("Windows port open command missing:\n%s", joined)
	}
	if _, err := backend.ClosePort(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backend.portStatePath(rule)); !os.IsNotExist(err) {
		t.Fatalf("port ownership state should be removed after close, err=%v", err)
	}
}
