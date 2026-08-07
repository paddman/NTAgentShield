//go:build linux

package tools

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paddman/NTAgentShield/internal/identity"
)

type linuxFakeRunner struct {
	calls  []string
	script string
	tables map[string]bool
}

func (f *linuxFakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	joined := strings.Join(args, " ")
	if joined == "--version" {
		return []byte("nftables v1"), nil
	}
	if strings.HasPrefix(joined, "list table inet ") {
		table := args[len(args)-1]
		if f.tables[table] {
			return []byte("table exists"), nil
		}
		return nil, errors.New("not found")
	}
	if strings.HasPrefix(joined, "delete table inet ") {
		delete(f.tables, args[len(args)-1])
		return nil, nil
	}
	return nil, nil
}

func (f *linuxFakeRunner) RunInput(_ context.Context, input, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	f.script = input
	if strings.Contains(input, "table inet ntshield_isolation") {
		f.tables[linuxIsolationTable] = true
	}
	if strings.Contains(input, "table inet ntshield_block") {
		f.tables[linuxBlockTable] = true
	}
	return nil, nil
}

func TestLinuxHostIsolationPreservesControlPlaneAndIsReversible(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &linuxFakeRunner{tables: map[string]bool{}}
	backend := &linuxNetworkBackend{runner: fake, dataDir: dir, identityKeyFile: identityPath, controlEndpoint: "https://203.0.113.10:9443/v1/agent/events"}
	result, err := backend.Isolate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result["isolated"] != true {
		t.Fatalf("unexpected isolation result: %#v", result)
	}
	for _, expected := range []string{"ip daddr 203.0.113.10 tcp dport 9443 accept", "udp dport 53 accept", "policy drop"} {
		if !strings.Contains(fake.script, expected) {
			t.Fatalf("isolation nft script missing %q:\n%s", expected, fake.script)
		}
	}
	if _, err := loadSignedContainmentState(filepath.Join(dir, "containment", "host-isolation.json"), identityPath, "host-isolation-linux-nft"); err != nil {
		t.Fatalf("signed isolation state invalid: %v", err)
	}
	if _, err := backend.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.tables[linuxIsolationTable] {
		t.Fatal("isolation table should be deleted on release")
	}
}

func TestLinuxFirewallBlockUsesSignedOwnedTable(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &linuxFakeRunner{tables: map[string]bool{}}
	backend := &linuxNetworkBackend{runner: fake, dataDir: dir, identityKeyFile: identityPath}
	address := netip.MustParseAddr("198.51.100.7")
	if _, err := backend.Block(context.Background(), address); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(fake.calls, "\n")
	if !strings.Contains(joined, "nft add element inet ntshield_block blocked4 { 198.51.100.7 }") {
		t.Fatalf("missing exact blocked element command:\n%s", joined)
	}
	if _, err := loadSignedContainmentState(backend.blockStatePath(), identityPath, "firewall-block-linux-nft"); err != nil {
		t.Fatalf("block table ownership state invalid: %v", err)
	}
	if _, err := backend.Unblock(context.Background(), address); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxFirewallRefusesUnownedNamedTable(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &linuxFakeRunner{tables: map[string]bool{linuxBlockTable: true}}
	backend := &linuxNetworkBackend{runner: fake, dataDir: dir, identityKeyFile: identityPath}
	_, err = backend.Block(context.Background(), netip.MustParseAddr("203.0.113.44"))
	if err == nil || !strings.Contains(err.Error(), "without signed") {
		t.Fatalf("expected unowned table rejection, got %v", err)
	}
}
