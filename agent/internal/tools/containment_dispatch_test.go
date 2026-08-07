package tools

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

type fakeNetworkBackend struct {
	lastOperation string
	lastIP        netip.Addr
}

func (f *fakeNetworkBackend) Isolate(context.Context) (map[string]interface{}, error) {
	f.lastOperation = "isolate"
	return map[string]interface{}{"isolated": true}, nil
}
func (f *fakeNetworkBackend) Release(context.Context) (map[string]interface{}, error) {
	f.lastOperation = "release"
	return map[string]interface{}{"released": true}, nil
}
func (f *fakeNetworkBackend) Block(_ context.Context, address netip.Addr) (map[string]interface{}, error) {
	f.lastOperation = "block"
	f.lastIP = address
	return map[string]interface{}{"blocked": true}, nil
}
func (f *fakeNetworkBackend) Unblock(_ context.Context, address netip.Addr) (map[string]interface{}, error) {
	f.lastOperation = "unblock"
	f.lastIP = address
	return map[string]interface{}{"unblocked": true}, nil
}

func TestHostContainmentRoutesReleaseExplicitly(t *testing.T) {
	backend := &fakeNetworkBackend{}
	tool := HostContainment{backend: backend}
	if _, err := tool.Execute(context.Background(), map[string]interface{}{"operation": "release"}); err != nil {
		t.Fatal(err)
	}
	if backend.lastOperation != "release" {
		t.Fatalf("expected release, got %q", backend.lastOperation)
	}
}

func TestFirewallContainmentRequiresExactIPAndRoutesUnblock(t *testing.T) {
	backend := &fakeNetworkBackend{}
	tool := FirewallContainment{backend: backend}
	if _, err := tool.Execute(context.Background(), map[string]interface{}{"operation": "unblock", "remote_ip": "203.0.113.8"}); err != nil {
		t.Fatal(err)
	}
	if backend.lastOperation != "unblock" || backend.lastIP.String() != "203.0.113.8" {
		t.Fatalf("unexpected unblock routing: op=%s ip=%s", backend.lastOperation, backend.lastIP)
	}
	if _, err := tool.Execute(context.Background(), map[string]interface{}{"remote_ip": "203.0.113.0/24"}); err == nil {
		t.Fatal("expected CIDR to be rejected; only exact IPs are allowed")
	}
}

func TestContainmentOperationDefaults(t *testing.T) {
	backend := &fakeNetworkBackend{}
	if _, err := (HostContainment{backend: backend}).Execute(context.Background(), map[string]interface{}{}); err != nil {
		t.Fatal(err)
	}
	if backend.lastOperation != "isolate" {
		t.Fatalf("expected isolate default, got %q", backend.lastOperation)
	}
	if _, err := (FirewallContainment{backend: backend}).Execute(context.Background(), map[string]interface{}{"remote_ip": "2001:db8::8"}); err != nil {
		t.Fatal(err)
	}
	if backend.lastOperation != "block" {
		t.Fatalf("expected block default, got %q", backend.lastOperation)
	}
}

func TestContainmentRejectsUnknownArguments(t *testing.T) {
	backend := &fakeNetworkBackend{}
	if _, err := (HostContainment{backend: backend}).Execute(context.Background(), map[string]interface{}{"operation": "isolate", "command": "anything"}); err == nil || !strings.Contains(err.Error(), "unsupported argument") {
		t.Fatalf("expected host unknown argument rejection, got %v", err)
	}
	if _, err := (FirewallContainment{backend: backend}).Execute(context.Background(), map[string]interface{}{"remote_ip": "203.0.113.9", "port": 443}); err == nil || !strings.Contains(err.Error(), "unsupported argument") {
		t.Fatalf("expected firewall unknown argument rejection, got %v", err)
	}
}
