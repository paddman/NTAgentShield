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
	lastPort      PortRule
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
func (f *fakeNetworkBackend) OpenPort(_ context.Context, rule PortRule) (map[string]interface{}, error) {
	f.lastOperation = "open-port"
	f.lastPort = rule
	return map[string]interface{}{"opened": true}, nil
}
func (f *fakeNetworkBackend) ClosePort(_ context.Context, rule PortRule) (map[string]interface{}, error) {
	f.lastOperation = "close-port"
	f.lastPort = rule
	return map[string]interface{}{"closed": true}, nil
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

func TestFirewallPortContainmentRoutesTypedOpenAndClose(t *testing.T) {
	backend := &fakeNetworkBackend{}
	tool := FirewallPortContainment{backend: backend}
	if _, err := tool.Execute(context.Background(), map[string]interface{}{
		"operation": "open", "protocol": "tcp", "direction": "inbound", "port": float64(8443),
	}); err != nil {
		t.Fatal(err)
	}
	if backend.lastOperation != "open-port" || backend.lastPort.Protocol != "TCP" || backend.lastPort.Direction != "inbound" || backend.lastPort.Port != 8443 {
		t.Fatalf("unexpected open routing: op=%s rule=%+v", backend.lastOperation, backend.lastPort)
	}
	if _, err := tool.Execute(context.Background(), map[string]interface{}{
		"operation": "close", "protocol": "UDP", "direction": "outbound", "port": 5353,
	}); err != nil {
		t.Fatal(err)
	}
	if backend.lastOperation != "close-port" || backend.lastPort.Protocol != "UDP" || backend.lastPort.Direction != "outbound" || backend.lastPort.Port != 5353 {
		t.Fatalf("unexpected close routing: op=%s rule=%+v", backend.lastOperation, backend.lastPort)
	}
}

func TestFirewallPortContainmentRejectsUnsafeArguments(t *testing.T) {
	backend := &fakeNetworkBackend{}
	tool := FirewallPortContainment{backend: backend}
	for _, args := range []map[string]interface{}{
		{"protocol": "TCP", "direction": "inbound", "port": 0},
		{"protocol": "TCP", "direction": "inbound", "port": 65536},
		{"protocol": "ICMP", "direction": "inbound", "port": 443},
		{"protocol": "TCP", "direction": "sideways", "port": 443},
		{"protocol": "TCP", "direction": "inbound", "port": 443, "command": "netsh"},
	} {
		if _, err := tool.Execute(context.Background(), args); err == nil {
			t.Fatalf("expected unsafe args to be rejected: %#v", args)
		}
	}
}
