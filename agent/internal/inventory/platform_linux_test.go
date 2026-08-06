//go:build linux

package inventory

import "testing"

func TestParseProcAddress(t *testing.T) {
	address, port, err := parseProcAddress("0100007F:1F90", false)
	if err != nil {
		t.Fatalf("parse IPv4 listener: %v", err)
	}
	if address != "127.0.0.1" || port != 8080 {
		t.Fatalf("unexpected listener %s:%d", address, port)
	}
}

func TestParseSoftwareLines(t *testing.T) {
	items := parseSoftwareLines("nginx\t1.24.0\nmysql-server\t8.0\n", "dpkg", 10)
	if len(items) != 2 {
		t.Fatalf("expected two items, got %d", len(items))
	}
	if items[0].Name != "nginx" || items[0].Version != "1.24.0" || items[0].Source != "dpkg" {
		t.Fatalf("unexpected first item: %#v", items[0])
	}
}
