//go:build windows

package inventory

import "testing"

func TestParseWindowsEndpoint(t *testing.T) {
	address, port, err := parseWindowsEndpoint("0.0.0.0:443")
	if err != nil {
		t.Fatalf("parse IPv4 endpoint: %v", err)
	}
	if address != "0.0.0.0" || port != 443 {
		t.Fatalf("unexpected endpoint %s:%d", address, port)
	}
	address, port, err = parseWindowsEndpoint("[::]:5985")
	if err != nil {
		t.Fatalf("parse IPv6 endpoint: %v", err)
	}
	if address != "::" || port != 5985 {
		t.Fatalf("unexpected IPv6 endpoint %s:%d", address, port)
	}
}

func TestParseCSVRecords(t *testing.T) {
	rows, err := parseCSVRecords("\"Name\",\"Version\"\r\n\"IIS\",\"10.0\"\r\n")
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	if len(rows) != 1 || rows[0]["Name"] != "IIS" || rows[0]["Version"] != "10.0" {
		t.Fatalf("unexpected rows: %#v", rows)
	}
}

func TestParseRegistryValue(t *testing.T) {
	output := "    MachineGuid    REG_SZ    11111111-2222-3333-4444-555555555555\r\n"
	value := parseRegistryValue(output, "MachineGuid")
	if value != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("unexpected registry value %q", value)
	}
}
