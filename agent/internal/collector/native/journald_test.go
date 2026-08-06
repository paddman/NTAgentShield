package native

import (
	"strings"
	"testing"
	"time"
)

func TestDecodeJournalRecordsAndNormalizeSSHFailure(t *testing.T) {
	content := `{"__CURSOR":"s=abc;i=1;b=boot-secret;m=1;t=64d1","__REALTIME_TIMESTAMP":"1786017600123456","_HOSTNAME":"linux01","_BOOT_ID":"boot-secret","_PID":"765","_EXE":"/usr/sbin/sshd","_COMM":"sshd","SYSLOG_IDENTIFIER":"sshd","_SYSTEMD_UNIT":"ssh.service","PRIORITY":"4","MESSAGE":"Failed password for invalid user admin from 203.0.113.25 port 60222 ssh2"}
{"__CURSOR":"s=abc;i=2;b=boot-secret;m=2;t=64d2","__REALTIME_TIMESTAMP":"1786017601123456","_HOSTNAME":"linux01","_COMM":"sudo","SYSLOG_IDENTIFIER":"sudo","PRIORITY":"5","MESSAGE":"paddman : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id"}`
	records, err := decodeJournalRecords(content)
	if err != nil {
		t.Fatalf("decode journald records: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected two records, got %d", len(records))
	}
	event := journalRecordToEvent("system-journal", records[0])
	if event.Kind != "auth.failure" || event.Actor.User != "admin" {
		t.Fatalf("unexpected SSH event: %#v", event)
	}
	if event.Network.SourceIP != "203.0.113.25" || event.Network.SourcePort != 60222 || event.Network.Direction != "inbound" {
		t.Fatalf("unexpected SSH network context: %#v", event.Network)
	}
	if event.ID != journalRecordToEvent("system-journal", records[0]).ID {
		t.Fatal("journald event ID must be deterministic")
	}
	journal := event.Attributes["journal"].(map[string]interface{})
	record := journal["record"].(map[string]interface{})
	if _, exists := record["__CURSOR"]; exists {
		t.Fatal("journald cursor must not be copied into event evidence")
	}
	bootHash, ok := record["boot_id_hash"].(string)
	if !ok || len(bootHash) != 64 || strings.Contains(bootHash, "boot-secret") {
		t.Fatalf("boot identifier was not pseudonymized: %#v", record["boot_id_hash"])
	}
	if !event.Timestamp.Equal(time.Unix(0, 1786017600123456*int64(time.Microsecond)).UTC()) {
		t.Fatalf("unexpected event timestamp: %s", event.Timestamp)
	}

	sudoEvent := journalRecordToEvent("system-journal", records[1])
	if sudoEvent.Kind != "privilege.sudo" {
		t.Fatalf("unexpected sudo event kind %q", sudoEvent.Kind)
	}
}

func TestJournalSeverityAndKind(t *testing.T) {
	if journalSeverity("2") != "critical" || journalSeverity("6") != "info" {
		t.Fatal("journald priority mapping changed unexpectedly")
	}
	if got := journalEventKind("kernel", "", "segfault", "kernel"); got != "kernel.message" {
		t.Fatalf("unexpected kernel kind %q", got)
	}
	if got := journalEventKind("sshd", "ssh.service", "Accepted publickey for root", "syslog"); got != "auth.success" {
		t.Fatalf("unexpected SSH success kind %q", got)
	}
}
