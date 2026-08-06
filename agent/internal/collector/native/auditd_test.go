package native

import (
	"bufio"
	"strings"
	"testing"
	"time"
)

func TestParseAuditFieldsAndNormalizeExecve(t *testing.T) {
	line := `type=EXECVE msg=audit(1786017600.125:812): argc=3 a0="/usr/bin/curl" a1="--password" a2="audit-secret" pid=421 ppid=400 uid=1000 auid=1000 ses=7 exe="/usr/bin/curl" success=yes`
	fields := parseAuditFields(line)
	if fields["type"] != "EXECVE" || fields["a0"] != "/usr/bin/curl" {
		t.Fatalf("unexpected audit fields: %#v", fields)
	}
	event := auditLineToEvent("linux-audit", "/var/log/audit/audit.log", line)
	if event.Kind != "process.start" || event.Process.PID != 421 || event.Process.PPID != 400 {
		t.Fatalf("unexpected audit process event: %#v", event)
	}
	if event.Process.CommandLine != "/usr/bin/curl --password audit-secret" {
		t.Fatalf("unexpected command line %q", event.Process.CommandLine)
	}
	expected := time.Unix(1786017600, 125000000).UTC()
	if !event.Timestamp.Equal(expected) {
		t.Fatalf("unexpected audit timestamp: got %s want %s", event.Timestamp, expected)
	}
	if event.ID != auditLineToEvent("linux-audit", "/var/log/audit/audit.log", line).ID {
		t.Fatal("audit event ID must be deterministic")
	}
}

func TestDecodeAuditProctitleAndAuthenticationFailure(t *testing.T) {
	if got := decodeAuditHex("2F62696E2F7368002D63006964"); got != "/bin/sh -c id" {
		t.Fatalf("unexpected decoded proctitle %q", got)
	}
	line := `type=USER_AUTH msg=audit(1786017601.000:813): pid=1000 uid=0 auid=4294967295 ses=4294967295 acct="root" exe="/usr/sbin/sshd" hostname=? addr=203.0.113.30 terminal=ssh res=failed`
	event := auditLineToEvent("linux-audit", "/var/log/audit/audit.log", line)
	if event.Kind != "auth.failure" || event.Actor.User != "root" {
		t.Fatalf("unexpected authentication event: %#v", event)
	}
	if event.Network.SourceIP != "203.0.113.30" || event.Network.Direction != "inbound" {
		t.Fatalf("unexpected authentication network context: %#v", event.Network)
	}
}

func TestReadAuditLineDoesNotCommitPartialEvidence(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("type=EXECVE msg=audit(1.0:1): a0=sh"))
	line, consumed, complete, err := readAuditLine(reader, maxAuditLineBytes)
	if err != nil {
		t.Fatalf("read partial line: %v", err)
	}
	if complete || line == "" || consumed == 0 {
		t.Fatalf("partial line was treated as complete: line=%q consumed=%d complete=%t", line, consumed, complete)
	}

	reader = bufio.NewReader(strings.NewReader("type=EXECVE msg=audit(1.0:1): a0=sh\n"))
	_, _, complete, err = readAuditLine(reader, maxAuditLineBytes)
	if err != nil || !complete {
		t.Fatalf("complete audit line was rejected: complete=%t err=%v", complete, err)
	}
}
