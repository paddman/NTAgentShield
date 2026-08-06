package native

import (
	"strings"
	"testing"
)

func TestDecodeWindowsEventsAndNormalizeSysmon(t *testing.T) {
	content := `<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
      <EventID>1</EventID>
      <Level>4</Level>
      <Task>1</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2026-08-06T12:00:00.1234567Z"/>
      <EventRecordID>1001</EventRecordID>
      <Correlation ActivityID="{11111111-1111-1111-1111-111111111111}"/>
      <Execution ProcessID="4321" ThreadID="99"/>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>web01.example.local</Computer>
      <Security UserID="S-1-5-18"/>
    </System>
    <EventData>
      <Data Name="ProcessId">1234</Data>
      <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -EncodedCommand SQBFAFgA</Data>
      <Data Name="ParentProcessId">456</Data>
      <Data Name="ParentImage">C:\Windows\System32\inetsrv\w3wp.exe</Data>
      <Data Name="User">IIS APPPOOL\DefaultAppPool</Data>
      <Data Name="Hashes">MD5=aaaaaaaa,SHA256=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB</Data>
    </EventData>
    <RenderingInfo xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <Message>Process Create</Message>
      <Level>Information</Level>
    </RenderingInfo>
  </Event>
</Events>`

	records, err := decodeWindowsEvents(content)
	if err != nil {
		t.Fatalf("decode Windows events: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	event := windowsRecordToEvent("sysmon-operational", "", records[0])
	if event.Kind != "process.start" {
		t.Fatalf("unexpected event kind %q", event.Kind)
	}
	if event.Process.PID != 1234 || event.Process.PPID != 456 {
		t.Fatalf("unexpected process IDs: %#v", event.Process)
	}
	if !strings.HasSuffix(strings.ToLower(event.Process.ParentImage), `\w3wp.exe`) {
		t.Fatalf("parent image was not normalized: %q", event.Process.ParentImage)
	}
	if event.Process.ExecutableSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("SHA-256 was not extracted: %q", event.Process.ExecutableSHA256)
	}
	if event.Asset.Hostname != "web01.example.local" || event.Trust != "untrusted_telemetry" {
		t.Fatalf("unexpected asset/trust: %#v %q", event.Asset, event.Trust)
	}
	if event.ID != windowsRecordToEvent("sysmon-operational", "", records[0]).ID {
		t.Fatal("Windows event ID must be deterministic for replay deduplication")
	}
}

func TestNormalizeWindowsAuthenticationFailure(t *testing.T) {
	content := `<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing"/>
      <EventID>4625</EventID>
      <Level>0</Level>
      <TimeCreated SystemTime="2026-08-06T12:05:00Z"/>
      <EventRecordID>9001</EventRecordID>
      <Channel>Security</Channel>
      <Computer>dc01.example.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">administrator</Data>
      <Data Name="TargetUserSid">S-1-0-0</Data>
      <Data Name="IpAddress">203.0.113.10</Data>
      <Data Name="IpPort">55000</Data>
      <Data Name="ProcessName">C:\Windows\System32\lsass.exe</Data>
    </EventData>
  </Event>
</Events>`
	records, err := decodeWindowsEvents(content)
	if err != nil || len(records) != 1 {
		t.Fatalf("decode authentication event: records=%d err=%v", len(records), err)
	}
	event := windowsRecordToEvent("security", "Security", records[0])
	if event.Kind != "auth.failure" || event.Actor.User != "administrator" {
		t.Fatalf("unexpected authentication event: %#v", event)
	}
	if event.Network.SourceIP != "203.0.113.10" || event.Network.SourcePort != 55000 {
		t.Fatalf("unexpected network context: %#v", event.Network)
	}
}

func TestWindowsXPathUsesRecordCursorAndAllowlistedEventIDs(t *testing.T) {
	query := windowsXPath(500, []int{1, 3, 11})
	for _, fragment := range []string{"EventRecordID > 500", "EventID=1", "EventID=3", "EventID=11"} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("query %q is missing %q", query, fragment)
		}
	}
	if strings.ContainsAny(query, "\r\n") {
		t.Fatalf("query contains an unexpected line break: %q", query)
	}
}
