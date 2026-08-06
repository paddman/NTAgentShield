package native

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/model"
)

type journalSource struct {
	config  config.NativeSource
	timeout time.Duration
	cursor  *cursorFile
}

var sshAuthentication = regexp.MustCompile(`(?i)\b(Failed|Accepted)\s+(?:password|publickey|keyboard-interactive)\s+for\s+(?:invalid user\s+)?([^\s]+)\s+from\s+([0-9a-f:.]+)\s+port\s+(\d+)`)

func (s *journalSource) ID() string   { return s.config.ID }
func (s *journalSource) Kind() string { return "journald" }

func (s *journalSource) Poll(ctx context.Context) (Batch, []error) {
	state := s.cursor.Snapshot()
	if !state.Initialized && !s.config.FromStart {
		records, err := s.query(ctx, "", time.Time{}, true, 1)
		if err != nil {
			return Batch{}, []error{err}
		}
		next := state
		next.Initialized = true
		if len(records) > 0 {
			next.JournalCursor = journalString(records[0], "__CURSOR")
		} else {
			next.JournalSince = time.Now().UTC()
		}
		return Batch{cursor: s.cursor, next: &next}, nil
	}
	if !state.Initialized {
		state.Initialized = true
		state.JournalSince = time.Unix(0, 0).UTC()
	}
	records, err := s.query(ctx, state.JournalCursor, state.JournalSince, false, s.config.MaxBatch)
	if err != nil {
		return Batch{}, []error{err}
	}
	if len(records) == 0 {
		if !s.cursor.Snapshot().Initialized {
			next := state
			return Batch{cursor: s.cursor, next: &next}, nil
		}
		return Batch{}, nil
	}
	events := make([]model.Event, 0, len(records))
	next := state
	for _, record := range records {
		cursor := journalString(record, "__CURSOR")
		if cursor == "" {
			continue
		}
		events = append(events, journalRecordToEvent(s.config.ID, record))
		next.JournalCursor = cursor
		next.JournalSince = time.Time{}
	}
	if len(events) == 0 {
		return Batch{}, []error{fmt.Errorf("journald source %s returned records without cursors", s.config.ID)}
	}
	return Batch{Events: events, cursor: s.cursor, next: &next}, nil
}

func (s *journalSource) query(ctx context.Context, afterCursor string, since time.Time, reverse bool, maximum int) ([]map[string]interface{}, error) {
	args := journalArguments(afterCursor, since, reverse, maximum, s.config.Units, s.config.Identifiers)
	output, err := runCommand(ctx, s.timeout, "journalctl", args...)
	if err != nil {
		return nil, fmt.Errorf("journald source %s: %w", s.config.ID, err)
	}
	records, err := decodeJournalRecords(output)
	if err != nil {
		return nil, fmt.Errorf("decode journald source %s: %w", s.config.ID, err)
	}
	return records, nil
}

func journalArguments(afterCursor string, since time.Time, reverse bool, maximum int, units, identifiers []string) []string {
	lineLimit := fmt.Sprintf("--lines=+%d", maximum)
	if reverse {
		lineLimit = fmt.Sprintf("--lines=%d", maximum)
	}
	args := []string{"--no-pager", "--quiet", "--all", "--output=json", lineLimit}
	if reverse {
		args = append(args, "--reverse")
	}
	if afterCursor != "" {
		args = append(args, "--after-cursor="+afterCursor)
	} else if !since.IsZero() {
		args = append(args, fmt.Sprintf("--since=@%d", since.UTC().Unix()))
	}
	for _, unit := range units {
		args = append(args, "--unit="+unit)
	}
	for _, identifier := range identifiers {
		args = append(args, "--identifier="+identifier)
	}
	return args
}

func decodeJournalRecords(content string) ([]map[string]interface{}, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	records := make([]map[string]interface{}, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "-- cursor:") {
			continue
		}
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.UseNumber()
		record := map[string]interface{}{}
		if err := decoder.Decode(&record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, scanner.Err()
}

func journalRecordToEvent(sourceID string, record map[string]interface{}) model.Event {
	cursor := journalString(record, "__CURSOR")
	message := journalString(record, "MESSAGE")
	identifier := firstValue(journalString(record, "SYSLOG_IDENTIFIER"), journalString(record, "_COMM"))
	unit := journalString(record, "_SYSTEMD_UNIT")
	timestamp := journalTimestamp(record)
	kind := journalEventKind(identifier, unit, message, journalString(record, "_TRANSPORT"))
	severity := journalSeverity(journalString(record, "PRIORITY"))
	user := journalString(record, "_UID")
	sourceIP := ""
	sourcePort := 0
	if match := sshAuthentication.FindStringSubmatch(message); match != nil {
		user = match[2]
		sourceIP = match[3]
		sourcePort, _ = strconv.Atoi(match[4])
	}
	attributes := cloneJournalRecord(record)
	delete(attributes, "__CURSOR")
	if bootID := journalString(record, "_BOOT_ID"); bootID != "" {
		attributes["boot_id_hash"] = journalIdentifierHash("boot", bootID)
	}
	delete(attributes, "_BOOT_ID")
	event := model.Event{
		ID:        deterministicEventID("journal", sourceID, cursor),
		Timestamp: timestamp,
		Kind:      kind,
		Severity:  severity,
		Trust:     model.TrustUntrustedTelemetry,
		Asset: model.Asset{
			Hostname: journalString(record, "_HOSTNAME"),
			OS:       "linux",
		},
		Actor: model.Actor{
			User:      user,
			AccountID: journalString(record, "_AUDIT_LOGINUID"),
		},
		Process: model.ProcessContext{
			PID:         flexibleInt(journalString(record, "_PID")),
			Image:       firstValue(journalString(record, "_EXE"), journalString(record, "_COMM")),
			CommandLine: journalString(record, "_CMDLINE"),
		},
		Network: model.NetworkContext{
			SourceIP:   sourceIP,
			SourcePort: sourcePort,
			Direction:  directionForJournalKind(kind),
		},
		Message: message,
		Attributes: map[string]interface{}{
			"journal": map[string]interface{}{
				"identifier": identifier,
				"unit":       unit,
				"transport":  journalString(record, "_TRANSPORT"),
				"facility":   journalString(record, "SYSLOG_FACILITY"),
				"record":     attributes,
			},
		},
		Provenance: model.Provenance{
			Source:       sourceID,
			Collector:    "linux-journald/journalctl",
			OriginalPath: unit,
		},
	}
	event.Prepare()
	return event
}

func journalEventKind(identifier, unit, message, transport string) string {
	lowerIdentifier := strings.ToLower(identifier)
	lowerUnit := strings.ToLower(unit)
	lowerMessage := strings.ToLower(message)
	if transport == "audit" || strings.Contains(lowerIdentifier, "audit") {
		return "linux.audit"
	}
	if strings.Contains(lowerIdentifier, "sshd") || strings.Contains(lowerUnit, "ssh") {
		switch {
		case strings.Contains(lowerMessage, "failed password"), strings.Contains(lowerMessage, "authentication failure"):
			return "auth.failure"
		case strings.Contains(lowerMessage, "accepted password"), strings.Contains(lowerMessage, "accepted publickey"):
			return "auth.success"
		case strings.Contains(lowerMessage, "session opened"):
			return "auth.session_open"
		case strings.Contains(lowerMessage, "session closed"):
			return "auth.session_close"
		}
		return "auth.ssh"
	}
	if strings.Contains(lowerIdentifier, "sudo") || strings.Contains(lowerUnit, "sudo") {
		return "privilege.sudo"
	}
	if strings.Contains(lowerUnit, ".service") && strings.Contains(lowerMessage, "started") {
		return "service.start"
	}
	if strings.Contains(lowerUnit, ".service") && (strings.Contains(lowerMessage, "stopped") || strings.Contains(lowerMessage, "failed")) {
		return "service.stop"
	}
	if transport == "kernel" || lowerIdentifier == "kernel" {
		return "kernel.message"
	}
	return "linux.journal"
}

func journalSeverity(priority string) model.Severity {
	value, err := strconv.Atoi(strings.TrimSpace(priority))
	if err != nil {
		return model.SeverityInfo
	}
	switch value {
	case 0, 1, 2:
		return model.SeverityCritical
	case 3:
		return model.SeverityHigh
	case 4:
		return model.SeverityMedium
	case 5:
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func journalTimestamp(record map[string]interface{}) time.Time {
	value := journalString(record, "__REALTIME_TIMESTAMP")
	microseconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || microseconds <= 0 {
		return time.Now().UTC()
	}
	return time.Unix(0, microseconds*int64(time.Microsecond)).UTC()
}

func journalString(record map[string]interface{}, key string) string {
	value, exists := record[key]
	if !exists || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case []interface{}:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, strings.TrimSpace(fmt.Sprint(item)))
		}
		return strings.Join(parts, " ")
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func cloneJournalRecord(record map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(record))
	for key, value := range record {
		result[key] = value
	}
	return result
}

func journalIdentifierHash(scope, value string) string {
	digest := sha256.Sum256([]byte(scope + "\x00" + value))
	return hex.EncodeToString(digest[:])
}

func directionForJournalKind(kind string) string {
	if strings.HasPrefix(kind, "auth.") {
		return "inbound"
	}
	return ""
}
