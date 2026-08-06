package native

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/model"
)

type windowsEventLogSource struct {
	config  config.NativeSource
	timeout time.Duration
	cursor  *cursorFile
}

type windowsEventRecord struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
			GUID string `xml:"Guid,attr"`
		} `xml:"Provider"`
		EventID struct {
			Value string `xml:",chardata"`
		} `xml:"EventID"`
		Level         int    `xml:"Level"`
		Task          int    `xml:"Task"`
		Opcode        int    `xml:"Opcode"`
		Keywords      string `xml:"Keywords"`
		EventRecordID uint64 `xml:"EventRecordID"`
		Correlation   struct {
			ActivityID        string `xml:"ActivityID,attr"`
			RelatedActivityID string `xml:"RelatedActivityID,attr"`
		} `xml:"Correlation"`
		Execution struct {
			ProcessID int `xml:"ProcessID,attr"`
			ThreadID  int `xml:"ThreadID,attr"`
		} `xml:"Execution"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
		Binary string `xml:"Binary"`
	} `xml:"EventData"`
	UserData struct {
		InnerXML string `xml:",innerxml"`
	} `xml:"UserData"`
	RenderingInfo struct {
		Message string `xml:"Message"`
		Level   string `xml:"Level"`
		Task    string `xml:"Task"`
		Opcode  string `xml:"Opcode"`
	} `xml:"RenderingInfo"`
}

func (s *windowsEventLogSource) ID() string   { return s.config.ID }
func (s *windowsEventLogSource) Kind() string { return "windows_eventlog" }

func (s *windowsEventLogSource) Poll(ctx context.Context) (Batch, []error) {
	state := s.cursor.Snapshot()
	if !state.Initialized && !s.config.FromStart {
		latest, err := s.query(ctx, "", true, 1)
		if err != nil {
			return Batch{}, []error{err}
		}
		next := state
		next.Initialized = true
		for _, record := range latest {
			if record.System.EventRecordID > next.WindowsRecordID {
				next.WindowsRecordID = record.System.EventRecordID
			}
		}
		return Batch{cursor: s.cursor, next: &next}, nil
	}
	if !state.Initialized {
		state.Initialized = true
	}
	query := windowsXPath(state.WindowsRecordID, s.config.EventIDs)
	records, err := s.query(ctx, query, false, s.config.MaxBatch)
	if err != nil {
		return Batch{}, []error{err}
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].System.EventRecordID < records[j].System.EventRecordID
	})
	events := make([]model.Event, 0, len(records))
	next := state
	for _, record := range records {
		if record.System.EventRecordID == 0 || record.System.EventRecordID <= state.WindowsRecordID {
			continue
		}
		events = append(events, windowsRecordToEvent(s.config.ID, s.config.Channel, record))
		if record.System.EventRecordID > next.WindowsRecordID {
			next.WindowsRecordID = record.System.EventRecordID
		}
	}
	if len(events) == 0 && next == s.cursor.Snapshot() {
		return Batch{}, nil
	}
	return Batch{Events: events, cursor: s.cursor, next: &next}, nil
}

func (s *windowsEventLogSource) query(ctx context.Context, query string, reverse bool, maximum int) ([]windowsEventRecord, error) {
	args := []string{"qe", s.config.Channel}
	if query != "" {
		args = append(args, "/q:"+query)
	}
	if reverse {
		args = append(args, "/rd:true")
	} else {
		args = append(args, "/rd:false")
	}
	args = append(args, fmt.Sprintf("/c:%d", maximum), "/f:xml", "/uni:false")
	output, err := runCommand(ctx, s.timeout, "wevtutil.exe", args...)
	if err != nil {
		return nil, fmt.Errorf("windows event source %s channel %s: %w", s.config.ID, s.config.Channel, err)
	}
	records, err := decodeWindowsEvents(output)
	if err != nil {
		return nil, fmt.Errorf("decode windows event source %s: %w", s.config.ID, err)
	}
	return records, nil
}

func windowsXPath(after uint64, eventIDs []int) string {
	conditions := []string{fmt.Sprintf("EventRecordID > %d", after)}
	if len(eventIDs) > 0 {
		parts := make([]string, 0, len(eventIDs))
		for _, eventID := range eventIDs {
			parts = append(parts, fmt.Sprintf("EventID=%d", eventID))
		}
		conditions = append(conditions, "("+strings.Join(parts, " or ")+")")
	}
	return "*[System[(" + strings.Join(conditions, ") and (") + ")]]"
}

func decodeWindowsEvents(content string) ([]windowsEventRecord, error) {
	content = strings.TrimPrefix(content, "\ufeff")
	content = stripXMLDeclarations(content)
	decoder := xml.NewDecoder(strings.NewReader(content))
	records := make([]windowsEventRecord, 0)
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Event" {
			continue
		}
		var record windowsEventRecord
		if err := decoder.DecodeElement(&record, &start); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func stripXMLDeclarations(content string) string {
	for {
		start := strings.Index(content, "<?xml")
		if start < 0 {
			return content
		}
		end := strings.Index(content[start:], "?>")
		if end < 0 {
			return content
		}
		content = content[:start] + content[start+end+2:]
	}
}

func windowsRecordToEvent(sourceID, configuredChannel string, record windowsEventRecord) model.Event {
	data := windowsEventData(record)
	eventID := flexibleInt(record.System.EventID.Value)
	channel := firstValue(record.System.Channel, configuredChannel)
	provider := record.System.Provider.Name
	kind := windowsEventKind(provider, channel, eventID)
	timestamp, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(record.System.TimeCreated.SystemTime))
	image := firstMapValue(data, "Image", "NewProcessName", "ProcessName", "Application")
	parentImage := firstMapValue(data, "ParentImage", "ParentProcessName", "CreatorProcessName")
	targetFile := firstMapValue(data, "TargetFilename", "ObjectName", "FileName")
	sourceIP := firstMapValue(data, "SourceIp", "SourceAddress", "IpAddress")
	destinationIP := firstMapValue(data, "DestinationIp", "DestAddress", "DestinationAddress")
	direction := firstMapValue(data, "Direction")
	if direction == "" && strings.EqualFold(firstMapValue(data, "Initiated"), "true") {
		direction = "outbound"
	}
	message := strings.TrimSpace(record.RenderingInfo.Message)
	if message == "" {
		message = fmt.Sprintf("Windows event %d from %s", eventID, provider)
	}
	event := model.Event{
		ID:        deterministicEventID("windows", sourceID, channel, strconv.FormatUint(record.System.EventRecordID, 10)),
		Timestamp: timestamp,
		Kind:      kind,
		Severity:  windowsEventSeverity(eventID, kind),
		Trust:     model.TrustUntrustedTelemetry,
		Asset: model.Asset{
			Hostname: record.System.Computer,
			OS:       "windows",
		},
		Actor: model.Actor{
			User:      firstMapValue(data, "User", "TargetUserName", "SubjectUserName", "AccountName"),
			AccountID: firstValue(firstMapValue(data, "UserSid", "TargetUserSid", "SubjectUserSid"), record.System.Security.UserID),
			SessionID: firstMapValue(data, "LogonId", "TargetLogonId", "SubjectLogonId"),
		},
		Process: model.ProcessContext{
			PID:              flexibleInt(firstMapValue(data, "ProcessId", "ProcessID", "NewProcessId")),
			PPID:             flexibleInt(firstMapValue(data, "ParentProcessId", "ParentProcessID", "ProcessId")),
			Image:            image,
			ParentImage:      parentImage,
			CommandLine:      firstMapValue(data, "CommandLine", "ProcessCommandLine"),
			ExecutableSHA256: hashFromWindowsHashes(firstMapValue(data, "Hashes", "Hash")),
			IntegrityLevel:   firstMapValue(data, "IntegrityLevel", "MandatoryLabel"),
		},
		Network: model.NetworkContext{
			SourceIP:        sourceIP,
			SourcePort:      flexibleInt(firstMapValue(data, "SourcePort", "IpPort")),
			DestinationIP:   destinationIP,
			DestinationPort: flexibleInt(firstMapValue(data, "DestinationPort", "DestPort")),
			Protocol:        firstMapValue(data, "Protocol"),
			Domain:          firstMapValue(data, "QueryName", "DestinationHostname"),
			Direction:       strings.ToLower(direction),
		},
		File: model.FileContext{
			Path:       targetFile,
			Operation:  windowsFileOperation(kind),
			SHA256:     hashFromWindowsHashes(firstMapValue(data, "Hashes", "Hash")),
			Executable: windowsExecutablePath(targetFile),
		},
		Message: message,
		Attributes: map[string]interface{}{
			"windows": map[string]interface{}{
				"event_id":             eventID,
				"record_id":            record.System.EventRecordID,
				"provider":             provider,
				"provider_guid":        record.System.Provider.GUID,
				"channel":              channel,
				"level":                record.System.Level,
				"task":                 record.System.Task,
				"opcode":               record.System.Opcode,
				"keywords":             record.System.Keywords,
				"activity_id":          record.System.Correlation.ActivityID,
				"related_activity_id":  record.System.Correlation.RelatedActivityID,
				"execution_process_id": record.System.Execution.ProcessID,
				"execution_thread_id":  record.System.Execution.ThreadID,
				"event_data":           data,
			},
		},
		Provenance: model.Provenance{
			Source:       sourceID,
			Collector:    "windows-eventlog/wevtutil",
			OriginalPath: channel,
		},
	}
	event.Prepare()
	return event
}

func windowsEventData(record windowsEventRecord) map[string]interface{} {
	result := make(map[string]interface{}, len(record.EventData.Data)+8)
	for index, item := range record.EventData.Data {
		key := strings.TrimSpace(item.Name)
		if key == "" {
			key = fmt.Sprintf("param_%d", index+1)
		}
		result[key] = strings.TrimSpace(item.Value)
	}
	if binary := strings.TrimSpace(record.EventData.Binary); binary != "" {
		result["binary"] = binary
	}
	for key, value := range flattenXMLLeaves(record.UserData.InnerXML) {
		if _, exists := result[key]; !exists {
			result[key] = value
		}
	}
	return result
}

func flattenXMLLeaves(content string) map[string]interface{} {
	result := map[string]interface{}{}
	if strings.TrimSpace(content) == "" {
		return result
	}
	decoder := xml.NewDecoder(strings.NewReader("<Root>" + content + "</Root>"))
	stack := make([]string, 0)
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch typed := token.(type) {
		case xml.StartElement:
			stack = append(stack, typed.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			value := strings.TrimSpace(string(typed))
			if value == "" || len(stack) == 0 {
				continue
			}
			key := stack[len(stack)-1]
			if key != "Root" {
				result[key] = value
			}
		}
	}
	return result
}

func windowsEventKind(provider, channel string, eventID int) string {
	lowerProvider := strings.ToLower(provider)
	lowerChannel := strings.ToLower(channel)
	if strings.Contains(lowerProvider, "sysmon") || strings.Contains(lowerChannel, "sysmon") {
		switch eventID {
		case 1:
			return "process.start"
		case 3:
			return "network.connect"
		case 6:
			return "driver.load"
		case 7:
			return "image.load"
		case 8:
			return "process.remote_thread"
		case 10:
			return "process.access"
		case 11:
			return "file.write"
		case 12, 13, 14:
			return "registry.modify"
		case 15:
			return "file.stream_create"
		case 17, 18:
			return "ipc.pipe"
		case 19, 20, 21:
			return "persistence.wmi"
		case 22:
			return "dns.query"
		case 23, 26:
			return "file.delete"
		case 25:
			return "process.tamper"
		case 29:
			return "file.executable_detected"
		}
		return "windows.sysmon"
	}
	switch eventID {
	case 4624:
		return "auth.success"
	case 4625:
		return "auth.failure"
	case 4648:
		return "auth.explicit_credentials"
	case 4672:
		return "privilege.special_logon"
	case 4688:
		return "process.start"
	case 4697, 7045:
		return "service.create"
	case 4698:
		return "persistence.scheduled_task"
	case 4720:
		return "identity.account_create"
	case 4728, 4732:
		return "identity.group_member_add"
	case 5156:
		return "network.connect"
	case 5157:
		return "network.block"
	case 1102:
		return "security.log_clear"
	default:
		return "windows.event"
	}
}

func windowsEventSeverity(eventID int, kind string) model.Severity {
	switch eventID {
	case 1102, 25:
		return model.SeverityCritical
	case 4697, 7045, 4720, 4728, 4732, 8, 10:
		return model.SeverityHigh
	case 4625, 4648, 4672, 4698, 5157, 6, 7, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 23, 26, 29:
		return model.SeverityMedium
	case 3, 22, 5156:
		return model.SeverityLow
	}
	if strings.Contains(kind, "tamper") || strings.Contains(kind, "log_clear") {
		return model.SeverityCritical
	}
	return model.SeverityInfo
}

func windowsFileOperation(kind string) string {
	switch kind {
	case "file.write", "file.stream_create", "file.executable_detected":
		return "create"
	case "file.delete":
		return "delete"
	default:
		return ""
	}
}

func windowsExecutablePath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".exe", ".dll", ".sys", ".com", ".scr", ".ps1", ".bat", ".cmd":
		return true
	default:
		return false
	}
}

func firstMapValue(values map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, exists := values[key]; exists {
			text := strings.TrimSpace(fmt.Sprint(value))
			if text != "" && text != "-" {
				return text
			}
		}
	}
	return ""
}

func firstValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func flexibleInt(value string) int {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return 0
	}
	parsed, err := strconv.ParseInt(value, 0, 64)
	if err != nil {
		parsed, _ = strconv.ParseInt(value, 10, 64)
	}
	return int(parsed)
}

func hashFromWindowsHashes(value string) string {
	for _, part := range strings.FieldsFunc(value, func(character rune) bool { return character == ',' || character == ';' }) {
		fields := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(fields) == 2 && strings.EqualFold(strings.TrimSpace(fields[0]), "SHA256") {
			return strings.ToLower(strings.TrimSpace(fields[1]))
		}
	}
	return ""
}
