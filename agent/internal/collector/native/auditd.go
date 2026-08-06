package native

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/model"
)

const maxAuditLineBytes = 1024 * 1024

type auditSource struct {
	config config.NativeSource
	cursor *cursorFile
}

var (
	auditKeyValue       = regexp.MustCompile(`([A-Za-z0-9_]+)=("(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s]+)`)
	auditMessageContext = regexp.MustCompile(`audit\((\d+)(?:\.(\d+))?:(\d+)\)`)
	auditArgumentKey    = regexp.MustCompile(`^a(\d+)$`)
)

func newAuditSource(source config.NativeSource, cursor *cursorFile) (Source, error) {
	if !filepath.IsAbs(source.Path) {
		return nil, fmt.Errorf("auditd source %s path must be absolute", source.ID)
	}
	return &auditSource{config: source, cursor: cursor}, nil
}

func (s *auditSource) ID() string   { return s.config.ID }
func (s *auditSource) Kind() string { return "auditd" }

func (s *auditSource) Poll(ctx context.Context) (Batch, []error) {
	file, err := os.Open(s.config.Path)
	if err != nil {
		return Batch{}, []error{fmt.Errorf("auditd source %s: %w", s.config.ID, err)}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Batch{}, []error{fmt.Errorf("auditd source %s stat: %w", s.config.ID, err)}
	}
	device, inode := platformFileIdentity(info)
	state := s.cursor.Snapshot()
	if !state.Initialized {
		next := state
		next.Initialized = true
		next.FileDevice = device
		next.FileInode = inode
		if s.config.FromStart {
			next.FileOffset = 0
		} else {
			next.FileOffset = info.Size()
		}
		return Batch{cursor: s.cursor, next: &next}, nil
	}
	start := state.FileOffset
	if (state.FileInode != 0 && inode != 0 && state.FileInode != inode) || (state.FileDevice != 0 && device != 0 && state.FileDevice != device) || info.Size() < start {
		start = 0
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return Batch{}, []error{fmt.Errorf("auditd source %s seek: %w", s.config.ID, err)}
	}
	reader := bufio.NewReaderSize(file, 64*1024)
	events := make([]model.Event, 0, s.config.MaxBatch)
	nextOffset := start
	for len(events) < s.config.MaxBatch {
		if err := ctx.Err(); err != nil {
			return Batch{}, []error{err}
		}
		line, consumed, complete, readErr := readAuditLine(reader, maxAuditLineBytes)
		if readErr != nil {
			return Batch{}, []error{fmt.Errorf("auditd source %s read: %w", s.config.ID, readErr)}
		}
		if !complete {
			break
		}
		nextOffset += int64(consumed)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		events = append(events, auditLineToEvent(s.config.ID, s.config.Path, line))
	}
	next := state
	next.Initialized = true
	next.FileDevice = device
	next.FileInode = inode
	next.FileOffset = nextOffset
	if len(events) == 0 && nextOffset == state.FileOffset && state.FileDevice == device && state.FileInode == inode {
		return Batch{}, nil
	}
	return Batch{Events: events, cursor: s.cursor, next: &next}, nil
}

func readAuditLine(reader *bufio.Reader, maximum int) (string, int, bool, error) {
	buffer := make([]byte, 0, 4096)
	consumed := 0
	for {
		part, err := reader.ReadSlice('\n')
		consumed += len(part)
		if len(buffer)+len(part) > maximum {
			return "", consumed, false, fmt.Errorf("audit line exceeds %d bytes", maximum)
		}
		buffer = append(buffer, part...)
		switch err {
		case nil:
			return string(buffer), consumed, true, nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			return string(buffer), consumed, false, nil
		default:
			return "", consumed, false, err
		}
	}
}

func auditLineToEvent(sourceID, path, line string) model.Event {
	fields := parseAuditFields(line)
	typeName := strings.ToUpper(fields["type"])
	timestamp, serial := auditTimestamp(fields["msg"])
	kind := auditEventKind(typeName, fields)
	commandLine := auditCommandLine(fields)
	filePath := firstValue(fields["name"], fields["path"])
	digest := sha256.Sum256([]byte(line))
	event := model.Event{
		ID:        deterministicEventID("auditd", sourceID, serial, typeName, hex.EncodeToString(digest[:])),
		Timestamp: timestamp,
		Kind:      kind,
		Severity:  auditSeverity(typeName, fields),
		Trust:     model.TrustUntrustedTelemetry,
		Asset:     model.Asset{OS: "linux"},
		Actor: model.Actor{
			User:      firstValue(fields["acct"], fields["uid"], fields["auid"]),
			AccountID: firstValue(fields["auid"], fields["ses"]),
			SessionID: fields["ses"],
		},
		Process: model.ProcessContext{
			PID:         flexibleInt(fields["pid"]),
			PPID:        flexibleInt(fields["ppid"]),
			Image:       firstValue(fields["exe"], fields["comm"]),
			CommandLine: commandLine,
		},
		Network: model.NetworkContext{
			SourceIP:   firstValue(fields["addr"], fields["hostname"]),
			SourcePort: flexibleInt(fields["port"]),
			Direction:  auditDirection(kind),
		},
		File: model.FileContext{
			Path:       filePath,
			Operation:  auditFileOperation(fields["nametype"], kind),
			Executable: auditExecutablePath(filePath),
		},
		Message: line,
		Attributes: map[string]interface{}{
			"audit": map[string]interface{}{
				"type":   typeName,
				"serial": serial,
				"fields": fields,
			},
		},
		Provenance: model.Provenance{
			Source:       sourceID,
			Collector:    "linux-auditd/file",
			OriginalPath: path,
		},
	}
	event.Prepare()
	return event
}

func parseAuditFields(line string) map[string]string {
	result := map[string]string{}
	for _, match := range auditKeyValue.FindAllStringSubmatch(line, -1) {
		if len(match) != 3 {
			continue
		}
		value := strings.TrimSpace(match[2])
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			if decoded, err := strconv.Unquote(value); err == nil {
				value = decoded
			}
		} else if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = strings.Trim(value, "'")
		}
		result[match[1]] = value
	}
	return result
}

func auditTimestamp(value string) (time.Time, string) {
	match := auditMessageContext.FindStringSubmatch(value)
	if match == nil {
		return time.Now().UTC(), "unknown"
	}
	seconds, _ := strconv.ParseInt(match[1], 10, 64)
	nanoseconds := int64(0)
	fraction := match[2]
	if fraction != "" {
		if len(fraction) > 9 {
			fraction = fraction[:9]
		}
		fraction += strings.Repeat("0", 9-len(fraction))
		nanoseconds, _ = strconv.ParseInt(fraction, 10, 64)
	}
	return time.Unix(seconds, nanoseconds).UTC(), match[3]
}

func auditCommandLine(fields map[string]string) string {
	if command := firstValue(fields["cmd"], fields["command"]); command != "" {
		return command
	}
	if proctitle := decodeAuditHex(fields["proctitle"]); proctitle != "" {
		return proctitle
	}
	type argument struct {
		index int
		value string
	}
	arguments := make([]argument, 0)
	for key, value := range fields {
		match := auditArgumentKey.FindStringSubmatch(key)
		if match == nil {
			continue
		}
		index, _ := strconv.Atoi(match[1])
		arguments = append(arguments, argument{index: index, value: value})
	}
	sort.Slice(arguments, func(i, j int) bool { return arguments[i].index < arguments[j].index })
	parts := make([]string, 0, len(arguments))
	for _, item := range arguments {
		parts = append(parts, item.value)
	}
	return strings.Join(parts, " ")
}

func decodeAuditHex(value string) string {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value)%2 != 0 {
		return ""
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
			return ""
		}
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(decoded), "\x00", " "))
}

func auditEventKind(typeName string, fields map[string]string) string {
	switch typeName {
	case "EXECVE", "USER_CMD":
		return "process.start"
	case "SYSCALL":
		return "process.syscall"
	case "PATH", "CWD":
		return "file.access"
	case "USER_AUTH", "USER_LOGIN", "USER_ACCT", "CRED_ACQ", "CRED_DISP":
		if auditSucceeded(fields) {
			return "auth.success"
		}
		return "auth.failure"
	case "SERVICE_START":
		return "service.start"
	case "SERVICE_STOP":
		return "service.stop"
	case "CONFIG_CHANGE":
		return "security.audit_config"
	case "AVC", "USER_AVC", "SELINUX_ERR":
		return "security.selinux_denial"
	case "ADD_USER":
		return "identity.account_create"
	case "DEL_USER":
		return "identity.account_delete"
	case "ADD_GROUP", "GRP_MGMT":
		return "identity.group_modify"
	}
	if strings.HasPrefix(typeName, "ANOM_") || strings.HasPrefix(typeName, "RESP_") {
		return "security.anomaly"
	}
	return "linux.audit"
}

func auditSeverity(typeName string, fields map[string]string) model.Severity {
	switch typeName {
	case "AVC", "USER_AVC", "SELINUX_ERR", "CONFIG_CHANGE":
		return model.SeverityHigh
	case "ADD_USER", "DEL_USER", "ADD_GROUP", "GRP_MGMT", "SERVICE_START", "SERVICE_STOP":
		return model.SeverityMedium
	}
	if strings.HasPrefix(typeName, "ANOM_") || strings.HasPrefix(typeName, "RESP_") {
		return model.SeverityHigh
	}
	if !auditSucceeded(fields) {
		return model.SeverityMedium
	}
	return model.SeverityInfo
}

func auditSucceeded(fields map[string]string) bool {
	value := strings.ToLower(firstValue(fields["success"], fields["res"], fields["result"]))
	switch value {
	case "yes", "success", "succeeded", "1":
		return true
	case "no", "failed", "failure", "0":
		return false
	default:
		return true
	}
}

func auditFileOperation(nameType, kind string) string {
	switch strings.ToUpper(nameType) {
	case "CREATE":
		return "create"
	case "DELETE":
		return "delete"
	case "NORMAL", "PARENT":
		return "access"
	}
	if kind == "file.access" {
		return "access"
	}
	return ""
}

func auditExecutablePath(path string) bool {
	if path == "" {
		return false
	}
	if strings.HasPrefix(path, "/bin/") || strings.HasPrefix(path, "/sbin/") || strings.HasPrefix(path, "/usr/bin/") || strings.HasPrefix(path, "/usr/sbin/") {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".sh", ".py", ".pl", ".so", ".bin", ".run":
		return true
	default:
		return false
	}
}

func auditDirection(kind string) string {
	if strings.HasPrefix(kind, "auth.") {
		return "inbound"
	}
	return ""
}
