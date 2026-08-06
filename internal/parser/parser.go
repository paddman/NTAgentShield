package parser

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
	"github.com/paddman/NTAgentShield/internal/normalize"
)

type Parser interface {
	Parse(line string) (*model.Event, error)
}

func New(format, source string) (Parser, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "raw", "text":
		return &rawParser{source: source}, nil
	case "jsonl", "event_jsonl":
		return &jsonParser{source: source}, nil
	case "iis", "iis_w3c":
		return &iisParser{source: source}, nil
	case "nginx", "nginx_combined":
		return &nginxParser{source: source}, nil
	case "syslog", "rfc3164":
		return &syslogParser{source: source}, nil
	case "mysql", "mysql_general":
		return &mysqlParser{source: source}, nil
	default:
		return nil, fmt.Errorf("unsupported log format %q", format)
	}
}

type rawParser struct{ source string }

func (p *rawParser) Parse(line string) (*model.Event, error) {
	if strings.TrimSpace(line) == "" {
		return nil, nil
	}
	event := &model.Event{
		Kind:     "log.observation",
		Severity: model.SeverityInfo,
		Trust:    model.TrustUntrustedTelemetry,
		Message:  line,
		Provenance: model.Provenance{
			Source:    p.source,
			Collector: "filetail/raw",
		},
	}
	event.Prepare()
	return event, nil
}

type jsonParser struct{ source string }

func (p *jsonParser) Parse(line string) (*model.Event, error) {
	if strings.TrimSpace(line) == "" {
		return nil, nil
	}
	var event model.Event
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return nil, fmt.Errorf("decode event json: %w", err)
	}
	event.Prepare()
	if event.Provenance.Source == "" {
		event.Provenance.Source = p.source
	}
	if event.Provenance.Collector == "" {
		event.Provenance.Collector = "filetail/jsonl"
	}
	return &event, nil
}

type iisParser struct {
	source string
	fields []string
}

func (p *iisParser) Parse(line string) (*model.Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}
	if strings.HasPrefix(line, "#Fields:") {
		p.fields = strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#Fields:")))
		return nil, nil
	}
	if strings.HasPrefix(line, "#") {
		return nil, nil
	}
	if len(p.fields) == 0 {
		return nil, errors.New("IIS W3C log is missing #Fields header")
	}
	values := strings.Fields(line)
	if len(values) < len(p.fields) {
		return nil, fmt.Errorf("IIS field count mismatch: got %d want %d", len(values), len(p.fields))
	}
	row := make(map[string]string, len(p.fields))
	for i, field := range p.fields {
		row[field] = dashToEmpty(values[i])
	}
	timestamp := time.Now().UTC()
	if row["date"] != "" && row["time"] != "" {
		if parsed, err := time.Parse("2006-01-02 15:04:05", row["date"]+" "+row["time"]); err == nil {
			timestamp = parsed.UTC()
		}
	}
	status, _ := strconv.Atoi(row["sc-status"])
	bytesSent, _ := strconv.ParseInt(row["sc-bytes"], 10, 64)
	duration, _ := strconv.ParseInt(row["time-taken"], 10, 64)
	path, _ := url.QueryUnescape(row["cs-uri-stem"])
	query, _ := url.QueryUnescape(row["cs-uri-query"])
	userAgent, _ := url.QueryUnescape(strings.ReplaceAll(row["cs(User-Agent)"], "+", " "))
	event := &model.Event{
		Timestamp: timestamp,
		Kind:      "web.request",
		Severity:  severityFromHTTP(status),
		Trust:     model.TrustUntrustedTelemetry,
		Actor:     model.Actor{User: row["cs-username"]},
		Network: model.NetworkContext{
			SourceIP:      row["c-ip"],
			DestinationIP: row["s-ip"],
		},
		HTTP: model.HTTPContext{
			Method:     row["cs-method"],
			Path:       path,
			Query:      query,
			Status:     status,
			UserAgent:  userAgent,
			Referer:    row["cs(Referer)"],
			Host:       row["cs-host"],
			BytesSent:  bytesSent,
			DurationMS: duration,
		},
		Message: fmt.Sprintf("%s %s status=%d", row["cs-method"], path, status),
		Attributes: map[string]interface{}{
			"site_name":    row["s-sitename"],
			"server_port":  row["s-port"],
			"substatus":    row["sc-substatus"],
			"win32_status": row["sc-win32-status"],
		},
		Provenance: model.Provenance{Source: p.source, Collector: "filetail/iis_w3c"},
	}
	event.Prepare()
	return event, nil
}

var nginxCombined = regexp.MustCompile(`^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+([^\s"]+)(?:\s+([^"]+))?"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"`)

type nginxParser struct{ source string }

func (p *nginxParser) Parse(line string) (*model.Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}
	match := nginxCombined.FindStringSubmatch(line)
	if match == nil {
		return nil, errors.New("line does not match nginx combined format")
	}
	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", match[3])
	if err != nil {
		return nil, fmt.Errorf("parse nginx timestamp: %w", err)
	}
	status, _ := strconv.Atoi(match[7])
	bytesSent, _ := strconv.ParseInt(dashToEmpty(match[8]), 10, 64)
	requestPath := match[5]
	parsedURL, _ := url.ParseRequestURI(requestPath)
	path := requestPath
	query := ""
	if parsedURL != nil {
		path = parsedURL.Path
		query = parsedURL.RawQuery
	}
	event := &model.Event{
		Timestamp: timestamp.UTC(),
		Kind:      "web.request",
		Severity:  severityFromHTTP(status),
		Trust:     model.TrustUntrustedTelemetry,
		Actor:     model.Actor{User: dashToEmpty(match[2])},
		Network:   model.NetworkContext{SourceIP: match[1]},
		HTTP: model.HTTPContext{
			Method:    match[4],
			Path:      path,
			Query:     query,
			Status:    status,
			Referer:   dashToEmpty(match[9]),
			UserAgent: dashToEmpty(match[10]),
			BytesSent: bytesSent,
		},
		Message:    fmt.Sprintf("%s %s status=%d", match[4], path, status),
		Attributes: map[string]interface{}{"http_version": match[6]},
		Provenance: model.Provenance{Source: p.source, Collector: "filetail/nginx_combined"},
	}
	event.Prepare()
	return event, nil
}

var syslogPattern = regexp.MustCompile(`^(?:<(\d{1,3})>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s?(.*)$`)

type syslogParser struct{ source string }

func (p *syslogParser) Parse(line string) (*model.Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}
	match := syslogPattern.FindStringSubmatch(line)
	if match == nil {
		event := &model.Event{Kind: "syslog.message", Message: line, Trust: model.TrustUntrustedTelemetry, Provenance: model.Provenance{Source: p.source, Collector: "filetail/syslog"}}
		event.Prepare()
		return event, nil
	}
	priority, _ := strconv.Atoi(match[1])
	year := time.Now().UTC().Year()
	timestamp, err := time.Parse("2006 Jan 2 15:04:05", fmt.Sprintf("%d %s", year, match[2]))
	if err != nil {
		timestamp = time.Now().UTC()
	}
	event := &model.Event{
		Timestamp: timestamp.UTC(),
		Kind:      "syslog.message",
		Severity:  severityFromSyslog(priority),
		Trust:     model.TrustUntrustedTelemetry,
		Asset:     model.Asset{Hostname: match[3]},
		Message:   match[5],
		Attributes: map[string]interface{}{
			"priority": priority,
			"program":  match[4],
		},
		Provenance: model.Provenance{Source: p.source, Collector: "filetail/syslog"},
	}
	event.Prepare()
	return event, nil
}

var mysqlGeneral = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\S+|\d{6}\s+\d{1,2}:\d{2}:\d{2})?\s*(\d+)?\s*(Connect|Query|Execute|Init DB|Quit)\s*(.*)$`)

type mysqlParser struct{ source string }

func (p *mysqlParser) Parse(line string) (*model.Event, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "/usr/") || strings.HasPrefix(line, "Time") {
		return nil, nil
	}
	match := mysqlGeneral.FindStringSubmatch(line)
	if match == nil {
		event := &model.Event{Kind: "database.log", Message: line, Trust: model.TrustUntrustedTelemetry, Database: model.DatabaseContext{Engine: "mysql"}, Provenance: model.Provenance{Source: p.source, Collector: "filetail/mysql_general"}}
		event.Prepare()
		return event, nil
	}
	command := strings.TrimSpace(match[3])
	payload := strings.TrimSpace(match[4])
	event := &model.Event{
		Kind:       "database.log",
		Severity:   model.SeverityInfo,
		Trust:      model.TrustUntrustedTelemetry,
		Database:   model.DatabaseContext{Engine: "mysql"},
		Message:    payload,
		Attributes: map[string]interface{}{"thread_id": match[2], "command": command},
		Provenance: model.Provenance{Source: p.source, Collector: "filetail/mysql_general"},
	}
	if command == "Query" || command == "Execute" {
		event.Kind = "database.query"
		event.Database.QueryFingerprint = normalize.SQLFingerprint(payload)
		event.Database.QueryVerbs = normalize.SQLVerbs(payload)
		event.Attributes["normalized_query"] = normalize.SQL(payload)
	}
	event.Prepare()
	return event, nil
}

func severityFromHTTP(status int) model.Severity {
	switch {
	case status >= 500:
		return model.SeverityMedium
	case status >= 400:
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func severityFromSyslog(priority int) model.Severity {
	severity := priority % 8
	switch severity {
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

func dashToEmpty(value string) string {
	if value == "-" {
		return ""
	}
	return value
}
