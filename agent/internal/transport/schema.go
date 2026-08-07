package transport

import (
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
)

type ControlPlaneEvent struct {
	EventID    string                 `json:"event_id"`
	AgentID    string                 `json:"agent_id"`
	TenantID   string                 `json:"tenant_id"`
	ObservedAt time.Time              `json:"observed_at"`
	SourceType string                 `json:"source_type"`
	EventType  string                 `json:"event_type"`
	Asset      AssetContext           `json:"asset"`
	Actor      ActorContext           `json:"actor"`
	Process    ProcessContext         `json:"process"`
	Network    NetworkContext         `json:"network"`
	File       FileContext            `json:"file"`
	Service    ServiceContext         `json:"service"`
	Registry   RegistryContext        `json:"registry"`
	Web        WebContext             `json:"web"`
	Database   DatabaseContext        `json:"database"`
	Message    string                 `json:"message,omitempty"`
	Tags       []string               `json:"tags,omitempty"`
	Raw        map[string]interface{} `json:"raw"`
}

type AssetContext struct {
	ID          string `json:"id"`
	Hostname    string `json:"hostname,omitempty"`
	IP          string `json:"ip,omitempty"`
	OS          string `json:"os,omitempty"`
	Role        string `json:"role,omitempty"`
	Criticality int    `json:"criticality"`
}

type ActorContext struct {
	User      string `json:"user,omitempty"`
	Domain    string `json:"domain,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Integrity string `json:"integrity,omitempty"`
}

type ProcessContext struct {
	Name        string `json:"name,omitempty"`
	Path        string `json:"path,omitempty"`
	PID         int    `json:"pid,omitempty"`
	ParentName  string `json:"parent_name,omitempty"`
	ParentPath  string `json:"parent_path,omitempty"`
	ParentPID   int    `json:"parent_pid,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Signer      string `json:"signer,omitempty"`
}

type NetworkContext struct {
	SourceIP        string `json:"source_ip,omitempty"`
	SourcePort      int    `json:"source_port,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	Direction       string `json:"direction,omitempty"`
	Domain          string `json:"domain,omitempty"`
	IsExternal      *bool  `json:"is_external,omitempty"`
}

type FileContext struct {
	Path      string `json:"path,omitempty"`
	Operation string `json:"operation,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Extension string `json:"extension,omitempty"`
}

type ServiceContext struct {
	Name       string `json:"name,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	StartType  string `json:"start_type,omitempty"`
	Action     string `json:"action,omitempty"`
}

type RegistryContext struct {
	Path      string `json:"path,omitempty"`
	ValueName string `json:"value_name,omitempty"`
	ValueData string `json:"value_data,omitempty"`
	Operation string `json:"operation,omitempty"`
}

type WebContext struct {
	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	Status    int    `json:"status,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Route     string `json:"route,omitempty"`
}

type DatabaseContext struct {
	Engine     string  `json:"engine,omitempty"`
	Database   string  `json:"database,omitempty"`
	Statement  string  `json:"statement,omitempty"`
	QueryShape string  `json:"query_shape,omitempty"`
	Rows       int64   `json:"rows,omitempty"`
	DurationMS float64 `json:"duration_ms,omitempty"`
}

func MapEvent(event model.Event) ControlPlaneEvent {
	assetID := strings.TrimSpace(event.Asset.ID)
	if assetID == "" {
		assetID = strings.TrimSpace(event.AgentID)
	}
	if assetID == "" {
		assetID = strings.TrimSpace(event.Asset.Hostname)
	}
	if assetID == "" {
		assetID = "unknown-asset"
	}

	sourceType := strings.TrimSpace(event.Provenance.Collector)
	if sourceType == "" {
		sourceType = strings.TrimSpace(event.Provenance.Source)
	}
	if sourceType == "" {
		sourceType = "ntagentshield-agent"
	}

	raw := cloneMap(event.Attributes)
	raw["agent_event_id"] = event.ID
	raw["agent_id"] = event.AgentID
	raw["trust"] = string(event.Trust)
	raw["severity"] = string(event.Severity)
	if event.Provenance.OriginalPath != "" {
		raw["original_path"] = event.Provenance.OriginalPath
	}
	if event.Provenance.LineNumber != 0 {
		raw["line_number"] = event.Provenance.LineNumber
	}
	if event.Provenance.ContentSHA256 != "" {
		raw["content_sha256"] = event.Provenance.ContentSHA256
	}
	if event.HTTP.Query != "" {
		raw["http_query"] = event.HTTP.Query
	}
	if event.Actor.AccountID != "" {
		raw["actor_account_id"] = event.Actor.AccountID
	}
	if event.File.Owner != "" {
		raw["file_owner"] = event.File.Owner
	}
	if event.File.Size != 0 {
		raw["file_size"] = event.File.Size
	}
	if event.File.Executable {
		raw["file_executable"] = true
	}

	mapped := ControlPlaneEvent{
		EventID:    event.ID,
		AgentID:    event.AgentID,
		TenantID:   event.TenantID,
		ObservedAt: event.Timestamp.UTC(),
		SourceType: sourceType,
		EventType:  event.Kind,
		Asset: AssetContext{
			ID:          assetID,
			Hostname:    event.Asset.Hostname,
			OS:          event.Asset.OS,
			Criticality: 3,
		},
		Actor: ActorContext{
			User:      event.Actor.User,
			SessionID: event.Actor.SessionID,
			Integrity: event.Process.IntegrityLevel,
		},
		Process: ProcessContext{
			Name:        pathBase(event.Process.Image),
			Path:        event.Process.Image,
			PID:         event.Process.PID,
			ParentName:  pathBase(event.Process.ParentImage),
			ParentPath:  event.Process.ParentImage,
			ParentPID:   event.Process.PPID,
			CommandLine: event.Process.CommandLine,
			SHA256:      event.Process.ExecutableSHA256,
			Signer:      event.Process.CodeSignatureInfo,
		},
		Network: NetworkContext{
			SourceIP:        event.Network.SourceIP,
			SourcePort:      event.Network.SourcePort,
			DestinationIP:   event.Network.DestinationIP,
			DestinationPort: event.Network.DestinationPort,
			Protocol:        event.Network.Protocol,
			Direction:       event.Network.Direction,
			Domain:          event.Network.Domain,
			IsExternal:      externalIP(event.Network.DestinationIP),
		},
		File: FileContext{
			Path:      event.File.Path,
			Operation: event.File.Operation,
			SHA256:    event.File.SHA256,
			Extension: strings.ToLower(filepath.Ext(event.File.Path)),
		},
		Web: WebContext{
			Method:    event.HTTP.Method,
			Path:      event.HTTP.Path,
			Status:    event.HTTP.Status,
			UserAgent: event.HTTP.UserAgent,
			RequestID: event.HTTP.RequestID,
		},
		Database: DatabaseContext{
			Engine:     event.Database.Engine,
			Database:   event.Database.Database,
			Statement:  attributeString(event.Attributes, "statement", "query", "sql"),
			QueryShape: event.Database.QueryFingerprint,
			Rows:       event.Database.Rows,
			DurationMS: float64(event.Database.DurationMS),
		},
		Message: event.Message,
		Tags: []string{
			"trust:" + string(event.Trust),
			"severity:" + string(event.Severity),
		},
		Raw: raw,
	}
	if len(event.Asset.IPs) > 0 {
		mapped.Asset.IP = event.Asset.IPs[0]
	}
	if strings.HasPrefix(event.Kind, "service.") || strings.HasPrefix(event.Kind, "persistence.service") {
		mapped.Service = ServiceContext{
			Name:       attributeString(event.Attributes, "service_name", "service"),
			BinaryPath: attributeString(event.Attributes, "binary_path", "image_path", "path"),
			StartType:  attributeString(event.Attributes, "start_type", "start_mode"),
			Action:     strings.TrimPrefix(event.Kind, "service."),
		}
	}
	if strings.HasPrefix(event.Kind, "registry.") {
		mapped.Registry = RegistryContext{
			Path:      attributeString(event.Attributes, "registry_path", "path"),
			ValueName: attributeString(event.Attributes, "value_name"),
			ValueData: attributeString(event.Attributes, "value_data"),
			Operation: strings.TrimPrefix(event.Kind, "registry."),
		}
	}
	return mapped
}

func cloneMap(source map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(source)+8)
	for key, value := range source {
		result[key] = value
	}
	return result
}

func attributeString(attributes map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := attributes[key]
		if !ok {
			continue
		}
		if text, ok := value.(string); ok {
			return strings.TrimSpace(text)
		}
	}
	return ""
}

func pathBase(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	return filepath.Base(value)
}

func externalIP(value string) *bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return nil
	}
	external := !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
	return &external
}
