package model

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const SchemaVersion = "0.1"

type TrustLevel string

const (
	TrustSystem             TrustLevel = "system"
	TrustSignedPolicy       TrustLevel = "signed_policy"
	TrustOperator           TrustLevel = "operator"
	TrustTrustedConfig      TrustLevel = "trusted_config"
	TrustUntrustedTelemetry TrustLevel = "untrusted_telemetry"
	TrustUntrustedCode      TrustLevel = "untrusted_code"
	TrustUntrustedNetwork   TrustLevel = "untrusted_network"
)

func (t TrustLevel) IsUntrusted() bool {
	switch t {
	case TrustUntrustedTelemetry, TrustUntrustedCode, TrustUntrustedNetwork:
		return true
	default:
		return false
	}
}

func ParseTrustLevel(value string) TrustLevel {
	switch TrustLevel(strings.ToLower(strings.TrimSpace(value))) {
	case TrustSystem:
		return TrustSystem
	case TrustSignedPolicy:
		return TrustSignedPolicy
	case TrustOperator:
		return TrustOperator
	case TrustTrustedConfig:
		return TrustTrustedConfig
	case TrustUntrustedCode:
		return TrustUntrustedCode
	case TrustUntrustedNetwork:
		return TrustUntrustedNetwork
	default:
		return TrustUntrustedTelemetry
	}
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Asset struct {
	ID       string   `json:"id,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	OS       string   `json:"os,omitempty"`
	IPs      []string `json:"ips,omitempty"`
}

type Actor struct {
	User      string `json:"user,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
}

type ProcessContext struct {
	PID               int    `json:"pid,omitempty"`
	PPID              int    `json:"ppid,omitempty"`
	Image             string `json:"image,omitempty"`
	ParentImage       string `json:"parent_image,omitempty"`
	CommandLine       string `json:"command_line,omitempty"`
	ExecutableSHA256  string `json:"executable_sha256,omitempty"`
	IntegrityLevel    string `json:"integrity_level,omitempty"`
	ContainerID       string `json:"container_id,omitempty"`
	CodeSignatureInfo string `json:"code_signature_info,omitempty"`
}

type NetworkContext struct {
	SourceIP        string `json:"source_ip,omitempty"`
	SourcePort      int    `json:"source_port,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	Domain          string `json:"domain,omitempty"`
	Direction       string `json:"direction,omitempty"`
}

type HTTPContext struct {
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	Query      string `json:"query,omitempty"`
	Status     int    `json:"status,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	Referer    string `json:"referer,omitempty"`
	Host       string `json:"host,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	BytesSent  int64  `json:"bytes_sent,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

type DatabaseContext struct {
	Engine           string   `json:"engine,omitempty"`
	Instance         string   `json:"instance,omitempty"`
	User             string   `json:"user,omitempty"`
	Database         string   `json:"database,omitempty"`
	QueryFingerprint string   `json:"query_fingerprint,omitempty"`
	QueryVerbs       []string `json:"query_verbs,omitempty"`
	Rows             int64    `json:"rows,omitempty"`
	DurationMS       int64    `json:"duration_ms,omitempty"`
}

type FileContext struct {
	Path       string `json:"path,omitempty"`
	Operation  string `json:"operation,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Size       int64  `json:"size,omitempty"`
	Owner      string `json:"owner,omitempty"`
	Executable bool   `json:"executable,omitempty"`
}

type Provenance struct {
	Source        string    `json:"source,omitempty"`
	Collector     string    `json:"collector,omitempty"`
	OriginalPath  string    `json:"original_path,omitempty"`
	LineNumber    int64     `json:"line_number,omitempty"`
	ReceivedAt    time.Time `json:"received_at,omitempty"`
	ContentSHA256 string    `json:"content_sha256,omitempty"`
}

type Event struct {
	SchemaVersion string                 `json:"schema_version"`
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	AgentID       string                 `json:"agent_id,omitempty"`
	TenantID      string                 `json:"tenant_id,omitempty"`
	Kind          string                 `json:"kind"`
	Severity      Severity               `json:"severity"`
	Trust         TrustLevel             `json:"trust"`
	Asset         Asset                  `json:"asset,omitempty"`
	Actor         Actor                  `json:"actor,omitempty"`
	Process       ProcessContext         `json:"process,omitempty"`
	Network       NetworkContext         `json:"network,omitempty"`
	HTTP          HTTPContext            `json:"http,omitempty"`
	Database      DatabaseContext        `json:"database,omitempty"`
	File          FileContext            `json:"file,omitempty"`
	Message       string                 `json:"message,omitempty"`
	Attributes    map[string]interface{} `json:"attributes,omitempty"`
	Provenance    Provenance             `json:"provenance,omitempty"`
}

func (e *Event) Prepare() {
	if e.SchemaVersion == "" {
		e.SchemaVersion = SchemaVersion
	}
	if e.ID == "" {
		e.ID = NewID("evt")
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	} else {
		e.Timestamp = e.Timestamp.UTC()
	}
	if e.Kind == "" {
		e.Kind = "log.observation"
	}
	if e.Severity == "" {
		e.Severity = SeverityInfo
	}
	if e.Trust == "" {
		e.Trust = TrustUntrustedTelemetry
	}
	if e.Attributes == nil {
		e.Attributes = map[string]interface{}{}
	}
	if e.Provenance.ReceivedAt.IsZero() {
		e.Provenance.ReceivedAt = time.Now().UTC()
	}
}

type Finding struct {
	SchemaVersion    string                 `json:"schema_version"`
	ID               string                 `json:"id"`
	Timestamp        time.Time              `json:"timestamp"`
	RuleID           string                 `json:"rule_id"`
	Title            string                 `json:"title"`
	Description      string                 `json:"description"`
	Severity         Severity               `json:"severity"`
	Confidence       int                    `json:"confidence"`
	Category         string                 `json:"category"`
	TenantID         string                 `json:"tenant_id,omitempty"`
	AgentID          string                 `json:"agent_id,omitempty"`
	Asset            Asset                  `json:"asset,omitempty"`
	EvidenceEventIDs []string               `json:"evidence_event_ids"`
	MITRETactics     []string               `json:"mitre_tactics,omitempty"`
	MITRETechniques  []string               `json:"mitre_techniques,omitempty"`
	Attributes       map[string]interface{} `json:"attributes,omitempty"`
	RecommendedSteps []string               `json:"recommended_steps,omitempty"`
}

func NewFinding(event Event, ruleID, title, description, category string, severity Severity, confidence int) Finding {
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}
	return Finding{
		SchemaVersion:    SchemaVersion,
		ID:               NewID("fnd"),
		Timestamp:        time.Now().UTC(),
		RuleID:           ruleID,
		Title:            title,
		Description:      description,
		Severity:         severity,
		Confidence:       confidence,
		Category:         category,
		TenantID:         event.TenantID,
		AgentID:          event.AgentID,
		Asset:            event.Asset,
		EvidenceEventIDs: []string{event.ID},
		Attributes:       map[string]interface{}{},
	}
}

type ActionRisk string

const (
	RiskObserve     ActionRisk = "observe"
	RiskContain     ActionRisk = "contain"
	RiskModify      ActionRisk = "modify"
	RiskDestructive ActionRisk = "destructive"
)

type ActionMode string

const (
	ModeObserve ActionMode = "observe"
	ModePlan    ActionMode = "plan"
	ModeAct     ActionMode = "act"
	ModeAuto    ActionMode = "auto"
)

type Approval struct {
	ID           string    `json:"id"`
	ActionDigest string    `json:"action_digest"`
	ApprovedBy   string    `json:"approved_by"`
	ApprovedAt   time.Time `json:"approved_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type ActionRequest struct {
	ID           string                 `json:"id"`
	Tool         string                 `json:"tool"`
	Args         map[string]interface{} `json:"args,omitempty"`
	Reason       string                 `json:"reason"`
	Risk         ActionRisk             `json:"risk"`
	Mode         ActionMode             `json:"mode"`
	TriggerTrust TrustLevel             `json:"trigger_trust"`
	RequestedBy  string                 `json:"requested_by"`
	RequestedAt  time.Time              `json:"requested_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	Approval     *Approval              `json:"approval,omitempty"`
}

func (a *ActionRequest) Prepare() {
	if a.ID == "" {
		a.ID = NewID("act")
	}
	if a.Args == nil {
		a.Args = map[string]interface{}{}
	}
	if a.Mode == "" {
		a.Mode = ModeObserve
	}
	if a.TriggerTrust == "" {
		a.TriggerTrust = TrustOperator
	}
	if a.RequestedAt.IsZero() {
		a.RequestedAt = time.Now().UTC()
	}
}

type Decision struct {
	Allowed          bool       `json:"allowed"`
	RequiresApproval bool       `json:"requires_approval"`
	Reason           string     `json:"reason"`
	EvaluatedAt      time.Time  `json:"evaluated_at"`
	Risk             ActionRisk `json:"risk"`
}

func NewID(prefix string) string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err == nil {
		return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(buf))
	}
	return fmt.Sprintf("%s_%d", prefix, time.Now().UTC().UnixNano())
}
