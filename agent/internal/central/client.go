package central

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/paddman/NTAgentShield/internal/buildinfo"
	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/model"
)

type HeartbeatStatus struct {
	AgentID      string
	TenantID     string
	ComputerName string
	Status       string
	Events       uint64
	Findings     uint64
	Errors       uint64
	QueueDepth   int
	LastError    string
}

type Client struct {
	cfg          config.Central
	baseURL      string
	agentID      string
	tenantID     string
	computerName string
	http         *http.Client
	logger       *log.Logger
	queue        chan queuedEvent
	keyMu        sync.RWMutex
	apiKey       string
}

type queuedEvent struct {
	event    model.Event
	findings []model.Finding
}

type httpError struct {
	Status int
	Body   string
}

func (e *httpError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("Central returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("Central returned HTTP %d: %s", e.Status, e.Body)
}

type registrationRequest struct {
	AgentID         string `json:"agentId"`
	ComputerName    string `json:"computerName"`
	AgentVersion    string `json:"agentVersion"`
	OSVersion       string `json:"osVersion"`
	HostIP          string `json:"hostIp,omitempty"`
	EnrollmentToken string `json:"enrollmentToken,omitempty"`
	RotateAPIKey    bool   `json:"rotateApiKey"`
	Platform        string `json:"platform"`
}

type registrationResponse struct {
	Accepted    bool   `json:"accepted"`
	Message     string `json:"message,omitempty"`
	AgentAPIKey string `json:"agentApiKey,omitempty"`
}

type heartbeatRequest struct {
	AgentID      string    `json:"agentId"`
	ComputerName string    `json:"computerName"`
	AgentVersion string    `json:"agentVersion"`
	OSVersion    string    `json:"osVersion"`
	HostIP       string    `json:"hostIp,omitempty"`
	TimestampUTC time.Time `json:"timestampUtc"`
	Status       string    `json:"status"`
	QueueDepth   int       `json:"localQueueDepth"`
	CentralURL   string    `json:"centralUrl"`
	Platform     string    `json:"platform"`
	LastError    string    `json:"lastError,omitempty"`
}

type ingestBatch struct {
	AgentID        string           `json:"agentId"`
	ComputerName   string           `json:"computerName"`
	AgentVersion   string           `json:"agentVersion"`
	SentAtUTC      time.Time        `json:"sentAtUtc"`
	IdempotencyKey string           `json:"idempotencyKey"`
	SecurityEvents []securityEvent  `json:"securityEvents"`
	Alerts         []detectionAlert `json:"alerts"`
}

type securityEvent struct {
	ID              int64     `json:"id"`
	TimestampUTC    time.Time `json:"timestampUtc"`
	ComputerName    string    `json:"computerName"`
	AgentID         string    `json:"agentId"`
	EventID         int       `json:"eventId"`
	Channel         string    `json:"channel"`
	ProviderName    string    `json:"providerName,omitempty"`
	Username        string    `json:"username,omitempty"`
	SourceIP        string    `json:"sourceIp,omitempty"`
	SourcePort      *int      `json:"sourcePort,omitempty"`
	DestinationIP   string    `json:"destinationIp,omitempty"`
	DestinationPort *int      `json:"destinationPort,omitempty"`
	ProcessID       *int      `json:"processId,omitempty"`
	ProcessPath     string    `json:"processPath,omitempty"`
	Status          string    `json:"status,omitempty"`
	RawXML          string    `json:"rawXml"`
	EventRecordID   int64     `json:"eventRecordId"`
	CollectedAtUTC  time.Time `json:"collectedAtUtc"`
}

type detectionAlert struct {
	AlertID       string    `json:"alertId"`
	TimestampUTC  time.Time `json:"timestampUtc"`
	ComputerName  string    `json:"computerName"`
	AgentID       string    `json:"agentId"`
	RuleID        string    `json:"ruleId"`
	RuleName      string    `json:"ruleName"`
	Severity      int       `json:"severity"`
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	SourceIP      string    `json:"sourceIp,omitempty"`
	DestinationIP string    `json:"destinationIp,omitempty"`
	Username      string    `json:"username,omitempty"`
	EventCount    int       `json:"eventCount"`
	EvidenceJSON  string    `json:"evidenceJson"`
	Suppressed    bool      `json:"suppressed"`
}

func New(cfg config.Central, agentID, tenantID, computerName string, logger *log.Logger) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("invalid Central URL")
	}
	if logger == nil {
		logger = log.Default()
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.AllowUntrustedServerCertificate {
		transport.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // Explicitly opt-in for controlled test environments.
		}
	}

	client := &Client{
		cfg:          cfg,
		baseURL:      strings.TrimRight(cfg.URL, "/"),
		agentID:      agentID,
		tenantID:     tenantID,
		computerName: computerName,
		http:         &http.Client{Transport: transport, Timeout: 30 * time.Second},
		logger:       logger,
		queue:        make(chan queuedEvent, cfg.QueueSize),
	}
	if key, err := readSecret(cfg.APIKeyFile); err != nil {
		return nil, fmt.Errorf("read Central API key: %w", err)
	} else {
		client.apiKey = key
	}
	return client, nil
}

func (c *Client) Enqueue(event model.Event, findings []model.Finding) bool {
	copyFindings := append([]model.Finding(nil), findings...)
	select {
	case c.queue <- queuedEvent{event: event, findings: copyFindings}:
		return true
	default:
		c.logger.Printf("Central queue full; event retained in local journal only")
		return false
	}
}

func (c *Client) QueueDepth() int {
	return len(c.queue)
}

func (c *Client) Run(ctx context.Context, status func() HeartbeatStatus) error {
	heartbeatInterval, err := time.ParseDuration(c.cfg.HeartbeatInterval)
	if err != nil {
		return fmt.Errorf("parse Central heartbeat interval: %w", err)
	}
	batchInterval, err := time.ParseDuration(c.cfg.BatchInterval)
	if err != nil {
		return fmt.Errorf("parse Central batch interval: %w", err)
	}

	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()
	batchTicker := time.NewTicker(batchInterval)
	defer batchTicker.Stop()
	retryTicker := time.NewTicker(15 * time.Second)
	defer retryTicker.Stop()

	registered := false
	tryRegister := func() {
		if err := c.Register(ctx, false); err != nil {
			c.logger.Printf("Central registration failed: %v", err)
			return
		}
		registered = true
		c.logger.Printf("Central registration accepted agent=%s url=%s", c.agentID, c.baseURL)
	}
	tryRegister()

	pending := make([]queuedEvent, 0, c.cfg.MaxBatch)
	flush := func() {
		if !registered || len(pending) == 0 {
			return
		}
		take := len(pending)
		if take > c.cfg.MaxBatch {
			take = c.cfg.MaxBatch
		}
		batch := append([]queuedEvent(nil), pending[:take]...)
		if err := c.sendBatch(ctx, batch); err != nil {
			c.logger.Printf("Central ingest failed: %v", err)
			if isUnauthorized(err) {
				registered = false
			}
			return
		}
		pending = pending[take:]
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case item := <-c.queue:
			if len(pending) >= c.cfg.QueueSize {
				c.logger.Printf("Central pending queue full; event retained in local journal only")
				continue
			}
			pending = append(pending, item)
			if len(pending) >= c.cfg.MaxBatch {
				flush()
			}
		case <-batchTicker.C:
			flush()
		case <-heartbeatTicker.C:
			if !registered {
				continue
			}
			if err := c.sendHeartbeat(ctx, status()); err != nil {
				c.logger.Printf("Central heartbeat failed: %v", err)
				if isUnauthorized(err) {
					registered = false
				}
			}
		case <-retryTicker.C:
			if !registered {
				tryRegister()
			}
		}
	}
}

func (c *Client) Register(ctx context.Context, rotate bool) error {
	token, err := readSecret(c.cfg.EnrollmentTokenFile)
	if err != nil {
		return fmt.Errorf("read enrollment token: %w", err)
	}
	info := buildinfo.Current()
	request := registrationRequest{
		AgentID:         c.agentID,
		ComputerName:    c.computerName,
		AgentVersion:    info.Version,
		OSVersion:       "go/" + info.Version,
		HostIP:          detectHostIP(),
		EnrollmentToken: token,
		RotateAPIKey:    rotate,
		Platform:        "linux",
	}
	var response registrationResponse
	if err := c.postJSON(ctx, "/api/v1/agents/register", request, false, &response); err != nil {
		return err
	}
	if !response.Accepted {
		return fmt.Errorf("Central rejected registration: %s", response.Message)
	}
	if response.AgentAPIKey != "" {
		if err := writeSecret(c.cfg.APIKeyFile, response.AgentAPIKey); err != nil {
			return fmt.Errorf("persist Central API key: %w", err)
		}
		c.keyMu.Lock()
		c.apiKey = response.AgentAPIKey
		c.keyMu.Unlock()
	}
	return nil
}

func (c *Client) sendHeartbeat(ctx context.Context, status HeartbeatStatus) error {
	state := status.Status
	if state == "" {
		state = "Healthy"
	}
	request := heartbeatRequest{
		AgentID:      c.agentID,
		ComputerName: c.computerName,
		AgentVersion: buildinfo.Current().Version,
		OSVersion:    "go/" + buildinfo.Current().Version,
		HostIP:       detectHostIP(),
		TimestampUTC: time.Now().UTC(),
		Status:       state,
		QueueDepth:   status.QueueDepth,
		CentralURL:   c.baseURL,
		Platform:     "linux",
		LastError:    status.LastError,
	}
	return c.postJSON(ctx, "/api/v1/agents/heartbeat", request, true, nil)
}

// detectHostIP returns a usable address for the host running the agent.
// Prefer IPv4 because it is the address operators most commonly use to
// identify an asset, while still supporting IPv6-only hosts.
func detectHostIP() string {
	var ipv6 string
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				return ipv4.String()
			}
			if ipv6 == "" {
				ipv6 = ip.String()
			}
		}
	}
	return ipv6
}

func (c *Client) sendBatch(ctx context.Context, items []queuedEvent) error {
	batch := ingestBatch{
		AgentID:        c.agentID,
		ComputerName:   c.computerName,
		AgentVersion:   buildinfo.Current().Version,
		SentAtUTC:      time.Now().UTC(),
		IdempotencyKey: newID("batch"),
		SecurityEvents: make([]securityEvent, 0, len(items)),
		Alerts:         make([]detectionAlert, 0),
	}
	for _, item := range items {
		batch.SecurityEvents = append(batch.SecurityEvents, toSecurityEvent(item.event))
		for _, finding := range item.findings {
			batch.Alerts = append(batch.Alerts, toDetectionAlert(finding))
		}
	}
	return c.postJSON(ctx, "/api/v1/ingest", batch, true, nil)
}

func (c *Client) postJSON(ctx context.Context, path string, payload interface{}, authenticated bool, response interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode Central request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("create Central request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if authenticated {
		c.keyMu.RLock()
		key := c.apiKey
		c.keyMu.RUnlock()
		if key == "" {
			return errors.New("Central API key is not available")
		}
		request.Header.Set("X-NTShield-Api-Key", key)
	}
	resp, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("Central request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &httpError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	if response != nil {
		if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
			return fmt.Errorf("decode Central response: %w", err)
		}
	}
	return nil
}

func isUnauthorized(err error) bool {
	var statusErr *httpError
	return errors.As(err, &statusErr) && (statusErr.Status == http.StatusUnauthorized || statusErr.Status == http.StatusForbidden)
}

func readSecret(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(content)), nil
}

func writeSecret(path, value string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("secret path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".central-key-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(value + "\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func newID(prefix string) string {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(buffer)
}

func toSecurityEvent(event model.Event) securityEvent {
	raw, _ := json.Marshal(event)
	collected := event.Provenance.ReceivedAt
	if collected.IsZero() {
		collected = time.Now().UTC()
	}
	return securityEvent{
		TimestampUTC:    event.Timestamp,
		ComputerName:    event.Asset.Hostname,
		AgentID:         event.AgentID,
		Channel:         event.Kind,
		ProviderName:    event.Provenance.Collector,
		Username:        event.Actor.User,
		SourceIP:        event.Network.SourceIP,
		SourcePort:      optionalInt(event.Network.SourcePort),
		DestinationIP:   event.Network.DestinationIP,
		DestinationPort: optionalInt(event.Network.DestinationPort),
		ProcessID:       optionalInt(event.Process.PID),
		ProcessPath:     event.Process.Image,
		Status:          event.Message,
		RawXML:          string(raw),
		CollectedAtUTC:  collected,
	}
}

func toDetectionAlert(finding model.Finding) detectionAlert {
	evidence, _ := json.Marshal(finding)
	return detectionAlert{
		AlertID:      finding.ID,
		TimestampUTC: finding.Timestamp,
		ComputerName: finding.Asset.Hostname,
		AgentID:      finding.AgentID,
		RuleID:       finding.RuleID,
		RuleName:     finding.Title,
		Severity:     centralSeverity(finding.Severity),
		Title:        finding.Title,
		Description:  finding.Description,
		EventCount:   len(finding.EvidenceEventIDs),
		EvidenceJSON: string(evidence),
	}
}

func centralSeverity(value model.Severity) int {
	switch value {
	case model.SeverityLow:
		return 1
	case model.SeverityMedium:
		return 2
	case model.SeverityHigh:
		return 3
	case model.SeverityCritical:
		return 4
	default:
		return 0
	}
}

func optionalInt(value int) *int {
	if value == 0 {
		return nil
	}
	return &value
}
