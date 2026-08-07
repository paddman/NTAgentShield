package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
)

var (
	nativeSourceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	windowsChannelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/ -]{0,127}$`)
)

type Source struct {
	ID        string           `json:"id"`
	Enabled   bool             `json:"enabled"`
	Path      string           `json:"path"`
	Format    string           `json:"format"`
	Trust     model.TrustLevel `json:"trust"`
	FromStart bool             `json:"from_start"`
	MaxBatch  int              `json:"max_batch"`
}

type NativeSource struct {
	ID             string   `json:"id"`
	Enabled        bool     `json:"enabled"`
	Kind           string   `json:"kind"`
	Channel        string   `json:"channel,omitempty"`
	EventIDs       []int    `json:"event_ids,omitempty"`
	Units          []string `json:"units,omitempty"`
	Identifiers    []string `json:"identifiers,omitempty"`
	Path           string   `json:"path,omitempty"`
	FromStart      bool     `json:"from_start"`
	MaxBatch       int      `json:"max_batch"`
	CommandTimeout string   `json:"command_timeout"`
}

type API struct {
	Enabled   bool   `json:"enabled"`
	Listen    string `json:"listen"`
	TokenFile string `json:"token_file"`
}

type ToolPolicy struct {
	PolicyFile   string   `json:"policy_file"`
	AllowedPaths []string `json:"allowed_paths"`
}

type AI struct {
	Enabled     bool   `json:"enabled"`
	Endpoint    string `json:"endpoint"`
	Model       string `json:"model"`
	APIKeyEnv   string `json:"api_key_env"`
	AllowRemote bool   `json:"allow_remote"`
	Timeout     string `json:"timeout"`
}

type Inventory struct {
	Enabled          bool   `json:"enabled"`
	Interval         string `json:"interval"`
	CommandTimeout   string `json:"command_timeout"`
	IncludeProcesses bool   `json:"include_processes"`
	IncludeServices  bool   `json:"include_services"`
	IncludeListeners bool   `json:"include_listeners"`
	IncludeSoftware  bool   `json:"include_software"`
	MaxItems         int    `json:"max_items"`
}

type Transport struct {
	Enabled            bool   `json:"enabled"`
	Endpoint           string `json:"endpoint"`
	CertFile           string `json:"cert_file"`
	KeyFile            string `json:"key_file"`
	CAFile             string `json:"ca_file"`
	ServerName         string `json:"server_name,omitempty"`
	Timeout            string `json:"timeout"`
	FlushInterval      string `json:"flush_interval"`
	BatchSize          int    `json:"batch_size"`
	PendingWarn        int    `json:"pending_warn"`
	AutoRenew          bool   `json:"auto_renew"`
	RenewalEndpoint    string `json:"renewal_endpoint"`
	RenewBefore        string `json:"renew_before"`
	RenewCheckInterval string `json:"renew_check_interval"`
}

type Config struct {
	AgentID       string         `json:"agent_id"`
	TenantID      string         `json:"tenant_id"`
	DataDir       string         `json:"data_dir"`
	PollInterval  time.Duration  `json:"-"`
	Poll          string         `json:"poll_interval"`
	Sources       []Source       `json:"sources"`
	NativeSources []NativeSource `json:"native_sources"`
	API           API            `json:"api"`
	Tools         ToolPolicy     `json:"tools"`
	AI            AI             `json:"ai"`
	Inventory     Inventory      `json:"inventory"`
	Transport     Transport      `json:"transport"`
}

func Default() Config {
	return Config{
		DataDir:      defaultDataDir(),
		PollInterval: 2 * time.Second,
		Poll:         "2s",
		API: API{
			Enabled:   true,
			Listen:    "127.0.0.1:9477",
			TokenFile: "agent-api.token",
		},
		Tools: ToolPolicy{
			PolicyFile:   "policies/default-policy.json",
			AllowedPaths: []string{"."},
		},
		AI: AI{Enabled: false, Timeout: "30s"},
		Inventory: Inventory{
			Enabled:          true,
			Interval:         "15m",
			CommandTimeout:   "10s",
			IncludeProcesses: true,
			IncludeServices:  true,
			IncludeListeners: true,
			IncludeSoftware:  true,
			MaxItems:         512,
		},
		Transport: Transport{
			Enabled:            false,
			Endpoint:           "",
			CertFile:           "certs/client.crt",
			KeyFile:            "agent-identity.key",
			CAFile:             "certs/ca.crt",
			Timeout:            "15s",
			FlushInterval:      "2s",
			BatchSize:          100,
			PendingWarn:        10000,
			AutoRenew:          true,
			RenewBefore:        "168h",
			RenewCheckInterval: "1h",
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(content, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if cfg.Poll == "" {
		cfg.Poll = "2s"
	}
	cfg.PollInterval, err = time.ParseDuration(cfg.Poll)
	if err != nil {
		return Config{}, fmt.Errorf("invalid poll_interval: %w", err)
	}
	cfg.applyDefaults(path)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults(configPath string) {
	base := filepath.Dir(configPath)
	if c.DataDir == "" {
		c.DataDir = defaultDataDir()
	}
	if !filepath.IsAbs(c.DataDir) {
		c.DataDir = filepath.Clean(filepath.Join(base, c.DataDir))
	}
	if c.API.Listen == "" {
		c.API.Listen = "127.0.0.1:9477"
	}
	if c.API.TokenFile == "" {
		c.API.TokenFile = "agent-api.token"
	}
	if !filepath.IsAbs(c.API.TokenFile) {
		c.API.TokenFile = filepath.Join(c.DataDir, c.API.TokenFile)
	}
	if c.Tools.PolicyFile == "" {
		c.Tools.PolicyFile = "policies/default-policy.json"
	}
	if !filepath.IsAbs(c.Tools.PolicyFile) {
		c.Tools.PolicyFile = filepath.Clean(filepath.Join(base, c.Tools.PolicyFile))
	}
	if c.Inventory.Interval == "" {
		c.Inventory.Interval = "15m"
	}
	if c.Inventory.CommandTimeout == "" {
		c.Inventory.CommandTimeout = "10s"
	}
	if c.Inventory.MaxItems <= 0 {
		c.Inventory.MaxItems = 512
	}
	if c.Transport.CertFile == "" {
		c.Transport.CertFile = "certs/client.crt"
	}
	if c.Transport.KeyFile == "" {
		c.Transport.KeyFile = "agent-identity.key"
	}
	if c.Transport.CAFile == "" {
		c.Transport.CAFile = "certs/ca.crt"
	}
	for _, target := range []*string{&c.Transport.CertFile, &c.Transport.KeyFile, &c.Transport.CAFile} {
		if !filepath.IsAbs(*target) {
			*target = filepath.Clean(filepath.Join(c.DataDir, *target))
		}
	}
	if c.Transport.Timeout == "" {
		c.Transport.Timeout = "15s"
	}
	if c.Transport.FlushInterval == "" {
		c.Transport.FlushInterval = "2s"
	}
	if c.Transport.BatchSize <= 0 {
		c.Transport.BatchSize = 100
	}
	if c.Transport.PendingWarn <= 0 {
		c.Transport.PendingWarn = 10000
	}
	if c.Transport.RenewBefore == "" {
		c.Transport.RenewBefore = "168h"
	}
	if c.Transport.RenewCheckInterval == "" {
		c.Transport.RenewCheckInterval = "1h"
	}
	if c.Transport.RenewalEndpoint == "" && c.Transport.Endpoint != "" {
		if endpoint, err := url.Parse(c.Transport.Endpoint); err == nil && endpoint.Scheme != "" && endpoint.Host != "" {
			endpoint.Path = "/v1/agent/certificate/renew"
			endpoint.RawPath = ""
			endpoint.RawQuery = ""
			endpoint.Fragment = ""
			c.Transport.RenewalEndpoint = endpoint.String()
		}
	}
	for i := range c.Sources {
		if c.Sources[i].Trust == "" {
			c.Sources[i].Trust = model.TrustUntrustedTelemetry
		}
		if c.Sources[i].MaxBatch <= 0 {
			c.Sources[i].MaxBatch = 1000
		}
		if !filepath.IsAbs(c.Sources[i].Path) {
			c.Sources[i].Path = filepath.Clean(filepath.Join(base, c.Sources[i].Path))
		}
	}
	for i := range c.NativeSources {
		source := &c.NativeSources[i]
		source.Kind = strings.ToLower(strings.TrimSpace(source.Kind))
		if source.MaxBatch <= 0 {
			source.MaxBatch = 256
		}
		if source.CommandTimeout == "" {
			source.CommandTimeout = "15s"
		}
		if (source.Kind == "auditd" || source.Kind == "linux_auditd") && source.Path == "" {
			source.Path = "/var/log/audit/audit.log"
		}
		if source.Path != "" && !filepath.IsAbs(source.Path) {
			source.Path = filepath.Clean(filepath.Join(base, source.Path))
		}
		for unitIndex := range source.Units {
			source.Units[unitIndex] = strings.TrimSpace(source.Units[unitIndex])
		}
		for identifierIndex := range source.Identifiers {
			source.Identifiers[identifierIndex] = strings.TrimSpace(source.Identifiers[identifierIndex])
		}
	}
	for i, path := range c.Tools.AllowedPaths {
		if !filepath.IsAbs(path) {
			c.Tools.AllowedPaths[i] = filepath.Clean(filepath.Join(base, path))
		}
	}
}

func (c Config) Validate() error {
	if c.PollInterval < 100*time.Millisecond || c.PollInterval > 24*time.Hour {
		return errors.New("poll_interval must be between 100ms and 24h")
	}
	if c.API.Enabled {
		host, _, err := net.SplitHostPort(c.API.Listen)
		if err != nil {
			return fmt.Errorf("invalid api.listen: %w", err)
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil || !ip.IsLoopback() {
			return errors.New("api.listen must be a loopback address; remote access uses the authenticated transport instead")
		}
	}
	if c.AI.Enabled {
		if strings.TrimSpace(c.AI.Endpoint) == "" || strings.TrimSpace(c.AI.Model) == "" {
			return errors.New("ai.endpoint and ai.model are required when AI is enabled")
		}
		if c.AI.Timeout == "" {
			c.AI.Timeout = "30s"
		}
		if _, err := time.ParseDuration(c.AI.Timeout); err != nil {
			return fmt.Errorf("invalid ai.timeout: %w", err)
		}
	}
	if c.Inventory.Enabled {
		interval, err := time.ParseDuration(c.Inventory.Interval)
		if err != nil {
			return fmt.Errorf("invalid inventory.interval: %w", err)
		}
		if interval < time.Minute || interval > 24*time.Hour {
			return errors.New("inventory.interval must be between 1m and 24h")
		}
		timeout, err := time.ParseDuration(c.Inventory.CommandTimeout)
		if err != nil {
			return fmt.Errorf("invalid inventory.command_timeout: %w", err)
		}
		if timeout < time.Second || timeout > 2*time.Minute {
			return errors.New("inventory.command_timeout must be between 1s and 2m")
		}
		if c.Inventory.MaxItems < 1 || c.Inventory.MaxItems > 10000 {
			return errors.New("inventory.max_items must be between 1 and 10000")
		}
	}
	if c.Transport.Enabled {
		if strings.TrimSpace(c.TenantID) == "" {
			return errors.New("tenant_id is required when transport is enabled")
		}
		if err := validateHTTPSURL(c.Transport.Endpoint, "transport.endpoint"); err != nil {
			return err
		}
		if c.Transport.CertFile == "" || c.Transport.KeyFile == "" || c.Transport.CAFile == "" {
			return errors.New("transport cert_file, key_file, and ca_file are required")
		}
		timeout, err := time.ParseDuration(c.Transport.Timeout)
		if err != nil {
			return fmt.Errorf("invalid transport.timeout: %w", err)
		}
		if timeout < time.Second || timeout > 2*time.Minute {
			return errors.New("transport.timeout must be between 1s and 2m")
		}
		flushInterval, err := time.ParseDuration(c.Transport.FlushInterval)
		if err != nil {
			return fmt.Errorf("invalid transport.flush_interval: %w", err)
		}
		if flushInterval < 250*time.Millisecond || flushInterval > time.Minute {
			return errors.New("transport.flush_interval must be between 250ms and 1m")
		}
		if c.Transport.BatchSize < 1 || c.Transport.BatchSize > 1000 {
			return errors.New("transport.batch_size must be between 1 and 1000")
		}
		if c.Transport.PendingWarn < 100 || c.Transport.PendingWarn > 1000000 {
			return errors.New("transport.pending_warn must be between 100 and 1000000")
		}
		if c.Transport.AutoRenew {
			if err := validateHTTPSURL(c.Transport.RenewalEndpoint, "transport.renewal_endpoint"); err != nil {
				return err
			}
			renewBefore, err := time.ParseDuration(c.Transport.RenewBefore)
			if err != nil {
				return fmt.Errorf("invalid transport.renew_before: %w", err)
			}
			if renewBefore < time.Hour || renewBefore > 90*24*time.Hour {
				return errors.New("transport.renew_before must be between 1h and 2160h")
			}
			checkInterval, err := time.ParseDuration(c.Transport.RenewCheckInterval)
			if err != nil {
				return fmt.Errorf("invalid transport.renew_check_interval: %w", err)
			}
			if checkInterval < time.Minute || checkInterval > 24*time.Hour {
				return errors.New("transport.renew_check_interval must be between 1m and 24h")
			}
		}
	}
	seen := map[string]struct{}{}
	for _, source := range c.Sources {
		if !source.Enabled {
			continue
		}
		if source.ID == "" || source.Path == "" || source.Format == "" {
			return errors.New("each enabled source requires id, path, and format")
		}
		if _, ok := seen[source.ID]; ok {
			return fmt.Errorf("duplicate source id %q", source.ID)
		}
		seen[source.ID] = struct{}{}
	}
	for _, source := range c.NativeSources {
		if !source.Enabled {
			continue
		}
		if !nativeSourceIDPattern.MatchString(source.ID) {
			return fmt.Errorf("native source id %q must match %s", source.ID, nativeSourceIDPattern.String())
		}
		if _, ok := seen[source.ID]; ok {
			return fmt.Errorf("duplicate source id %q", source.ID)
		}
		seen[source.ID] = struct{}{}
		if source.MaxBatch < 1 || source.MaxBatch > 5000 {
			return fmt.Errorf("native source %s max_batch must be between 1 and 5000", source.ID)
		}
		timeout, err := time.ParseDuration(source.CommandTimeout)
		if err != nil {
			return fmt.Errorf("native source %s command_timeout: %w", source.ID, err)
		}
		if timeout < time.Second || timeout > 2*time.Minute {
			return fmt.Errorf("native source %s command_timeout must be between 1s and 2m", source.ID)
		}
		switch source.Kind {
		case "windows_eventlog", "wineventlog", "sysmon":
			if !windowsChannelPattern.MatchString(source.Channel) {
				return fmt.Errorf("native source %s has invalid Windows event channel", source.ID)
			}
			if len(source.EventIDs) > 128 {
				return fmt.Errorf("native source %s supports at most 128 event IDs", source.ID)
			}
			for _, eventID := range source.EventIDs {
				if eventID < 1 || eventID > 65535 {
					return fmt.Errorf("native source %s has invalid event ID %d", source.ID, eventID)
				}
			}
		case "journald", "journalctl":
			if len(source.Units) > 32 || len(source.Identifiers) > 32 {
				return fmt.Errorf("native source %s supports at most 32 units and identifiers", source.ID)
			}
			for _, value := range append(append([]string{}, source.Units...), source.Identifiers...) {
				if value == "" || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") {
					return fmt.Errorf("native source %s contains an invalid journald filter", source.ID)
				}
			}
		case "auditd", "linux_auditd":
			if source.Path == "" || !filepath.IsAbs(source.Path) {
				return fmt.Errorf("native source %s auditd path must be absolute", source.ID)
			}
		default:
			return fmt.Errorf("native source %s has unsupported kind %q", source.ID, source.Kind)
		}
	}
	return nil
}

func validateHTTPSURL(value, name string) error {
	endpoint, err := url.Parse(strings.TrimSpace(value))
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return fmt.Errorf("%s must be an absolute https URL", name)
	}
	return nil
}

func EnsureAgentID(cfg *Config) error {
	if cfg.AgentID != "" {
		return nil
	}
	if err := EnsureDataDir(*cfg); err != nil {
		return err
	}
	identityPath := filepath.Join(cfg.DataDir, "agent.id")
	if content, err := os.ReadFile(identityPath); err == nil {
		identity := strings.TrimSpace(string(content))
		if !strings.HasPrefix(identity, "agent_") || len(identity) < 20 {
			return errors.New("persisted agent identity is invalid")
		}
		cfg.AgentID = identity
		return os.Chmod(identityPath, 0o600)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read persisted agent identity: %w", err)
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("generate agent id: %w", err)
	}
	cfg.AgentID = "agent_" + hex.EncodeToString(buf)
	if err := os.WriteFile(identityPath, []byte(cfg.AgentID+"\n"), 0o600); err != nil {
		return fmt.Errorf("persist agent identity: %w", err)
	}
	return nil
}

func EnsureDataDir(cfg Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return os.Chmod(cfg.DataDir, 0o700)
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if base := os.Getenv("ProgramData"); base != "" {
			return filepath.Join(base, "NTAgentShield")
		}
	}
	return "./data"
}
