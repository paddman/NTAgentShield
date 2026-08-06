package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
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

type Config struct {
	AgentID      string        `json:"agent_id"`
	TenantID     string        `json:"tenant_id"`
	DataDir      string        `json:"data_dir"`
	PollInterval time.Duration `json:"-"`
	Poll         string        `json:"poll_interval"`
	Sources      []Source      `json:"sources"`
	API          API           `json:"api"`
	Tools        ToolPolicy    `json:"tools"`
	AI           AI            `json:"ai"`
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
			return errors.New("api.listen must be a loopback address; remote control plane transport is intentionally not implemented in the foundation")
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
