package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/paddman/NTAgentShield/internal/api"
	"github.com/paddman/NTAgentShield/internal/buildinfo"
	"github.com/paddman/NTAgentShield/internal/collector/filetail"
	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/detection"
	"github.com/paddman/NTAgentShield/internal/model"
	"github.com/paddman/NTAgentShield/internal/redact"
	"github.com/paddman/NTAgentShield/internal/store"
)

type Runtime struct {
	cfg          config.Config
	hostname     string
	journal      *store.Journal
	detector     *detection.Engine
	tailers      []*filetail.Tailer
	logger       *log.Logger
	startedAt    time.Time
	eventCount   atomic.Uint64
	findingCount atomic.Uint64
	errorCount   atomic.Uint64
}

type Status struct {
	Status      string         `json:"status"`
	AgentID     string         `json:"agent_id"`
	TenantID    string         `json:"tenant_id,omitempty"`
	Hostname    string         `json:"hostname"`
	StartedAt   time.Time      `json:"started_at"`
	Uptime      string         `json:"uptime"`
	Events      uint64         `json:"events"`
	Findings    uint64         `json:"findings"`
	Errors      uint64         `json:"errors"`
	Sources     int            `json:"sources"`
	AIEnabled   bool           `json:"ai_enabled"`
	Build       buildinfo.Info `json:"build"`
	SafetyModel string         `json:"safety_model"`
}

func New(cfg config.Config, logger *log.Logger) (*Runtime, error) {
	if logger == nil {
		logger = log.New(os.Stdout, "ntagentshield ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	}
	if err := config.EnsureDataDir(cfg); err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	journal, err := store.Open(filepath.Join(cfg.DataDir, "evidence.journal.jsonl"))
	if err != nil {
		return nil, err
	}
	runtime := &Runtime{
		cfg:       cfg,
		hostname:  hostname,
		journal:   journal,
		detector:  detection.New(),
		logger:    logger,
		startedAt: time.Now().UTC(),
	}
	for _, source := range cfg.Sources {
		if !source.Enabled {
			continue
		}
		tailer, err := filetail.New(source)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize source %s: %w", source.ID, err)
		}
		runtime.tailers = append(runtime.tailers, tailer)
	}
	return runtime, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	startup := map[string]interface{}{
		"agent_id":     r.cfg.AgentID,
		"tenant_id":    r.cfg.TenantID,
		"hostname":     r.hostname,
		"sources":      len(r.tailers),
		"build":        buildinfo.Current(),
		"ai_enabled":   r.cfg.AI.Enabled,
		"safety_model": "untrusted evidence -> deterministic policy gate -> typed tools",
	}
	if _, err := r.journal.Append("agent.start", startup); err != nil {
		return err
	}
	r.logger.Printf("agent started id=%s sources=%d ai_enabled=%t", r.cfg.AgentID, len(r.tailers), r.cfg.AI.Enabled)

	errCh := make(chan error, 1)
	if r.cfg.API.Enabled {
		token, err := api.EnsureToken(r.cfg.API.TokenFile)
		if err != nil {
			return err
		}
		server := api.New(r.cfg.API.Listen, token, func() interface{} { return r.Status() }, r.Ingest)
		go func() { errCh <- server.Run(ctx) }()
		r.logger.Printf("local API listening on %s; command execution is not exposed", r.cfg.API.Listen)
	}

	r.poll()
	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_, _ = r.journal.Append("agent.stop", map[string]interface{}{"reason": ctx.Err().Error(), "status": r.Status()})
			return nil
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("local API: %w", err)
			}
		case <-ticker.C:
			r.poll()
		}
	}
}

func (r *Runtime) poll() {
	for _, tailer := range r.tailers {
		events, errs := tailer.Poll()
		for _, err := range errs {
			r.errorCount.Add(1)
			r.logger.Printf("collector error: %v", err)
			_, _ = r.journal.Append("collector.error", map[string]string{"error": err.Error()})
		}
		for _, event := range events {
			if _, err := r.process(event); err != nil {
				r.errorCount.Add(1)
				r.logger.Printf("event processing error: %v", err)
			}
		}
	}
}

func (r *Runtime) Ingest(_ context.Context, event model.Event) ([]model.Finding, error) {
	return r.process(event)
}

func (r *Runtime) process(event model.Event) ([]model.Finding, error) {
	event.Prepare()
	event.AgentID = r.cfg.AgentID
	event.TenantID = r.cfg.TenantID
	if event.Asset.Hostname == "" {
		event.Asset.Hostname = r.hostname
	}
	redact.Event(&event)
	if _, err := r.journal.Append("event", event); err != nil {
		return nil, err
	}
	r.eventCount.Add(1)
	findings := r.detector.Inspect(event)
	for _, finding := range findings {
		if _, err := r.journal.Append("finding", finding); err != nil {
			return findings, err
		}
		r.findingCount.Add(1)
		encoded, _ := json.Marshal(finding)
		r.logger.Printf("finding %s", encoded)
	}
	return findings, nil
}

func (r *Runtime) Status() Status {
	return Status{
		Status:      "running",
		AgentID:     r.cfg.AgentID,
		TenantID:    r.cfg.TenantID,
		Hostname:    r.hostname,
		StartedAt:   r.startedAt,
		Uptime:      time.Since(r.startedAt).Round(time.Second).String(),
		Events:      r.eventCount.Load(),
		Findings:    r.findingCount.Load(),
		Errors:      r.errorCount.Load(),
		Sources:     len(r.tailers),
		AIEnabled:   r.cfg.AI.Enabled,
		Build:       buildinfo.Current(),
		SafetyModel: "AI may analyze evidence; only typed tools behind deterministic policy may act",
	}
}

func (r *Runtime) Close() error {
	return r.journal.Close()
}
