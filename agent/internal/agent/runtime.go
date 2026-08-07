package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/paddman/NTAgentShield/internal/api"
	"github.com/paddman/NTAgentShield/internal/baseline"
	"github.com/paddman/NTAgentShield/internal/buildinfo"
	"github.com/paddman/NTAgentShield/internal/collector/filetail"
	"github.com/paddman/NTAgentShield/internal/collector/native"
	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/detection"
	"github.com/paddman/NTAgentShield/internal/inventory"
	"github.com/paddman/NTAgentShield/internal/model"
	"github.com/paddman/NTAgentShield/internal/redact"
	"github.com/paddman/NTAgentShield/internal/store"
)

type Runtime struct {
	cfg                config.Config
	hostname           string
	journal            *store.Journal
	detector           *detection.Engine
	tailers            []*filetail.Tailer
	nativeSources      []native.Source
	inventoryCollector *inventory.Collector
	baselineStore      *baseline.Store
	inventoryInterval  time.Duration
	logger             *log.Logger
	startedAt          time.Time
	eventCount         atomic.Uint64
	findingCount       atomic.Uint64
	errorCount         atomic.Uint64
	inventoryCount     atomic.Uint64
	nativeEventCount   atomic.Uint64
	lastInventoryNano  atomic.Int64
}

type Status struct {
	Status            string         `json:"status"`
	AgentID           string         `json:"agent_id"`
	TenantID          string         `json:"tenant_id,omitempty"`
	Hostname          string         `json:"hostname"`
	StartedAt         time.Time      `json:"started_at"`
	Uptime            string         `json:"uptime"`
	Events            uint64         `json:"events"`
	Findings          uint64         `json:"findings"`
	Errors            uint64         `json:"errors"`
	Sources           int            `json:"sources"`
	FileSources       int            `json:"file_sources"`
	NativeSources     int            `json:"native_sources"`
	NativeEvents      uint64         `json:"native_events"`
	AIEnabled         bool           `json:"ai_enabled"`
	InventoryEnabled  bool           `json:"inventory_enabled"`
	InventoryRuns     uint64         `json:"inventory_runs"`
	LastInventoryAt   *time.Time     `json:"last_inventory_at,omitempty"`
	InventoryInterval string         `json:"inventory_interval,omitempty"`
	Build             buildinfo.Info `json:"build"`
	SafetyModel       string         `json:"safety_model"`
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
	for _, sourceConfig := range cfg.NativeSources {
		if !sourceConfig.Enabled {
			continue
		}
		source, err := native.New(sourceConfig, cfg.DataDir)
		if errors.Is(err, native.ErrUnsupportedPlatform) {
			logger.Printf("native source skipped id=%s kind=%s reason=%v", sourceConfig.ID, sourceConfig.Kind, err)
			continue
		}
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize native source %s: %w", sourceConfig.ID, err)
		}
		runtime.nativeSources = append(runtime.nativeSources, source)
	}
	if cfg.Inventory.Enabled {
		interval, err := time.ParseDuration(cfg.Inventory.Interval)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize inventory interval: %w", err)
		}
		timeout, err := time.ParseDuration(cfg.Inventory.CommandTimeout)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize inventory command timeout: %w", err)
		}
		collector, err := inventory.New(inventory.Options{
			IncludeProcesses: cfg.Inventory.IncludeProcesses,
			IncludeServices:  cfg.Inventory.IncludeServices,
			IncludeListeners: cfg.Inventory.IncludeListeners,
			IncludeSoftware:  cfg.Inventory.IncludeSoftware,
			MaxItems:         cfg.Inventory.MaxItems,
			CommandTimeout:   timeout,
		})
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize inventory: %w", err)
		}
		baselineStore, err := baseline.New(cfg.DataDir)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize signed inventory baseline: %w", err)
		}
		storedBaseline, exists, err := baselineStore.Load()
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("load signed inventory baseline: %w", err)
		}
		if exists {
			runtime.detector.SeedInventoryBaseline(storedBaseline)
			logger.Printf("verified persistent signed inventory baseline loaded")
		}
		runtime.inventoryCollector = collector
		runtime.baselineStore = baselineStore
		runtime.inventoryInterval = interval
	}
	return runtime, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	startup := map[string]interface{}{
		"agent_id":                r.cfg.AgentID,
		"tenant_id":               r.cfg.TenantID,
		"hostname":                r.hostname,
		"file_sources":            len(r.tailers),
		"native_sources":          len(r.nativeSources),
		"inventory_enabled":       r.inventoryCollector != nil,
		"signed_baseline_enabled": r.baselineStore != nil,
		"inventory_interval":      r.cfg.Inventory.Interval,
		"build":                   buildinfo.Current(),
		"ai_enabled":              r.cfg.AI.Enabled,
		"safety_model":            "untrusted evidence -> deterministic policy gate -> typed tools",
	}
	if _, err := r.journal.Append("agent.start", startup); err != nil {
		return err
	}
	r.logger.Printf("agent started id=%s file_sources=%d native_sources=%d inventory_enabled=%t ai_enabled=%t", r.cfg.AgentID, len(r.tailers), len(r.nativeSources), r.inventoryCollector != nil, r.cfg.AI.Enabled)

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

	r.collectInventory(ctx, true)
	r.poll(ctx)
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
			r.poll(ctx)
			r.collectInventory(ctx, false)
		}
	}
}

func (r *Runtime) poll(ctx context.Context) {
	r.pollFiles(ctx)
	r.pollNative(ctx)
}

func (r *Runtime) pollFiles(ctx context.Context) {
	for _, tailer := range r.tailers {
		if err := ctx.Err(); err != nil {
			return
		}
		events, errs := tailer.Poll()
		for _, err := range errs {
			r.recordCollectorError("file-tail", err)
		}
		for _, event := range events {
			if _, err := r.process(event); err != nil {
				r.errorCount.Add(1)
				r.logger.Printf("event processing error: %v", err)
			}
		}
	}
}

func (r *Runtime) pollNative(ctx context.Context) {
	for _, source := range r.nativeSources {
		if err := ctx.Err(); err != nil {
			return
		}
		batch, errs := source.Poll(ctx)
		for _, err := range errs {
			r.recordCollectorError(source.Kind()+"/"+source.ID(), err)
		}
		processed := true
		for _, event := range batch.Events {
			if _, err := r.process(event); err != nil {
				processed = false
				r.recordCollectorError(source.Kind()+"/"+source.ID(), err)
				break
			}
			r.nativeEventCount.Add(1)
		}
		if processed {
			if err := batch.Acknowledge(); err != nil {
				r.recordCollectorError(source.Kind()+"/"+source.ID()+"/cursor", err)
			}
		}
	}
}

func (r *Runtime) collectInventory(ctx context.Context, force bool) {
	if r.inventoryCollector == nil || ctx.Err() != nil {
		return
	}
	lastNano := r.lastInventoryNano.Load()
	if !force && lastNano != 0 && time.Since(time.Unix(0, lastNano)) < r.inventoryInterval {
		return
	}
	event, err := r.inventoryCollector.Event(ctx)
	if err != nil {
		r.recordCollectorError("native-inventory", err)
		return
	}
	redact.Event(&event)
	if _, err := r.process(event); err != nil {
		r.recordCollectorError("native-inventory", err)
		return
	}
	if r.baselineStore != nil {
		snapshot, err := baseline.SnapshotFromEvent(event)
		if err != nil {
			r.recordCollectorError("inventory-baseline", err)
			return
		}
		if err := r.baselineStore.Save(snapshot); err != nil {
			r.recordCollectorError("inventory-baseline", err)
			return
		}
	}
	collectedAt := time.Now().UTC()
	r.lastInventoryNano.Store(collectedAt.UnixNano())
	r.inventoryCount.Add(1)
	r.logger.Printf("asset inventory collected processes=%t services=%t listeners=%t software=%t", r.cfg.Inventory.IncludeProcesses, r.cfg.Inventory.IncludeServices, r.cfg.Inventory.IncludeListeners, r.cfg.Inventory.IncludeSoftware)
}

func (r *Runtime) recordCollectorError(collector string, err error) {
	if err == nil {
		return
	}
	r.errorCount.Add(1)
	r.logger.Printf("collector error collector=%s error=%v", collector, err)
	_, _ = r.journal.Append("collector.error", map[string]string{"collector": collector, "error": err.Error()})
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
	sourceCount := len(r.tailers) + len(r.nativeSources)
	if r.inventoryCollector != nil {
		sourceCount++
	}
	var lastInventoryAt *time.Time
	if lastNano := r.lastInventoryNano.Load(); lastNano != 0 {
		value := time.Unix(0, lastNano).UTC()
		lastInventoryAt = &value
	}
	return Status{
		Status:            "running",
		AgentID:           r.cfg.AgentID,
		TenantID:          r.cfg.TenantID,
		Hostname:          r.hostname,
		StartedAt:         r.startedAt,
		Uptime:            time.Since(r.startedAt).Round(time.Second).String(),
		Events:            r.eventCount.Load(),
		Findings:          r.findingCount.Load(),
		Errors:            r.errorCount.Load(),
		Sources:           sourceCount,
		FileSources:       len(r.tailers),
		NativeSources:     len(r.nativeSources),
		NativeEvents:      r.nativeEventCount.Load(),
		AIEnabled:         r.cfg.AI.Enabled,
		InventoryEnabled:  r.inventoryCollector != nil,
		InventoryRuns:     r.inventoryCount.Load(),
		LastInventoryAt:   lastInventoryAt,
		InventoryInterval: r.cfg.Inventory.Interval,
		Build:             buildinfo.Current(),
		SafetyModel:       "AI may analyze evidence; only typed tools behind deterministic policy may act",
	}
}

func (r *Runtime) Close() error {
	return r.journal.Close()
}
