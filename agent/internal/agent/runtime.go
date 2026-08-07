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
	"github.com/paddman/NTAgentShield/internal/central"
	"github.com/paddman/NTAgentShield/internal/collector/filetail"
	"github.com/paddman/NTAgentShield/internal/collector/native"
	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/detection"
	"github.com/paddman/NTAgentShield/internal/enrollment"
	"github.com/paddman/NTAgentShield/internal/inventory"
	"github.com/paddman/NTAgentShield/internal/model"
	"github.com/paddman/NTAgentShield/internal/redact"
	"github.com/paddman/NTAgentShield/internal/store"
	"github.com/paddman/NTAgentShield/internal/transport"
)

type Runtime struct {
	cfg                      config.Config
	hostname                 string
	journal                  *store.Journal
	detector                 *detection.Engine
	tailers                  []*filetail.Tailer
	nativeSources            []native.Source
	inventoryCollector       *inventory.Collector
	baselineStore            *baseline.Store
	inventoryInterval        time.Duration
	transportOutbox          *transport.Outbox
	transportSender          *transport.Sender
	transportFlushInterval   time.Duration
	logger                   *log.Logger
	startedAt                time.Time
	eventCount               atomic.Uint64
	findingCount             atomic.Uint64
	errorCount               atomic.Uint64
	inventoryCount           atomic.Uint64
	nativeEventCount         atomic.Uint64
	transportSentCount       atomic.Uint64
	transportDeadLetterCount atomic.Uint64
	transportErrorCount      atomic.Uint64
	certificateRenewalCount  atomic.Uint64
	lastInventoryNano        atomic.Int64
	lastTransportSuccessNano atomic.Int64
	lastCertificateRenewNano atomic.Int64
	central                  *central.Client
}

type Status struct {
	Status                   string         `json:"status"`
	AgentID                  string         `json:"agent_id"`
	TenantID                 string         `json:"tenant_id,omitempty"`
	Hostname                 string         `json:"hostname"`
	StartedAt                time.Time      `json:"started_at"`
	Uptime                   string         `json:"uptime"`
	Events                   uint64         `json:"events"`
	Findings                 uint64         `json:"findings"`
	Errors                   uint64         `json:"errors"`
	Sources                  int            `json:"sources"`
	FileSources              int            `json:"file_sources"`
	NativeSources            int            `json:"native_sources"`
	NativeEvents             uint64         `json:"native_events"`
	AIEnabled                bool           `json:"ai_enabled"`
	InventoryEnabled         bool           `json:"inventory_enabled"`
	InventoryRuns            uint64         `json:"inventory_runs"`
	LastInventoryAt          *time.Time     `json:"last_inventory_at,omitempty"`
	InventoryInterval        string         `json:"inventory_interval,omitempty"`
	TransportEnabled         bool           `json:"transport_enabled"`
	TransportPending         int            `json:"transport_pending"`
	TransportPendingBytes    int64          `json:"transport_pending_bytes"`
	TransportDeadLetter      int            `json:"transport_dead_letter"`
	TransportDeadLetterBytes int64          `json:"transport_dead_letter_bytes"`
	TransportSent            uint64         `json:"transport_sent"`
	TransportErrors          uint64         `json:"transport_errors"`
	TransportBackpressure    bool           `json:"transport_backpressure"`
	LastTransportSuccessAt   *time.Time     `json:"last_transport_success_at,omitempty"`
	CertificateAutoRenew     bool           `json:"certificate_auto_renew"`
	CertificateExpiresAt     *time.Time     `json:"certificate_expires_at,omitempty"`
	CertificateRenewals      uint64         `json:"certificate_renewals"`
	LastCertificateRenewAt   *time.Time     `json:"last_certificate_renew_at,omitempty"`
	Build                    buildinfo.Info `json:"build"`
	SafetyModel              string         `json:"safety_model"`
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
	if cfg.Transport.Enabled {
		outbox, err := transport.OpenOutbox(cfg.DataDir)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize telemetry outbox: %w", err)
		}
		timeout, err := time.ParseDuration(cfg.Transport.Timeout)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize telemetry timeout: %w", err)
		}
		flushInterval, err := time.ParseDuration(cfg.Transport.FlushInterval)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize telemetry flush interval: %w", err)
		}
		renewBefore := time.Duration(0)
		renewCheckInterval := time.Duration(0)
		if cfg.Transport.AutoRenew {
			renewBefore, err = time.ParseDuration(cfg.Transport.RenewBefore)
			if err != nil {
				_ = journal.Close()
				return nil, fmt.Errorf("initialize certificate renew-before interval: %w", err)
			}
			renewCheckInterval, err = time.ParseDuration(cfg.Transport.RenewCheckInterval)
			if err != nil {
				_ = journal.Close()
				return nil, fmt.Errorf("initialize certificate renewal check interval: %w", err)
			}
		}
		sender, err := transport.NewSender(outbox, transport.SenderOptions{
			Endpoint:           cfg.Transport.Endpoint,
			AgentID:            cfg.AgentID,
			TenantID:           cfg.TenantID,
			CertFile:           cfg.Transport.CertFile,
			KeyFile:            cfg.Transport.KeyFile,
			CAFile:             cfg.Transport.CAFile,
			ServerName:         cfg.Transport.ServerName,
			Timeout:            timeout,
			AutoRenew:          cfg.Transport.AutoRenew,
			RenewalEndpoint:    cfg.Transport.RenewalEndpoint,
			RenewBefore:        renewBefore,
			RenewCheckInterval: renewCheckInterval,
		})
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize telemetry sender: %w", err)
		}
		runtime.transportOutbox = outbox
		runtime.transportSender = sender
		runtime.transportFlushInterval = flushInterval
	}
	if cfg.Central.Enabled {
		client, err := central.New(cfg.Central, cfg.AgentID, cfg.TenantID, hostname, logger)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize Central transport: %w", err)
		}
		runtime.central = client
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
		"transport_enabled":       r.transportSender != nil,
		"central_enabled":         r.central != nil,
		"certificate_auto_renew":  r.cfg.Transport.AutoRenew,
		"build":                   buildinfo.Current(),
		"ai_enabled":              r.cfg.AI.Enabled,
		"safety_model":            "untrusted evidence -> deterministic policy gate -> typed tools",
	}
	if _, err := r.journal.Append("agent.start", startup); err != nil {
		return err
	}
	r.logger.Printf("agent started id=%s file_sources=%d native_sources=%d inventory_enabled=%t transport_enabled=%t central_enabled=%t ai_enabled=%t", r.cfg.AgentID, len(r.tailers), len(r.nativeSources), r.inventoryCollector != nil, r.transportSender != nil, r.central != nil, r.cfg.AI.Enabled)

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
	if r.transportSender != nil {
		go r.runTransport(ctx)
	}
	if r.central != nil {
		go func() {
			if err := r.central.Run(ctx, r.centralStatus); err != nil {
				r.logger.Printf("Central transport stopped: %v", err)
			}
		}()
		r.logger.Printf("Central transport enabled url=%s", r.cfg.Central.URL)
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

func (r *Runtime) runTransport(ctx context.Context) {
	delay := time.Duration(0)
	lastError := ""
	backpressureLogged := false
	for {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		} else if ctx.Err() != nil {
			return
		}

		result, err := r.transportSender.Flush(ctx, r.cfg.Transport.BatchSize)
		r.transportSentCount.Add(uint64(result.Sent))
		r.transportDeadLetterCount.Add(uint64(result.DeadLetter))
		if result.CertificateRenewed {
			r.certificateRenewalCount.Add(1)
			r.lastCertificateRenewNano.Store(time.Now().UTC().UnixNano())
			r.logger.Printf("Agent client certificate renewed expires_at=%v", result.CertificateExpiresAt)
			_, _ = r.journal.Append("identity.certificate_renewed", map[string]interface{}{
				"expires_at": result.CertificateExpiresAt,
			})
		}
		if result.Sent > 0 {
			r.lastTransportSuccessNano.Store(time.Now().UTC().UnixNano())
		}
		if result.DeadLetter > 0 {
			_, _ = r.journal.Append("transport.dead_letter", map[string]interface{}{
				"count": result.DeadLetter,
			})
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			r.transportErrorCount.Add(1)
			r.errorCount.Add(1)
			message := err.Error()
			if message != lastError {
				r.logger.Printf("telemetry transport error: %v", err)
				_, _ = r.journal.Append("transport.error", map[string]string{"error": message})
				lastError = message
			}
			if delay <= 0 {
				delay = r.transportFlushInterval
			}
			delay *= 2
			if delay > time.Minute {
				delay = time.Minute
			}
		} else {
			if lastError != "" {
				r.logger.Printf("telemetry transport recovered")
				_, _ = r.journal.Append("transport.recovered", map[string]interface{}{"sent": result.Sent})
				lastError = ""
			}
			delay = r.transportFlushInterval
		}

		if stats, statsErr := r.transportOutbox.Stats(); statsErr == nil {
			backpressure := stats.Pending >= r.cfg.Transport.PendingWarn
			if backpressure && !backpressureLogged {
				r.logger.Printf("telemetry outbox backpressure pending=%d bytes=%d", stats.Pending, stats.PendingBytes)
				_, _ = r.journal.Append("transport.backpressure", map[string]interface{}{
					"pending": stats.Pending,
					"bytes":   stats.PendingBytes,
				})
			}
			if !backpressure && backpressureLogged {
				_, _ = r.journal.Append("transport.backpressure_cleared", map[string]interface{}{
					"pending": stats.Pending,
				})
			}
			backpressureLogged = backpressure
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
	if r.transportOutbox != nil {
		if err := r.transportOutbox.Enqueue(event); err != nil {
			return findings, fmt.Errorf("queue telemetry for Control Plane: %w", err)
		}
	}
	if r.central != nil {
		r.central.Enqueue(event, findings)
	}
	return findings, nil
}

func (r *Runtime) centralStatus() central.HeartbeatStatus {
	status := r.Status()
	return central.HeartbeatStatus{
		AgentID:      status.AgentID,
		TenantID:     status.TenantID,
		ComputerName: status.Hostname,
		Status:       status.Status,
		Events:       status.Events,
		Findings:     status.Findings,
		Errors:       status.Errors,
		QueueDepth:   r.central.QueueDepth(),
	}
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
	var lastTransportSuccessAt *time.Time
	if lastNano := r.lastTransportSuccessNano.Load(); lastNano != 0 {
		value := time.Unix(0, lastNano).UTC()
		lastTransportSuccessAt = &value
	}
	var lastCertificateRenewAt *time.Time
	if lastNano := r.lastCertificateRenewNano.Load(); lastNano != 0 {
		value := time.Unix(0, lastNano).UTC()
		lastCertificateRenewAt = &value
	}
	var certificateExpiresAt *time.Time
	if r.cfg.Transport.Enabled {
		if expiry, err := enrollment.CertificateExpiry(r.cfg.Transport.CertFile); err == nil {
			value := expiry.UTC()
			certificateExpiresAt = &value
		}
	}
	transportStats := transport.OutboxStats{}
	if r.transportOutbox != nil {
		if stats, err := r.transportOutbox.Stats(); err == nil {
			transportStats = stats
		}
	}
	return Status{
		Status:                   "running",
		AgentID:                  r.cfg.AgentID,
		TenantID:                 r.cfg.TenantID,
		Hostname:                 r.hostname,
		StartedAt:                r.startedAt,
		Uptime:                   time.Since(r.startedAt).Round(time.Second).String(),
		Events:                   r.eventCount.Load(),
		Findings:                 r.findingCount.Load(),
		Errors:                   r.errorCount.Load(),
		Sources:                  sourceCount,
		FileSources:              len(r.tailers),
		NativeSources:            len(r.nativeSources),
		NativeEvents:             r.nativeEventCount.Load(),
		AIEnabled:                r.cfg.AI.Enabled,
		InventoryEnabled:         r.inventoryCollector != nil,
		InventoryRuns:            r.inventoryCount.Load(),
		LastInventoryAt:          lastInventoryAt,
		InventoryInterval:        r.cfg.Inventory.Interval,
		TransportEnabled:         r.transportSender != nil,
		TransportPending:         transportStats.Pending,
		TransportPendingBytes:    transportStats.PendingBytes,
		TransportDeadLetter:      transportStats.DeadLetter,
		TransportDeadLetterBytes: transportStats.DeadLetterBty,
		TransportSent:            r.transportSentCount.Load(),
		TransportErrors:          r.transportErrorCount.Load(),
		TransportBackpressure:    r.transportOutbox != nil && transportStats.Pending >= r.cfg.Transport.PendingWarn,
		LastTransportSuccessAt:   lastTransportSuccessAt,
		CertificateAutoRenew:     r.cfg.Transport.Enabled && r.cfg.Transport.AutoRenew,
		CertificateExpiresAt:     certificateExpiresAt,
		CertificateRenewals:      r.certificateRenewalCount.Load(),
		LastCertificateRenewAt:   lastCertificateRenewAt,
		Build:                    buildinfo.Current(),
		SafetyModel:              "AI may analyze evidence; only typed tools behind deterministic policy may act",
	}
}

func (r *Runtime) Close() error {
	return r.journal.Close()
}
