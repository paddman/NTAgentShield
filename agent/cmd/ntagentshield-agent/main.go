package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/paddman/NTAgentShield/internal/agent"
	"github.com/paddman/NTAgentShield/internal/buildinfo"
	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/policyupdate"
	"github.com/paddman/NTAgentShield/internal/responseexec"
	"github.com/paddman/NTAgentShield/internal/servicehost"
)

func main() {
	configPath := flag.String("config", "config/agent.example.json", "path to agent JSON configuration")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		_ = json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
		return
	}
	if err := servicehost.Run("NTAgentShield", func(ctx context.Context) error {
		return runAgent(ctx, *configPath)
	}); err != nil {
		fatal("run Agent service host", err)
	}
}

func runAgent(ctx context.Context, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	if err := config.EnsureAgentID(&cfg); err != nil {
		return fmt.Errorf("initialize agent identity: %w", err)
	}
	logger := log.New(os.Stdout, "ntagentshield ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	runtime, err := agent.New(cfg, logger)
	if err != nil {
		return fmt.Errorf("initialize agent: %w", err)
	}
	defer runtime.Close()

	if cfg.Transport.Enabled {
		timeout, err := time.ParseDuration(cfg.Transport.Timeout)
		if err != nil {
			return fmt.Errorf("initialize secure control transport timeout: %w", err)
		}
		policyRunner, err := policyupdate.NewRunner(policyupdate.RunnerOptions{
			DataDir:           cfg.DataDir,
			AgentID:           cfg.AgentID,
			TenantID:          cfg.TenantID,
			PolicyFile:        cfg.Tools.PolicyFile,
			TransportEndpoint: cfg.Transport.Endpoint,
			CertFile:          cfg.Transport.CertFile,
			KeyFile:           cfg.Transport.KeyFile,
			CAFile:            cfg.Transport.CAFile,
			ServerName:        cfg.Transport.ServerName,
			Timeout:           timeout,
			Interval:          5 * time.Minute,
		})
		if err == nil {
			go policyRunner.Run(ctx, logger)
			logger.Printf("signed policy distribution enabled; rollback state is Agent-signed")
		} else if !errors.Is(err, policyupdate.ErrNotConfigured) {
			return fmt.Errorf("initialize signed policy distribution: %w", err)
		}

		responseRunner, err := responseexec.NewRunner(responseexec.RunnerOptions{
			DataDir:           cfg.DataDir,
			AgentID:           cfg.AgentID,
			TenantID:          cfg.TenantID,
			PolicyFile:        cfg.Tools.PolicyFile,
			AllowedPaths:      cfg.Tools.AllowedPaths,
			TransportEndpoint: cfg.Transport.Endpoint,
			CertFile:          cfg.Transport.CertFile,
			KeyFile:           cfg.Transport.KeyFile,
			CAFile:            cfg.Transport.CAFile,
			ServerName:        cfg.Transport.ServerName,
			Timeout:           timeout,
			Interval:          5 * time.Second,
		})
		if err != nil {
			return fmt.Errorf("initialize signed response broker: %w", err)
		}
		go responseRunner.Run(ctx, logger)
		logger.Printf("signed response broker enabled; crash-safe replay ledger is active")
	}

	if err := runtime.Run(ctx); err != nil {
		return fmt.Errorf("run agent: %w", err)
	}
	return nil
}

func fatal(operation string, err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}
