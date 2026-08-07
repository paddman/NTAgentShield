package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/paddman/NTAgentShield/internal/agent"
	"github.com/paddman/NTAgentShield/internal/buildinfo"
	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/policyupdate"
	"github.com/paddman/NTAgentShield/internal/responseexec"
)

func main() {
	configPath := flag.String("config", "config/agent.example.json", "path to agent JSON configuration")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		_ = json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
		return
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal("load configuration", err)
	}
	if err := config.EnsureAgentID(&cfg); err != nil {
		fatal("initialize agent identity", err)
	}
	logger := log.New(os.Stdout, "ntagentshield ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	runtime, err := agent.New(cfg, logger)
	if err != nil {
		fatal("initialize agent", err)
	}
	defer runtime.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Transport.Enabled {
		timeout, err := time.ParseDuration(cfg.Transport.Timeout)
		if err != nil {
			fatal("initialize secure control transport timeout", err)
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
			fatal("initialize signed policy distribution", err)
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
			fatal("initialize signed response broker", err)
		}
		go responseRunner.Run(ctx, logger)
		logger.Printf("signed response broker enabled; crash-safe replay ledger is active")
	}

	if err := runtime.Run(ctx); err != nil {
		fatal("run agent", err)
	}
}

func fatal(operation string, err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}
