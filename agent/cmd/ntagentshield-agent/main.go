package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/paddman/NTAgentShield/internal/agent"
	"github.com/paddman/NTAgentShield/internal/buildinfo"
	"github.com/paddman/NTAgentShield/internal/config"
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
	if err := runtime.Run(ctx); err != nil {
		fatal("run agent", err)
	}
}

func fatal(operation string, err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}
