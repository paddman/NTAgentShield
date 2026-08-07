package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/enrollment"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	set := flag.NewFlagSet("ntagentshield-enroll", flag.ContinueOnError)
	configPath := set.String("config", "config/agent.example.json", "agent configuration file")
	endpoint := set.String("endpoint", "", "HTTPS enrollment endpoint, for example https://control.example/v1/enrollment")
	tokenFile := set.String("token-file", "", "file containing the short-lived bootstrap enrollment token")
	bootstrapCA := set.String("bootstrap-ca", "", "optional CA file used to verify the enrollment HTTPS server")
	timeoutText := set.String("timeout", "30s", "enrollment request timeout")
	if err := set.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*endpoint) == "" || strings.TrimSpace(*tokenFile) == "" {
		return fmt.Errorf("--endpoint and --token-file are required")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if err := config.EnsureAgentID(&cfg); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.TenantID) == "" {
		return fmt.Errorf("tenant_id is required in the agent configuration")
	}
	token, err := os.ReadFile(*tokenFile)
	if err != nil {
		return fmt.Errorf("read enrollment token: %w", err)
	}
	timeout, err := time.ParseDuration(*timeoutText)
	if err != nil {
		return fmt.Errorf("invalid timeout: %w", err)
	}
	hostname, _ := os.Hostname()
	bundle, err := enrollment.Enroll(context.Background(), enrollment.Options{
		Endpoint:        *endpoint,
		BootstrapToken:  strings.TrimSpace(string(token)),
		BootstrapCAFile: *bootstrapCA,
		DataDir:         cfg.DataDir,
		AgentID:         cfg.AgentID,
		TenantID:        cfg.TenantID,
		Hostname:        hostname,
		Timeout:         timeout,
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(bundle)
}
