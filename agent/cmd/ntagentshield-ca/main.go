package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/gateway"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "token":
		return runToken(args[1:])
	default:
		return usageError()
	}
}

func runInit(args []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	stateDir := flags.String("state-dir", "", "gateway PKI and state directory")
	dnsNames := flags.String("dns", "localhost", "comma-separated gateway DNS SANs")
	ipAddresses := flags.String("ip", "127.0.0.1", "comma-separated gateway IP SANs")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*stateDir) == "" {
		return errors.New("--state-dir is required")
	}
	ips := make([]net.IP, 0)
	for _, value := range splitCSV(*ipAddresses) {
		parsed := net.ParseIP(value)
		if parsed == nil {
			return fmt.Errorf("invalid IP SAN %q", value)
		}
		ips = append(ips, parsed)
	}
	paths, err := gateway.InitializePKI(gateway.PKIOptions{
		StateDir:    *stateDir,
		DNSNames:    splitCSV(*dnsNames),
		IPAddresses: ips,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
		"status":             "initialized",
		"state_dir":          paths.Directory,
		"ca_certificate":     paths.RootCertificate,
		"gateway_certificate": paths.ServerCertificate,
	})
}

func runToken(args []string) error {
	flags := flag.NewFlagSet("token", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	stateDir := flags.String("state-dir", "", "gateway state directory")
	tenantID := flags.String("tenant", "", "tenant identifier bound to the token")
	agentID := flags.String("agent", "", "optional agent identifier bound to the token")
	ttlText := flags.String("ttl", "15m", "token lifetime between 1m and 7d")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*stateDir) == "" || strings.TrimSpace(*tenantID) == "" {
		return errors.New("--state-dir and --tenant are required")
	}
	ttl, err := time.ParseDuration(*ttlText)
	if err != nil {
		return fmt.Errorf("parse token TTL: %w", err)
	}
	store, err := gateway.OpenTokenStore(*stateDir)
	if err != nil {
		return err
	}
	created, err := store.Create(strings.TrimSpace(*tenantID), strings.TrimSpace(*agentID), ttl, time.Now().UTC())
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Enrollment token is shown once. Store it in an approved secret channel; the gateway persists only its SHA-256 hash.")
	return json.NewEncoder(os.Stdout).Encode(created)
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, exists := seen[part]; exists {
			continue
		}
		seen[part] = struct{}{}
		result = append(result, part)
	}
	return result
}

func usageError() error {
	return errors.New("usage: ntagentshield-ca <init|token> [options]")
}
