package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/paddman/NTAgentShield/internal/buildinfo"
	"github.com/paddman/NTAgentShield/internal/secureupdate"
)

func main() {
	manifestURL := flag.String("manifest-url", "", "HTTPS URL of signed update envelope")
	publicKeyPath := flag.String("public-key", "", "path to pinned Ed25519 update public key")
	targetPath := flag.String("target", "", "installed ntagentshield-agent.exe path")
	serviceName := flag.String("service", "NTAgentShield", "Windows Service name")
	currentVersion := flag.String("current-version", buildinfo.Current().Version, "installed semantic version")
	timeout := flag.Duration("timeout", 10*time.Minute, "overall update timeout")
	flag.Parse()

	if *manifestURL == "" || *publicKeyPath == "" || *targetPath == "" {
		fatal("--manifest-url, --public-key and --target are required")
	}
	publicKey, err := os.ReadFile(*publicKeyPath)
	if err != nil {
		fatal(fmt.Sprintf("read update public key: %v", err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	envelope, err := secureupdate.FetchEnvelope(ctx, *manifestURL)
	if err != nil {
		fatal(err.Error())
	}
	manifest, err := secureupdate.VerifyEnvelope(
		envelope,
		publicKey,
		*currentVersion,
		time.Now().UTC(),
	)
	if err != nil {
		fatal(err.Error())
	}
	targetDirectory := filepath.Dir(*targetPath)
	staged, err := secureupdate.DownloadArtifact(ctx, manifest, targetDirectory)
	if err != nil {
		fatal(err.Error())
	}
	if err := secureupdate.InstallWindowsServiceUpdate(staged, *targetPath, *serviceName); err != nil {
		_ = os.Remove(staged)
		fatal(err.Error())
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status":  "updated",
		"version": manifest.Version,
		"target":  *targetPath,
		"service": *serviceName,
	})
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
