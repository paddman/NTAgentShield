package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type envelope struct {
	TenantID         string                 `json:"tenant_id"`
	AssetID          string                 `json:"asset_id"`
	SourceType       string                 `json:"source_type"`
	AssetRole        string                 `json:"asset_role,omitempty"`
	AssetCriticality int                    `json:"asset_criticality"`
	Data             map[string]interface{} `json:"data"`
}

type config struct {
	Server      string
	Tenant      string
	Asset       string
	Source      string
	Role        string
	Criticality int
	Input       string
	Spool       string
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "ntshield-agent:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.Server, "server", env("NTSHIELD_SERVER", "http://127.0.0.1:8080"), "NTAgentShield API URL")
	flag.StringVar(&cfg.Tenant, "tenant", env("NTSHIELD_TENANT", "demo"), "tenant identifier")
	flag.StringVar(&cfg.Asset, "asset", env("NTSHIELD_ASSET", hostname()), "asset identifier")
	flag.StringVar(&cfg.Source, "source", env("NTSHIELD_SOURCE", "sysmon"), "source parser: sysmon, windows_security, nginx, iis, mysql_audit, auditd")
	flag.StringVar(&cfg.Role, "role", env("NTSHIELD_ASSET_ROLE", "unknown"), "asset role")
	flag.IntVar(&cfg.Criticality, "criticality", 3, "asset criticality 1-5")
	flag.StringVar(&cfg.Input, "input", "-", "JSONL input path or - for stdin")
	flag.StringVar(&cfg.Spool, "spool", env("NTSHIELD_SPOOL", "./data/agent-spool.jsonl"), "failed delivery spool")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	if cfg.Tenant == "" || cfg.Asset == "" || cfg.Source == "" {
		return errors.New("tenant, asset, and source are required")
	}
	if err := flushSpool(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "spool flush warning:", err)
	}
	reader, closeFn, err := inputReader(cfg.Input)
	if err != nil {
		return err
	}
	defer closeFn()

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		payload := bytes.TrimSpace(scanner.Bytes())
		if len(payload) == 0 || payload[0] == '#' {
			continue
		}
		var data map[string]interface{}
		if err := json.Unmarshal(payload, &data); err != nil {
			fmt.Fprintf(os.Stderr, "skip invalid JSON at line %d: %v\n", line, err)
			continue
		}
		env := envelope{TenantID: cfg.Tenant, AssetID: cfg.Asset, SourceType: cfg.Source, AssetRole: cfg.Role, AssetCriticality: cfg.Criticality, Data: data}
		body, _ := json.Marshal(env)
		if err := post(cfg.Server, body); err != nil {
			if spoolErr := appendSpool(cfg.Spool, body); spoolErr != nil {
				return fmt.Errorf("delivery failed (%v) and spool failed (%w)", err, spoolErr)
			}
			fmt.Fprintf(os.Stderr, "delivery failed; event spooled: %v\n", err)
		}
	}
	return scanner.Err()
}

func post(server string, body []byte) error {
	client := &http.Client{Timeout: 20 * time.Second}
	url := strings.TrimRight(server, "/") + "/v1/events/raw"
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("server returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	return nil
}

func appendSpool(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(body, '\n'))
	return err
}

func flushSpool(cfg config) error {
	file, err := os.Open(cfg.Spool)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	var remaining [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		body := append([]byte(nil), scanner.Bytes()...)
		if err := post(cfg.Server, body); err != nil {
			remaining = append(remaining, body)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	tmp := cfg.Spool + ".tmp"
	if len(remaining) == 0 {
		return os.Remove(cfg.Spool)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Spool), 0o750); err != nil {
		return err
	}
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	for _, body := range remaining {
		_, _ = out.Write(append(body, '\n'))
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, cfg.Spool)
}

func inputReader(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, func() {}, err
	}
	return file, func() { _ = file.Close() }, nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func hostname() string {
	value, err := os.Hostname()
	if err != nil || value == "" {
		return "unknown-host"
	}
	return value
}
