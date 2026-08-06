package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/paddman/NTAgentShield/internal/ai"
	"github.com/paddman/NTAgentShield/internal/buildinfo"
	"github.com/paddman/NTAgentShield/internal/codescan"
	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/detection"
	"github.com/paddman/NTAgentShield/internal/model"
	"github.com/paddman/NTAgentShield/internal/parser"
	"github.com/paddman/NTAgentShield/internal/policy"
	"github.com/paddman/NTAgentShield/internal/redact"
	"github.com/paddman/NTAgentShield/internal/store"
	"github.com/paddman/NTAgentShield/internal/tools"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "help", "-h", "--help":
		usage()
		return
	case "version":
		err = printJSON(buildinfo.Current())
	case "doctor":
		err = doctor(os.Args[2:])
	case "scan-log":
		err = scanLog(os.Args[2:])
	case "scan-event":
		err = scanEvent(os.Args[2:])
	case "scan-code":
		err = scanCode(os.Args[2:])
	case "ai-analyze":
		err = aiAnalyze(os.Args[2:])
	case "verify-store":
		err = verifyStore(os.Args[2:])
	case "policy-check":
		err = policyCheck(os.Args[2:])
	case "tool":
		err = runTool(os.Args[2:])
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	_, _ = fmt.Fprintln(os.Stderr, `NTAgentShield control utility

Usage:
  ntagentshieldctl version
  ntagentshieldctl doctor --config config/agent.example.json
  ntagentshieldctl scan-log --format iis_w3c --file examples/logs/iis.log
  ntagentshieldctl scan-event --file examples/events/web-worker-shell.json
  ntagentshieldctl scan-code --path ./src
  ntagentshieldctl ai-analyze --config config/agent.local-ai.json --event examples/events/web-worker-shell.json
  ntagentshieldctl verify-store --path data/evidence.journal.jsonl
  ntagentshieldctl policy-check --policy policies/default-policy.json --tool host.isolate --risk contain --trust untrusted_telemetry
  ntagentshieldctl tool --config config/agent.example.json --name file.sha256 --args '{"path":"examples/logs/iis.log"}'`)
}

func doctor(args []string) error {
	set := flag.NewFlagSet("doctor", flag.ContinueOnError)
	configPath := set.String("config", "config/agent.example.json", "configuration file")
	if err := set.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if err := config.EnsureDataDir(cfg); err != nil {
		return err
	}
	activeSources := 0
	missingSources := []string{}
	for _, source := range cfg.Sources {
		if !source.Enabled {
			continue
		}
		activeSources++
		matches, _ := filepath.Glob(source.Path)
		if len(matches) == 0 {
			missingSources = append(missingSources, source.ID+":"+source.Path)
		}
	}
	activePolicy, err := policy.Load(cfg.Tools.PolicyFile)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{
		"status":          "ok",
		"config":          *configPath,
		"data_dir":        cfg.DataDir,
		"api_listen":      cfg.API.Listen,
		"active_sources":  activeSources,
		"missing_sources": missingSources,
		"policy_version":  activePolicy.Version,
		"ai_enabled":      cfg.AI.Enabled,
		"warning":         "missing source files are warnings because some logs are created only after the service starts",
	})
}

func scanLog(args []string) error {
	set := flag.NewFlagSet("scan-log", flag.ContinueOnError)
	format := set.String("format", "raw", "raw, jsonl, iis_w3c, nginx_combined, syslog, mysql_general")
	path := set.String("file", "", "log file")
	source := set.String("source", "manual-scan", "source name")
	if err := set.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("--file is required")
	}
	file, err := os.Open(*path)
	if err != nil {
		return err
	}
	defer file.Close()
	logParser, err := parser.New(*format, *source)
	if err != nil {
		return err
	}
	detector := detection.New()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	events := 0
	findingCount := 0
	line := 0
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		line++
		event, parseErr := logParser.Parse(scanner.Text())
		if parseErr != nil {
			_ = encoder.Encode(map[string]interface{}{"type": "parse_error", "line": line, "error": parseErr.Error()})
			continue
		}
		if event == nil {
			continue
		}
		event.Provenance.OriginalPath = *path
		event.Provenance.LineNumber = int64(line)
		redact.Event(event)
		events++
		for _, finding := range detector.Inspect(*event) {
			findingCount++
			_ = encoder.Encode(map[string]interface{}{"type": "finding", "finding": finding})
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return encoder.Encode(map[string]interface{}{"type": "summary", "events": events, "findings": findingCount})
}

func scanEvent(args []string) error {
	set := flag.NewFlagSet("scan-event", flag.ContinueOnError)
	path := set.String("file", "", "JSON event file")
	if err := set.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("--file is required")
	}
	content, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var event model.Event
	if err := json.Unmarshal(content, &event); err != nil {
		return err
	}
	event.Prepare()
	redact.Event(&event)
	return printJSON(map[string]interface{}{"event": event, "findings": detection.New().Inspect(event)})
}

func scanCode(args []string) error {
	set := flag.NewFlagSet("scan-code", flag.ContinueOnError)
	path := set.String("path", ".", "source tree to scan")
	if err := set.Parse(args); err != nil {
		return err
	}
	result, err := codescan.New().Scan(context.Background(), *path)
	if err != nil {
		return err
	}
	return printJSON(result)
}

func aiAnalyze(args []string) error {
	set := flag.NewFlagSet("ai-analyze", flag.ContinueOnError)
	configPath := set.String("config", "config/agent.local-ai.json", "configuration file with AI enabled")
	eventPath := set.String("event", "", "JSON event file")
	objective := set.String("objective", "", "investigation objective")
	if err := set.Parse(args); err != nil {
		return err
	}
	if *eventPath == "" {
		return errors.New("--event is required")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(*eventPath)
	if err != nil {
		return err
	}
	var event model.Event
	if err := json.Unmarshal(content, &event); err != nil {
		return err
	}
	event.Prepare()
	findings := detection.New().Inspect(event)
	client, err := ai.New(cfg.AI)
	if err != nil {
		return err
	}
	analysis, err := client.Analyze(context.Background(), ai.IncidentBundle{Objective: *objective, Events: []model.Event{event}, Findings: findings})
	if err != nil {
		return err
	}
	return printJSON(analysis)
}

func verifyStore(args []string) error {
	set := flag.NewFlagSet("verify-store", flag.ContinueOnError)
	path := set.String("path", "data/evidence.journal.jsonl", "journal path")
	if err := set.Parse(args); err != nil {
		return err
	}
	sequence, lastHash, err := store.VerifyFile(*path)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{"status": "valid", "records": sequence, "last_hash": lastHash, "path": *path})
}

func policyCheck(args []string) error {
	set := flag.NewFlagSet("policy-check", flag.ContinueOnError)
	policyPath := set.String("policy", "policies/default-policy.json", "policy path")
	tool := set.String("tool", "file.sha256", "tool name")
	risk := set.String("risk", "observe", "observe, contain, modify, destructive")
	trust := set.String("trust", "untrusted_telemetry", "trigger trust")
	mode := set.String("mode", "auto", "observe, plan, act, auto")
	if err := set.Parse(args); err != nil {
		return err
	}
	activePolicy, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}
	request := model.ActionRequest{
		Tool:         *tool,
		Risk:         model.ActionRisk(*risk),
		Mode:         model.ActionMode(*mode),
		TriggerTrust: model.ParseTrustLevel(*trust),
		RequestedAt:  time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Minute),
	}
	return printJSON(policy.New(activePolicy).Evaluate(request))
}

func runTool(args []string) error {
	set := flag.NewFlagSet("tool", flag.ContinueOnError)
	configPath := set.String("config", "config/agent.example.json", "configuration file")
	name := set.String("name", "", "typed tool name")
	arguments := set.String("args", "{}", "JSON object with tool arguments")
	if err := set.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("--name is required")
	}
	var toolArgs map[string]interface{}
	if err := json.Unmarshal([]byte(*arguments), &toolArgs); err != nil {
		return fmt.Errorf("decode --args: %w", err)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	activePolicy, err := policy.Load(cfg.Tools.PolicyFile)
	if err != nil {
		return err
	}
	registry, err := safeRegistry(policy.New(activePolicy), cfg.Tools.AllowedPaths)
	if err != nil {
		return err
	}
	request := model.ActionRequest{
		Tool:         *name,
		Args:         toolArgs,
		Reason:       "operator CLI request",
		Mode:         model.ModeObserve,
		TriggerTrust: model.TrustOperator,
		RequestedBy:  os.Getenv("USER"),
		RequestedAt:  time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Minute),
	}
	result, decision, err := registry.Execute(context.Background(), request)
	if err != nil {
		return err
	}
	return printJSON(map[string]interface{}{"decision": decision, "result": result})
}

func safeRegistry(engine *policy.Engine, roots []string) (*tools.Registry, error) {
	registry := tools.NewRegistry(engine)
	if err := registry.Register(tools.HostInfo{}); err != nil {
		return nil, err
	}
	stat, err := tools.NewFileStat(roots)
	if err != nil {
		return nil, err
	}
	hash, err := tools.NewFileSHA256(roots)
	if err != nil {
		return nil, err
	}
	lines, err := tools.NewFileReadLines(roots)
	if err != nil {
		return nil, err
	}
	for _, tool := range []tools.Tool{stat, hash, lines} {
		if err := registry.Register(tool); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func printJSON(value interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
