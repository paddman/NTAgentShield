//go:build windows

package tools

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type windowsNetworkBackend struct {
	runner          commandRunner
	dataDir         string
	identityKeyFile string
	controlEndpoint string
}

func newNetworkContainmentBackend(options ContainmentOptions) (networkContainmentBackend, error) {
	if options.DataDir == "" || options.IdentityKeyFile == "" || options.ControlEndpoint == "" {
		return nil, errors.New("network containment requires data directory, Agent identity key, and Control Plane endpoint")
	}
	return &windowsNetworkBackend{runner: osCommandRunner{}, dataDir: options.DataDir, identityKeyFile: options.IdentityKeyFile, controlEndpoint: options.ControlEndpoint}, nil
}

func (b *windowsNetworkBackend) isolationDir() string {
	return filepath.Join(b.dataDir, "containment")
}
func (b *windowsNetworkBackend) isolationStatePath() string {
	return filepath.Join(b.isolationDir(), "host-isolation.json")
}
func (b *windowsNetworkBackend) firewallBackupPath() string {
	return filepath.Join(b.isolationDir(), "windows-firewall-pre-isolation.wfw")
}
func (b *windowsNetworkBackend) blockStatePath(address netip.Addr) string {
	digest := sha256.Sum256([]byte(address.String()))
	return filepath.Join(b.isolationDir(), "firewall-block-"+hex.EncodeToString(digest[:8])+".json")
}

func (b *windowsNetworkBackend) portStatePath(rule PortRule) string {
	digest := sha256.Sum256([]byte(portRuleKey(rule)))
	return filepath.Join(b.isolationDir(), "firewall-port-"+hex.EncodeToString(digest[:8])+".json")
}

func (b *windowsNetworkBackend) Isolate(ctx context.Context) (map[string]interface{}, error) {
	state, stateErr := loadSignedContainmentState(b.isolationStatePath(), b.identityKeyFile, "host-isolation-windows-firewall")
	stateExists := stateErr == nil
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return nil, stateErr
	}
	if stateExists {
		if _, _, err := b.validateIsolationBackup(state); err != nil {
			return nil, err
		}
		targets, err := resolveControlTargets(ctx, b.controlEndpoint)
		if err != nil {
			return nil, err
		}
		if err := b.applyIsolationPolicy(ctx, targets); err != nil {
			return nil, err
		}
		return map[string]interface{}{"isolated": true, "already_isolated": true, "reconciled": true, "state": state.Data}, nil
	}

	if _, err := os.Stat(b.firewallBackupPath()); err == nil {
		return nil, errors.New("Windows Firewall backup exists without signed isolation state; refusing to overwrite recovery evidence")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(b.isolationDir(), 0o700); err != nil {
		return nil, err
	}
	targets, err := resolveControlTargets(ctx, b.controlEndpoint)
	if err != nil {
		return nil, err
	}
	backup := b.firewallBackupPath()
	if _, err := b.runner.Run(ctx, "netsh", "advfirewall", "export", backup); err != nil {
		return nil, fmt.Errorf("export Windows Firewall policy before isolation: %w", err)
	}
	backupHash, err := sha256File(backup)
	if err != nil {
		_ = os.Remove(backup)
		return nil, fmt.Errorf("hash Windows Firewall backup: %w", err)
	}
	stateData := map[string]interface{}{"backend": "windows-firewall", "backup_path": backup, "backup_sha256": backupHash, "control_targets": windowsControlTargetStrings(targets), "dns_allowed": true}
	if err := saveSignedContainmentState(b.isolationStatePath(), b.identityKeyFile, "host-isolation-windows-firewall", stateData); err != nil {
		_ = os.Remove(backup)
		return nil, fmt.Errorf("persist Windows isolation intent: %w", err)
	}
	if err := b.applyIsolationPolicy(ctx, targets); err != nil {
		rollbackOutput, rollbackErr := b.runner.Run(ctx, "netsh", "advfirewall", "import", backup)
		if rollbackErr == nil {
			_ = os.Remove(b.isolationStatePath())
			_ = os.Remove(backup)
			return nil, err
		}
		return nil, fmt.Errorf("%v; automatic Windows Firewall rollback failed: %v: %s", err, rollbackErr, strings.TrimSpace(string(rollbackOutput)))
	}
	return map[string]interface{}{"isolated": true, "backend": "windows-firewall", "control_targets": windowsControlTargetStrings(targets)}, nil
}

func (b *windowsNetworkBackend) applyIsolationPolicy(ctx context.Context, targets []controlTarget) error {
	const controlRule = "NTAgentShield-Control"
	_, _ = b.runner.Run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+controlRule)
	for _, target := range targets {
		args := []string{"advfirewall", "firewall", "add", "rule", "name=" + controlRule, "dir=out", "action=allow", "protocol=TCP", "remoteip=" + target.IP.String(), "remoteport=" + strconv.Itoa(int(target.Port)), "profile=any", "enable=yes"}
		if _, err := b.runner.Run(ctx, "netsh", args...); err != nil {
			return fmt.Errorf("allow Control Plane through Windows isolation: %w", err)
		}
	}
	for _, protocol := range []string{"UDP", "TCP"} {
		name := "NTAgentShield-DNS-" + protocol
		_, _ = b.runner.Run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
		if _, err := b.runner.Run(ctx, "netsh", "advfirewall", "firewall", "add", "rule", "name="+name, "dir=out", "action=allow", "protocol="+protocol, "remoteport=53", "profile=any", "enable=yes"); err != nil {
			return fmt.Errorf("allow DNS through Windows isolation: %w", err)
		}
	}
	if _, err := b.runner.Run(ctx, "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"); err != nil {
		return fmt.Errorf("enable Windows host isolation: %w", err)
	}
	return nil
}

func (b *windowsNetworkBackend) Release(ctx context.Context) (map[string]interface{}, error) {
	state, err := loadSignedContainmentState(b.isolationStatePath(), b.identityKeyFile, "host-isolation-windows-firewall")
	if errors.Is(err, os.ErrNotExist) {
		if _, backupErr := os.Stat(b.firewallBackupPath()); backupErr == nil {
			return nil, errors.New("Windows Firewall isolation backup exists without signed state; refusing unverifiable restore")
		} else if !errors.Is(backupErr, os.ErrNotExist) {
			return nil, backupErr
		}
		return map[string]interface{}{"released": true, "already_released": true}, nil
	}
	if err != nil {
		return nil, err
	}
	backupPath, _, err := b.validateIsolationBackup(state)
	if err != nil {
		return nil, err
	}
	if _, err := b.runner.Run(ctx, "netsh", "advfirewall", "import", backupPath); err != nil {
		return nil, fmt.Errorf("restore Windows Firewall policy: %w", err)
	}
	if err := os.Remove(b.isolationStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.Remove(backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return map[string]interface{}{"released": true, "backend": "windows-firewall"}, nil
}

func (b *windowsNetworkBackend) validateIsolationBackup(state signedContainmentState) (string, string, error) {
	backupPath, ok := state.Data["backup_path"].(string)
	if !ok || backupPath == "" || filepath.Clean(backupPath) != filepath.Clean(b.firewallBackupPath()) {
		return "", "", errors.New("signed Windows isolation state contains an invalid backup path")
	}
	expectedHash, ok := state.Data["backup_sha256"].(string)
	if !ok || len(expectedHash) != 64 {
		return "", "", errors.New("signed Windows isolation state is missing firewall backup digest")
	}
	actualHash, err := sha256File(backupPath)
	if err != nil {
		return "", "", fmt.Errorf("read Windows Firewall backup: %w", err)
	}
	if !strings.EqualFold(actualHash, expectedHash) {
		return "", "", errors.New("Windows Firewall backup digest does not match signed isolation state")
	}
	return backupPath, expectedHash, nil
}

func (b *windowsNetworkBackend) Block(ctx context.Context, address netip.Addr) (map[string]interface{}, error) {
	if err := os.MkdirAll(b.isolationDir(), 0o700); err != nil {
		return nil, err
	}
	statePath := b.blockStatePath(address)
	state, stateErr := loadSignedContainmentState(statePath, b.identityKeyFile, "firewall-block-windows")
	stateExists := stateErr == nil
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return nil, stateErr
	}

	var name string
	createdState := false
	if stateExists {
		remoteIP, remoteOK := state.Data["remote_ip"].(string)
		rule, ruleOK := state.Data["rule"].(string)
		if !remoteOK || remoteIP != address.String() || !ruleOK || !strings.HasPrefix(rule, windowsBlockRulePrefix(address)+"-") {
			return nil, errors.New("signed Windows Firewall block ownership state is invalid")
		}
		name = rule
	} else {
		var err error
		name, err = newWindowsBlockRuleName(address)
		if err != nil {
			return nil, err
		}
		stateData := map[string]interface{}{"backend": "windows-firewall", "remote_ip": address.String(), "rule": name}
		if err := saveSignedContainmentState(statePath, b.identityKeyFile, "firewall-block-windows", stateData); err != nil {
			return nil, fmt.Errorf("persist Windows Firewall block ownership intent: %w", err)
		}
		createdState = true
	}

	if err := b.applyBlockRule(ctx, name, address); err != nil {
		if createdState {
			_ = os.Remove(statePath)
		}
		return nil, err
	}
	return map[string]interface{}{"remote_ip": address.String(), "blocked": true, "backend": "windows-firewall", "rule": name, "reapplied": stateExists}, nil
}

func (b *windowsNetworkBackend) applyBlockRule(ctx context.Context, name string, address netip.Addr) error {
	_, _ = b.runner.Run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
	for _, direction := range []string{"in", "out"} {
		if _, err := b.runner.Run(ctx, "netsh", "advfirewall", "firewall", "add", "rule", "name="+name, "dir="+direction, "action=block", "remoteip="+address.String(), "profile=any", "enable=yes"); err != nil {
			_, _ = b.runner.Run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
			return fmt.Errorf("add Windows Firewall IP block: %w", err)
		}
	}
	return nil
}

func (b *windowsNetworkBackend) Unblock(ctx context.Context, address netip.Addr) (map[string]interface{}, error) {
	statePath := b.blockStatePath(address)
	state, err := loadSignedContainmentState(statePath, b.identityKeyFile, "firewall-block-windows")
	if errors.Is(err, os.ErrNotExist) {
		return map[string]interface{}{"remote_ip": address.String(), "unblocked": true, "already_unblocked": true}, nil
	}
	if err != nil {
		return nil, err
	}
	remoteIP, remoteOK := state.Data["remote_ip"].(string)
	name, ruleOK := state.Data["rule"].(string)
	if !remoteOK || remoteIP != address.String() || !ruleOK || !strings.HasPrefix(name, windowsBlockRulePrefix(address)+"-") {
		return nil, errors.New("signed Windows Firewall block ownership state is invalid")
	}
	if _, err := b.runner.Run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name); err != nil {
		return nil, fmt.Errorf("delete Windows Firewall IP block: %w", err)
	}
	if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return map[string]interface{}{"remote_ip": address.String(), "unblocked": true, "backend": "windows-firewall", "rule": name}, nil
}

func (b *windowsNetworkBackend) OpenPort(ctx context.Context, rule PortRule) (map[string]interface{}, error) {
	if err := os.MkdirAll(b.isolationDir(), 0o700); err != nil {
		return nil, err
	}
	statePath := b.portStatePath(rule)
	state, stateErr := loadSignedContainmentState(statePath, b.identityKeyFile, "firewall-port-windows")
	stateExists := stateErr == nil
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return nil, stateErr
	}

	var name string
	createdState := false
	if stateExists {
		var err error
		name, err = validateWindowsPortState(state, rule)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		name, err = newWindowsPortRuleName(rule)
		if err != nil {
			return nil, err
		}
		stateData := map[string]interface{}{
			"backend":   "windows-firewall",
			"protocol":  rule.Protocol,
			"direction": rule.Direction,
			"port":      int(rule.Port),
			"rule":      name,
		}
		if err := saveSignedContainmentState(statePath, b.identityKeyFile, "firewall-port-windows", stateData); err != nil {
			return nil, fmt.Errorf("persist Windows Firewall port ownership intent: %w", err)
		}
		createdState = true
	}

	if err := b.applyPortRule(ctx, name, rule); err != nil {
		if createdState {
			_ = os.Remove(statePath)
		}
		return nil, err
	}
	return map[string]interface{}{
		"operation": "open",
		"protocol":  rule.Protocol,
		"direction": rule.Direction,
		"port":      int(rule.Port),
		"opened":    true,
		"backend":   "windows-firewall",
		"rule":      name,
		"reapplied": stateExists,
	}, nil
}

func (b *windowsNetworkBackend) ClosePort(ctx context.Context, rule PortRule) (map[string]interface{}, error) {
	statePath := b.portStatePath(rule)
	state, err := loadSignedContainmentState(statePath, b.identityKeyFile, "firewall-port-windows")
	if errors.Is(err, os.ErrNotExist) {
		return map[string]interface{}{"operation": "close", "protocol": rule.Protocol, "direction": rule.Direction, "port": int(rule.Port), "closed": true, "already_closed": true}, nil
	}
	if err != nil {
		return nil, err
	}
	name, err := validateWindowsPortState(state, rule)
	if err != nil {
		return nil, err
	}
	if _, err := b.runner.Run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name); err != nil {
		return nil, fmt.Errorf("delete Windows Firewall port rule: %w", err)
	}
	if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return map[string]interface{}{"operation": "close", "protocol": rule.Protocol, "direction": rule.Direction, "port": int(rule.Port), "closed": true, "backend": "windows-firewall", "rule": name}, nil
}

func (b *windowsNetworkBackend) applyPortRule(ctx context.Context, name string, rule PortRule) error {
	_, _ = b.runner.Run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
	portKey := "localport="
	if rule.Direction == "outbound" {
		portKey = "remoteport="
	}
	args := []string{
		"advfirewall", "firewall", "add", "rule", "name=" + name,
		"dir=" + map[string]string{"inbound": "in", "outbound": "out"}[rule.Direction],
		"action=allow", "protocol=" + rule.Protocol, portKey + strconv.Itoa(int(rule.Port)),
		"profile=any", "enable=yes",
	}
	if _, err := b.runner.Run(ctx, "netsh", args...); err != nil {
		_, _ = b.runner.Run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
		return fmt.Errorf("add Windows Firewall port rule: %w", err)
	}
	return nil
}

func portRuleKey(rule PortRule) string {
	return fmt.Sprintf("%s|%s|%d", rule.Protocol, rule.Direction, rule.Port)
}

func windowsPortRulePrefix(rule PortRule) string {
	digest := sha256.Sum256([]byte(portRuleKey(rule)))
	return "NTAgentShield-Port-" + hex.EncodeToString(digest[:6])
}

func newWindowsPortRuleName(rule PortRule) (string, error) {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate Windows Firewall port rule identity: %w", err)
	}
	return windowsPortRulePrefix(rule) + "-" + hex.EncodeToString(random), nil
}

func validateWindowsPortState(state signedContainmentState, rule PortRule) (string, error) {
	if state.Data["backend"] != "windows-firewall" || state.Data["protocol"] != rule.Protocol || state.Data["direction"] != rule.Direction {
		return "", errors.New("signed Windows Firewall port ownership state is invalid")
	}
	port, ok := state.Data["port"].(float64)
	if !ok || port != float64(rule.Port) {
		return "", errors.New("signed Windows Firewall port ownership state is invalid")
	}
	name, ok := state.Data["rule"].(string)
	if !ok || !strings.HasPrefix(name, windowsPortRulePrefix(rule)+"-") {
		return "", errors.New("signed Windows Firewall port ownership state is invalid")
	}
	return name, nil
}

func windowsBlockRulePrefix(address netip.Addr) string {
	digest := sha256.Sum256([]byte(address.String()))
	return "NTAgentShield-Block-" + hex.EncodeToString(digest[:6])
}

func newWindowsBlockRuleName(address netip.Addr) (string, error) {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate Windows Firewall rule identity: %w", err)
	}
	return windowsBlockRulePrefix(address) + "-" + hex.EncodeToString(random), nil
}

func windowsControlTargetStrings(targets []controlTarget) []string {
	items := make([]string, 0, len(targets))
	for _, target := range targets {
		items = append(items, target.String())
	}
	return items
}
