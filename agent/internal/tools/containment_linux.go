//go:build linux

package tools

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const linuxIsolationTable = "ntshield_isolation"
const linuxBlockTable = "ntshield_block"

type linuxNetworkBackend struct {
	runner          commandRunner
	dataDir         string
	identityKeyFile string
	controlEndpoint string
}

func newNetworkContainmentBackend(options ContainmentOptions) (networkContainmentBackend, error) {
	if options.DataDir == "" || options.IdentityKeyFile == "" || options.ControlEndpoint == "" {
		return nil, errors.New("network containment requires data directory, Agent identity key, and Control Plane endpoint")
	}
	return &linuxNetworkBackend{runner: osCommandRunner{}, dataDir: options.DataDir, identityKeyFile: options.IdentityKeyFile, controlEndpoint: options.ControlEndpoint}, nil
}

func (b *linuxNetworkBackend) isolationStatePath() string {
	return filepath.Join(b.dataDir, "containment", "host-isolation.json")
}

func (b *linuxNetworkBackend) blockStatePath() string {
	return filepath.Join(b.dataDir, "containment", "firewall-block-linux.json")
}

func (b *linuxNetworkBackend) Isolate(ctx context.Context) (map[string]interface{}, error) {
	if _, err := b.runner.Run(ctx, "nft", "--version"); err != nil {
		return nil, errors.New("nftables is required for Linux host isolation")
	}
	state, stateErr := loadSignedContainmentState(b.isolationStatePath(), b.identityKeyFile, "host-isolation-linux-nft")
	stateExists := stateErr == nil
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return nil, stateErr
	}
	_, tableErr := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxIsolationTable)
	tableExists := tableErr == nil
	if tableExists && !stateExists {
		return nil, errors.New("nftables isolation table exists without signed NTAgentShield state")
	}
	if stateExists {
		if state.Data["table"] != linuxIsolationTable || state.Data["backend"] != "nftables" {
			return nil, errors.New("signed Linux isolation ownership state is invalid")
		}
		if tableExists {
			return map[string]interface{}{"isolated": true, "already_isolated": true, "state": state.Data}, nil
		}
	}

	targets, err := resolveControlTargets(ctx, b.controlEndpoint)
	if err != nil {
		return nil, err
	}
	if !stateExists {
		stateData := map[string]interface{}{"backend": "nftables", "table": linuxIsolationTable, "control_targets": controlTargetStrings(targets), "dns_allowed": true}
		if err := saveSignedContainmentState(b.isolationStatePath(), b.identityKeyFile, "host-isolation-linux-nft", stateData); err != nil {
			return nil, fmt.Errorf("persist host isolation intent: %w", err)
		}
	}
	if err := b.applyIsolationTable(ctx, targets); err != nil {
		if !stateExists {
			_ = os.Remove(b.isolationStatePath())
		}
		return nil, err
	}
	return map[string]interface{}{"isolated": true, "backend": "nftables", "control_targets": controlTargetStrings(targets), "recovered": stateExists}, nil
}

func (b *linuxNetworkBackend) applyIsolationTable(ctx context.Context, targets []controlTarget) error {
	if _, err := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxIsolationTable); err == nil {
		return nil
	}
	script := linuxIsolationScript(targets)
	if _, err := b.runner.RunInput(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("install nftables host isolation: %w", err)
	}
	return nil
}

func (b *linuxNetworkBackend) Release(ctx context.Context) (map[string]interface{}, error) {
	state, err := loadSignedContainmentState(b.isolationStatePath(), b.identityKeyFile, "host-isolation-linux-nft")
	if errors.Is(err, os.ErrNotExist) {
		if _, listErr := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxIsolationTable); listErr == nil {
			return nil, errors.New("nftables isolation table exists without signed state; refusing blind deletion")
		}
		return map[string]interface{}{"released": true, "already_released": true}, nil
	}
	if err != nil {
		return nil, err
	}
	if state.Data["table"] != linuxIsolationTable || state.Data["backend"] != "nftables" {
		return nil, errors.New("signed Linux isolation ownership state is invalid")
	}
	if _, listErr := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxIsolationTable); listErr != nil {
		if err := os.Remove(b.isolationStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return map[string]interface{}{"released": true, "already_released": true, "recovered_stale_state": true}, nil
	}
	if _, err := b.runner.Run(ctx, "nft", "delete", "table", "inet", linuxIsolationTable); err != nil {
		return nil, fmt.Errorf("delete nftables isolation table: %w", err)
	}
	if err := os.Remove(b.isolationStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove isolation state: %w", err)
	}
	return map[string]interface{}{"released": true, "backend": state.Data["backend"]}, nil
}

func (b *linuxNetworkBackend) Block(ctx context.Context, address netip.Addr) (map[string]interface{}, error) {
	if _, err := b.runner.Run(ctx, "nft", "--version"); err != nil {
		return nil, errors.New("nftables is required for Linux firewall containment")
	}
	if _, err := b.ensureBlockTable(ctx, true); err != nil {
		return nil, err
	}
	familySet := "blocked4"
	if address.Is6() {
		familySet = "blocked6"
	}
	_, _ = b.runner.Run(ctx, "nft", "delete", "element", "inet", linuxBlockTable, familySet, "{", address.String(), "}")
	if _, err := b.runner.Run(ctx, "nft", "add", "element", "inet", linuxBlockTable, familySet, "{", address.String(), "}"); err != nil {
		return nil, fmt.Errorf("add nftables blocked IP: %w", err)
	}
	return map[string]interface{}{"remote_ip": address.String(), "blocked": true, "backend": "nftables"}, nil
}

func (b *linuxNetworkBackend) Unblock(ctx context.Context, address netip.Addr) (map[string]interface{}, error) {
	owned, err := b.ensureBlockTable(ctx, false)
	if err != nil {
		return nil, err
	}
	if !owned {
		return map[string]interface{}{"remote_ip": address.String(), "unblocked": true, "already_unblocked": true}, nil
	}
	familySet := "blocked4"
	if address.Is6() {
		familySet = "blocked6"
	}
	if _, err := b.runner.Run(ctx, "nft", "delete", "element", "inet", linuxBlockTable, familySet, "{", address.String(), "}"); err != nil {
		return nil, fmt.Errorf("delete nftables blocked IP: %w", err)
	}
	return map[string]interface{}{"remote_ip": address.String(), "unblocked": true, "backend": "nftables"}, nil
}

func (b *linuxNetworkBackend) ensureBlockTable(ctx context.Context, create bool) (bool, error) {
	state, stateErr := loadSignedContainmentState(b.blockStatePath(), b.identityKeyFile, "firewall-block-linux-nft")
	stateExists := stateErr == nil
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return false, stateErr
	}
	if stateExists && (state.Data["table"] != linuxBlockTable || state.Data["backend"] != "nftables") {
		return false, errors.New("signed nftables block-table ownership state is invalid")
	}
	_, tableErr := b.runner.Run(ctx, "nft", "list", "table", "inet", linuxBlockTable)
	tableExists := tableErr == nil

	if tableExists && !stateExists {
		return false, errors.New("nftables block table exists without signed NTAgentShield ownership state")
	}
	if stateExists && tableExists {
		return true, nil
	}
	if stateExists && !tableExists && !create {
		if err := os.Remove(b.blockStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		return false, nil
	}
	if !stateExists && !create {
		return false, nil
	}

	createdState := false
	if !stateExists {
		stateData := map[string]interface{}{"backend": "nftables", "table": linuxBlockTable}
		if err := saveSignedContainmentState(b.blockStatePath(), b.identityKeyFile, "firewall-block-linux-nft", stateData); err != nil {
			return false, fmt.Errorf("persist nftables block-table ownership intent: %w", err)
		}
		createdState = true
	}
	if err := b.createBlockTable(ctx); err != nil {
		if createdState {
			_ = os.Remove(b.blockStatePath())
		}
		return false, err
	}
	return true, nil
}

func (b *linuxNetworkBackend) createBlockTable(ctx context.Context) error {
	script := `table inet ntshield_block {
    set blocked4 { type ipv4_addr; }
    set blocked6 { type ipv6_addr; }
    chain input {
        type filter hook input priority -250; policy accept;
        ip saddr @blocked4 drop
        ip6 saddr @blocked6 drop
    }
    chain output {
        type filter hook output priority -250; policy accept;
        ip daddr @blocked4 drop
        ip6 daddr @blocked6 drop
    }
}
`
	if _, err := b.runner.RunInput(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("create NTAgentShield nftables block table: %w", err)
	}
	return nil
}

func linuxIsolationScript(targets []controlTarget) string {
	var outputRules strings.Builder
	for _, target := range targets {
		port := strconv.Itoa(int(target.Port))
		if target.IP.Is4() {
			fmt.Fprintf(&outputRules, "        ip daddr %s tcp dport %s accept\n", target.IP.String(), port)
		} else {
			fmt.Fprintf(&outputRules, "        ip6 daddr %s tcp dport %s accept\n", target.IP.String(), port)
		}
	}
	return fmt.Sprintf(`table inet ntshield_isolation {
    chain input {
        type filter hook input priority -300; policy drop;
        iifname "lo" accept
        ct state established,related accept
        udp sport 67 udp dport 68 accept
    }
    chain output {
        type filter hook output priority -300; policy drop;
        oifname "lo" accept
        ct state established,related accept
%s        udp dport 53 accept
        tcp dport 53 accept
        udp sport 68 udp dport 67 accept
    }
}
`, outputRules.String())
}

func controlTargetStrings(targets []controlTarget) []string {
	items := make([]string, 0, len(targets))
	for _, target := range targets {
		items = append(items, target.String())
	}
	return items
}
