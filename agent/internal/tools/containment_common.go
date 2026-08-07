package tools

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/identity"
	"github.com/paddman/NTAgentShield/internal/model"
)

const containmentStateSchema = "ntagentshield-containment-state/v1"

type ContainmentOptions struct {
	DataDir         string
	IdentityKeyFile string
	ControlEndpoint string
	AllowedPaths    []string
}

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
	RunInput(context.Context, string, string, ...string) ([]byte, error)
}

type osCommandRunner struct{}

func (osCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (osCommandRunner) RunInput(ctx context.Context, input, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = strings.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

type controlTarget struct {
	IP   netip.Addr `json:"-"`
	Port uint16     `json:"port"`
}

func (t controlTarget) String() string {
	return net.JoinHostPort(t.IP.String(), strconv.Itoa(int(t.Port)))
}

func resolveControlTargets(ctx context.Context, endpoint string) ([]controlTarget, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return nil, fmt.Errorf("parse control endpoint: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, errors.New("host isolation requires an https control endpoint")
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, errors.New("control endpoint hostname is required")
	}
	port := uint16(443)
	if text := parsed.Port(); text != "" {
		value, err := strconv.ParseUint(text, 10, 16)
		if err != nil || value == 0 {
			return nil, errors.New("control endpoint port is invalid")
		}
		port = uint16(value)
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return []controlTarget{{IP: address.Unmap(), Port: port}}, nil
	}
	resolver := net.Resolver{}
	addresses, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve control endpoint %q before isolation: %w", host, err)
	}
	seen := map[string]bool{}
	targets := make([]controlTarget, 0, len(addresses))
	for _, item := range addresses {
		address, ok := netip.AddrFromSlice(item.IP)
		if !ok {
			continue
		}
		address = address.Unmap()
		key := address.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, controlTarget{IP: address, Port: port})
	}
	if len(targets) == 0 {
		return nil, errors.New("control endpoint resolved to no usable IP addresses")
	}
	return targets, nil
}

func normalizeRemoteIP(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, errors.New("remote_ip must be one exact IPv4 or IPv6 address")
	}
	address = address.Unmap()
	if address.IsUnspecified() || address.IsMulticast() {
		return netip.Addr{}, errors.New("remote_ip cannot be unspecified or multicast")
	}
	return address, nil
}

type networkContainmentBackend interface {
	Isolate(context.Context) (map[string]interface{}, error)
	Release(context.Context) (map[string]interface{}, error)
	Block(context.Context, netip.Addr) (map[string]interface{}, error)
	Unblock(context.Context, netip.Addr) (map[string]interface{}, error)
}

type HostIsolate struct{ backend networkContainmentBackend }
type HostRelease struct{ backend networkContainmentBackend }
type FirewallBlock struct{ backend networkContainmentBackend }
type FirewallUnblock struct{ backend networkContainmentBackend }

func (HostIsolate) Spec() Spec {
	return Spec{Name: "host.isolate", Description: "Isolate host network while preserving the authenticated Control Plane path", Risk: model.RiskContain}
}
func (HostRelease) Spec() Spec {
	return Spec{Name: "host.release", Description: "Release NTAgentShield host network isolation and restore the prior firewall state", Risk: model.RiskContain}
}
func (FirewallBlock) Spec() Spec {
	return Spec{Name: "firewall.block", Description: "Block one exact remote IP bidirectionally using the platform firewall", Risk: model.RiskContain}
}
func (FirewallUnblock) Spec() Spec {
	return Spec{Name: "firewall.unblock", Description: "Remove the NTAgentShield block for one exact remote IP", Risk: model.RiskContain}
}

func (t HostIsolate) Execute(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	return t.backend.Isolate(ctx)
}
func (t HostRelease) Execute(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	return t.backend.Release(ctx)
}
func (t FirewallBlock) Execute(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	text, err := stringArg(args, "remote_ip")
	if err != nil {
		return nil, err
	}
	address, err := normalizeRemoteIP(text)
	if err != nil {
		return nil, err
	}
	return t.backend.Block(ctx, address)
}
func (t FirewallUnblock) Execute(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	text, err := stringArg(args, "remote_ip")
	if err != nil {
		return nil, err
	}
	address, err := normalizeRemoteIP(text)
	if err != nil {
		return nil, err
	}
	return t.backend.Unblock(ctx, address)
}

type signedContainmentState struct {
	Schema    string                 `json:"schema"`
	Kind      string                 `json:"kind"`
	CreatedAt time.Time              `json:"created_at"`
	Data      map[string]interface{} `json:"data"`
	Signature string                 `json:"signature"`
}

func saveSignedContainmentState(path, identityKeyFile, kind string, data map[string]interface{}) error {
	privateKey, err := identity.Load(identityKeyFile)
	if err != nil {
		return fmt.Errorf("load Agent identity for containment state: %w", err)
	}
	state := signedContainmentState{Schema: containmentStateSchema, Kind: kind, CreatedAt: time.Now().UTC(), Data: data}
	unsigned, err := containmentStateBytes(state)
	if err != nil {
		return err
	}
	state.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writePrivateFile(path, encoded)
}

func loadSignedContainmentState(path, identityKeyFile, expectedKind string) (signedContainmentState, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return signedContainmentState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var state signedContainmentState
	if err := decoder.Decode(&state); err != nil {
		return signedContainmentState{}, fmt.Errorf("decode containment state: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return signedContainmentState{}, errors.New("containment state contains trailing JSON")
		}
		return signedContainmentState{}, fmt.Errorf("decode trailing containment state data: %w", err)
	}
	if state.Schema != containmentStateSchema || state.Kind != expectedKind {
		return signedContainmentState{}, errors.New("containment state schema/kind mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(state.Signature)
	if err != nil {
		return signedContainmentState{}, errors.New("decode containment state signature")
	}
	privateKey, err := identity.Load(identityKeyFile)
	if err != nil {
		return signedContainmentState{}, fmt.Errorf("load Agent identity for containment state: %w", err)
	}
	unsigned, err := containmentStateBytes(state)
	if err != nil {
		return signedContainmentState{}, err
	}
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), unsigned, signature) {
		return signedContainmentState{}, errors.New("containment state signature verification failed")
	}
	return state, nil
}

func containmentStateBytes(state signedContainmentState) ([]byte, error) {
	state.Signature = ""
	return json.Marshal(state)
}

func writePrivateFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(temporary, 0o600)
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return os.Chmod(path, 0o600)
}

func sha256File(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func publicKeyFromPEM(content []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("public key PEM is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key must use Ed25519")
	}
	return key, nil
}
