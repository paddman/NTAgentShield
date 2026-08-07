package policyupdate

import (
	"bytes"
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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/identity"
	"github.com/paddman/NTAgentShield/internal/policy"
)

const policySchema = "ntshield-policy/v1"

type Bundle struct {
	PayloadB64   string `json:"payload_b64"`
	SignatureB64 string `json:"signature_b64"`
	SHA256       string `json:"sha256"`
}

type Payload struct {
	Schema    string          `json:"schema"`
	Epoch     uint64          `json:"epoch"`
	Version   string          `json:"version"`
	TenantID  string          `json:"tenant_id"`
	AgentIDs  []string        `json:"agent_ids"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Policy    json.RawMessage `json:"policy"`
}

type State struct {
	Epoch           uint64    `json:"epoch"`
	Version         string    `json:"version"`
	BundleDigest    string    `json:"bundle_digest"`
	PolicyDigest    string    `json:"policy_digest"`
	BundleExpiresAt time.Time `json:"bundle_expires_at"`
	AppliedAt       time.Time `json:"applied_at"`
	Signature       string    `json:"signature"`
}

type ApplyResult struct {
	Applied bool           `json:"applied"`
	Epoch   uint64         `json:"epoch"`
	Version string         `json:"version"`
	Digest  string         `json:"digest"`
	Policy  *policy.Policy `json:"-"`
}

type ManagerOptions struct {
	AgentID         string
	TenantID        string
	PolicyFile      string
	TrustRootFile   string
	IdentityKeyFile string
	StateFile       string
}

type Manager struct {
	options     ManagerOptions
	trustRoot   ed25519.PublicKey
	identityKey ed25519.PrivateKey
	state       State
}

func NewManager(options ManagerOptions) (*Manager, error) {
	if strings.TrimSpace(options.AgentID) == "" || strings.TrimSpace(options.TenantID) == "" {
		return nil, errors.New("policy updater requires agent_id and tenant_id")
	}
	if options.PolicyFile == "" || options.TrustRootFile == "" || options.IdentityKeyFile == "" || options.StateFile == "" {
		return nil, errors.New("policy updater requires policy, trust root, identity key, and state files")
	}
	trustRoot, err := loadTrustRoot(options.TrustRootFile)
	if err != nil {
		return nil, err
	}
	identityKey, err := identity.Load(options.IdentityKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load policy state signing identity: %w", err)
	}
	manager := &Manager{options: options, trustRoot: trustRoot, identityKey: identityKey}
	if err := manager.loadState(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *Manager) Apply(bundle Bundle) (ApplyResult, error) {
	payloadBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bundle.PayloadB64))
	if err != nil {
		return ApplyResult{}, errors.New("decode signed policy payload")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bundle.SignatureB64))
	if err != nil {
		return ApplyResult{}, errors.New("decode signed policy signature")
	}
	digest := sha256.Sum256(payloadBytes)
	digestHex := hex.EncodeToString(digest[:])
	if !strings.EqualFold(digestHex, strings.TrimSpace(bundle.SHA256)) {
		return ApplyResult{}, errors.New("signed policy bundle digest mismatch")
	}
	if !ed25519.Verify(m.trustRoot, payloadBytes, signature) {
		return ApplyResult{}, errors.New("signed policy bundle signature verification failed")
	}

	var payload Payload
	if err := decodeJSONStrict(payloadBytes, &payload); err != nil {
		return ApplyResult{}, fmt.Errorf("decode signed policy payload: %w", err)
	}
	if err := m.validatePayload(payload); err != nil {
		return ApplyResult{}, err
	}

	active := policy.Default()
	if err := decodeJSONStrict(payload.Policy, &active); err != nil {
		return ApplyResult{}, fmt.Errorf("decode policy document: %w", err)
	}
	if strings.TrimSpace(active.Version) == "" {
		return ApplyResult{}, errors.New("policy document version is required")
	}
	if active.Version != payload.Version {
		return ApplyResult{}, errors.New("policy document version does not match signed envelope")
	}
	if active.MaxActionTTLSeconds <= 0 || active.MaxActionTTLSeconds > 86400 {
		return ApplyResult{}, errors.New("policy max_action_ttl_seconds must be between 1 and 86400")
	}

	if payload.Epoch < m.state.Epoch {
		return ApplyResult{}, fmt.Errorf("policy rollback rejected: epoch %d is below applied epoch %d", payload.Epoch, m.state.Epoch)
	}
	if payload.Epoch == m.state.Epoch {
		if strings.EqualFold(digestHex, m.state.BundleDigest) {
			return ApplyResult{Epoch: payload.Epoch, Version: payload.Version, Digest: digestHex, Policy: &active}, nil
		}
		return ApplyResult{}, errors.New("policy epoch conflict: same epoch has a different digest")
	}

	policyBytes, err := json.MarshalIndent(active, "", "  ")
	if err != nil {
		return ApplyResult{}, fmt.Errorf("encode active policy: %w", err)
	}
	policyBytes = append(policyBytes, '\n')
	policyDigest := sha256.Sum256(policyBytes)
	policyDigestHex := hex.EncodeToString(policyDigest[:])

	previousPolicy, previousExists, err := readOptionalFile(m.options.PolicyFile)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("read last-known-good policy: %w", err)
	}
	if err := replaceFile(m.options.PolicyFile, policyBytes, 0o600); err != nil {
		return ApplyResult{}, fmt.Errorf("install signed policy: %w", err)
	}
	state := State{
		Epoch:           payload.Epoch,
		Version:         payload.Version,
		BundleDigest:    digestHex,
		PolicyDigest:    policyDigestHex,
		BundleExpiresAt: payload.ExpiresAt.UTC(),
		AppliedAt:       time.Now().UTC(),
	}
	if err := m.saveState(state); err != nil {
		if restoreErr := restoreOptionalFile(m.options.PolicyFile, previousPolicy, previousExists, 0o600); restoreErr != nil {
			return ApplyResult{}, fmt.Errorf("persist signed policy rollback state: %v; restore last-known-good policy: %w", err, restoreErr)
		}
		return ApplyResult{}, err
	}
	m.state = state
	return ApplyResult{Applied: true, Epoch: payload.Epoch, Version: payload.Version, Digest: digestHex, Policy: &active}, nil
}

func (m *Manager) validatePayload(payload Payload) error {
	now := time.Now().UTC()
	if payload.Schema != policySchema {
		return errors.New("unsupported signed policy schema")
	}
	if payload.Epoch < 1 {
		return errors.New("signed policy epoch must be at least 1")
	}
	if strings.TrimSpace(payload.Version) == "" {
		return errors.New("signed policy version is required")
	}
	if payload.TenantID != m.options.TenantID {
		return errors.New("signed policy tenant does not match Agent tenant")
	}
	if !slices.Contains(payload.AgentIDs, "*") && !slices.Contains(payload.AgentIDs, m.options.AgentID) {
		return errors.New("signed policy scope does not include this Agent")
	}
	if payload.IssuedAt.IsZero() || payload.ExpiresAt.IsZero() {
		return errors.New("signed policy validity window is required")
	}
	if payload.IssuedAt.After(now.Add(5 * time.Minute)) {
		return errors.New("signed policy issued_at is too far in the future")
	}
	if !payload.ExpiresAt.After(now) || !payload.ExpiresAt.After(payload.IssuedAt) {
		return errors.New("signed policy bundle is expired or has an invalid validity window")
	}
	return nil
}

func (m *Manager) loadState() error {
	content, err := os.ReadFile(m.options.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read signed policy state: %w", err)
	}
	var state State
	if err := decodeJSONStrict(content, &state); err != nil {
		return fmt.Errorf("decode signed policy state: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(state.Signature)
	if err != nil {
		return errors.New("decode signed policy state signature")
	}
	state.Signature = ""
	unsigned, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if !ed25519.Verify(m.identityKey.Public().(ed25519.PublicKey), unsigned, signature) {
		return errors.New("signed policy rollback state verification failed")
	}
	if state.Epoch > 0 {
		policyBytes, err := os.ReadFile(m.options.PolicyFile)
		if err != nil {
			return fmt.Errorf("read policy protected by rollback state: %w", err)
		}
		digest := sha256.Sum256(policyBytes)
		if !strings.EqualFold(hex.EncodeToString(digest[:]), state.PolicyDigest) {
			return errors.New("active policy does not match signed rollback state")
		}
	}
	m.state = state
	return nil
}

func (m *Manager) saveState(state State) error {
	state.Signature = ""
	unsigned, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode policy rollback state: %w", err)
	}
	state.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(m.identityKey, unsigned))
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode signed policy rollback state: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := replaceFile(m.options.StateFile, encoded, 0o600); err != nil {
		return fmt.Errorf("persist signed policy rollback state: %w", err)
	}
	return nil
}

func decodeJSONStrict(content []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON content")
		}
		return err
	}
	return nil
}

func loadTrustRoot(path string) (ed25519.PublicKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy signing trust root: %w", err)
	}
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("policy signing trust root is not a public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse policy signing trust root: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("policy signing trust root must use Ed25519")
	}
	return publicKey, nil
}

func readOptionalFile(path string) ([]byte, bool, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return content, true, nil
}

func restoreOptionalFile(path string, content []byte, existed bool, mode os.FileMode) error {
	if existed {
		return replaceFile(path, content, mode)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func replaceFile(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".new"
	backup := path + ".bak"
	if err := os.WriteFile(temporary, content, mode); err != nil {
		return err
	}
	_ = os.Chmod(temporary, mode)
	_ = os.Remove(backup)
	hadExisting := false
	if _, err := os.Stat(path); err == nil {
		hadExisting = true
		if err := os.Rename(path, backup); err != nil {
			_ = os.Remove(temporary)
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		if hadExisting {
			_ = os.Rename(backup, path)
		}
		_ = os.Remove(temporary)
		return err
	}
	if hadExisting {
		_ = os.Remove(backup)
	}
	return os.Chmod(path, mode)
}
