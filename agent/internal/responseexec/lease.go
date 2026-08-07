package responseexec

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
	"os"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
	"github.com/paddman/NTAgentShield/internal/policy"
)

const responseSchema = "ntshield-response/v1"

type SignedLease struct {
	PayloadB64   string `json:"payload_b64"`
	SignatureB64 string `json:"signature_b64"`
	SHA256       string `json:"sha256"`
}

type Lease struct {
	Schema          string                 `json:"schema"`
	ActionID        string                 `json:"action_id"`
	TenantID        string                 `json:"tenant_id"`
	AgentID         string                 `json:"agent_id"`
	IncidentID      string                 `json:"incident_id,omitempty"`
	Tool            string                 `json:"tool"`
	Args            map[string]interface{} `json:"args"`
	Reason          string                 `json:"reason"`
	Risk            model.ActionRisk       `json:"risk"`
	RequestedBy     string                 `json:"requested_by"`
	RequestedAt     time.Time              `json:"requested_at"`
	ApprovedBy      string                 `json:"approved_by"`
	ApprovedAt      time.Time              `json:"approved_at"`
	ActionExpiresAt time.Time              `json:"action_expires_at"`
	LeaseIssuedAt   time.Time              `json:"lease_issued_at"`
	LeaseExpiresAt  time.Time              `json:"lease_expires_at"`
}

func VerifyLease(bundle SignedLease, trustRootFile, tenantID, agentID string, now time.Time) (Lease, error) {
	payloadBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bundle.PayloadB64))
	if err != nil {
		return Lease{}, errors.New("decode response lease payload")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bundle.SignatureB64))
	if err != nil {
		return Lease{}, errors.New("decode response lease signature")
	}
	digest := sha256.Sum256(payloadBytes)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), strings.TrimSpace(bundle.SHA256)) {
		return Lease{}, errors.New("response lease digest mismatch")
	}
	trustRoot, err := loadResponseTrustRoot(trustRootFile)
	if err != nil {
		return Lease{}, err
	}
	if !ed25519.Verify(trustRoot, payloadBytes, signature) {
		return Lease{}, errors.New("response lease signature verification failed")
	}
	var lease Lease
	if err := decodeStrict(payloadBytes, &lease); err != nil {
		return Lease{}, fmt.Errorf("decode response lease: %w", err)
	}
	if lease.Schema != responseSchema {
		return Lease{}, errors.New("unsupported response lease schema")
	}
	if strings.TrimSpace(lease.ActionID) == "" || strings.TrimSpace(lease.Tool) == "" {
		return Lease{}, errors.New("response lease action_id and tool are required")
	}
	if lease.TenantID != tenantID || lease.AgentID != agentID {
		return Lease{}, errors.New("response lease scope does not match this Agent/Tenant")
	}
	if lease.Risk != model.RiskContain && lease.Risk != model.RiskModify {
		return Lease{}, errors.New("response lease risk is not a state-changing approved risk")
	}
	if strings.TrimSpace(lease.RequestedBy) == "" || strings.TrimSpace(lease.ApprovedBy) == "" {
		return Lease{}, errors.New("response lease operator approval metadata is incomplete")
	}
	if lease.RequestedAt.IsZero() || lease.ApprovedAt.IsZero() || lease.ActionExpiresAt.IsZero() || lease.LeaseIssuedAt.IsZero() || lease.LeaseExpiresAt.IsZero() {
		return Lease{}, errors.New("response lease time bounds are incomplete")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	if lease.LeaseIssuedAt.After(now.Add(5 * time.Minute)) {
		return Lease{}, errors.New("response lease issued_at is too far in the future")
	}
	if !lease.LeaseExpiresAt.After(now) || !lease.ActionExpiresAt.After(now) {
		return Lease{}, errors.New("response lease or action has expired")
	}
	if lease.LeaseExpiresAt.After(lease.ActionExpiresAt) || lease.ApprovedAt.Before(lease.RequestedAt) {
		return Lease{}, errors.New("response lease has an invalid approval or expiry ordering")
	}
	if lease.Args == nil {
		lease.Args = map[string]interface{}{}
	}
	return lease, nil
}

func (l Lease) ActionRequest() (model.ActionRequest, string, error) {
	request := model.ActionRequest{
		ID:           l.ActionID,
		Tool:         l.Tool,
		Args:         l.Args,
		Reason:       l.Reason,
		Risk:         l.Risk,
		Mode:         model.ModeAct,
		TriggerTrust: model.TrustOperator,
		RequestedBy:  l.RequestedBy,
		RequestedAt:  l.RequestedAt.UTC(),
		ExpiresAt:    l.ActionExpiresAt.UTC(),
	}
	digest, err := policy.ActionDigest(request)
	if err != nil {
		return model.ActionRequest{}, "", fmt.Errorf("calculate response action digest: %w", err)
	}
	request.Approval = &model.Approval{
		ID:           "broker:" + l.ActionID,
		ActionDigest: digest,
		ApprovedBy:   l.ApprovedBy,
		ApprovedAt:   l.ApprovedAt.UTC(),
		ExpiresAt:    l.LeaseExpiresAt.UTC(),
	}
	return request, digest, nil
}

func loadResponseTrustRoot(path string) (ed25519.PublicKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read response signing trust root: %w", err)
	}
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("response signing trust root is not a public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse response signing trust root: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("response signing trust root must use Ed25519")
	}
	return publicKey, nil
}

func decodeStrict(content []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("unexpected trailing JSON content")
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("unexpected trailing JSON value")
	}
	return nil
}
