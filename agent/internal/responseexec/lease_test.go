package responseexec

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
)

func TestVerifyLeaseBindsApprovalAndRejectsWrongScope(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustPath := writeResponseTrustRoot(t, publicKey)
	now := time.Now().UTC()
	lease := Lease{
		Schema:          responseSchema,
		ActionID:        "rsp-1",
		TenantID:        "tenant-a",
		AgentID:         "agent-a",
		Tool:            "process.terminate",
		Args:            map[string]interface{}{"pid": 4242},
		Reason:          "contain confirmed malicious process",
		Risk:            model.RiskContain,
		RequestedBy:     "soc-proposer",
		RequestedAt:     now.Add(-2 * time.Minute),
		ApprovedBy:      "soc-approver",
		ApprovedAt:      now.Add(-time.Minute),
		ActionExpiresAt: now.Add(4 * time.Minute),
		LeaseIssuedAt:   now.Add(-time.Second),
		LeaseExpiresAt:  now.Add(time.Minute),
	}
	bundle := signLease(t, privateKey, lease)
	verified, err := VerifyLease(bundle, trustPath, "tenant-a", "agent-a", now)
	if err != nil {
		t.Fatal(err)
	}
	request, digest, err := verified.ActionRequest()
	if err != nil {
		t.Fatal(err)
	}
	if digest == "" || request.Approval == nil || request.Approval.ActionDigest != digest {
		t.Fatalf("approval was not bound to exact local action: %+v", request.Approval)
	}
	if request.TriggerTrust != model.TrustOperator || request.Mode != model.ModeAct {
		t.Fatalf("unexpected response action trust/mode: %+v", request)
	}
	if _, err := VerifyLease(bundle, trustPath, "tenant-b", "agent-a", now); err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("expected tenant scope rejection, got %v", err)
	}
}

func TestVerifyLeaseRejectsBadSignerExpiryAndUnknownFields(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	trustPath := writeResponseTrustRoot(t, publicKey)
	now := time.Now().UTC()
	lease := Lease{
		Schema:          responseSchema,
		ActionID:        "rsp-2",
		TenantID:        "tenant-a",
		AgentID:         "agent-a",
		Tool:            "process.terminate",
		Args:            map[string]interface{}{"pid": 5000},
		Reason:          "test",
		Risk:            model.RiskContain,
		RequestedBy:     "requester",
		RequestedAt:     now.Add(-2 * time.Minute),
		ApprovedBy:      "approver",
		ApprovedAt:      now.Add(-time.Minute),
		ActionExpiresAt: now.Add(2 * time.Minute),
		LeaseIssuedAt:   now.Add(-time.Minute),
		LeaseExpiresAt:  now.Add(time.Minute),
	}
	if _, err := VerifyLease(signLease(t, attacker, lease), trustPath, "tenant-a", "agent-a", now); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signer rejection, got %v", err)
	}
	lease.LeaseExpiresAt = now.Add(-time.Second)
	if _, err := VerifyLease(signLease(t, privateKey, lease), trustPath, "tenant-a", "agent-a", now); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry rejection, got %v", err)
	}

	payload := []byte(`{"schema":"ntshield-response/v1","action_id":"rsp-x","tenant_id":"tenant-a","agent_id":"agent-a","tool":"process.terminate","args":{"pid":5000},"reason":"x","risk":"contain","requested_by":"a","requested_at":"2026-08-07T00:00:00Z","approved_by":"b","approved_at":"2026-08-07T00:00:01Z","action_expires_at":"2026-08-08T00:00:00Z","lease_issued_at":"2026-08-07T00:00:02Z","lease_expires_at":"2026-08-08T00:00:00Z","unexpected":true}`)
	sum := sha256.Sum256(payload)
	unknown := SignedLease{
		PayloadB64:   base64.StdEncoding.EncodeToString(payload),
		SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
		SHA256:       hex.EncodeToString(sum[:]),
	}
	if _, err := VerifyLease(unknown, trustPath, "tenant-a", "agent-a", now); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected strict JSON rejection, got %v", err)
	}
}

func writeResponseTrustRoot(t *testing.T, publicKey ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "response-signing.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func signLease(t *testing.T, privateKey ed25519.PrivateKey, lease Lease) SignedLease {
	t.Helper()
	payload, err := json.Marshal(lease)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	return SignedLease{
		PayloadB64:   base64.StdEncoding.EncodeToString(payload),
		SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
		SHA256:       hex.EncodeToString(sum[:]),
	}
}
