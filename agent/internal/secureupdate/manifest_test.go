package secureupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"runtime"
	"testing"
	"time"
)

func TestVerifyEnvelopeBindsVersionTargetHashAndExpiry(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	manifest := Manifest{
		Schema:      ManifestSchema,
		Version:     "1.2.0",
		PublishedAt: now.Add(-time.Minute),
		ExpiresAt:   now.Add(24 * time.Hour),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		ArtifactURL: "https://updates.example.test/ntagentshield-agent.exe",
		SHA256:      "a3b2a536e7f40f4c65f09f27ea0cf7e81b9b624c41fbfe5c0a62a354caefb9f0",
		Size:        1024,
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(SignedEnvelope{
		PayloadB64:   base64.StdEncoding.EncodeToString(payload),
		SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
		KeyID:        "release-2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	verified, err := VerifyEnvelope(envelope, publicPEM, "1.1.9", now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Version != "1.2.0" {
		t.Fatalf("unexpected version %q", verified.Version)
	}

	envelope[len(envelope)-2] ^= 1
	if _, err := VerifyEnvelope(envelope, publicPEM, "1.1.9", now); err == nil {
		t.Fatal("tampered envelope was accepted")
	}
}

func TestCompareVersionsRejectsRollbackAndNonCanonicalVersions(t *testing.T) {
	comparison, err := CompareVersions("2.0.0", "1.9.9")
	if err != nil || comparison != 1 {
		t.Fatalf("unexpected comparison=%d err=%v", comparison, err)
	}
	if _, err := CompareVersions("1.0.0", "dev"); err == nil {
		t.Fatal("development version should fail closed")
	}
	if _, err := ParseVersion("1.01.0"); err == nil {
		t.Fatal("non-canonical version should be rejected")
	}
}
