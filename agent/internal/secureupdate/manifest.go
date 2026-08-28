package secureupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	ManifestSchema   = "ntshield-update/v1"
	MaxEnvelopeBytes = 64 * 1024
	MaxArtifactBytes = int64(1024 * 1024 * 1024)
)

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type SignedEnvelope struct {
	PayloadB64   string `json:"payload_b64"`
	SignatureB64 string `json:"signature_b64"`
	KeyID        string `json:"key_id"`
}

type Manifest struct {
	Schema      string    `json:"schema"`
	Version     string    `json:"version"`
	PublishedAt time.Time `json:"published_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	ArtifactURL string    `json:"artifact_url"`
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
}

func VerifyEnvelope(
	envelopeJSON []byte,
	publicKeyPEM []byte,
	currentVersion string,
	now time.Time,
) (Manifest, error) {
	if len(envelopeJSON) == 0 || len(envelopeJSON) > MaxEnvelopeBytes {
		return Manifest{}, fmt.Errorf("signed update envelope must be between 1 and %d bytes", MaxEnvelopeBytes)
	}
	var envelope SignedEnvelope
	if err := decodeStrict(envelopeJSON, &envelope); err != nil {
		return Manifest{}, fmt.Errorf("decode signed update envelope: %w", err)
	}
	if envelope.KeyID == "" || len(envelope.KeyID) > 128 {
		return Manifest{}, errors.New("update signing key_id is invalid")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.PayloadB64)
	if err != nil || len(payload) == 0 || len(payload) > MaxEnvelopeBytes {
		return Manifest{}, errors.New("update payload encoding is invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Manifest{}, errors.New("update signature encoding is invalid")
	}
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return Manifest{}, err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return Manifest{}, errors.New("update signature verification failed")
	}
	var manifest Manifest
	if err := decodeStrict(payload, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode signed update manifest: %w", err)
	}
	if err := manifest.Validate(currentVersion, runtime.GOOS, runtime.GOARCH, now); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (manifest Manifest) Validate(
	currentVersion string,
	targetOS string,
	targetArch string,
	now time.Time,
) error {
	if manifest.Schema != ManifestSchema {
		return fmt.Errorf("unsupported update manifest schema %q", manifest.Schema)
	}
	if _, err := ParseVersion(manifest.Version); err != nil {
		return fmt.Errorf("invalid update version: %w", err)
	}
	comparison, err := CompareVersions(manifest.Version, currentVersion)
	if err != nil {
		return fmt.Errorf("compare update version: %w", err)
	}
	if comparison <= 0 {
		return fmt.Errorf("update version %s is not newer than %s", manifest.Version, currentVersion)
	}
	currentTime := now.UTC()
	if manifest.PublishedAt.IsZero() || manifest.PublishedAt.After(currentTime.Add(5*time.Minute)) {
		return errors.New("update manifest published_at is invalid")
	}
	if manifest.ExpiresAt.IsZero() || !manifest.ExpiresAt.After(currentTime) {
		return errors.New("update manifest has expired")
	}
	if manifest.ExpiresAt.Sub(manifest.PublishedAt) > 30*24*time.Hour {
		return errors.New("update manifest validity exceeds 30 days")
	}
	if manifest.OS != targetOS || manifest.Arch != targetArch {
		return fmt.Errorf(
			"update target mismatch: manifest=%s/%s runtime=%s/%s",
			manifest.OS,
			manifest.Arch,
			targetOS,
			targetArch,
		)
	}
	parsedURL, err := url.Parse(manifest.ArtifactURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil {
		return errors.New("artifact_url must be an absolute HTTPS URL without credentials")
	}
	manifest.SHA256 = strings.ToLower(manifest.SHA256)
	if !sha256Pattern.MatchString(manifest.SHA256) {
		return errors.New("update artifact sha256 is invalid")
	}
	if _, err := hex.DecodeString(manifest.SHA256); err != nil {
		return errors.New("update artifact sha256 is invalid")
	}
	if manifest.Size < 1 || manifest.Size > MaxArtifactBytes {
		return fmt.Errorf("update artifact size must be between 1 and %d bytes", MaxArtifactBytes)
	}
	return nil
}

type Version struct {
	Major int
	Minor int
	Patch int
}

func ParseVersion(value string) (Version, error) {
	normalized := strings.TrimPrefix(strings.TrimSpace(value), "v")
	if strings.ContainsAny(normalized, "+-") {
		return Version{}, errors.New("pre-release and build metadata are not accepted for Agent updates")
	}
	parts := strings.Split(normalized, ".")
	if len(parts) != 3 {
		return Version{}, errors.New("version must use major.minor.patch")
	}
	values := [3]int{}
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return Version{}, errors.New("version components must be canonical decimal integers")
		}
		parsed, err := strconv.Atoi(part)
		if err != nil || parsed < 0 || parsed > 1_000_000 {
			return Version{}, errors.New("version component is invalid")
		}
		values[index] = parsed
	}
	return Version{Major: values[0], Minor: values[1], Patch: values[2]}, nil
}

func CompareVersions(candidate string, current string) (int, error) {
	left, err := ParseVersion(candidate)
	if err != nil {
		return 0, err
	}
	right, err := ParseVersion(current)
	if err != nil {
		return 0, err
	}
	leftValues := [3]int{left.Major, left.Minor, left.Patch}
	rightValues := [3]int{right.Major, right.Minor, right.Patch}
	for index := range leftValues {
		if leftValues[index] > rightValues[index] {
			return 1, nil
		}
		if leftValues[index] < rightValues[index] {
			return -1, nil
		}
	}
	return 0, nil
}

func parsePublicKey(content []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(content)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("update public key must contain one PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse update public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("update public key must use Ed25519")
	}
	return publicKey, nil
}

func decodeStrict(content []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("unexpected trailing JSON content")
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("unexpected trailing JSON value")
	}
	return nil
}
