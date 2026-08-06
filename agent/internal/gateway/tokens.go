package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
)

const (
	tokenStoreVersion = 1
	maxTokenStoreBytes = 16 * 1024 * 1024
	maxTokenEntries = 10000
)

type TokenEntry struct {
	ID                    string     `json:"id"`
	TokenSHA256           string     `json:"token_sha256"`
	TenantID              string     `json:"tenant_id"`
	AllowedAgentID        string     `json:"allowed_agent_id,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	ExpiresAt             time.Time  `json:"expires_at"`
	ConsumedAt            *time.Time `json:"consumed_at,omitempty"`
	IssuedAgentID         string     `json:"issued_agent_id,omitempty"`
	IssuedPublicKeySHA256 string     `json:"issued_public_key_sha256,omitempty"`
	IssuedCertificatePEM  string     `json:"issued_certificate_pem,omitempty"`
	IssuedCertificateSerial string   `json:"issued_certificate_serial,omitempty"`
	IssuedCertificateExpiresAt time.Time `json:"issued_certificate_expires_at,omitempty"`
}

type CreatedToken struct {
	ID             string    `json:"id"`
	EnrollmentToken string   `json:"enrollment_token"`
	TenantID       string    `json:"tenant_id"`
	AllowedAgentID string    `json:"allowed_agent_id,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type IssuedIdentity struct {
	CertificatePEM    string
	CertificateSerial string
	ExpiresAt         time.Time
}

type RedeemedToken struct {
	Entry  TokenEntry
	Reused bool
}

type tokenEnvelope struct {
	Version       int          `json:"version"`
	Entries       []TokenEntry `json:"entries"`
	PayloadSHA256 string       `json:"payload_sha256"`
}

type TokenStore struct {
	mu      sync.Mutex
	path    string
	entries []TokenEntry
}

func OpenTokenStore(stateDir string) (*TokenStore, error) {
	directory := filepath.Clean(stateDir)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create token store directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("secure token store directory: %w", err)
	}
	store := &TokenStore{path: filepath.Join(directory, "enrollment-tokens.json")}
	file, err := os.Open(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open enrollment token store: %w", err)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxTokenStoreBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read enrollment token store: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close enrollment token store: %w", closeErr)
	}
	if len(content) > maxTokenStoreBytes {
		return nil, fmt.Errorf("enrollment token store exceeds %d bytes", maxTokenStoreBytes)
	}
	var envelope tokenEnvelope
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode enrollment token store: %w", err)
	}
	if envelope.Version != tokenStoreVersion || len(envelope.Entries) > maxTokenEntries {
		return nil, errors.New("enrollment token store version or entry count is invalid")
	}
	expected, err := tokenPayloadHash(envelope.Entries)
	if err != nil {
		return nil, err
	}
	if !constantEqual(expected, envelope.PayloadSHA256) {
		return nil, errors.New("enrollment token store integrity hash mismatch")
	}
	for _, entry := range envelope.Entries {
		if err := validateTokenEntry(entry); err != nil {
			return nil, err
		}
	}
	store.entries = append([]TokenEntry(nil), envelope.Entries...)
	if err := os.Chmod(store.path, 0o600); err != nil {
		return nil, fmt.Errorf("secure enrollment token store: %w", err)
	}
	return store, nil
}

func (s *TokenStore) Create(tenantID, allowedAgentID string, ttl time.Duration, now time.Time) (CreatedToken, error) {
	if s == nil {
		return CreatedToken{}, errors.New("token store is not initialized")
	}
	if err := enrollment.ValidateIdentity("tenant_id", tenantID); err != nil {
		return CreatedToken{}, err
	}
	if allowedAgentID != "" {
		if err := enrollment.ValidateIdentity("allowed_agent_id", allowedAgentID); err != nil {
			return CreatedToken{}, err
		}
	}
	if ttl < time.Minute || ttl > 7*24*time.Hour {
		return CreatedToken{}, errors.New("enrollment token TTL must be between 1m and 7d")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	plainBytes := make([]byte, 32)
	if _, err := rand.Read(plainBytes); err != nil {
		return CreatedToken{}, fmt.Errorf("generate enrollment token: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(plainBytes)
	identifierBytes := make([]byte, 12)
	if _, err := rand.Read(identifierBytes); err != nil {
		return CreatedToken{}, fmt.Errorf("generate enrollment token id: %w", err)
	}
	entry := TokenEntry{
		ID:             hex.EncodeToString(identifierBytes),
		TokenSHA256:    tokenHash(plain),
		TenantID:       tenantID,
		AllowedAgentID: allowedAgentID,
		CreatedAt:      now,
		ExpiresAt:      now.Add(ttl),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := pruneTokens(s.entries, now)
	if len(candidate) >= maxTokenEntries {
		return CreatedToken{}, errors.New("enrollment token store has reached its entry limit")
	}
	candidate = append(candidate, entry)
	if err := s.save(candidate); err != nil {
		return CreatedToken{}, err
	}
	s.entries = candidate
	return CreatedToken{
		ID:              entry.ID,
		EnrollmentToken: plain,
		TenantID:        tenantID,
		AllowedAgentID:  allowedAgentID,
		ExpiresAt:       entry.ExpiresAt,
	}, nil
}

func (s *TokenStore) Redeem(token, agentID, publicKeySHA256 string, now time.Time, issue func(tenantID string) (IssuedIdentity, error)) (RedeemedToken, error) {
	if s == nil || issue == nil {
		return RedeemedToken{}, errors.New("token store and certificate issuer are required")
	}
	if len(token) < 32 || len(token) > 512 {
		return RedeemedToken{}, errors.New("enrollment token is invalid")
	}
	if err := enrollment.ValidateIdentity("agent_id", agentID); err != nil {
		return RedeemedToken{}, err
	}
	if len(publicKeySHA256) != 64 {
		return RedeemedToken{}, errors.New("enrollment public key hash is invalid")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	hash := tokenHash(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	for position := range s.entries {
		if constantEqual(s.entries[position].TokenSHA256, hash) {
			index = position
			break
		}
	}
	if index < 0 {
		return RedeemedToken{}, errors.New("enrollment token is invalid")
	}
	entry := s.entries[index]
	if now.After(entry.ExpiresAt) {
		return RedeemedToken{}, errors.New("enrollment token has expired")
	}
	if entry.AllowedAgentID != "" && entry.AllowedAgentID != agentID {
		return RedeemedToken{}, errors.New("enrollment token is not valid for this agent")
	}
	if entry.ConsumedAt != nil {
		if entry.IssuedAgentID == agentID && constantEqual(entry.IssuedPublicKeySHA256, publicKeySHA256) && entry.IssuedCertificatePEM != "" && now.Before(entry.IssuedCertificateExpiresAt) {
			return RedeemedToken{Entry: entry, Reused: true}, nil
		}
		return RedeemedToken{}, errors.New("enrollment token has already been consumed")
	}
	issued, err := issue(entry.TenantID)
	if err != nil {
		return RedeemedToken{}, err
	}
	if issued.CertificatePEM == "" || issued.CertificateSerial == "" || !issued.ExpiresAt.After(now) {
		return RedeemedToken{}, errors.New("certificate issuer returned invalid identity material")
	}
	consumedAt := now
	entry.ConsumedAt = &consumedAt
	entry.IssuedAgentID = agentID
	entry.IssuedPublicKeySHA256 = publicKeySHA256
	entry.IssuedCertificatePEM = issued.CertificatePEM
	entry.IssuedCertificateSerial = issued.CertificateSerial
	entry.IssuedCertificateExpiresAt = issued.ExpiresAt.UTC()
	candidate := append([]TokenEntry(nil), s.entries...)
	candidate[index] = entry
	if err := s.save(candidate); err != nil {
		return RedeemedToken{}, err
	}
	s.entries = candidate
	return RedeemedToken{Entry: entry}, nil
}

func (s *TokenStore) save(entries []TokenEntry) error {
	payloadHash, err := tokenPayloadHash(entries)
	if err != nil {
		return err
	}
	envelope := tokenEnvelope{Version: tokenStoreVersion, Entries: entries, PayloadSHA256: payloadHash}
	content, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("encode enrollment token store: %w", err)
	}
	if len(content) > maxTokenStoreBytes {
		return errors.New("enrollment token store exceeds size limit")
	}
	return atomicPrivateWrite(s.path, append(content, '\n'))
}

func tokenPayloadHash(entries []TokenEntry) (string, error) {
	content, err := json.Marshal(entries)
	if err != nil {
		return "", fmt.Errorf("encode enrollment token payload: %w", err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func tokenHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func validateTokenEntry(entry TokenEntry) error {
	if len(entry.ID) != 24 || len(entry.TokenSHA256) != 64 {
		return errors.New("enrollment token store contains an invalid token identifier or hash")
	}
	if err := enrollment.ValidateIdentity("tenant_id", entry.TenantID); err != nil {
		return err
	}
	if entry.AllowedAgentID != "" {
		if err := enrollment.ValidateIdentity("allowed_agent_id", entry.AllowedAgentID); err != nil {
			return err
		}
	}
	if entry.CreatedAt.IsZero() || !entry.ExpiresAt.After(entry.CreatedAt) {
		return errors.New("enrollment token store contains invalid timestamps")
	}
	return nil
}

func pruneTokens(entries []TokenEntry, now time.Time) []TokenEntry {
	cutoff := now.Add(-30 * 24 * time.Hour)
	result := make([]TokenEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.ExpiresAt.Before(cutoff) {
			continue
		}
		result = append(result, entry)
	}
	return result
}

func atomicPrivateWrite(path string, content []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".token-store-*.tmp")
	if err != nil {
		return fmt.Errorf("create token store temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure token store temporary file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write token store temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync token store temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close token store temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("replace token store: rename failed: %v; remove failed: %w", err, removeErr)
		}
		if retryErr := os.Rename(temporaryPath, path); retryErr != nil {
			return fmt.Errorf("replace token store: %w", retryErr)
		}
	}
	removeTemporary = false
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure token store: %w", err)
	}
	return nil
}

func constantEqual(left, right string) bool {
	if len(left) != len(right) || len(left) == 0 {
		return false
	}
	var difference byte
	for index := 0; index < len(left); index++ {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
