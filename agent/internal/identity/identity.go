package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const privateKeyFilename = "agent-identity.key"

func Ensure(dataDir string) (ed25519.PrivateKey, string, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, "", fmt.Errorf("create identity data dir: %w", err)
	}
	path := filepath.Join(dataDir, privateKeyFilename)
	if key, err := Load(path); err == nil {
		if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
			return nil, "", fmt.Errorf("protect identity key: %w", chmodErr)
		}
		return key, path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate identity key: %w", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("encode identity key: %w", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	if err := writePrivateFile(path, block); err != nil {
		return nil, "", err
	}
	return key, path, nil
}

func Load(path string) (ed25519.PrivateKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(content)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("identity key is not a single PKCS#8 private key PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse identity key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("identity key must be Ed25519")
	}
	return key, nil
}

func Fingerprint(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:])
}

func writePrivateFile(path string, content []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		return fmt.Errorf("write identity key: %w", err)
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("protect identity key: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("install identity key: %w", err)
	}
	return nil
}
