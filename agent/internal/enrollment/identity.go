package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func EnsurePrivateKey(stateDir string) (*ecdsa.PrivateKey, StatePaths, error) {
	paths := Paths(stateDir)
	if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
		return nil, paths, fmt.Errorf("create enrollment state directory: %w", err)
	}
	if err := os.Chmod(paths.Directory, 0o700); err != nil {
		return nil, paths, fmt.Errorf("secure enrollment state directory: %w", err)
	}
	content, err := os.ReadFile(paths.PrivateKey)
	if err == nil {
		block, _ := pem.Decode(content)
		if block == nil || block.Type != "EC PRIVATE KEY" {
			return nil, paths, errors.New("endpoint identity key is not an EC private key")
		}
		key, parseErr := x509.ParseECPrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, paths, fmt.Errorf("parse endpoint identity key: %w", parseErr)
		}
		if key.Curve != elliptic.P256() {
			return nil, paths, errors.New("endpoint identity key must use ECDSA P-256")
		}
		if chmodErr := os.Chmod(paths.PrivateKey, 0o600); chmodErr != nil {
			return nil, paths, fmt.Errorf("secure endpoint identity key: %w", chmodErr)
		}
		return key, paths, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, paths, fmt.Errorf("read endpoint identity key: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, paths, fmt.Errorf("generate endpoint identity key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, paths, fmt.Errorf("marshal endpoint identity key: %w", err)
	}
	content = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := atomicWrite(paths.PrivateKey, content, 0o600); err != nil {
		return nil, paths, err
	}
	return key, paths, nil
}

func CreateCSR(key *ecdsa.PrivateKey, agentID string) ([]byte, error) {
	if key == nil {
		return nil, errors.New("endpoint identity key is required")
	}
	if err := ValidateIdentity("agent_id", agentID); err != nil {
		return nil, err
	}
	template := &x509.CertificateRequest{
		Subject: pkixName(agentID),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate request: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func PublicKeyHash(publicKey interface{}) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:]), nil
}

func SaveEnrollment(paths StatePaths, certificatePEM, caPEM []byte, metadata Metadata) error {
	if len(certificatePEM) == 0 || len(caPEM) == 0 {
		return errors.New("certificate and CA chain are required")
	}
	metadataContent, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("encode enrollment metadata: %w", err)
	}
	if err := atomicWrite(paths.Certificate, certificatePEM, 0o600); err != nil {
		return err
	}
	if err := atomicWrite(paths.CA, caPEM, 0o600); err != nil {
		return err
	}
	if err := atomicWrite(paths.Metadata, append(metadataContent, '\n'), 0o600); err != nil {
		return err
	}
	return nil
}

func atomicWrite(path string, content []byte, mode fs.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".ntagentshield-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary state file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return fmt.Errorf("secure temporary state file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write temporary state file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary state file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary state file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return fmt.Errorf("replace state file: rename failed: %v; remove failed: %w", err, removeErr)
		}
		if retryErr := os.Rename(temporaryPath, path); retryErr != nil {
			return fmt.Errorf("replace state file: %w", retryErr)
		}
	}
	removeTemporary = false
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("secure state file: %w", err)
	}
	return nil
}
