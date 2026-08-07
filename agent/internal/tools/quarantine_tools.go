package tools

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/identity"
	"github.com/paddman/NTAgentShield/internal/model"
)

const quarantineSchema = "ntagentshield-quarantine/v1"

var quarantineIDPattern = regexp.MustCompile(`^q_[a-f0-9]{16}_[a-f0-9]{16}$`)

type quarantineManifest struct {
	Schema         string    `json:"schema"`
	QuarantineID   string    `json:"quarantine_id"`
	OriginalPath   string    `json:"original_path"`
	QuarantinePath string    `json:"quarantine_path"`
	SHA256         string    `json:"sha256"`
	Size           int64     `json:"size"`
	OriginalMode   uint32    `json:"original_mode"`
	QuarantinedAt  time.Time `json:"quarantined_at"`
	Signature      string    `json:"signature"`
}

type FileQuarantine struct {
	guard           *pathGuard
	dataDir         string
	identityKeyFile string
}

type FileRestore struct {
	guard           *pathGuard
	dataDir         string
	identityKeyFile string
}

func NewFileQuarantine(roots []string, dataDir, identityKeyFile string) (*FileQuarantine, error) {
	guard, err := newPathGuard(roots)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(dataDir) == "" || strings.TrimSpace(identityKeyFile) == "" {
		return nil, errors.New("file quarantine requires data directory and Agent identity key")
	}
	return &FileQuarantine{guard: guard, dataDir: dataDir, identityKeyFile: identityKeyFile}, nil
}

func NewFileRestore(roots []string, dataDir, identityKeyFile string) (*FileRestore, error) {
	guard, err := newPathGuard(roots)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(dataDir) == "" || strings.TrimSpace(identityKeyFile) == "" {
		return nil, errors.New("file restore requires data directory and Agent identity key")
	}
	return &FileRestore{guard: guard, dataDir: dataDir, identityKeyFile: identityKeyFile}, nil
}

func (*FileQuarantine) Spec() Spec {
	return Spec{Name: "file.quarantine", Description: "Move one allowlisted regular file into the Agent quarantine store after optional SHA-256 pinning", Risk: model.RiskContain}
}

func (*FileRestore) Spec() Spec {
	return Spec{Name: "file.restore", Description: "Restore one Agent-signed quarantine object to its original allowlisted path", Risk: model.RiskContain}
}

func (t *FileQuarantine) Execute(_ context.Context, args map[string]interface{}) (interface{}, error) {
	pathText, err := stringArg(args, "path")
	if err != nil {
		return nil, err
	}
	resolved, err := t.guard.resolve(pathText)
	if err != nil {
		return nil, err
	}
	expectedHash := ""
	if value, ok := args["expected_sha256"]; ok {
		text, ok := value.(string)
		if !ok {
			return nil, errors.New("expected_sha256 must be a string")
		}
		expectedHash = strings.ToLower(strings.TrimSpace(text))
		if expectedHash != "" && !isSHA256Hex(expectedHash) {
			return nil, errors.New("expected_sha256 must contain 64 lowercase/uppercase hex characters")
		}
	}

	source, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("open quarantine source: %w", err)
	}
	defer source.Close()
	before, err := source.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat quarantine source: %w", err)
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("file.quarantine only accepts regular files")
	}

	quarantineDir := filepath.Join(t.dataDir, "quarantine")
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return nil, fmt.Errorf("create quarantine directory: %w", err)
	}
	temporary, err := os.CreateTemp(quarantineDir, ".incoming-*")
	if err != nil {
		return nil, fmt.Errorf("create quarantine temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	_ = temporary.Chmod(0o600)
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hasher), source)
	if copyErr != nil {
		return nil, fmt.Errorf("copy quarantine source: %w", copyErr)
	}
	if err := temporary.Sync(); err != nil {
		return nil, fmt.Errorf("sync quarantine temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return nil, fmt.Errorf("close quarantine temporary file: %w", err)
	}
	after, err := source.Stat()
	if err != nil {
		return nil, fmt.Errorf("restat quarantine source: %w", err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || written != before.Size() {
		return nil, errors.New("quarantine source changed while it was being copied; refusing removal")
	}
	if err := source.Close(); err != nil {
		return nil, fmt.Errorf("close quarantine source before removal: %w", err)
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if expectedHash != "" && digest != expectedHash {
		return nil, fmt.Errorf("quarantine SHA-256 mismatch: got %s", digest)
	}
	pathDigest := sha256.Sum256([]byte(resolved))
	quarantineID := fmt.Sprintf("q_%s_%s", hex.EncodeToString(pathDigest[:8]), digest[:16])
	finalPath := filepath.Join(quarantineDir, quarantineID+".bin")
	manifestPath := filepath.Join(quarantineDir, quarantineID+".json")
	if _, err := os.Stat(manifestPath); err == nil {
		return nil, errors.New("quarantine object already exists; refusing to overwrite signed evidence")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.Rename(temporaryName, finalPath); err != nil {
		return nil, fmt.Errorf("commit quarantine file: %w", err)
	}
	committed = true
	manifest := quarantineManifest{
		Schema:         quarantineSchema,
		QuarantineID:   quarantineID,
		OriginalPath:   resolved,
		QuarantinePath: finalPath,
		SHA256:         digest,
		Size:           written,
		OriginalMode:   uint32(before.Mode().Perm()),
		QuarantinedAt:  time.Now().UTC(),
	}
	if err := saveQuarantineManifest(manifestPath, t.identityKeyFile, manifest); err != nil {
		_ = os.Remove(finalPath)
		return nil, err
	}
	if err := os.Remove(resolved); err != nil {
		_ = os.Remove(manifestPath)
		_ = os.Remove(finalPath)
		return nil, fmt.Errorf("remove original after quarantine copy: %w", err)
	}
	return map[string]interface{}{
		"quarantine_id": quarantineID,
		"original_path": resolved,
		"sha256":        digest,
		"size":          written,
		"quarantined":   true,
	}, nil
}

func (t *FileRestore) Execute(_ context.Context, args map[string]interface{}) (interface{}, error) {
	quarantineID, err := stringArg(args, "quarantine_id")
	if err != nil {
		return nil, err
	}
	quarantineID = strings.ToLower(strings.TrimSpace(quarantineID))
	if !quarantineIDPattern.MatchString(quarantineID) {
		return nil, errors.New("quarantine_id format is invalid")
	}
	quarantineDir := filepath.Join(t.dataDir, "quarantine")
	manifestPath := filepath.Join(quarantineDir, quarantineID+".json")
	manifest, err := loadQuarantineManifest(manifestPath, t.identityKeyFile)
	if err != nil {
		return nil, err
	}
	if manifest.QuarantineID != quarantineID {
		return nil, errors.New("quarantine manifest ID mismatch")
	}
	expectedQuarantinePath := filepath.Join(quarantineDir, quarantineID+".bin")
	if filepath.Clean(manifest.QuarantinePath) != filepath.Clean(expectedQuarantinePath) {
		return nil, errors.New("quarantine manifest contains an unexpected object path")
	}
	if manifest.Size < 0 || !isSHA256Hex(strings.ToLower(manifest.SHA256)) {
		return nil, errors.New("quarantine manifest contains invalid file metadata")
	}
	resolved, err := t.resolveRestoreTarget(manifest.OriginalPath)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(resolved) != filepath.Clean(manifest.OriginalPath) {
		return nil, errors.New("restore target canonical path changed")
	}

	source, err := os.Open(manifest.QuarantinePath)
	if err != nil {
		return nil, fmt.Errorf("open quarantine object: %w", err)
	}
	defer source.Close()
	destination, err := os.OpenFile(resolved, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(manifest.OriginalMode))
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, errors.New("restore target already exists; refusing overwrite")
		}
		return nil, fmt.Errorf("create restore target without overwrite: %w", err)
	}
	restoreCommitted := false
	defer func() {
		_ = destination.Close()
		if !restoreCommitted {
			_ = os.Remove(resolved)
		}
	}()
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hasher), source)
	if err != nil {
		return nil, fmt.Errorf("copy quarantine object for restore: %w", err)
	}
	if err := destination.Sync(); err != nil {
		return nil, fmt.Errorf("sync restored file: %w", err)
	}
	if err := destination.Close(); err != nil {
		return nil, fmt.Errorf("close restored file: %w", err)
	}
	if err := source.Close(); err != nil {
		return nil, fmt.Errorf("close quarantine object before cleanup: %w", err)
	}
	restoredHash := hex.EncodeToString(hasher.Sum(nil))
	if written != manifest.Size || !strings.EqualFold(restoredHash, manifest.SHA256) {
		return nil, errors.New("restored content does not match signed quarantine manifest")
	}
	_ = os.Chmod(resolved, os.FileMode(manifest.OriginalMode))
	restoreCommitted = true
	if err := os.Remove(manifest.QuarantinePath); err != nil {
		return nil, fmt.Errorf("restored file is durable but quarantine object cleanup failed: %w", err)
	}
	if err := os.Remove(manifestPath); err != nil {
		return nil, fmt.Errorf("restored file is durable but quarantine manifest cleanup failed: %w", err)
	}
	return map[string]interface{}{
		"quarantine_id": quarantineID,
		"restored_path": resolved,
		"sha256":        manifest.SHA256,
		"restored":      true,
	}, nil
}

func (t *FileRestore) resolveRestoreTarget(originalPath string) (string, error) {
	absolute, err := filepath.Abs(originalPath)
	if err != nil {
		return "", fmt.Errorf("resolve restore target: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", fmt.Errorf("resolve restore target parent symlinks: %w", err)
	}
	candidate := filepath.Clean(filepath.Join(parent, filepath.Base(absolute)))
	for _, root := range t.guard.allowedRoots {
		relative, err := filepath.Rel(root, candidate)
		if err != nil {
			continue
		}
		if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("restore target %q is outside allowed roots after resolving parent symlinks", originalPath)
}

func saveQuarantineManifest(path, identityKeyFile string, manifest quarantineManifest) error {
	privateKey, err := identity.Load(identityKeyFile)
	if err != nil {
		return fmt.Errorf("load Agent identity for quarantine manifest: %w", err)
	}
	unsigned, err := quarantineManifestBytes(manifest)
	if err != nil {
		return err
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writePrivateFile(path, encoded)
}

func loadQuarantineManifest(path, identityKeyFile string) (quarantineManifest, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return quarantineManifest{}, fmt.Errorf("read quarantine manifest: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	var manifest quarantineManifest
	if err := decoder.Decode(&manifest); err != nil {
		return quarantineManifest{}, fmt.Errorf("decode quarantine manifest: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return quarantineManifest{}, errors.New("quarantine manifest contains trailing JSON")
		}
		return quarantineManifest{}, fmt.Errorf("decode trailing quarantine manifest data: %w", err)
	}
	if manifest.Schema != quarantineSchema {
		return quarantineManifest{}, errors.New("unsupported quarantine manifest schema")
	}
	signature, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil {
		return quarantineManifest{}, errors.New("decode quarantine manifest signature")
	}
	privateKey, err := identity.Load(identityKeyFile)
	if err != nil {
		return quarantineManifest{}, fmt.Errorf("load Agent identity for quarantine manifest: %w", err)
	}
	unsigned, err := quarantineManifestBytes(manifest)
	if err != nil {
		return quarantineManifest{}, err
	}
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), unsigned, signature) {
		return quarantineManifest{}, errors.New("quarantine manifest signature verification failed")
	}
	return manifest, nil
}

func quarantineManifestBytes(manifest quarantineManifest) ([]byte, error) {
	manifest.Signature = ""
	return json.Marshal(manifest)
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
