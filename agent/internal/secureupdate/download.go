package secureupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func FetchEnvelope(ctx context.Context, address string) ([]byte, error) {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("manifest URL must be an absolute HTTPS URL without credentials")
	}
	client := secureHTTPClient()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download signed update manifest: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download signed update manifest: HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, MaxEnvelopeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read signed update manifest: %w", err)
	}
	if len(content) == 0 || len(content) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("signed update manifest exceeds %d bytes", MaxEnvelopeBytes)
	}
	return content, nil
}

func DownloadArtifact(
	ctx context.Context,
	manifest Manifest,
	targetDirectory string,
) (string, error) {
	if err := os.MkdirAll(targetDirectory, 0o700); err != nil {
		return "", fmt.Errorf("create update staging directory: %w", err)
	}
	temporary, err := os.CreateTemp(targetDirectory, ".ntshield-update-*.staged")
	if err != nil {
		return "", fmt.Errorf("create update staging file: %w", err)
	}
	stagedPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(stagedPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return "", fmt.Errorf("secure update staging file: %w", err)
	}

	client := secureHTTPClient()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, manifest.ArtifactURL, nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("download update artifact: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download update artifact: HTTP %d", response.StatusCode)
	}
	if response.ContentLength > manifest.Size && response.ContentLength >= 0 {
		return "", fmt.Errorf("update artifact Content-Length exceeds signed size")
	}

	hash := sha256.New()
	written, err := io.Copy(
		io.MultiWriter(temporary, hash),
		io.LimitReader(response.Body, manifest.Size+1),
	)
	if err != nil {
		return "", fmt.Errorf("write update artifact: %w", err)
	}
	if written != manifest.Size {
		return "", fmt.Errorf("update artifact size mismatch: got %d want %d", written, manifest.Size)
	}
	actualHash := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actualHash, manifest.SHA256) {
		return "", fmt.Errorf("update artifact SHA-256 mismatch")
	}
	if err := temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync update artifact: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close update artifact: %w", err)
	}
	keep = true
	return filepath.Clean(stagedPath), nil
}

func secureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Minute,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many update redirects")
			}
			if request.URL.Scheme != "https" || request.URL.User != nil {
				return fmt.Errorf("update redirect must remain credential-free HTTPS")
			}
			return nil
		},
	}
}
