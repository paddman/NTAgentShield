package responseexec

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
	"github.com/paddman/NTAgentShield/internal/identity"
)

const maxResponseHTTPBody = 4 << 20

type ClientOptions struct {
	TransportEndpoint string
	AgentID           string
	TenantID          string
	CertFile          string
	KeyFile           string
	CAFile            string
	ServerName        string
	TrustRootFile     string
	Timeout           time.Duration
}

type Client struct {
	options    ClientOptions
	privateKey ed25519.PrivateKey
	httpClient *http.Client
	baseURL    *url.URL
}

func NewClient(options ClientOptions) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(options.TransportEndpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("response transport endpoint must be an absolute https URL")
	}
	if strings.TrimSpace(options.AgentID) == "" || strings.TrimSpace(options.TenantID) == "" {
		return nil, errors.New("response client requires agent_id and tenant_id")
	}
	if options.Timeout < time.Second || options.Timeout > 2*time.Minute {
		return nil, errors.New("response client timeout must be between 1s and 2m")
	}
	if strings.TrimSpace(options.TrustRootFile) == "" {
		return nil, errors.New("response signing trust root path is required")
	}
	privateKey, err := identity.Load(options.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load response request signing key: %w", err)
	}
	tlsConfig, err := enrollment.ClientTLSConfig(
		options.CertFile, options.KeyFile, options.CAFile, options.ServerName,
	)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   min(10*time.Second, options.Timeout),
		ResponseHeaderTimeout: options.Timeout,
	}
	return &Client{
		options:    options,
		privateKey: privateKey,
		httpClient: &http.Client{Timeout: options.Timeout, Transport: transport},
		baseURL:    parsed,
	}, nil
}

func (c *Client) EnsureTrustRoot(ctx context.Context) error {
	endpoint := c.endpoint("/v1/agent/response-trust-root")
	body, status, err := c.signedGET(ctx, endpoint)
	if err != nil {
		if _, statErr := os.Stat(c.options.TrustRootFile); statErr == nil {
			return nil
		}
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("response trust-root endpoint HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	var payload struct {
		PublicKeyPEM string `json:"public_key_pem"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("decode response trust root: %w", err)
	}
	remoteKey, err := parseResponsePublicKey([]byte(payload.PublicKeyPEM))
	if err != nil {
		return err
	}
	current, err := os.ReadFile(c.options.TrustRootFile)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(c.options.TrustRootFile), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(c.options.TrustRootFile, []byte(payload.PublicKeyPEM), 0o600); err != nil {
			return fmt.Errorf("pin response signing trust root: %w", err)
		}
		return os.Chmod(c.options.TrustRootFile, 0o600)
	}
	if err != nil {
		return fmt.Errorf("read pinned response signing trust root: %w", err)
	}
	localKey, err := parseResponsePublicKey(current)
	if err != nil {
		return err
	}
	if !localKey.Equal(remoteKey) {
		return errors.New("response signing trust root changed; explicit trust rotation is required")
	}
	return nil
}

func (c *Client) Fetch(ctx context.Context) (*SignedLease, error) {
	body, status, err := c.signedGET(ctx, c.endpoint("/v1/agent/responses"))
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("response lease endpoint HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	var lease SignedLease
	if err := json.Unmarshal(body, &lease); err != nil {
		return nil, fmt.Errorf("decode signed response lease: %w", err)
	}
	return &lease, nil
}

func (c *Client) PostResult(ctx context.Context, actionID string, body []byte) error {
	if strings.TrimSpace(actionID) == "" || !json.Valid(body) {
		return errors.New("response result requires an action ID and valid JSON body")
	}
	endpoint := c.endpoint("/v1/agent/responses/" + url.PathEscape(actionID) + "/result")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create response result request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NTShield-Agent-ID", c.options.AgentID)
	req.Header.Set("X-NTShield-Tenant-ID", c.options.TenantID)
	req.Header.Set("X-NTShield-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(c.privateKey, body)))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post response result: %w", err)
	}
	responseBody, readErr := readBoundedResponse(resp)
	if readErr != nil {
		return readErr
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("response result endpoint HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func (c *Client) signedGET(ctx context.Context, endpoint string) ([]byte, int, error) {
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, 0, err
	}
	message := []byte("GET\n" + parsed.Path + "\n" + timestamp + "\n" + c.options.TenantID + "\n" + c.options.AgentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create signed response GET: %w", err)
	}
	req.Header.Set("X-NTShield-Agent-ID", c.options.AgentID)
	req.Header.Set("X-NTShield-Tenant-ID", c.options.TenantID)
	req.Header.Set("X-NTShield-Timestamp", timestamp)
	req.Header.Set("X-NTShield-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(c.privateKey, message)))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("signed response GET failed: %w", err)
	}
	body, err := readBoundedResponse(resp)
	return body, resp.StatusCode, err
}

func (c *Client) endpoint(path string) string {
	copyURL := *c.baseURL
	copyURL.Path = path
	copyURL.RawPath = ""
	copyURL.RawQuery = ""
	copyURL.Fragment = ""
	return copyURL.String()
}

func readBoundedResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseHTTPBody))
	if err != nil {
		return nil, fmt.Errorf("read response transport body: %w", err)
	}
	return body, nil
}

func parseResponsePublicKey(content []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("response signing trust root is not a public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse response signing trust root: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("response signing trust root must use Ed25519")
	}
	return key, nil
}
