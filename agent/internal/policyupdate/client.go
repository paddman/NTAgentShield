package policyupdate

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
	"github.com/paddman/NTAgentShield/internal/identity"
)

const maxPolicyResponseBytes = 4 << 20

type ClientOptions struct {
	Endpoint   string
	AgentID    string
	TenantID   string
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
	Timeout    time.Duration
}

type Client struct {
	options    ClientOptions
	privateKey ed25519.PrivateKey
	httpClient *http.Client
}

func NewClient(options ClientOptions) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(options.Endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("policy endpoint must be an absolute https URL")
	}
	if strings.TrimSpace(options.AgentID) == "" || strings.TrimSpace(options.TenantID) == "" {
		return nil, errors.New("policy client requires agent_id and tenant_id")
	}
	if options.Timeout < time.Second || options.Timeout > 2*time.Minute {
		return nil, errors.New("policy client timeout must be between 1s and 2m")
	}
	privateKey, err := identity.Load(options.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load policy request signing key: %w", err)
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
	}, nil
}

func (c *Client) Fetch(ctx context.Context) (*Bundle, error) {
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	message := RequestMessage(c.options.AgentID, c.options.TenantID, timestamp)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(c.privateKey, message))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.options.Endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create policy request: %w", err)
	}
	req.Header.Set("X-NTShield-Agent-ID", c.options.AgentID)
	req.Header.Set("X-NTShield-Tenant-ID", c.options.TenantID)
	req.Header.Set("X-NTShield-Timestamp", timestamp)
	req.Header.Set("X-NTShield-Signature", signature)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch signed policy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read signed policy response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signed policy endpoint HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var bundle Bundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return nil, fmt.Errorf("decode signed policy bundle: %w", err)
	}
	return &bundle, nil
}

func RequestMessage(agentID, tenantID, timestamp string) []byte {
	return []byte("GET\n/v1/agent/policy\n" + timestamp + "\n" + tenantID + "\n" + agentID)
}

func EndpointFromTransport(transportEndpoint string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(transportEndpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", errors.New("cannot derive policy endpoint from invalid transport endpoint")
	}
	parsed.Path = "/v1/agent/policy"
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}
