package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
)

const maxReceiptBytes = 256 * 1024

type Client struct {
	metadata enrollment.Metadata
	endpoint *url.URL
	http     *http.Client
	transport *http.Transport
}

type ClientOptions struct {
	StateDir   string
	Endpoint   string
	ServerName string
	Timeout    time.Duration
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	if options.Timeout < time.Second || options.Timeout > 2*time.Minute {
		return nil, errors.New("transport timeout must be between 1s and 2m")
	}
	paths := enrollment.Paths(options.StateDir)
	metadataContent, err := os.ReadFile(paths.Metadata)
	if err != nil {
		return nil, fmt.Errorf("read enrollment metadata: %w", err)
	}
	var metadata enrollment.Metadata
	decoder := json.NewDecoder(bytes.NewReader(metadataContent))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decode enrollment metadata: %w", err)
	}
	if metadata.Version != enrollment.ProtocolVersion {
		return nil, fmt.Errorf("unsupported enrollment metadata version %d", metadata.Version)
	}
	if err := enrollment.ValidateIdentity("tenant_id", metadata.TenantID); err != nil {
		return nil, err
	}
	if err := enrollment.ValidateIdentity("agent_id", metadata.AgentID); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(paths.Certificate, paths.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load endpoint certificate and key: %w", err)
	}
	caContent, err := os.ReadFile(paths.CA)
	if err != nil {
		return nil, fmt.Errorf("read control-plane CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caContent) {
		return nil, errors.New("control-plane CA file contains no certificate")
	}
	rawEndpoint := strings.TrimSpace(options.Endpoint)
	if rawEndpoint == "" {
		rawEndpoint = metadata.ControlPlaneURL
	}
	endpoint, err := eventEndpoint(rawEndpoint)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
		ServerName:   strings.TrimSpace(options.ServerName),
	}
	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: options.Timeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("evidence transport redirects are not allowed")
		},
	}
	return &Client{metadata: metadata, endpoint: endpoint, http: client, transport: transport}, nil
}

func (c *Client) Close() {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

func (c *Client) Send(ctx context.Context, batch Batch) (Receipt, error) {
	if c == nil || c.http == nil || c.endpoint == nil {
		return Receipt{}, errors.New("transport client is not initialized")
	}
	if batch.TenantID != c.metadata.TenantID || batch.AgentID != c.metadata.AgentID {
		return Receipt{}, errors.New("batch identity does not match enrolled endpoint identity")
	}
	if batch.PayloadSHA256 == "" {
		if err := batch.Seal(); err != nil {
			return Receipt{}, err
		}
	} else if err := batch.Validate(); err != nil {
		return Receipt{}, err
	}
	content, err := json.Marshal(batch)
	if err != nil {
		return Receipt{}, fmt.Errorf("encode evidence batch: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(content))
	if err != nil {
		return Receipt{}, fmt.Errorf("create evidence request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "NTAgentShield-Transport/1")
	response, err := c.http.Do(request)
	if err != nil {
		return Receipt{}, fmt.Errorf("send evidence batch: %w", err)
	}
	defer response.Body.Close()
	responseContent, err := io.ReadAll(io.LimitReader(response.Body, maxReceiptBytes+1))
	if err != nil {
		return Receipt{}, fmt.Errorf("read evidence receipt: %w", err)
	}
	if len(responseContent) > maxReceiptBytes {
		return Receipt{}, errors.New("evidence receipt exceeds size limit")
	}
	if response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusOK {
		return Receipt{}, fmt.Errorf("evidence gateway returned HTTP %d: %s", response.StatusCode, safeError(responseContent))
	}
	var receipt Receipt
	decoder = json.NewDecoder(bytes.NewReader(responseContent))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode evidence receipt: %w", err)
	}
	if receipt.TenantID != batch.TenantID || receipt.AgentID != batch.AgentID || receipt.Sequence != batch.Sequence || receipt.PayloadSHA256 != batch.PayloadSHA256 {
		return Receipt{}, errors.New("evidence receipt does not match the submitted batch")
	}
	if receipt.Status != "accepted" && receipt.Status != "duplicate" {
		return Receipt{}, fmt.Errorf("unsupported evidence receipt status %q", receipt.Status)
	}
	return receipt, nil
}

func eventEndpoint(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("parse control-plane endpoint: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("control-plane endpoint must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("control-plane endpoint must not contain credentials, query, or fragment")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/v1/agent/events"
	return parsed, nil
}

func safeError(content []byte) string {
	text := strings.TrimSpace(string(content))
	if len(text) > 512 {
		text = text[:512]
	}
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\n", " ")
	if text == "" {
		return "request rejected"
	}
	return text
}
