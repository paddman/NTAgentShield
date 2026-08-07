package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/identity"
)

const maxEnrollmentResponseBytes = 2 << 20

type Options struct {
	Endpoint        string
	BootstrapToken  string
	BootstrapCAFile string
	DataDir         string
	AgentID         string
	TenantID        string
	Hostname        string
	Timeout         time.Duration
}

type RenewalOptions struct {
	Endpoint   string
	AgentID    string
	TenantID   string
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
	Timeout    time.Duration
}

type Request struct {
	AgentID  string `json:"agent_id"`
	TenantID string `json:"tenant_id"`
	Hostname string `json:"hostname,omitempty"`
	CSRPEM   string `json:"csr_pem"`
}

type RenewalRequest struct {
	AgentID  string `json:"agent_id"`
	TenantID string `json:"tenant_id"`
	CSRPEM   string `json:"csr_pem"`
}

type Response struct {
	AgentID                   string    `json:"agent_id"`
	TenantID                  string    `json:"tenant_id"`
	CertificatePEM            string    `json:"certificate_pem"`
	CACertificatePEM          string    `json:"ca_certificate_pem"`
	ExpiresAt                 time.Time `json:"expires_at"`
	PolicySigningPublicKeyPEM string    `json:"policy_signing_public_key_pem,omitempty"`
}

type Bundle struct {
	AgentID     string    `json:"agent_id"`
	TenantID    string    `json:"tenant_id"`
	Certificate string    `json:"certificate_file"`
	PrivateKey  string    `json:"private_key_file"`
	CA          string    `json:"ca_file"`
	ExpiresAt   time.Time `json:"expires_at"`
	Fingerprint string    `json:"identity_fingerprint"`
}

func Enroll(ctx context.Context, options Options) (Bundle, error) {
	if err := validateOptions(options); err != nil {
		return Bundle{}, err
	}
	privateKey, privateKeyPath, err := identity.Ensure(options.DataDir)
	if err != nil {
		return Bundle{}, err
	}
	csrPEM, err := createCSR(privateKey, options.AgentID, options.TenantID, options.Hostname)
	if err != nil {
		return Bundle{}, err
	}
	requestBody, err := json.Marshal(Request{
		AgentID: options.AgentID, TenantID: options.TenantID, Hostname: options.Hostname, CSRPEM: string(csrPEM),
	})
	if err != nil {
		return Bundle{}, fmt.Errorf("encode enrollment request: %w", err)
	}

	tlsConfig, err := bootstrapTLSConfig(options.BootstrapCAFile)
	if err != nil {
		return Bundle{}, err
	}
	client := &http.Client{
		Timeout: options.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, options.Endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return Bundle{}, fmt.Errorf("create enrollment request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(options.BootstrapToken))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Bundle{}, fmt.Errorf("enrollment request failed: %w", err)
	}
	body, err := readResponse(resp)
	if err != nil {
		return Bundle{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Bundle{}, fmt.Errorf("enrollment rejected with HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	response, err := decodeAndVerifyResponse(body, privateKey, options.AgentID, options.TenantID)
	if err != nil {
		return Bundle{}, err
	}

	certDir := filepath.Join(options.DataDir, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return Bundle{}, fmt.Errorf("create certificate directory: %w", err)
	}
	certPath := filepath.Join(certDir, "client.crt")
	caPath := filepath.Join(certDir, "ca.crt")
	if err := atomicWrite(certPath, []byte(response.CertificatePEM), 0o600); err != nil {
		return Bundle{}, err
	}
	if err := atomicWrite(caPath, []byte(response.CACertificatePEM), 0o644); err != nil {
		return Bundle{}, err
	}
	if err := persistPolicySigningKey(
		filepath.Join(options.DataDir, "policy-signing.pub"),
		response.PolicySigningPublicKeyPEM,
	); err != nil {
		return Bundle{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return Bundle{
		AgentID:     options.AgentID,
		TenantID:    options.TenantID,
		Certificate: certPath,
		PrivateKey:  privateKeyPath,
		CA:          caPath,
		ExpiresAt:   response.ExpiresAt,
		Fingerprint: identity.Fingerprint(publicKey),
	}, nil
}

func Renew(ctx context.Context, options RenewalOptions) (Response, error) {
	if err := validateRenewalOptions(options); err != nil {
		return Response{}, err
	}
	privateKey, err := identity.Load(options.KeyFile)
	if err != nil {
		return Response{}, fmt.Errorf("load renewal identity key: %w", err)
	}
	csrPEM, err := createCSR(privateKey, options.AgentID, options.TenantID, "")
	if err != nil {
		return Response{}, err
	}
	requestBody, err := json.Marshal(RenewalRequest{
		AgentID:  options.AgentID,
		TenantID: options.TenantID,
		CSRPEM:   string(csrPEM),
	})
	if err != nil {
		return Response{}, fmt.Errorf("encode certificate renewal request: %w", err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, requestBody))
	tlsConfig, err := ClientTLSConfig(options.CertFile, options.KeyFile, options.CAFile, options.ServerName)
	if err != nil {
		return Response{}, err
	}
	client := &http.Client{
		Timeout: options.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, options.Endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return Response{}, fmt.Errorf("create certificate renewal request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NTShield-Agent-ID", options.AgentID)
	req.Header.Set("X-NTShield-Tenant-ID", options.TenantID)
	req.Header.Set("X-NTShield-Signature", signature)
	resp, err := client.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("certificate renewal request failed: %w", err)
	}
	body, err := readResponse(resp)
	if err != nil {
		return Response{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("certificate renewal rejected with HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	response, err := decodeAndVerifyResponse(body, privateKey, options.AgentID, options.TenantID)
	if err != nil {
		return Response{}, err
	}
	if err := atomicWrite(options.CertFile, []byte(response.CertificatePEM), 0o600); err != nil {
		return Response{}, err
	}
	if err := atomicWrite(options.CAFile, []byte(response.CACertificatePEM), 0o644); err != nil {
		return Response{}, err
	}
	if err := persistPolicySigningKey(
		filepath.Join(filepath.Dir(options.KeyFile), "policy-signing.pub"),
		response.PolicySigningPublicKeyPEM,
	); err != nil {
		return Response{}, err
	}
	return response, nil
}

func ClientTLSConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, fmt.Errorf("load mTLS client certificate: %w", err)
	}
	roots, err := loadCertPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: strings.TrimSpace(serverName),
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("reload mTLS client certificate: %w", err)
			}
			return &certificate, nil
		},
	}, nil
}

func CertificateExpiry(certFile string) (time.Time, error) {
	content, err := os.ReadFile(certFile)
	if err != nil {
		return time.Time{}, fmt.Errorf("read client certificate: %w", err)
	}
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, errors.New("client certificate file contains no certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse client certificate: %w", err)
	}
	return certificate.NotAfter.UTC(), nil
}

func validateOptions(options Options) error {
	if strings.TrimSpace(options.AgentID) == "" || strings.TrimSpace(options.TenantID) == "" {
		return errors.New("agent_id and tenant_id are required for enrollment")
	}
	if strings.TrimSpace(options.BootstrapToken) == "" {
		return errors.New("bootstrap enrollment token is required")
	}
	if err := validateHTTPSEndpoint(options.Endpoint, "enrollment"); err != nil {
		return err
	}
	if options.Timeout < time.Second || options.Timeout > 2*time.Minute {
		return errors.New("enrollment timeout must be between 1s and 2m")
	}
	return nil
}

func validateRenewalOptions(options RenewalOptions) error {
	if strings.TrimSpace(options.AgentID) == "" || strings.TrimSpace(options.TenantID) == "" {
		return errors.New("agent_id and tenant_id are required for certificate renewal")
	}
	if err := validateHTTPSEndpoint(options.Endpoint, "certificate renewal"); err != nil {
		return err
	}
	if options.CertFile == "" || options.KeyFile == "" || options.CAFile == "" {
		return errors.New("certificate renewal requires cert, key, and CA files")
	}
	if options.Timeout < time.Second || options.Timeout > 2*time.Minute {
		return errors.New("certificate renewal timeout must be between 1s and 2m")
	}
	return nil
}

func validateHTTPSEndpoint(value, name string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%s endpoint must be an absolute https URL", name)
	}
	return nil
}

func createCSR(privateKey ed25519.PrivateKey, agentID, tenantID, hostname string) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         strings.TrimSpace(agentID),
			OrganizationalUnit: []string{strings.TrimSpace(tenantID)},
		},
	}
	if hostname = strings.TrimSpace(hostname); hostname != "" {
		template.DNSNames = []string{hostname}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create enrollment CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func bootstrapTLSConfig(caFile string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(caFile) == "" {
		return config, nil
	}
	roots, err := loadCertPool(caFile)
	if err != nil {
		return nil, err
	}
	config.RootCAs = roots
	return config, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(content) {
		return nil, errors.New("CA file contains no valid certificates")
	}
	return roots, nil
}

func decodeAndVerifyResponse(body []byte, privateKey ed25519.PrivateKey, agentID, tenantID string) (Response, error) {
	var response Response
	if err := json.Unmarshal(body, &response); err != nil {
		return Response{}, fmt.Errorf("decode enrollment response: %w", err)
	}
	if response.AgentID != agentID || response.TenantID != tenantID {
		return Response{}, errors.New("certificate response identity does not match request")
	}
	if err := verifyIssuedCertificate(response, privateKey, agentID); err != nil {
		return Response{}, err
	}
	return response, nil
}

func verifyIssuedCertificate(response Response, privateKey ed25519.PrivateKey, agentID string) error {
	certificateBlock, _ := pem.Decode([]byte(response.CertificatePEM))
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" {
		return errors.New("enrollment response contains an invalid client certificate")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse enrolled client certificate: %w", err)
	}
	issuedPublicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !issuedPublicKey.Equal(privateKey.Public()) {
		return errors.New("issued certificate public key does not match agent identity")
	}
	if certificate.Subject.CommonName != agentID {
		return errors.New("issued certificate common name does not match agent_id")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(response.CACertificatePEM)) {
		return errors.New("enrollment response contains an invalid CA certificate")
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("verify enrolled client certificate: %w", err)
	}
	return nil
}

func persistPolicySigningKey(path, content string) error {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}
	block, _ := pem.Decode([]byte(content))
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("policy signing trust root is not a valid public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse policy signing trust root: %w", err)
	}
	if _, ok := parsed.(ed25519.PublicKey); !ok {
		return errors.New("policy signing trust root must use Ed25519")
	}
	encoded := append([]byte(content), '\n')
	if existing, err := os.ReadFile(path); err == nil {
		if bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(encoded)) {
			return nil
		}
		return errors.New("policy signing trust root changed; explicit trust rotation is required")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing policy signing trust root: %w", err)
	}
	return atomicWrite(path, encoded, 0o644)
}

func readResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollmentResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read certificate response: %w", err)
	}
	return body, nil
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, mode); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := os.Chmod(temporary, mode); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("protect %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("install %s: %w", filepath.Base(path), err)
	}
	return nil
}
