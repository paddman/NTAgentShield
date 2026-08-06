package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
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
	"strings"
	"time"
)

const maxEnrollmentResponseBytes = 2 * 1024 * 1024

type ClientOptions struct {
	Endpoint         string
	EnrollmentToken string
	AgentID          string
	ExpectedTenantID string
	StateDir         string
	BootstrapCAPath  string
	ServerName       string
	Timeout          time.Duration
}

func Enroll(ctx context.Context, options ClientOptions) (Metadata, error) {
	if err := ValidateIdentity("agent_id", options.AgentID); err != nil {
		return Metadata{}, err
	}
	if options.ExpectedTenantID != "" {
		if err := ValidateIdentity("expected_tenant_id", options.ExpectedTenantID); err != nil {
			return Metadata{}, err
		}
	}
	if len(options.EnrollmentToken) < 32 || len(options.EnrollmentToken) > 512 {
		return Metadata{}, errors.New("enrollment token length is invalid")
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	if options.Timeout < time.Second || options.Timeout > 2*time.Minute {
		return Metadata{}, errors.New("enrollment timeout must be between 1s and 2m")
	}
	endpoint, err := enrollmentEndpoint(options.Endpoint)
	if err != nil {
		return Metadata{}, err
	}
	bootstrapCA, err := os.ReadFile(options.BootstrapCAPath)
	if err != nil {
		return Metadata{}, fmt.Errorf("read bootstrap CA: %w", err)
	}
	bootstrapCertificates, err := parseCertificates(bootstrapCA)
	if err != nil {
		return Metadata{}, fmt.Errorf("parse bootstrap CA: %w", err)
	}
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(bootstrapCA) {
		return Metadata{}, errors.New("bootstrap CA file contains no trusted certificate")
	}
	key, paths, err := EnsurePrivateKey(options.StateDir)
	if err != nil {
		return Metadata{}, err
	}
	csrPEM, err := CreateCSR(key, options.AgentID)
	if err != nil {
		return Metadata{}, err
	}
	nonce, err := randomNonce()
	if err != nil {
		return Metadata{}, err
	}
	requestBody := BootstrapRequest{
		Version:          ProtocolVersion,
		EnrollmentToken:  options.EnrollmentToken,
		AgentID:          options.AgentID,
		ExpectedTenantID: options.ExpectedTenantID,
		CSRPEM:           string(csrPEM),
		Nonce:            nonce,
		RequestedAt:      time.Now().UTC(),
	}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		return Metadata{}, fmt.Errorf("encode enrollment request: %w", err)
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    rootPool,
		ServerName: strings.TrimSpace(options.ServerName),
	}
	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: options.Timeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("enrollment redirects are not allowed")
		},
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return Metadata{}, fmt.Errorf("create enrollment request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("User-Agent", "NTAgentShield-Enrollment/1")
	response, err := client.Do(httpRequest)
	if err != nil {
		return Metadata{}, fmt.Errorf("perform enrollment request: %w", err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, maxEnrollmentResponseBytes+1))
	if err != nil {
		return Metadata{}, fmt.Errorf("read enrollment response: %w", err)
	}
	if len(content) > maxEnrollmentResponseBytes {
		return Metadata{}, errors.New("enrollment response exceeds size limit")
	}
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return Metadata{}, fmt.Errorf("enrollment server returned HTTP %d: %s", response.StatusCode, safeServerError(content))
	}
	var result BootstrapResponse
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return Metadata{}, fmt.Errorf("decode enrollment response: %w", err)
	}
	metadata, certificatePEM, caPEM, err := validateEnrollmentResponse(result, key, options.AgentID, options.ExpectedTenantID, bootstrapCertificates)
	if err != nil {
		return Metadata{}, err
	}
	if err := SaveEnrollment(paths, certificatePEM, caPEM, metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func enrollmentEndpoint(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("parse enrollment endpoint: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("enrollment endpoint must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("enrollment endpoint must not contain credentials, query, or fragment")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/v1/enrollment/bootstrap"
	return parsed, nil
}

func validateEnrollmentResponse(result BootstrapResponse, key *ecdsa.PrivateKey, agentID, expectedTenantID string, bootstrapCertificates []*x509.Certificate) (Metadata, []byte, []byte, error) {
	if result.Version != ProtocolVersion {
		return Metadata{}, nil, nil, fmt.Errorf("unsupported enrollment response version %d", result.Version)
	}
	if result.AgentID != agentID {
		return Metadata{}, nil, nil, errors.New("enrollment response agent identity mismatch")
	}
	if err := ValidateIdentity("tenant_id", result.TenantID); err != nil {
		return Metadata{}, nil, nil, err
	}
	if expectedTenantID != "" && result.TenantID != expectedTenantID {
		return Metadata{}, nil, nil, errors.New("enrollment response tenant identity mismatch")
	}
	certificatePEM := []byte(result.CertificatePEM)
	caPEM := []byte(result.CAPEM)
	certificates, err := parseCertificates(certificatePEM)
	if err != nil || len(certificates) != 1 {
		return Metadata{}, nil, nil, errors.New("enrollment response must contain exactly one endpoint certificate")
	}
	caCertificates, err := parseCertificates(caPEM)
	if err != nil || len(caCertificates) == 0 {
		return Metadata{}, nil, nil, errors.New("enrollment response CA chain is invalid")
	}
	if !certificateInSet(caCertificates[0], bootstrapCertificates) {
		return Metadata{}, nil, nil, errors.New("enrollment response CA does not match the pinned bootstrap CA")
	}
	certificate := certificates[0]
	publicKeyHash, err := PublicKeyHash(certificate.PublicKey)
	if err != nil {
		return Metadata{}, nil, nil, err
	}
	expectedPublicKeyHash, err := PublicKeyHash(&key.PublicKey)
	if err != nil {
		return Metadata{}, nil, nil, err
	}
	if publicKeyHash != expectedPublicKeyHash {
		return Metadata{}, nil, nil, errors.New("issued certificate public key does not match the endpoint identity key")
	}
	roots := x509.NewCertPool()
	for _, caCertificate := range caCertificates {
		roots.AddCert(caCertificate)
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now().UTC()}); err != nil {
		return Metadata{}, nil, nil, fmt.Errorf("verify issued endpoint certificate: %w", err)
	}
	tenantID, certificateAgentID, err := ParseSPIFFEIdentity(certificate)
	if err != nil {
		return Metadata{}, nil, nil, err
	}
	if tenantID != result.TenantID || certificateAgentID != agentID {
		return Metadata{}, nil, nil, errors.New("issued certificate SPIFFE identity mismatch")
	}
	controlPlaneURL, err := url.Parse(result.ControlPlaneURL)
	if err != nil || controlPlaneURL.Scheme != "https" || controlPlaneURL.Host == "" || controlPlaneURL.User != nil {
		return Metadata{}, nil, nil, errors.New("control plane URL in enrollment response is invalid")
	}
	if result.ExpiresAt.IsZero() || !result.ExpiresAt.Equal(certificate.NotAfter) {
		return Metadata{}, nil, nil, errors.New("certificate expiry metadata mismatch")
	}
	metadata := Metadata{
		Version:           ProtocolVersion,
		TenantID:          tenantID,
		AgentID:           certificateAgentID,
		SPIFFEID:          certificate.URIs[0].String(),
		CertificateSerial: certificate.SerialNumber.String(),
		IssuedAt:          result.IssuedAt.UTC(),
		ExpiresAt:         certificate.NotAfter.UTC(),
		ControlPlaneURL:   controlPlaneURL.String(),
		CAFingerprint:     CertificateFingerprint(caCertificates[0]),
	}
	return metadata, certificatePEM, caPEM, nil
}

func parseCertificates(content []byte) ([]*x509.Certificate, error) {
	certificates := make([]*x509.Certificate, 0)
	remaining := content
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, errors.New("certificate PEM contains no certificates")
	}
	return certificates, nil
}

func certificateInSet(target *x509.Certificate, values []*x509.Certificate) bool {
	if target == nil {
		return false
	}
	fingerprint := CertificateFingerprint(target)
	for _, value := range values {
		if CertificateFingerprint(value) == fingerprint {
			return true
		}
	}
	return false
}

func randomNonce() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate enrollment nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func safeServerError(content []byte) string {
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
