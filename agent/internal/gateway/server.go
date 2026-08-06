package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
	"github.com/paddman/NTAgentShield/internal/transport"
)

const (
	maxEnrollmentRequestBytes = 1024 * 1024
	maxEvidenceRequestBytes   = 8 * 1024 * 1024
)

type ServerConfig struct {
	StateDir          string
	Listen            string
	PublicURL         string
	ClientCertificateTTL time.Duration
	EnrollmentClockSkew time.Duration
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
}

type Server struct {
	config   ServerConfig
	pki      *PKI
	tokens   *TokenStore
	batches  *BatchStore
	logger   *log.Logger
	limiter  *enrollmentLimiter
	handler  http.Handler
}

func NewServer(config ServerConfig, logger *log.Logger) (*Server, error) {
	if strings.TrimSpace(config.StateDir) == "" {
		return nil, errors.New("gateway state directory is required")
	}
	if strings.TrimSpace(config.Listen) == "" {
		config.Listen = "127.0.0.1:9443"
	}
	publicURL, err := validatePublicURL(config.PublicURL)
	if err != nil {
		return nil, err
	}
	config.PublicURL = publicURL
	if config.ClientCertificateTTL == 0 {
		config.ClientCertificateTTL = 30 * 24 * time.Hour
	}
	if config.ClientCertificateTTL < time.Hour || config.ClientCertificateTTL > 90*24*time.Hour {
		return nil, errors.New("client certificate TTL must be between 1h and 90d")
	}
	if config.EnrollmentClockSkew == 0 {
		config.EnrollmentClockSkew = 5 * time.Minute
	}
	if config.EnrollmentClockSkew < time.Minute || config.EnrollmentClockSkew > 15*time.Minute {
		return nil, errors.New("enrollment clock skew must be between 1m and 15m")
	}
	if config.ReadHeaderTimeout == 0 {
		config.ReadHeaderTimeout = 10 * time.Second
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 60 * time.Second
	}
	if logger == nil {
		logger = log.Default()
	}
	pki, err := LoadPKI(config.StateDir)
	if err != nil {
		return nil, err
	}
	tokens, err := OpenTokenStore(config.StateDir)
	if err != nil {
		return nil, err
	}
	batches, err := OpenBatchStore(config.StateDir)
	if err != nil {
		return nil, err
	}
	server := &Server{
		config:  config,
		pki:     pki,
		tokens:  tokens,
		batches: batches,
		logger:  logger,
		limiter: newEnrollmentLimiter(30, time.Minute),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.handleHealth)
	mux.HandleFunc("POST /v1/enrollment/bootstrap", server.handleBootstrap)
	mux.HandleFunc("POST /v1/agent/events", server.handleEvents)
	server.handler = server.securityHeaders(mux)
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) TLSConfig() *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(s.pki.RootCertificate)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{s.pki.ServerTLS},
		ClientCAs:    roots,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		NextProtos:   []string{"h2", "http/1.1"},
	}
}

func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.config.Listen, err)
	}
	tlsListener := tls.NewListener(listener, s.TLSConfig())
	httpServer := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: s.config.ReadHeaderTimeout,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       s.config.IdleTimeout,
		MaxHeaderBytes:    32 * 1024,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.Serve(tlsListener)
	}()
	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shutdown gateway: %w", err)
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) handleHealth(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"protocol": enrollment.ProtocolVersion,
		"time":     time.Now().UTC(),
	})
}

func (s *Server) handleBootstrap(response http.ResponseWriter, request *http.Request) {
	remoteIP := requestRemoteIP(request)
	if !s.limiter.Allow(remoteIP, time.Now().UTC()) {
		writeAPIError(response, http.StatusTooManyRequests, "enrollment_rate_limited")
		return
	}
	var bootstrap enrollment.BootstrapRequest
	if err := decodeStrictJSON(response, request, maxEnrollmentRequestBytes, &bootstrap); err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_enrollment_request")
		return
	}
	if bootstrap.Version != enrollment.ProtocolVersion {
		writeAPIError(response, http.StatusBadRequest, "unsupported_enrollment_version")
		return
	}
	if err := enrollment.ValidateIdentity("agent_id", bootstrap.AgentID); err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_agent_identity")
		return
	}
	if bootstrap.ExpectedTenantID != "" {
		if err := enrollment.ValidateIdentity("expected_tenant_id", bootstrap.ExpectedTenantID); err != nil {
			writeAPIError(response, http.StatusBadRequest, "invalid_tenant_identity")
			return
		}
	}
	now := time.Now().UTC()
	if bootstrap.RequestedAt.IsZero() || bootstrap.RequestedAt.Before(now.Add(-s.config.EnrollmentClockSkew)) || bootstrap.RequestedAt.After(now.Add(s.config.EnrollmentClockSkew)) {
		writeAPIError(response, http.StatusBadRequest, "enrollment_clock_skew")
		return
	}
	if !validNonce(bootstrap.Nonce) {
		writeAPIError(response, http.StatusBadRequest, "invalid_enrollment_nonce")
		return
	}
	csr, err := parseCSR([]byte(bootstrap.CSRPEM))
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_certificate_request")
		return
	}
	publicKeyHash, err := enrollment.PublicKeyHash(csr.PublicKey)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_certificate_public_key")
		return
	}
	redeemed, err := s.tokens.Redeem(bootstrap.EnrollmentToken, bootstrap.AgentID, publicKeyHash, now, func(tenantID string) (IssuedIdentity, error) {
		if bootstrap.ExpectedTenantID != "" && bootstrap.ExpectedTenantID != tenantID {
			return IssuedIdentity{}, errors.New("enrollment token tenant does not match endpoint expectation")
		}
		certificatePEM, certificate, issueErr := s.pki.IssueClientCertificate(csr, tenantID, bootstrap.AgentID, s.config.ClientCertificateTTL, now)
		if issueErr != nil {
			return IssuedIdentity{}, issueErr
		}
		return IssuedIdentity{
			CertificatePEM:    string(certificatePEM),
			CertificateSerial: certificate.SerialNumber.String(),
			ExpiresAt:         certificate.NotAfter.UTC(),
		}, nil
	})
	if err != nil {
		s.logger.Printf("enrollment rejected remote_ip=%s agent_id=%s reason=%s", remoteIP, bootstrap.AgentID, enrollmentErrorCode(err))
		writeAPIError(response, http.StatusUnauthorized, enrollmentErrorCode(err))
		return
	}
	issuedAt := now
	if redeemed.Entry.ConsumedAt != nil {
		issuedAt = redeemed.Entry.ConsumedAt.UTC()
	}
	status := http.StatusCreated
	if redeemed.Reused {
		status = http.StatusOK
	}
	result := enrollment.BootstrapResponse{
		Version:           enrollment.ProtocolVersion,
		TenantID:          redeemed.Entry.TenantID,
		AgentID:           redeemed.Entry.IssuedAgentID,
		CertificatePEM:    redeemed.Entry.IssuedCertificatePEM,
		CAPEM:             string(s.pki.RootPEM),
		CertificateSerial: redeemed.Entry.IssuedCertificateSerial,
		IssuedAt:          issuedAt,
		ExpiresAt:         redeemed.Entry.IssuedCertificateExpiresAt.UTC(),
		ControlPlaneURL:   s.config.PublicURL,
	}
	s.logger.Printf("enrollment issued tenant_id=%s agent_id=%s reused=%t remote_ip=%s", result.TenantID, result.AgentID, redeemed.Reused, remoteIP)
	writeJSON(response, status, result)
}

func (s *Server) handleEvents(response http.ResponseWriter, request *http.Request) {
	certificate, err := verifiedClientCertificate(request)
	if err != nil {
		writeAPIError(response, http.StatusUnauthorized, "mutual_tls_required")
		return
	}
	tenantID, agentID, err := enrollment.ParseSPIFFEIdentity(certificate)
	if err != nil {
		writeAPIError(response, http.StatusForbidden, "invalid_certificate_identity")
		return
	}
	var batch transport.Batch
	if err := decodeStrictJSON(response, request, maxEvidenceRequestBytes, &batch); err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_evidence_batch")
		return
	}
	if batch.TenantID != tenantID || batch.AgentID != agentID {
		writeAPIError(response, http.StatusForbidden, "batch_certificate_identity_mismatch")
		return
	}
	if batch.CreatedAt.After(time.Now().UTC().Add(5 * time.Minute)) {
		writeAPIError(response, http.StatusBadRequest, "batch_timestamp_in_future")
		return
	}
	receipt, err := s.batches.Accept(batch, certificate.SerialNumber.String(), time.Now().UTC())
	if err != nil {
		switch {
		case errors.Is(err, ErrSequenceGap), errors.Is(err, ErrSequenceFork), errors.Is(err, ErrPreviousHash):
			writeAPIError(response, http.StatusConflict, sequenceErrorCode(err))
		default:
			s.logger.Printf("evidence batch rejected tenant_id=%s agent_id=%s sequence=%d reason=%v", tenantID, agentID, batch.Sequence, err)
			writeAPIError(response, http.StatusBadRequest, "invalid_evidence_batch")
		}
		return
	}
	status := http.StatusAccepted
	if receipt.Status == "duplicate" {
		status = http.StatusOK
	}
	writeJSON(response, status, receipt)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(response, request)
	})
}

func validatePublicURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse gateway public URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("gateway public URL must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	return parsed.String(), nil
}

func verifiedClientCertificate(request *http.Request) (*x509.Certificate, error) {
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 {
		return nil, errors.New("verified client certificate is missing")
	}
	certificate := request.TLS.PeerCertificates[0]
	if certificate.IsCA {
		return nil, errors.New("client certificate must not be a CA")
	}
	return certificate, nil
}

func parseCSR(content []byte) (*x509.CertificateRequest, error) {
	block, remaining := pem.Decode(content)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(remaining)) != 0 {
		return nil, errors.New("CSR PEM must contain exactly one certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	return csr, nil
}

func decodeStrictJSON(response http.ResponseWriter, request *http.Request, maximum int64, target interface{}) error {
	request.Body = http.MaxBytesReader(response, request.Body, maximum)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request contains multiple JSON values")
		}
		return err
	}
	return nil
}

func validNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func writeJSON(response http.ResponseWriter, status int, value interface{}) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeAPIError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]string{"error": code})
}

func requestRemoteIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

func enrollmentErrorCode(err error) string {
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "expired"):
		return "enrollment_token_expired"
	case strings.Contains(text, "already been consumed"):
		return "enrollment_token_consumed"
	case strings.Contains(text, "not valid for this agent"):
		return "enrollment_agent_mismatch"
	case strings.Contains(text, "tenant"):
		return "enrollment_tenant_mismatch"
	default:
		return "enrollment_token_invalid"
	}
}

func sequenceErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrSequenceGap):
		return "batch_sequence_gap"
	case errors.Is(err, ErrSequenceFork):
		return "batch_sequence_fork"
	default:
		return "batch_previous_hash_mismatch"
	}
}

type enrollmentLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	attempts map[string]rateWindow
}

type rateWindow struct {
	StartedAt time.Time
	Count     int
}

func newEnrollmentLimiter(limit int, window time.Duration) *enrollmentLimiter {
	return &enrollmentLimiter{limit: limit, window: window, attempts: map[string]rateWindow{}}
}

func (l *enrollmentLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.attempts[key]
	if entry.StartedAt.IsZero() || now.Sub(entry.StartedAt) >= l.window {
		entry = rateWindow{StartedAt: now, Count: 0}
	}
	entry.Count++
	l.attempts[key] = entry
	if len(l.attempts) > 10000 {
		for currentKey, current := range l.attempts {
			if now.Sub(current.StartedAt) >= 2*l.window {
				delete(l.attempts, currentKey)
			}
		}
	}
	return entry.Count <= l.limit
}
