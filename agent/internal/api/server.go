package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
)

type StatusProvider func() interface{}
type IngestFunc func(context.Context, model.Event) ([]model.Finding, error)

type Server struct {
	listen string
	token  string
	status StatusProvider
	ingest IngestFunc
}

func New(listen, token string, status StatusProvider, ingest IngestFunc) *Server {
	return &Server{listen: listen, token: token, status: status, ingest: ingest}
}

func EnsureToken(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err == nil {
		token := strings.TrimSpace(string(content))
		if len(token) < 32 {
			return "", errors.New("existing API token is too short")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return "", fmt.Errorf("secure API token permissions: %w", err)
		}
		return token, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read API token: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create API token directory: %w", err)
	}
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate API token: %w", err)
	}
	token := hex.EncodeToString(buffer)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write API token: %w", err)
	}
	return token, nil
}

func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("listen on local API: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("GET /v1/status", s.auth(http.HandlerFunc(s.statusHandler)))
	mux.Handle("POST /v1/events", s.auth(http.HandlerFunc(s.ingestHandler)))
	server := &http.Server{
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	errCh := make(chan error, 1)
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
			return
		}
		errCh <- nil
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case serveErr := <-errCh:
		return serveErr
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) statusHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.status())
}

func (s *Server) ingestHandler(w http.ResponseWriter, r *http.Request) {
	if s.ingest == nil {
		writeError(w, http.StatusNotImplemented, "event ingestion is disabled")
		return
	}
	body := http.MaxBytesReader(w, r.Body, 1024*1024)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var event model.Event
	if err := decoder.Decode(&event); err != nil {
		writeError(w, http.StatusBadRequest, "invalid event: "+err.Error())
		return
	}
	if err := ensureSingleJSONValue(decoder); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Remote callers cannot claim trusted provenance. Authentication identifies the sender;
	// it does not turn attacker-controlled payloads into instructions.
	event.Trust = model.TrustUntrustedNetwork
	event.Provenance.Source = "local-api"
	event.Provenance.Collector = "http/event-ingest"
	event.Prepare()
	findings, err := s.ingest(r.Context(), event)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ingest failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"event_id": event.ID, "findings": findings})
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if provided == "" || len(provided) != len(s.token) || subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func ensureSingleJSONValue(decoder *json.Decoder) error {
	var extra interface{}
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return errors.New("request must contain exactly one JSON value")
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
