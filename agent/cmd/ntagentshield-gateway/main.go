package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/paddman/NTAgentShield/internal/gateway"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	stateDir := flag.String("state-dir", "", "gateway PKI and state directory")
	listen := flag.String("listen", "127.0.0.1:9443", "gateway listen address")
	publicURL := flag.String("public-url", "", "public HTTPS URL returned to enrolled agents")
	clientCertificateTTL := flag.Duration("client-cert-ttl", 30*24*time.Hour, "client certificate lifetime")
	enrollmentClockSkew := flag.Duration("enrollment-clock-skew", 5*time.Minute, "allowed enrollment request clock skew")
	flag.Parse()
	if strings.TrimSpace(*stateDir) == "" || strings.TrimSpace(*publicURL) == "" {
		return errors.New("--state-dir and --public-url are required")
	}
	logger := log.New(os.Stderr, "ntagentshield-gateway ", log.LstdFlags|log.LUTC)
	server, err := gateway.NewServer(gateway.ServerConfig{
		StateDir:             *stateDir,
		Listen:               *listen,
		PublicURL:            *publicURL,
		ClientCertificateTTL: *clientCertificateTTL,
		EnrollmentClockSkew:  *enrollmentClockSkew,
	}, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Printf("starting listen=%s public_url=%s", *listen, *publicURL)
	return server.Run(ctx)
}
