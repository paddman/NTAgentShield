package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	endpoint := flag.String("endpoint", "", "gateway HTTPS base URL")
	agentID := flag.String("agent-id", "", "agent identity")
	tenantID := flag.String("tenant", "", "expected tenant identity")
	stateDir := flag.String("state-dir", "", "endpoint identity state directory")
	bootstrapCA := flag.String("bootstrap-ca", "", "pinned gateway CA certificate")
	serverName := flag.String("server-name", "", "optional TLS server-name override")
	tokenEnvironment := flag.String("token-env", "NTAGENTSHIELD_ENROLLMENT_TOKEN", "environment variable containing the one-time enrollment token")
	timeout := flag.Duration("timeout", 30*time.Second, "enrollment request timeout")
	flag.Parse()
	for name, value := range map[string]string{
		"--endpoint":     *endpoint,
		"--agent-id":     *agentID,
		"--tenant":       *tenantID,
		"--state-dir":    *stateDir,
		"--bootstrap-ca": *bootstrapCA,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if strings.TrimSpace(*tokenEnvironment) == "" {
		return errors.New("--token-env must name an environment variable")
	}
	token := os.Getenv(*tokenEnvironment)
	if token == "" {
		return fmt.Errorf("environment variable %s is empty", *tokenEnvironment)
	}
	_ = os.Unsetenv(*tokenEnvironment)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	metadata, err := enrollment.Enroll(ctx, enrollment.ClientOptions{
		Endpoint:         *endpoint,
		EnrollmentToken: token,
		AgentID:          *agentID,
		ExpectedTenantID: *tenantID,
		StateDir:         *stateDir,
		BootstrapCAPath:  *bootstrapCA,
		ServerName:       *serverName,
		Timeout:          *timeout,
	})
	token = ""
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(metadata)
}
