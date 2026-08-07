package policyupdate

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

var ErrNotConfigured = errors.New("signed policy distribution is not configured")

type RunnerOptions struct {
	DataDir           string
	AgentID           string
	TenantID          string
	PolicyFile        string
	TransportEndpoint string
	CertFile          string
	KeyFile           string
	CAFile            string
	ServerName        string
	Timeout           time.Duration
	Interval          time.Duration
}

type Runner struct {
	manager  *Manager
	client   *Client
	interval time.Duration
}

func NewRunner(options RunnerOptions) (*Runner, error) {
	trustRoot := filepath.Join(options.DataDir, "policy-signing.pub")
	if _, err := os.Stat(trustRoot); errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotConfigured
	} else if err != nil {
		return nil, fmt.Errorf("inspect policy signing trust root: %w", err)
	}
	if options.Interval <= 0 {
		options.Interval = 5 * time.Minute
	}
	endpoint, err := EndpointFromTransport(options.TransportEndpoint)
	if err != nil {
		return nil, err
	}
	manager, err := NewManager(ManagerOptions{
		AgentID:         options.AgentID,
		TenantID:        options.TenantID,
		PolicyFile:      options.PolicyFile,
		TrustRootFile:   trustRoot,
		IdentityKeyFile: options.KeyFile,
		StateFile:       filepath.Join(options.DataDir, "policy-state.json"),
	})
	if err != nil {
		return nil, err
	}
	client, err := NewClient(ClientOptions{
		Endpoint:   endpoint,
		AgentID:    options.AgentID,
		TenantID:   options.TenantID,
		CertFile:   options.CertFile,
		KeyFile:    options.KeyFile,
		CAFile:     options.CAFile,
		ServerName: options.ServerName,
		Timeout:    options.Timeout,
	})
	if err != nil {
		return nil, err
	}
	return &Runner{manager: manager, client: client, interval: options.Interval}, nil
}

func (r *Runner) Sync(ctx context.Context) (ApplyResult, error) {
	bundle, err := r.client.Fetch(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	if bundle == nil {
		return ApplyResult{}, nil
	}
	return r.manager.Apply(*bundle)
}

func (r *Runner) Run(ctx context.Context, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	sync := func() {
		result, err := r.Sync(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				logger.Printf("signed policy sync rejected/error: %v", err)
			}
			return
		}
		if result.Applied {
			logger.Printf("signed policy applied epoch=%d version=%s digest=%s", result.Epoch, result.Version, result.Digest)
		}
	}
	sync()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sync()
		}
	}
}
