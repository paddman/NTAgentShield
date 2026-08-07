package tools

import (
	"github.com/paddman/NTAgentShield/internal/policy"
)

func NewFoundationRegistry(policyPath string, allowedPaths []string) (*Registry, error) {
	activePolicy, err := policy.Load(policyPath)
	if err != nil {
		return nil, err
	}
	registry := NewRegistry(policy.New(activePolicy))
	if err := registry.Register(HostInfo{}); err != nil {
		return nil, err
	}
	if err := registry.Register(ProcessTerminate{}); err != nil {
		return nil, err
	}
	stat, err := NewFileStat(allowedPaths)
	if err != nil {
		return nil, err
	}
	hash, err := NewFileSHA256(allowedPaths)
	if err != nil {
		return nil, err
	}
	lines, err := NewFileReadLines(allowedPaths)
	if err != nil {
		return nil, err
	}
	for _, tool := range []Tool{stat, hash, lines} {
		if err := registry.Register(tool); err != nil {
			return nil, err
		}
	}
	return registry, nil
}
