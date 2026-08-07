package tools

import "fmt"

func NewResponseRegistry(policyPath string, options ContainmentOptions) (*Registry, error) {
	registry, err := NewFoundationRegistry(policyPath, options.AllowedPaths)
	if err != nil {
		return nil, err
	}
	backend, err := newNetworkContainmentBackend(options)
	if err != nil {
		return nil, err
	}
	quarantine, err := NewFileQuarantine(options.AllowedPaths, options.DataDir, options.IdentityKeyFile)
	if err != nil {
		return nil, err
	}
	restore, err := NewFileRestore(options.AllowedPaths, options.DataDir, options.IdentityKeyFile)
	if err != nil {
		return nil, err
	}
	for _, tool := range []Tool{
		HostContainment{backend: backend},
		FirewallContainment{backend: backend},
		FileContainment{quarantine: quarantine, restore: restore},
	} {
		if err := registry.Register(tool); err != nil {
			return nil, fmt.Errorf("register containment tool %s: %w", tool.Spec().Name, err)
		}
	}
	return registry, nil
}
