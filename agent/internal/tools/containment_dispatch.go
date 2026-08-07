package tools

import (
	"context"
	"errors"
	"strings"

	"github.com/paddman/NTAgentShield/internal/model"
)

// HostContainment keeps the Control Plane catalog stable while making isolation
// reversible through an exact signed argument. operation defaults to isolate.
type HostContainment struct{ backend networkContainmentBackend }

type FirewallContainment struct{ backend networkContainmentBackend }

type FileContainment struct {
	quarantine *FileQuarantine
	restore    *FileRestore
}

func (HostContainment) Spec() Spec {
	return Spec{Name: "host.isolate", Description: "Isolate or release host networking through one signed typed containment action", Risk: model.RiskContain}
}
func (FirewallContainment) Spec() Spec {
	return Spec{Name: "firewall.block", Description: "Block or unblock one exact remote IP through one signed typed containment action", Risk: model.RiskContain}
}
func (FileContainment) Spec() Spec {
	return Spec{Name: "file.quarantine", Description: "Quarantine or restore one allowlisted file through one signed typed containment action", Risk: model.RiskContain}
}

func (t HostContainment) Execute(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if err := rejectUnknownArgs(args, "operation"); err != nil {
		return nil, err
	}
	operation, err := containmentOperation(args, "isolate")
	if err != nil {
		return nil, err
	}
	switch operation {
	case "isolate":
		return t.backend.Isolate(ctx)
	case "release":
		return t.backend.Release(ctx)
	default:
		return nil, errors.New("host.isolate operation must be isolate or release")
	}
}

func (t FirewallContainment) Execute(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if err := rejectUnknownArgs(args, "operation", "remote_ip"); err != nil {
		return nil, err
	}
	operation, err := containmentOperation(args, "block")
	if err != nil {
		return nil, err
	}
	text, err := stringArg(args, "remote_ip")
	if err != nil {
		return nil, err
	}
	address, err := normalizeRemoteIP(text)
	if err != nil {
		return nil, err
	}
	switch operation {
	case "block":
		return t.backend.Block(ctx, address)
	case "unblock":
		return t.backend.Unblock(ctx, address)
	default:
		return nil, errors.New("firewall.block operation must be block or unblock")
	}
}

func (t FileContainment) Execute(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	operation, err := containmentOperation(args, "quarantine")
	if err != nil {
		return nil, err
	}
	switch operation {
	case "quarantine":
		if err := rejectUnknownArgs(args, "operation", "path", "expected_sha256"); err != nil {
			return nil, err
		}
		return t.quarantine.Execute(ctx, args)
	case "restore":
		if err := rejectUnknownArgs(args, "operation", "quarantine_id"); err != nil {
			return nil, err
		}
		return t.restore.Execute(ctx, args)
	default:
		return nil, errors.New("file.quarantine operation must be quarantine or restore")
	}
}

func containmentOperation(args map[string]interface{}, fallback string) (string, error) {
	value, ok := args["operation"]
	if !ok {
		return fallback, nil
	}
	text, ok := value.(string)
	if !ok {
		return "", errors.New("operation must be a string")
	}
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return fallback, nil
	}
	return text, nil
}
