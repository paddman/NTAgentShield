package tools

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/paddman/NTAgentShield/internal/model"
)

// ProcessTerminate is intentionally PID-scoped. It does not accept a process
// name or shell command, which keeps the response surface deterministic and
// prevents wildcard/process-name expansion from becoming a remote command path.
type ProcessTerminate struct{}

func (ProcessTerminate) Spec() Spec {
	return Spec{
		Name:        "process.terminate",
		Description: "Terminate one non-system process by exact PID after signed approval and local policy evaluation",
		Risk:        model.RiskContain,
	}
}

func (ProcessTerminate) Execute(_ context.Context, args map[string]interface{}) (interface{}, error) {
	pid := intArg(args, "pid", 0)
	if pid <= 4 {
		return nil, errors.New("pid must identify a non-system process greater than 4")
	}
	if pid == os.Getpid() {
		return nil, errors.New("refusing to terminate the NTAgentShield process")
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := process.Kill(); err != nil {
		return nil, fmt.Errorf("terminate process %d: %w", pid, err)
	}
	return map[string]interface{}{"pid": pid, "terminated": true}, nil
}
