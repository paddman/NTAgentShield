package tools

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestProcessTerminateRejectsSystemAndAgentPID(t *testing.T) {
	tool := ProcessTerminate{}
	if _, err := tool.Execute(context.Background(), map[string]interface{}{"pid": 1}); err == nil || !strings.Contains(err.Error(), "non-system") {
		t.Fatalf("expected system PID rejection, got %v", err)
	}
	if _, err := tool.Execute(context.Background(), map[string]interface{}{"pid": os.Getpid()}); err == nil || !strings.Contains(err.Error(), "NTAgentShield") {
		t.Fatalf("expected self-termination rejection, got %v", err)
	}
}
