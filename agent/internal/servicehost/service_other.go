//go:build !windows

package servicehost

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// Run executes the Agent under a signal-aware console host on non-Windows systems.
func Run(_ string, run func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx)
}
