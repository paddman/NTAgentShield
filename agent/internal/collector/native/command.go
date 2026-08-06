package native

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	maxCommandOutput = 32 * 1024 * 1024
	maxCommandError  = 64 * 1024
)

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *limitedBuffer) Write(content []byte) (int, error) {
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		return 0, errors.New("command output limit exceeded")
	}
	if len(content) > remaining {
		_, _ = b.buffer.Write(content[:remaining])
		return remaining, errors.New("command output limit exceeded")
	}
	return b.buffer.Write(content)
}

func (b *limitedBuffer) String() string {
	return b.buffer.String()
}

func runCommand(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(commandContext, name, args...)
	command.Env = append(os.Environ(), "LC_ALL=C")
	stdout := &limitedBuffer{limit: maxCommandOutput}
	stderr := &limitedBuffer{limit: maxCommandError}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if commandContext.Err() != nil {
			return "", commandContext.Err()
		}
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return "", fmt.Errorf("%s failed: %w: %s", name, err, message)
		}
		return "", fmt.Errorf("%s failed: %w", name, err)
	}
	return stdout.String(), nil
}
