package native

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/config"
)

func New(source config.NativeSource, dataDir string) (Source, error) {
	timeout, err := time.ParseDuration(source.CommandTimeout)
	if err != nil {
		return nil, fmt.Errorf("native source %s command timeout: %w", source.ID, err)
	}
	cursor, err := openCursor(filepath.Clean(dataDir), source.ID, strings.ToLower(source.Kind))
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(source.Kind) {
	case "windows_eventlog", "wineventlog", "sysmon":
		if runtime.GOOS != "windows" {
			return nil, fmt.Errorf("%w: %s requires Windows", ErrUnsupportedPlatform, source.Kind)
		}
		return &windowsEventLogSource{config: source, timeout: timeout, cursor: cursor}, nil
	case "journald", "journalctl":
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("%w: %s requires Linux", ErrUnsupportedPlatform, source.Kind)
		}
		return &journalSource{config: source, timeout: timeout, cursor: cursor}, nil
	case "auditd", "linux_auditd":
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("%w: %s requires Linux", ErrUnsupportedPlatform, source.Kind)
		}
		return newAuditSource(source, cursor)
	default:
		return nil, errors.New("unsupported native telemetry source kind")
	}
}
