package tools

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/paddman/NTAgentShield/internal/model"
)

type pathGuard struct {
	allowedRoots []string
}

func newPathGuard(roots []string) (*pathGuard, error) {
	if len(roots) == 0 {
		return nil, errors.New("at least one allowed root is required")
	}
	guard := &pathGuard{}
	for _, root := range roots {
		absolute, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		if evaluated, err := filepath.EvalSymlinks(absolute); err == nil {
			absolute = evaluated
		}
		guard.allowedRoots = append(guard.allowedRoots, filepath.Clean(absolute))
	}
	return guard, nil
}

func (g *pathGuard) resolve(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if evaluated, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = evaluated
	}
	absolute = filepath.Clean(absolute)
	for _, root := range g.allowedRoots {
		relative, err := filepath.Rel(root, absolute)
		if err != nil {
			continue
		}
		if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))) {
			return absolute, nil
		}
	}
	return "", fmt.Errorf("path %q is outside allowed roots", path)
}

type HostInfo struct{}

func (HostInfo) Spec() Spec {
	return Spec{Name: "host.info", Description: "Return non-sensitive local host and runtime information", Risk: model.RiskObserve}
}

func (HostInfo) Execute(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	hostname, _ := os.Hostname()
	return map[string]interface{}{
		"hostname": hostname,
		"goos":     runtime.GOOS,
		"goarch":   runtime.GOARCH,
		"cpus":     runtime.NumCPU(),
	}, nil
}

type FileStat struct{ guard *pathGuard }

type FileSHA256 struct{ guard *pathGuard }

type FileReadLines struct{ guard *pathGuard }

func NewFileStat(roots []string) (*FileStat, error) {
	guard, err := newPathGuard(roots)
	return &FileStat{guard: guard}, err
}

func NewFileSHA256(roots []string) (*FileSHA256, error) {
	guard, err := newPathGuard(roots)
	return &FileSHA256{guard: guard}, err
}

func NewFileReadLines(roots []string) (*FileReadLines, error) {
	guard, err := newPathGuard(roots)
	return &FileReadLines{guard: guard}, err
}

func (*FileStat) Spec() Spec {
	return Spec{Name: "file.stat", Description: "Return metadata for a file within an allowlisted root", Risk: model.RiskObserve}
}

func (t *FileStat) Execute(_ context.Context, args map[string]interface{}) (interface{}, error) {
	path, err := stringArg(args, "path")
	if err != nil {
		return nil, err
	}
	resolved, err := t.guard.resolve(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"path":          resolved,
		"size":          info.Size(),
		"mode":          info.Mode().String(),
		"modified_at":   info.ModTime().UTC(),
		"is_directory":  info.IsDir(),
		"is_executable": info.Mode()&0o111 != 0,
	}, nil
}

func (*FileSHA256) Spec() Spec {
	return Spec{Name: "file.sha256", Description: "Calculate SHA-256 for a file within an allowlisted root", Risk: model.RiskObserve}
}

func (t *FileSHA256) Execute(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	path, err := stringArg(args, "path")
	if err != nil {
		return nil, err
	}
	resolved, err := t.guard.resolve(path)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	hasher := sha256.New()
	buffer := make([]byte, 128*1024)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		count, readErr := file.Read(buffer)
		if count > 0 {
			_, _ = hasher.Write(buffer[:count])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	return map[string]interface{}{"path": resolved, "sha256": hex.EncodeToString(hasher.Sum(nil))}, nil
}

func (*FileReadLines) Spec() Spec {
	return Spec{Name: "file.read_lines", Description: "Read a bounded number of text lines from an allowlisted file", Risk: model.RiskObserve}
}

func (t *FileReadLines) Execute(_ context.Context, args map[string]interface{}) (interface{}, error) {
	path, err := stringArg(args, "path")
	if err != nil {
		return nil, err
	}
	resolved, err := t.guard.resolve(path)
	if err != nil {
		return nil, err
	}
	maxLines := intArg(args, "max_lines", 100)
	if maxLines < 1 || maxLines > 500 {
		return nil, errors.New("max_lines must be between 1 and 500")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 512*1024))
	scanner.Buffer(make([]byte, 64*1024), 512*1024)
	lines := make([]string, 0, maxLines)
	for scanner.Scan() && len(lines) < maxLines {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return map[string]interface{}{"path": resolved, "lines": lines, "truncated": len(lines) == maxLines}, nil
}

func stringArg(args map[string]interface{}, key string) (string, error) {
	value, ok := args[key]
	if !ok {
		return "", fmt.Errorf("%s is required", key)
	}
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("%s must be a non-empty string", key)
	}
	return text, nil
}

func intArg(args map[string]interface{}, key string, fallback int) int {
	value, ok := args[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		return typed
	case float64:
		return int(typed)
	default:
		return fallback
	}
}
