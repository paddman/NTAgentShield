package filetail

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/paddman/NTAgentShield/internal/config"
	"github.com/paddman/NTAgentShield/internal/model"
	"github.com/paddman/NTAgentShield/internal/parser"
)

const maxReadPerPoll = 8 * 1024 * 1024

type Tailer struct {
	mu      sync.Mutex
	cfg     config.Source
	parser  parser.Parser
	offsets map[string]int64
	seen    map[string]bool
}

func New(cfg config.Source) (*Tailer, error) {
	logParser, err := parser.New(cfg.Format, cfg.ID)
	if err != nil {
		return nil, err
	}
	return &Tailer{cfg: cfg, parser: logParser, offsets: map[string]int64{}, seen: map[string]bool{}}, nil
}

func (t *Tailer) Poll() ([]model.Event, []error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	paths, err := filepath.Glob(t.cfg.Path)
	if err != nil {
		return nil, []error{fmt.Errorf("source %s glob: %w", t.cfg.ID, err)}
	}
	if len(paths) == 0 && !strings.ContainsAny(t.cfg.Path, "*?[") {
		paths = []string{t.cfg.Path}
	}
	var events []model.Event
	var errorsFound []error
	remaining := t.cfg.MaxBatch
	for _, path := range paths {
		if remaining <= 0 {
			break
		}
		collected, errs := t.pollFile(path, remaining)
		events = append(events, collected...)
		errorsFound = append(errorsFound, errs...)
		remaining -= len(collected)
	}
	return events, errorsFound
}

func (t *Tailer) pollFile(path string, maxEvents int) ([]model.Event, []error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("stat %s: %w", path, err)}
	}
	if info.IsDir() {
		return nil, []error{fmt.Errorf("source path %s is a directory", path)}
	}
	offset, known := t.offsets[path]
	if !known {
		if t.cfg.FromStart {
			offset = 0
		} else {
			offset = info.Size()
		}
		t.offsets[path] = offset
		t.seen[path] = true
		if !t.cfg.FromStart {
			return nil, nil
		}
	}
	if info.Size() < offset {
		offset = 0
		t.offsets[path] = 0
	}
	if info.Size() == offset {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, []error{fmt.Errorf("open %s: %w", path, err)}
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, []error{fmt.Errorf("seek %s: %w", path, err)}
	}
	limit := info.Size() - offset
	if limit > maxReadPerPoll {
		limit = maxReadPerPoll
	}
	buffer := make([]byte, limit)
	count, err := io.ReadFull(file, buffer)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, []error{fmt.Errorf("read %s: %w", path, err)}
	}
	buffer = buffer[:count]
	lastNewline := bytes.LastIndexByte(buffer, '\n')
	if lastNewline < 0 {
		return nil, nil
	}
	complete := buffer[:lastNewline+1]
	segments := bytes.SplitAfter(complete, []byte{'\n'})
	var events []model.Event
	var errorsFound []error
	consumed := 0
	lineNumber := int64(0)
	for _, segment := range segments {
		if len(segment) == 0 {
			continue
		}
		if len(events) >= maxEvents {
			break
		}
		consumed += len(segment)
		lineNumber++
		line := strings.TrimSuffix(strings.TrimSuffix(string(segment), "\n"), "\r")
		event, parseErr := t.parser.Parse(line)
		if parseErr != nil {
			errorsFound = append(errorsFound, fmt.Errorf("parse %s line %d: %w", path, lineNumber, parseErr))
			continue
		}
		if event == nil {
			continue
		}
		if event.Trust == "" {
			event.Trust = t.cfg.Trust
		}
		event.Provenance.OriginalPath = path
		event.Provenance.LineNumber = lineNumber
		hash := sha256.Sum256([]byte(line))
		event.Provenance.ContentSHA256 = hex.EncodeToString(hash[:])
		event.Prepare()
		events = append(events, *event)
	}
	t.offsets[path] = offset + int64(consumed)
	return events, errorsFound
}
