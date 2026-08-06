package outbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	lockHeartbeatInterval = 15 * time.Second
	lockStaleAfter        = 2 * time.Minute
)

type processLock struct {
	path      string
	heartbeat string
	stop      chan struct{}
	done      chan struct{}
	once      sync.Once
}

func acquireProcessLock(directory string) (*processLock, error) {
	path := filepath.Join(directory, ".outbox.lock")
	for attempt := 0; attempt < 2; attempt++ {
		err := os.Mkdir(path, 0o700)
		if err == nil {
			heartbeat := filepath.Join(path, "heartbeat")
			content := []byte("pid=" + strconv.Itoa(os.Getpid()) + "\nstarted_at=" + time.Now().UTC().Format(time.RFC3339Nano) + "\n")
			if writeErr := os.WriteFile(heartbeat, content, 0o600); writeErr != nil {
				_ = os.RemoveAll(path)
				return nil, fmt.Errorf("write outbox lock heartbeat: %w", writeErr)
			}
			lock := &processLock{path: path, heartbeat: heartbeat, stop: make(chan struct{}), done: make(chan struct{})}
			go lock.runHeartbeat()
			return lock, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("acquire outbox process lock: %w", err)
		}
		info, statErr := os.Stat(filepath.Join(path, "heartbeat"))
		if statErr == nil && time.Since(info.ModTime()) > lockStaleAfter {
			if removeErr := os.RemoveAll(path); removeErr != nil {
				return nil, fmt.Errorf("remove stale outbox process lock: %w", removeErr)
			}
			continue
		}
		return nil, errors.New("another NTAgentShield outbox process is active")
	}
	return nil, errors.New("unable to acquire outbox process lock")
}

func (l *processLock) runHeartbeat() {
	defer close(l.done)
	ticker := time.NewTicker(lockHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case now := <-ticker.C:
			_ = os.Chtimes(l.heartbeat, now, now)
		}
	}
}

func (l *processLock) Close() error {
	if l == nil {
		return nil
	}
	var result error
	l.once.Do(func() {
		close(l.stop)
		<-l.done
		if err := os.RemoveAll(l.path); err != nil {
			result = fmt.Errorf("release outbox process lock: %w", err)
		}
	})
	return result
}
