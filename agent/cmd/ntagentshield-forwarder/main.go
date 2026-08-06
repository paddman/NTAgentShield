package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/paddman/NTAgentShield/internal/outbox"
	"github.com/paddman/NTAgentShield/internal/transport"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("ntagentshield-forwarder", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	identityDir := flags.String("identity-dir", "", "enrolled endpoint identity directory")
	journalPath := flags.String("journal", "", "hash-chained evidence journal path")
	outboxDir := flags.String("outbox-dir", "", "durable outbox state and spool directory")
	endpoint := flags.String("endpoint", "", "optional gateway HTTPS base URL override")
	serverName := flags.String("server-name", "", "optional TLS server-name override")
	pollInterval := flags.Duration("poll-interval", 5*time.Second, "journal and delivery polling interval")
	maxPending := flags.Int("max-pending-batches", 1024, "maximum durable pending batches")
	maxSpoolBytes := flags.Int64("max-spool-bytes", 1024*1024*1024, "maximum spool bytes before backpressure")
	maxBatchItems := flags.Int("max-batch-items", 256, "maximum journal records per batch")
	maxBatchBytes := flags.Int64("max-batch-bytes", 4*1024*1024, "maximum encoded batch bytes")
	baseBackoff := flags.Duration("base-backoff", 2*time.Second, "initial delivery retry delay")
	maxBackoff := flags.Duration("max-backoff", 5*time.Minute, "maximum delivery retry delay")
	requestTimeout := flags.Duration("request-timeout", 30*time.Second, "gateway request timeout")
	statusPath := flags.String("status-file", "", "optional atomic JSON status file")
	once := flags.Bool("once", false, "run one build/delivery cycle and exit")
	unblock := flags.Uint64("unblock", 0, "unblock one pending sequence and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"--identity-dir": *identityDir,
		"--journal":      *journalPath,
		"--outbox-dir":   *outboxDir,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if *pollInterval < 250*time.Millisecond || *pollInterval > time.Hour {
		return errors.New("poll interval must be between 250ms and 1h")
	}
	logger := log.New(os.Stderr, "ntagentshield-forwarder ", log.LstdFlags|log.LUTC)
	client, err := transport.NewClient(transport.ClientOptions{
		StateDir:   *identityDir,
		Endpoint:   *endpoint,
		ServerName: *serverName,
		Timeout:    *requestTimeout,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	store, err := outbox.Open(outbox.Config{
		Directory:         *outboxDir,
		JournalPath:       *journalPath,
		MaxPendingBatches: *maxPending,
		MaxSpoolBytes:     *maxSpoolBytes,
		MaxBatchItems:     *maxBatchItems,
		MaxBatchBytes:     *maxBatchBytes,
		BaseBackoff:       *baseBackoff,
		MaxBackoff:        *maxBackoff,
	}, client.Metadata())
	if err != nil {
		return err
	}
	defer store.Close()
	if *unblock > 0 {
		if err := store.Unblock(*unblock); err != nil {
			return err
		}
		return writeStatus(*statusPath, store.Status())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		cycleErr := runCycle(ctx, store, client, logger)
		if statusErr := writeStatus(*statusPath, store.Status()); statusErr != nil {
			logger.Printf("status write failed: %v", statusErr)
		}
		if cycleErr != nil {
			logger.Printf("cycle failed: %v", cycleErr)
		}
		if *once {
			return cycleErr
		}
		timer := time.NewTimer(*pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func runCycle(ctx context.Context, store *outbox.Store, sender outbox.Sender, logger *log.Logger) error {
	if ctx.Err() != nil {
		return nil
	}
	for created := 0; created < 32; created++ {
		result, err := store.BuildNext(time.Now().UTC())
		if err != nil {
			return err
		}
		if result.Backpressured {
			logger.Printf("outbox backpressure pending_batches=%d pending_bytes=%d", store.Status().PendingBatches, store.Status().PendingBytes)
			break
		}
		if !result.Created {
			break
		}
		logger.Printf("spooled batch sequence=%d journal=%d..%d items=%d bytes=%d", result.Pending.Sequence, result.Pending.JournalFrom, result.Pending.JournalTo, result.Pending.ItemCount, result.Pending.SizeBytes)
	}
	for delivered := 0; delivered < 32; delivered++ {
		result, err := store.DeliverNext(ctx, sender, time.Now().UTC())
		if err != nil {
			return err
		}
		if result.Blocked {
			logger.Printf("outbox blocked; operator review required")
			break
		}
		if !result.Attempted {
			break
		}
		logger.Printf("delivered batch sequence=%d status=%s", result.Receipt.Sequence, result.Receipt.Status)
	}
	return nil
}

func writeStatus(path string, status outbox.Status) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	content, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary := path + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(temporary, append(content, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return os.Chmod(path, 0o600)
}
