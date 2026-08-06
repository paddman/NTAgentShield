package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/transport"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	stateDir := flag.String("state-dir", "", "enrolled endpoint identity directory")
	endpoint := flag.String("endpoint", "", "optional gateway HTTPS base URL override")
	serverName := flag.String("server-name", "", "optional TLS server-name override")
	filePath := flag.String("file", "", "JSON evidence payload file")
	itemType := flag.String("type", "event", "evidence type: event, finding, or audit")
	itemID := flag.String("id", "", "optional evidence item id")
	sequence := flag.Uint64("sequence", 1, "batch sequence")
	previousHash := flag.String("previous-hash", "", "previous accepted batch hash")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	flag.Parse()
	if strings.TrimSpace(*stateDir) == "" || strings.TrimSpace(*filePath) == "" {
		return errors.New("--state-dir and --file are required")
	}
	file, err := os.Open(*filePath)
	if err != nil {
		return fmt.Errorf("open evidence file: %w", err)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, transport.MaxItemBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return fmt.Errorf("read evidence file: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close evidence file: %w", closeErr)
	}
	if len(content) == 0 || len(content) > transport.MaxItemBytes || !json.Valid(content) {
		return errors.New("evidence file must contain one valid JSON value within the size limit")
	}
	identifier := strings.TrimSpace(*itemID)
	if identifier == "" {
		var header struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(content, &header)
		identifier = strings.TrimSpace(header.ID)
	}
	if identifier == "" {
		digest := sha256.Sum256(content)
		identifier = "sha256:" + hex.EncodeToString(digest[:])
	}
	client, err := transport.NewClient(transport.ClientOptions{
		StateDir:   *stateDir,
		Endpoint:   *endpoint,
		ServerName: *serverName,
		Timeout:    *timeout,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	metadata := client.Metadata()
	batch := transport.Batch{
		Version:      transport.BatchProtocolVersion,
		TenantID:     metadata.TenantID,
		AgentID:      metadata.AgentID,
		Sequence:     *sequence,
		PreviousHash: strings.ToLower(strings.TrimSpace(*previousHash)),
		CreatedAt:    time.Now().UTC(),
		Items: []transport.EvidenceItem{{
			Type:    strings.ToLower(strings.TrimSpace(*itemType)),
			ID:      identifier,
			Payload: json.RawMessage(content),
		}},
	}
	if err := batch.Seal(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	receipt, err := client.Send(ctx, batch)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
		"receipt":   receipt,
		"batch_hash": batch.PayloadSHA256,
	})
}
