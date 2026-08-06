package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/paddman/NTAgentShield/internal/inventory"
)

func main() {
	processes := flag.Bool("processes", true, "include running processes")
	services := flag.Bool("services", true, "include operating-system services")
	listeners := flag.Bool("listeners", true, "include listening TCP/UDP sockets")
	software := flag.Bool("software", true, "include installed software/packages")
	maxItems := flag.Int("max-items", 512, "maximum records retained per inventory category")
	timeoutText := flag.String("command-timeout", "10s", "timeout for each fixed operating-system inventory command")
	compact := flag.Bool("compact", false, "emit compact JSON")
	flag.Parse()

	timeout, err := time.ParseDuration(*timeoutText)
	if err != nil {
		fatal(fmt.Errorf("invalid command timeout: %w", err))
	}
	collector, err := inventory.New(inventory.Options{
		IncludeProcesses: *processes,
		IncludeServices:  *services,
		IncludeListeners: *listeners,
		IncludeSoftware:  *software,
		MaxItems:         *maxItems,
		CommandTimeout:   timeout,
	})
	if err != nil {
		fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	snapshot, err := collector.Collect(ctx)
	if err != nil {
		fatal(err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if !*compact {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(snapshot); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
