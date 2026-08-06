package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
)

type Collector struct {
	options Options
}

type platformSnapshot struct {
	OSName        string
	OSVersion     string
	KernelVersion string
	MachineID     string
	BootID        string
	UptimeSeconds int64
	Processes     []Process
	Services      []Service
	Listeners     []Listener
	Software      []Software
	Warnings      []string
}

func New(options Options) (*Collector, error) {
	if options.MaxItems == 0 {
		options.MaxItems = 512
	}
	if options.CommandTimeout == 0 {
		options.CommandTimeout = 10 * time.Second
	}
	if options.MaxItems < 1 || options.MaxItems > 10000 {
		return nil, errors.New("inventory max items must be between 1 and 10000")
	}
	if options.CommandTimeout < time.Second || options.CommandTimeout > 2*time.Minute {
		return nil, errors.New("inventory command timeout must be between 1s and 2m")
	}
	return &Collector{options: options}, nil
}

func (c *Collector) Collect(ctx context.Context) (Snapshot, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	interfaces, interfaceWarnings := collectInterfaces()
	platform, platformErr := collectPlatform(ctx, c.options)

	snapshot := Snapshot{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().UTC(),
		Hostname:      hostname,
		OS:            runtime.GOOS,
		OSName:        platform.OSName,
		OSVersion:     platform.OSVersion,
		KernelVersion: platform.KernelVersion,
		Architecture:  runtime.GOARCH,
		MachineIDHash: hashIdentifier("machine", platform.MachineID),
		BootIDHash:    hashIdentifier("boot", platform.BootID),
		UptimeSeconds: platform.UptimeSeconds,
		CPUCount:      runtime.NumCPU(),
		GoVersion:     runtime.Version(),
		Interfaces:    interfaces,
		Processes:     platform.Processes,
		Services:      platform.Services,
		Listeners:     platform.Listeners,
		Software:      platform.Software,
		Warnings:      append(interfaceWarnings, platform.Warnings...),
		Truncated:     map[string]bool{},
	}

	sortSnapshot(&snapshot)
	snapshot.Processes = capItems(snapshot.Processes, c.options.MaxItems, snapshot.Truncated, "processes")
	snapshot.Services = capItems(snapshot.Services, c.options.MaxItems, snapshot.Truncated, "services")
	snapshot.Listeners = capItems(snapshot.Listeners, c.options.MaxItems, snapshot.Truncated, "listeners")
	snapshot.Software = capItems(snapshot.Software, c.options.MaxItems, snapshot.Truncated, "software")
	if len(snapshot.Truncated) == 0 {
		snapshot.Truncated = nil
	}
	if platformErr != nil {
		return snapshot, platformErr
	}
	return snapshot, nil
}

func (c *Collector) Event(ctx context.Context) (model.Event, error) {
	snapshot, err := c.Collect(ctx)
	ips := make([]string, 0)
	for _, iface := range snapshot.Interfaces {
		if iface.IsLoopback {
			continue
		}
		for _, address := range iface.Addresses {
			host, _, splitErr := net.ParseCIDR(address)
			if splitErr == nil {
				ips = append(ips, host.String())
			} else if parsed := net.ParseIP(address); parsed != nil {
				ips = append(ips, parsed.String())
			}
		}
	}
	sort.Strings(ips)
	event := model.Event{
		Kind:     "asset.inventory",
		Severity: model.SeverityInfo,
		Trust:    model.TrustUntrustedTelemetry,
		Asset: model.Asset{
			Hostname: snapshot.Hostname,
			OS:       snapshot.OS,
			IPs:      uniqueStrings(ips),
		},
		Message: "periodic host asset inventory",
		Attributes: map[string]interface{}{
			"inventory": snapshot,
		},
		Provenance: model.Provenance{
			Source:    "local-host",
			Collector: "native-inventory",
		},
	}
	event.Prepare()
	return event, err
}

func collectInterfaces() ([]NetworkInterface, []string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, []string{"network interfaces: " + err.Error()}
	}
	result := make([]NetworkInterface, 0, len(interfaces))
	warnings := make([]string, 0)
	for _, iface := range interfaces {
		addresses, addressErr := iface.Addrs()
		if addressErr != nil {
			warnings = append(warnings, "interface "+iface.Name+": "+addressErr.Error())
		}
		addressValues := make([]string, 0, len(addresses))
		for _, address := range addresses {
			addressValues = append(addressValues, address.String())
		}
		sort.Strings(addressValues)
		flags := strings.Fields(strings.ReplaceAll(iface.Flags.String(), "|", " "))
		result = append(result, NetworkInterface{
			Name:       iface.Name,
			Index:      iface.Index,
			MAC:        iface.HardwareAddr.String(),
			MTU:        iface.MTU,
			Flags:      flags,
			Addresses:  addressValues,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
			IsUp:       iface.Flags&net.FlagUp != 0,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Index == result[j].Index {
			return result[i].Name < result[j].Name
		}
		return result[i].Index < result[j].Index
	})
	return result, warnings
}

func sortSnapshot(snapshot *Snapshot) {
	sort.Slice(snapshot.Processes, func(i, j int) bool {
		if snapshot.Processes[i].PID == snapshot.Processes[j].PID {
			return snapshot.Processes[i].Name < snapshot.Processes[j].Name
		}
		return snapshot.Processes[i].PID < snapshot.Processes[j].PID
	})
	sort.Slice(snapshot.Services, func(i, j int) bool { return snapshot.Services[i].Name < snapshot.Services[j].Name })
	sort.Slice(snapshot.Listeners, func(i, j int) bool {
		left, right := snapshot.Listeners[i], snapshot.Listeners[j]
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		if left.Address != right.Address {
			return left.Address < right.Address
		}
		return left.PID < right.PID
	})
	sort.Slice(snapshot.Software, func(i, j int) bool {
		if snapshot.Software[i].Name == snapshot.Software[j].Name {
			return snapshot.Software[i].Version < snapshot.Software[j].Version
		}
		return snapshot.Software[i].Name < snapshot.Software[j].Name
	})
	sort.Strings(snapshot.Warnings)
}

func capItems[T any](values []T, maximum int, truncated map[string]bool, key string) []T {
	if len(values) <= maximum {
		return values
	}
	truncated[key] = true
	return values[:maximum]
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := values[:0]
	last := ""
	for _, value := range values {
		if value == "" || value == last {
			continue
		}
		result = append(result, value)
		last = value
	}
	return result
}

func hashIdentifier(scope, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(scope + "\x00" + value))
	return hex.EncodeToString(digest[:])
}
