//go:build linux

package inventory

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func collectPlatform(ctx context.Context, options Options) (platformSnapshot, error) {
	result := platformSnapshot{}
	osRelease := parseKeyValueFile("/etc/os-release")
	result.OSName = firstNonEmpty(osRelease["PRETTY_NAME"], osRelease["NAME"], "Linux")
	result.OSVersion = firstNonEmpty(osRelease["VERSION_ID"], osRelease["VERSION"])
	result.KernelVersion = readTrimmed("/proc/sys/kernel/osrelease")
	result.MachineID = firstNonEmpty(readTrimmed("/etc/machine-id"), readTrimmed("/var/lib/dbus/machine-id"))
	result.BootID = readTrimmed("/proc/sys/kernel/random/boot_id")
	result.UptimeSeconds = linuxUptime()

	if options.IncludeProcesses {
		processes, err := collectLinuxProcesses(ctx, options.MaxItems+1)
		if err != nil {
			result.Warnings = append(result.Warnings, "process inventory: "+err.Error())
		} else {
			result.Processes = processes
		}
	}
	if options.IncludeServices {
		services, err := collectSystemdServices(ctx, options.CommandTimeout, options.MaxItems+1)
		if err != nil {
			result.Warnings = append(result.Warnings, "service inventory: "+err.Error())
		} else {
			result.Services = services
		}
	}
	if options.IncludeListeners {
		listeners, warnings := collectProcListeners(options.MaxItems + 1)
		result.Listeners = listeners
		result.Warnings = append(result.Warnings, warnings...)
	}
	if options.IncludeSoftware {
		software, err := collectLinuxSoftware(ctx, options.CommandTimeout, options.MaxItems+1)
		if err != nil {
			result.Warnings = append(result.Warnings, "software inventory: "+err.Error())
		} else {
			result.Software = software
		}
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func collectLinuxProcesses(ctx context.Context, limit int) ([]Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	result := make([]Process, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		base := filepath.Join("/proc", entry.Name())
		status := parseKeyValueFile(filepath.Join(base, "status"))
		name := status["Name"]
		if name == "" {
			continue
		}
		ppid, _ := strconv.Atoi(firstField(status["PPid"]))
		rssKB, _ := strconv.ParseInt(firstField(status["VmRSS"]), 10, 64)
		commandLine := ""
		if content, readErr := os.ReadFile(filepath.Join(base, "cmdline")); readErr == nil {
			commandLine = strings.TrimSpace(strings.ReplaceAll(string(content), "\x00", " "))
		}
		executable, _ := os.Readlink(filepath.Join(base, "exe"))
		result = append(result, Process{
			PID:         pid,
			PPID:        ppid,
			Name:        name,
			Executable:  executable,
			CommandLine: commandLine,
			User:        firstField(status["Uid"]),
			RSSBytes:    rssKB * 1024,
		})
		if len(result) >= limit {
			break
		}
	}
	return result, nil
}

func collectSystemdServices(ctx context.Context, timeout time.Duration, limit int) ([]Service, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, errorsWithContext("systemctl unavailable", err)
	}
	output, err := runInventoryCommand(ctx, timeout, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager")
	if err != nil {
		return nil, err
	}
	result := make([]Service, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		description := ""
		if len(fields) > 4 {
			description = strings.Join(fields[4:], " ")
		}
		result = append(result, Service{
			Name:        strings.TrimPrefix(fields[0], "●"),
			State:       fields[2],
			SubState:    fields[3],
			Description: description,
		})
		if len(result) >= limit {
			break
		}
	}
	return result, scanner.Err()
}

func collectProcListeners(limit int) ([]Listener, []string) {
	files := []struct {
		path     string
		protocol string
		ipv6     bool
		tcp      bool
	}{
		{"/proc/net/tcp", "tcp", false, true},
		{"/proc/net/tcp6", "tcp6", true, true},
		{"/proc/net/udp", "udp", false, false},
		{"/proc/net/udp6", "udp6", true, false},
	}
	result := make([]Listener, 0)
	warnings := make([]string, 0)
	for _, source := range files {
		listeners, err := parseProcNetFile(source.path, source.protocol, source.ipv6, source.tcp, limit-len(result))
		if err != nil && !os.IsNotExist(err) {
			warnings = append(warnings, source.path+": "+err.Error())
		}
		result = append(result, listeners...)
		if len(result) >= limit {
			break
		}
	}
	return result, warnings
}

func parseProcNetFile(path, protocol string, ipv6, tcp bool, limit int) ([]Listener, error) {
	if limit <= 0 {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := make([]Listener, 0)
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		if line == 1 {
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		if tcp && fields[3] != "0A" {
			continue
		}
		address, port, err := parseProcAddress(fields[1], ipv6)
		if err != nil {
			continue
		}
		state := fields[3]
		if tcp && state == "0A" {
			state = "LISTEN"
		}
		result = append(result, Listener{Protocol: protocol, Address: address, Port: port, State: state})
		if len(result) >= limit {
			break
		}
	}
	return result, scanner.Err()
}

func parseProcAddress(value string, ipv6 bool) (string, int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid socket address")
	}
	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}
	decoded, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, err
	}
	if !ipv6 {
		if len(decoded) != net.IPv4len {
			return "", 0, fmt.Errorf("invalid IPv4 address")
		}
		for left, right := 0, len(decoded)-1; left < right; left, right = left+1, right-1 {
			decoded[left], decoded[right] = decoded[right], decoded[left]
		}
	} else {
		if len(decoded) != net.IPv6len {
			return "", 0, fmt.Errorf("invalid IPv6 address")
		}
		for offset := 0; offset < len(decoded); offset += 4 {
			decoded[offset], decoded[offset+3] = decoded[offset+3], decoded[offset]
			decoded[offset+1], decoded[offset+2] = decoded[offset+2], decoded[offset+1]
		}
	}
	return net.IP(decoded).String(), int(port64), nil
}

func collectLinuxSoftware(ctx context.Context, timeout time.Duration, limit int) ([]Software, error) {
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		output, runErr := runInventoryCommand(ctx, timeout, "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n")
		if runErr != nil {
			return nil, runErr
		}
		return parseSoftwareLines(output, "dpkg", limit), nil
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		output, runErr := runInventoryCommand(ctx, timeout, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
		if runErr != nil {
			return nil, runErr
		}
		return parseSoftwareLines(output, "rpm", limit), nil
	}
	return nil, fmt.Errorf("no supported package inventory command found")
}

func parseSoftwareLines(output, source string, limit int) []Software {
	result := make([]Software, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		item := Software{Name: strings.TrimSpace(parts[0]), Source: source}
		if len(parts) == 2 {
			item.Version = strings.TrimSpace(parts[1])
		}
		if item.Name == "" {
			continue
		}
		result = append(result, item)
		if len(result) >= limit {
			break
		}
	}
	return result
}

func runInventoryCommand(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, name, args...)
	output, err := command.CombinedOutput()
	if commandCtx.Err() != nil {
		return "", commandCtx.Err()
	}
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 512 {
			message = message[:512]
		}
		if message != "" {
			return "", fmt.Errorf("%s failed: %w: %s", name, err, message)
		}
		return "", fmt.Errorf("%s failed: %w", name, err)
	}
	return string(output), nil
}

func parseKeyValueFile(path string) map[string]string {
	result := map[string]string{}
	file, err := os.Open(path)
	if err != nil {
		return result
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		separator := "="
		if !strings.Contains(line, separator) {
			separator = ":"
		}
		parts := strings.SplitN(line, separator, 2)
		if len(parts) != 2 {
			continue
		}
		result[strings.TrimSpace(parts[0])] = strings.Trim(strings.TrimSpace(parts[1]), "\"")
	}
	return result
}

func linuxUptime() int64 {
	value := readTrimmed("/proc/uptime")
	seconds, _ := strconv.ParseFloat(firstField(value), 64)
	return int64(seconds)
}

func readTrimmed(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(content))
}

func firstField(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func errorsWithContext(message string, err error) error {
	return fmt.Errorf("%s: %w", message, err)
}
