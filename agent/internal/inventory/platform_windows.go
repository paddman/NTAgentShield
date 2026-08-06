//go:build windows

package inventory

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	windowsOSCommand = "Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,@{Name='LastBoot';Expression={$_.ConvertToDateTime($_.LastBootUpTime).ToUniversalTime().ToString('o')}} | ConvertTo-Csv -NoTypeInformation"
	windowsProcessCommand = "Get-WmiObject Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,WorkingSetSize | ConvertTo-Csv -NoTypeInformation"
	windowsServiceCommand = "Get-WmiObject Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName | ConvertTo-Csv -NoTypeInformation"
	windowsSoftwareCommand = "$paths=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher,PSPath | ConvertTo-Csv -NoTypeInformation"
)

func collectPlatform(ctx context.Context, options Options) (platformSnapshot, error) {
	result := platformSnapshot{OSName: "Windows"}
	if _, err := exec.LookPath("powershell.exe"); err == nil {
		if output, runErr := runWindowsCommand(ctx, options.CommandTimeout, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsOSCommand); runErr == nil {
			rows, parseErr := parseCSVRecords(output)
			if parseErr != nil {
				result.Warnings = append(result.Warnings, "operating system inventory: "+parseErr.Error())
			} else if len(rows) > 0 {
				row := rows[0]
				result.OSName = firstNonEmptyWindows(row["Caption"], "Windows")
				result.OSVersion = row["Version"]
				result.KernelVersion = row["BuildNumber"]
				if boot, parseTimeErr := time.Parse(time.RFC3339Nano, row["LastBoot"]); parseTimeErr == nil {
					result.BootID = boot.UTC().Format(time.RFC3339Nano)
					result.UptimeSeconds = int64(time.Since(boot).Seconds())
				}
			}
		} else {
			result.Warnings = append(result.Warnings, "operating system inventory: "+runErr.Error())
		}
	} else if output, runErr := runWindowsCommand(ctx, options.CommandTimeout, "cmd.exe", "/c", "ver"); runErr == nil {
		result.OSVersion = strings.TrimSpace(output)
	} else {
		result.Warnings = append(result.Warnings, "operating system inventory: "+runErr.Error())
	}

	if output, err := runWindowsCommand(ctx, options.CommandTimeout, "reg.exe", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid"); err == nil {
		result.MachineID = parseRegistryValue(output, "MachineGuid")
	} else {
		result.Warnings = append(result.Warnings, "machine identity: "+err.Error())
	}

	if options.IncludeProcesses {
		processes, err := collectWindowsProcesses(ctx, options.CommandTimeout, options.MaxItems+1)
		if err != nil {
			result.Warnings = append(result.Warnings, "process inventory: "+err.Error())
		} else {
			result.Processes = processes
		}
	}
	if options.IncludeServices {
		services, err := collectWindowsServices(ctx, options.CommandTimeout, options.MaxItems+1)
		if err != nil {
			result.Warnings = append(result.Warnings, "service inventory: "+err.Error())
		} else {
			result.Services = services
		}
	}
	if options.IncludeListeners {
		listeners, err := collectWindowsListeners(ctx, options.CommandTimeout, options.MaxItems+1)
		if err != nil {
			result.Warnings = append(result.Warnings, "listener inventory: "+err.Error())
		} else {
			result.Listeners = listeners
		}
	}
	if options.IncludeSoftware {
		software, err := collectWindowsSoftware(ctx, options.CommandTimeout, options.MaxItems+1)
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

func collectWindowsProcesses(ctx context.Context, timeout time.Duration, limit int) ([]Process, error) {
	if _, err := exec.LookPath("powershell.exe"); err == nil {
		output, runErr := runWindowsCommand(ctx, timeout, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsProcessCommand)
		if runErr != nil {
			return nil, runErr
		}
		rows, parseErr := parseCSVRecords(output)
		if parseErr != nil {
			return nil, parseErr
		}
		result := make([]Process, 0, minWindows(len(rows), limit))
		for _, row := range rows {
			pid, _ := strconv.Atoi(row["ProcessId"])
			if pid <= 0 || row["Name"] == "" {
				continue
			}
			ppid, _ := strconv.Atoi(row["ParentProcessId"])
			rss, _ := strconv.ParseInt(row["WorkingSetSize"], 10, 64)
			result = append(result, Process{PID: pid, PPID: ppid, Name: row["Name"], Executable: row["ExecutablePath"], CommandLine: row["CommandLine"], RSSBytes: rss})
			if len(result) >= limit {
				break
			}
		}
		return result, nil
	}

	output, err := runWindowsCommand(ctx, timeout, "tasklist.exe", "/FO", "CSV", "/NH")
	if err != nil {
		return nil, err
	}
	reader := csv.NewReader(strings.NewReader(output))
	result := make([]Process, 0)
	for {
		record, readErr := reader.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return result, readErr
		}
		if len(record) < 2 {
			continue
		}
		pid, _ := strconv.Atoi(strings.ReplaceAll(record[1], ",", ""))
		result = append(result, Process{PID: pid, Name: record[0]})
		if len(result) >= limit {
			break
		}
	}
	return result, nil
}

func collectWindowsServices(ctx context.Context, timeout time.Duration, limit int) ([]Service, error) {
	if _, err := exec.LookPath("powershell.exe"); err == nil {
		output, runErr := runWindowsCommand(ctx, timeout, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsServiceCommand)
		if runErr != nil {
			return nil, runErr
		}
		rows, parseErr := parseCSVRecords(output)
		if parseErr != nil {
			return nil, parseErr
		}
		result := make([]Service, 0, minWindows(len(rows), limit))
		for _, row := range rows {
			if row["Name"] == "" {
				continue
			}
			result = append(result, Service{Name: row["Name"], DisplayName: row["DisplayName"], State: row["State"], StartMode: row["StartMode"], Description: row["PathName"]})
			if len(result) >= limit {
				break
			}
		}
		return result, nil
	}

	output, err := runWindowsCommand(ctx, timeout, "sc.exe", "query", "state=", "all")
	if err != nil {
		return nil, err
	}
	result := make([]Service, 0)
	current := Service{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SERVICE_NAME:") {
			if current.Name != "" {
				result = append(result, current)
				if len(result) >= limit {
					break
				}
			}
			current = Service{Name: strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:"))}
		} else if strings.HasPrefix(line, "STATE") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				fields := strings.Fields(parts[1])
				if len(fields) >= 2 {
					current.State = fields[1]
				}
			}
		}
	}
	if current.Name != "" && len(result) < limit {
		result = append(result, current)
	}
	return result, scanner.Err()
}

func collectWindowsListeners(ctx context.Context, timeout time.Duration, limit int) ([]Listener, error) {
	result := make([]Listener, 0)
	for _, protocol := range []string{"tcp", "udp"} {
		output, err := runWindowsCommand(ctx, timeout, "netstat.exe", "-ano", "-p", protocol)
		if err != nil {
			return result, err
		}
		scanner := bufio.NewScanner(strings.NewReader(output))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 || !strings.EqualFold(fields[0], protocol) {
				continue
			}
			if protocol == "tcp" && (len(fields) < 5 || !strings.EqualFold(fields[3], "LISTENING")) {
				continue
			}
			address, port, parseErr := parseWindowsEndpoint(fields[1])
			if parseErr != nil {
				continue
			}
			pidField := fields[len(fields)-1]
			pid, _ := strconv.Atoi(pidField)
			state := ""
			if protocol == "tcp" {
				state = fields[3]
			}
			result = append(result, Listener{Protocol: protocol, Address: address, Port: port, PID: pid, State: state})
			if len(result) >= limit {
				return result, nil
			}
		}
		if err := scanner.Err(); err != nil {
			return result, err
		}
	}
	return result, nil
}

func collectWindowsSoftware(ctx context.Context, timeout time.Duration, limit int) ([]Software, error) {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		return nil, fmt.Errorf("powershell.exe unavailable: %w", err)
	}
	output, err := runWindowsCommand(ctx, timeout, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsSoftwareCommand)
	if err != nil {
		return nil, err
	}
	rows, err := parseCSVRecords(output)
	if err != nil {
		return nil, err
	}
	result := make([]Software, 0, minWindows(len(rows), limit))
	for _, row := range rows {
		if row["DisplayName"] == "" {
			continue
		}
		result = append(result, Software{Name: row["DisplayName"], Version: row["DisplayVersion"], Publisher: row["Publisher"], Source: "registry"})
		if len(result) >= limit {
			break
		}
	}
	return result, nil
}

func parseCSVRecords(output string) ([]map[string]string, error) {
	reader := csv.NewReader(strings.NewReader(strings.TrimSpace(output)))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	headers := records[0]
	result := make([]map[string]string, 0, len(records)-1)
	for _, record := range records[1:] {
		row := map[string]string{}
		for index, header := range headers {
			if index < len(record) {
				row[strings.TrimSpace(header)] = strings.TrimSpace(record[index])
			}
		}
		result = append(result, row)
	}
	return result, nil
}

func parseRegistryValue(output, name string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 3 && strings.EqualFold(fields[0], name) {
			return strings.Join(fields[2:], " ")
		}
	}
	return ""
}

func parseWindowsEndpoint(value string) (string, int, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "*:*" {
		return "", 0, fmt.Errorf("invalid endpoint")
	}
	if strings.HasPrefix(value, "[") {
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			return "", 0, err
		}
		portNumber, err := strconv.Atoi(port)
		return host, portNumber, err
	}
	separator := strings.LastIndex(value, ":")
	if separator <= 0 {
		return "", 0, fmt.Errorf("invalid endpoint")
	}
	port, err := strconv.Atoi(value[separator+1:])
	if err != nil {
		return "", 0, err
	}
	return value[:separator], port, nil
}

func runWindowsCommand(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
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

func firstNonEmptyWindows(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func minWindows(left, right int) int {
	if left < right {
		return left
	}
	return right
}
