package inventorydrift

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/paddman/NTAgentShield/internal/inventory"
)

var sensitivePorts = map[int]struct{}{
	21: {}, 22: {}, 23: {}, 25: {}, 53: {}, 80: {}, 110: {}, 111: {}, 135: {}, 139: {}, 143: {}, 389: {}, 443: {}, 445: {}, 465: {}, 587: {}, 636: {}, 993: {}, 995: {},
	1433: {}, 1521: {}, 2049: {}, 2375: {}, 2376: {}, 3000: {}, 3306: {}, 3389: {}, 5432: {}, 5601: {}, 5672: {}, 5900: {}, 5985: {}, 5986: {}, 6379: {},
	6443: {}, 8080: {}, 8443: {}, 8888: {}, 9000: {}, 9090: {}, 9200: {}, 9300: {}, 11211: {}, 15672: {}, 27017: {},
}

func project(snapshot inventory.Snapshot, previous *Baseline) Baseline {
	processByPID := make(map[int]string, len(snapshot.Processes))
	for _, process := range snapshot.Processes {
		image := firstNonEmpty(process.Executable, process.Name)
		if process.PID > 0 && image != "" {
			processByPID[process.PID] = image
		}
	}

	current := Baseline{
		SchemaVersion: SchemaVersion,
		CapturedAt:    snapshot.CollectedAt.UTC(),
		Hostname:      snapshot.Hostname,
		OS:            snapshot.OS,
		Services:      projectServices(snapshot),
		Listeners:     projectListeners(snapshot, processByPID),
		Software:      projectSoftware(snapshot),
		Interfaces:    projectInterfaces(snapshot),
		ProcessImages: projectProcessImages(snapshot),
		Complete: Completeness{
			Services:      !snapshot.Truncated["services"],
			Listeners:     !snapshot.Truncated["listeners"],
			Software:      !snapshot.Truncated["software"],
			Interfaces:    true,
			ProcessImages: !snapshot.Truncated["processes"],
		},
	}
	if previous == nil {
		return current
	}
	if !current.Complete.Services {
		current.Services = cloneServices(previous.Services)
		current.Complete.Services = previous.Complete.Services
	}
	if !current.Complete.Listeners {
		current.Listeners = cloneListeners(previous.Listeners)
		current.Complete.Listeners = previous.Complete.Listeners
	}
	if !current.Complete.Software {
		current.Software = cloneSoftware(previous.Software)
		current.Complete.Software = previous.Complete.Software
	}
	if !current.Complete.ProcessImages {
		current.ProcessImages = cloneProcessImages(previous.ProcessImages)
		current.Complete.ProcessImages = previous.Complete.ProcessImages
	}
	return current
}

func projectServices(snapshot inventory.Snapshot) []ServiceState {
	result := make([]ServiceState, 0, len(snapshot.Services))
	seen := map[string]struct{}{}
	for _, service := range snapshot.Services {
		name := strings.TrimSpace(service.Name)
		if name == "" {
			continue
		}
		key := canonical(snapshot.OS, name)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, ServiceState{
			Key:         key,
			Name:        name,
			DisplayName: strings.TrimSpace(service.DisplayName),
			State:       strings.ToLower(strings.TrimSpace(service.State)),
			StartMode:   strings.ToLower(strings.TrimSpace(service.StartMode)),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result
}

func projectListeners(snapshot inventory.Snapshot, processByPID map[int]string) []ListenerState {
	result := make([]ListenerState, 0, len(snapshot.Listeners))
	seen := map[string]struct{}{}
	for _, listener := range snapshot.Listeners {
		protocol := strings.ToLower(strings.TrimSpace(listener.Protocol))
		address := normalizeAddress(listener.Address)
		if protocol == "" || listener.Port < 1 || listener.Port > 65535 {
			continue
		}
		key := protocol + "|" + address + "|" + strconv.Itoa(listener.Port)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		_, sensitive := sensitivePorts[listener.Port]
		result = append(result, ListenerState{
			Key:          key,
			Protocol:     protocol,
			Address:      address,
			Port:         listener.Port,
			PID:          listener.PID,
			ProcessImage: strings.TrimSpace(processByPID[listener.PID]),
			Exposed:      listenerExposed(address),
			Sensitive:    sensitive,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result
}

func projectSoftware(snapshot inventory.Snapshot) []SoftwareState {
	result := make([]SoftwareState, 0, len(snapshot.Software))
	seen := map[string]struct{}{}
	for _, software := range snapshot.Software {
		name := strings.TrimSpace(software.Name)
		if name == "" {
			continue
		}
		source := strings.ToLower(strings.TrimSpace(software.Source))
		key := source + "|" + canonical(snapshot.OS, name)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, SoftwareState{
			Key:       key,
			Name:      name,
			Version:   strings.TrimSpace(software.Version),
			Publisher: strings.TrimSpace(software.Publisher),
			Source:    source,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result
}

func projectInterfaces(snapshot inventory.Snapshot) []InterfaceState {
	result := make([]InterfaceState, 0, len(snapshot.Interfaces))
	for _, networkInterface := range snapshot.Interfaces {
		name := strings.TrimSpace(networkInterface.Name)
		if name == "" {
			continue
		}
		addresses := append([]string(nil), networkInterface.Addresses...)
		for index := range addresses {
			addresses[index] = strings.TrimSpace(addresses[index])
		}
		sort.Strings(addresses)
		addresses = uniqueStrings(addresses)
		result = append(result, InterfaceState{
			Key:       canonical(snapshot.OS, name),
			Name:      name,
			MACHash:   hashScoped("mac", networkInterface.MAC),
			Addresses: addresses,
			IsUp:      networkInterface.IsUp,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result
}

func projectProcessImages(snapshot inventory.Snapshot) []ProcessImage {
	result := make([]ProcessImage, 0, len(snapshot.Processes))
	seen := map[string]struct{}{}
	for _, process := range snapshot.Processes {
		name := strings.TrimSpace(process.Name)
		executable := strings.TrimSpace(process.Executable)
		identity := firstNonEmpty(executable, name)
		if identity == "" {
			continue
		}
		key := canonical(snapshot.OS, filepath.Clean(identity))
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, ProcessImage{
			Key:        key,
			Name:       name,
			Executable: executable,
			Suspicious: suspiciousExecutablePath(snapshot.OS, executable),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result
}

func canonical(osName, value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(osName, "windows") {
		value = strings.ReplaceAll(value, "/", `\`)
		return strings.ToLower(value)
	}
	return value
}

func normalizeAddress(value string) string {
	value = strings.TrimSpace(strings.Trim(value, "[]"))
	if value == "" || value == "*" {
		return "0.0.0.0"
	}
	if zone := strings.LastIndex(value, "%"); zone > 0 {
		value = value[:zone]
	}
	if parsed := net.ParseIP(value); parsed != nil {
		return parsed.String()
	}
	return strings.ToLower(value)
}

func listenerExposed(address string) bool {
	if address == "0.0.0.0" || address == "::" {
		return true
	}
	parsed := net.ParseIP(address)
	if parsed == nil {
		return true
	}
	return !parsed.IsLoopback()
}

func suspiciousExecutablePath(osName, value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	normalized := strings.ToLower(strings.ReplaceAll(value, `\`, "/"))
	if strings.EqualFold(osName, "windows") {
		for _, fragment := range []string{"/users/", "/programdata/", "/windows/temp/", "/appdata/local/temp/", "/appdata/roaming/", "/recycle", "/downloads/"} {
			if strings.Contains(normalized, fragment) {
				return true
			}
		}
		return false
	}
	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/home/"} {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	return false
}

func hashScoped(scope, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(scope + "\x00" + value))
	return hex.EncodeToString(digest[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
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

func cloneServices(values []ServiceState) []ServiceState {
	return append([]ServiceState(nil), values...)
}

func cloneListeners(values []ListenerState) []ListenerState {
	return append([]ListenerState(nil), values...)
}

func cloneSoftware(values []SoftwareState) []SoftwareState {
	return append([]SoftwareState(nil), values...)
}

func cloneProcessImages(values []ProcessImage) []ProcessImage {
	return append([]ProcessImage(nil), values...)
}
