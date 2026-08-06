package inventory

import "time"

const SchemaVersion = "0.1"

type Options struct {
	IncludeProcesses bool
	IncludeServices  bool
	IncludeListeners bool
	IncludeSoftware  bool
	MaxItems         int
	CommandTimeout   time.Duration
}

type Snapshot struct {
	SchemaVersion string             `json:"schema_version"`
	CollectedAt   time.Time          `json:"collected_at"`
	Hostname      string             `json:"hostname"`
	OS            string             `json:"os"`
	OSName        string             `json:"os_name,omitempty"`
	OSVersion     string             `json:"os_version,omitempty"`
	KernelVersion string             `json:"kernel_version,omitempty"`
	Architecture  string             `json:"architecture"`
	MachineID     string             `json:"machine_id,omitempty"`
	BootID        string             `json:"boot_id,omitempty"`
	UptimeSeconds int64              `json:"uptime_seconds,omitempty"`
	CPUCount      int                `json:"cpu_count"`
	GoVersion     string             `json:"go_version"`
	Interfaces    []NetworkInterface `json:"interfaces,omitempty"`
	Processes     []Process          `json:"processes,omitempty"`
	Services      []Service          `json:"services,omitempty"`
	Listeners     []Listener         `json:"listeners,omitempty"`
	Software      []Software         `json:"software,omitempty"`
	Warnings      []string           `json:"warnings,omitempty"`
	Truncated     map[string]bool    `json:"truncated,omitempty"`
}

type NetworkInterface struct {
	Name       string   `json:"name"`
	Index      int      `json:"index"`
	MAC        string   `json:"mac,omitempty"`
	MTU        int      `json:"mtu,omitempty"`
	Flags      []string `json:"flags,omitempty"`
	Addresses  []string `json:"addresses,omitempty"`
	IsLoopback bool     `json:"is_loopback"`
	IsUp       bool     `json:"is_up"`
}

type Process struct {
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid,omitempty"`
	Name        string `json:"name"`
	Executable  string `json:"executable,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	User        string `json:"user,omitempty"`
	RSSBytes    int64  `json:"rss_bytes,omitempty"`
}

type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	State       string `json:"state,omitempty"`
	SubState    string `json:"sub_state,omitempty"`
	StartMode   string `json:"start_mode,omitempty"`
	Description string `json:"description,omitempty"`
}

type Listener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	PID      int    `json:"pid,omitempty"`
	State    string `json:"state,omitempty"`
}

type Software struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	Source    string `json:"source,omitempty"`
}
