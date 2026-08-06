package inventorydrift

import (
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
)

const (
	SchemaVersion    = 1
	maxBaselineBytes = 16 * 1024 * 1024
)

type Completeness struct {
	Services      bool `json:"services"`
	Listeners     bool `json:"listeners"`
	Software      bool `json:"software"`
	Interfaces    bool `json:"interfaces"`
	ProcessImages bool `json:"process_images"`
}

type Baseline struct {
	SchemaVersion int              `json:"schema_version"`
	CapturedAt    time.Time        `json:"captured_at"`
	Hostname      string           `json:"hostname"`
	OS            string           `json:"os"`
	Complete      Completeness     `json:"complete"`
	Services      []ServiceState   `json:"services,omitempty"`
	Listeners     []ListenerState  `json:"listeners,omitempty"`
	Software      []SoftwareState  `json:"software,omitempty"`
	Interfaces    []InterfaceState `json:"interfaces,omitempty"`
	ProcessImages []ProcessImage   `json:"process_images,omitempty"`
}

type ServiceState struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	State       string `json:"state,omitempty"`
	StartMode   string `json:"start_mode,omitempty"`
}

type ListenerState struct {
	Key          string `json:"key"`
	Protocol     string `json:"protocol"`
	Address      string `json:"address"`
	Port         int    `json:"port"`
	PID          int    `json:"pid,omitempty"`
	ProcessImage string `json:"process_image,omitempty"`
	Exposed      bool   `json:"exposed"`
	Sensitive    bool   `json:"sensitive"`
}

type SoftwareState struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	Source    string `json:"source,omitempty"`
}

type InterfaceState struct {
	Key       string   `json:"key"`
	Name      string   `json:"name"`
	MACHash   string   `json:"mac_hash,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	IsUp      bool     `json:"is_up"`
}

type ProcessImage struct {
	Key        string `json:"key"`
	Name       string `json:"name"`
	Executable string `json:"executable,omitempty"`
	Suspicious bool   `json:"suspicious"`
}

type Plan struct {
	Initial      bool
	Events       []model.Event
	Next         Baseline
	PreviousHash string
	CurrentHash  string
	TotalChanges int
	Truncated    bool
}

type envelope struct {
	Version       int      `json:"version"`
	Baseline      Baseline `json:"baseline"`
	PayloadSHA256 string   `json:"payload_sha256"`
}
