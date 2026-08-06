package enrollment

import "time"

const (
	ProtocolVersion   = 1
	SPIFFETrustDomain = "ntshield.local"
)

type BootstrapRequest struct {
	Version          int       `json:"version"`
	EnrollmentToken  string    `json:"enrollment_token"`
	AgentID          string    `json:"agent_id"`
	ExpectedTenantID string    `json:"expected_tenant_id,omitempty"`
	CSRPEM           string    `json:"csr_pem"`
	Nonce            string    `json:"nonce"`
	RequestedAt      time.Time `json:"requested_at"`
}

type BootstrapResponse struct {
	Version          int       `json:"version"`
	TenantID         string    `json:"tenant_id"`
	AgentID          string    `json:"agent_id"`
	CertificatePEM   string    `json:"certificate_pem"`
	CAPEM            string    `json:"ca_pem"`
	CertificateSerial string   `json:"certificate_serial"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	ControlPlaneURL  string    `json:"control_plane_url"`
}

type Metadata struct {
	Version           int       `json:"version"`
	TenantID          string    `json:"tenant_id"`
	AgentID           string    `json:"agent_id"`
	SPIFFEID          string    `json:"spiffe_id"`
	CertificateSerial string    `json:"certificate_serial"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	ControlPlaneURL   string    `json:"control_plane_url"`
	CAFingerprint     string    `json:"ca_sha256"`
}

type StatePaths struct {
	Directory    string
	PrivateKey   string
	Certificate  string
	CA           string
	Metadata     string
}
