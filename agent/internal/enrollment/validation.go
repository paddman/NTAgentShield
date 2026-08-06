package enrollment

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

var identityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func ValidateIdentity(label, value string) error {
	if !identityPattern.MatchString(value) {
		return fmt.Errorf("%s must match %s", label, identityPattern.String())
	}
	return nil
}

func SPIFFEURI(tenantID, agentID string) (*url.URL, error) {
	if err := ValidateIdentity("tenant_id", tenantID); err != nil {
		return nil, err
	}
	if err := ValidateIdentity("agent_id", agentID); err != nil {
		return nil, err
	}
	return url.Parse(fmt.Sprintf("spiffe://%s/tenant/%s/agent/%s", SPIFFETrustDomain, tenantID, agentID))
}

func ParseSPIFFEIdentity(certificate *x509.Certificate) (string, string, error) {
	if certificate == nil {
		return "", "", errors.New("client certificate is missing")
	}
	for _, uri := range certificate.URIs {
		if uri == nil || uri.Scheme != "spiffe" || uri.Host != SPIFFETrustDomain {
			continue
		}
		segments := strings.Split(strings.Trim(uri.EscapedPath(), "/"), "/")
		if len(segments) != 4 || segments[0] != "tenant" || segments[2] != "agent" {
			continue
		}
		tenantID, err := url.PathUnescape(segments[1])
		if err != nil {
			return "", "", fmt.Errorf("decode tenant identity: %w", err)
		}
		agentID, err := url.PathUnescape(segments[3])
		if err != nil {
			return "", "", fmt.Errorf("decode agent identity: %w", err)
		}
		if err := ValidateIdentity("tenant_id", tenantID); err != nil {
			return "", "", err
		}
		if err := ValidateIdentity("agent_id", agentID); err != nil {
			return "", "", err
		}
		return tenantID, agentID, nil
	}
	return "", "", errors.New("certificate does not contain the required NTAgentShield SPIFFE URI")
}

func Paths(stateDir string) StatePaths {
	directory := filepath.Clean(stateDir)
	return StatePaths{
		Directory:   directory,
		PrivateKey:  filepath.Join(directory, "identity.key.pem"),
		Certificate: filepath.Join(directory, "identity.crt.pem"),
		CA:          filepath.Join(directory, "ca.crt.pem"),
		Metadata:    filepath.Join(directory, "enrollment.json"),
	}
}

func CertificateFingerprint(certificate *x509.Certificate) string {
	if certificate == nil {
		return ""
	}
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
}
