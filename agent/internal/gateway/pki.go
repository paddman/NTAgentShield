package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/paddman/NTAgentShield/internal/enrollment"
)

const (
	rootCertificateFile   = "ca.crt.pem"
	rootPrivateKeyFile    = "ca.key.pem"
	serverCertificateFile = "gateway.crt.pem"
	serverPrivateKeyFile  = "gateway.key.pem"
)

type PKIPaths struct {
	Directory         string
	RootCertificate   string
	RootPrivateKey    string
	ServerCertificate string
	ServerPrivateKey  string
}

type PKI struct {
	Paths           PKIPaths
	RootCertificate *x509.Certificate
	RootPrivateKey  *ecdsa.PrivateKey
	RootPEM         []byte
	ServerTLS       tls.Certificate
}

type PKIOptions struct {
	StateDir string
	DNSNames []string
	IPAddresses []net.IP
	Now      time.Time
}

func Paths(stateDir string) PKIPaths {
	directory := filepath.Clean(stateDir)
	return PKIPaths{
		Directory:         directory,
		RootCertificate:   filepath.Join(directory, rootCertificateFile),
		RootPrivateKey:    filepath.Join(directory, rootPrivateKeyFile),
		ServerCertificate: filepath.Join(directory, serverCertificateFile),
		ServerPrivateKey:  filepath.Join(directory, serverPrivateKeyFile),
	}
}

func InitializePKI(options PKIOptions) (PKIPaths, error) {
	paths := Paths(options.StateDir)
	if len(options.DNSNames) == 0 && len(options.IPAddresses) == 0 {
		return paths, errors.New("at least one gateway DNS name or IP address is required")
	}
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	} else {
		options.Now = options.Now.UTC()
	}
	if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
		return paths, fmt.Errorf("create PKI directory: %w", err)
	}
	if err := os.Chmod(paths.Directory, 0o700); err != nil {
		return paths, fmt.Errorf("secure PKI directory: %w", err)
	}
	for _, path := range []string{paths.RootCertificate, paths.RootPrivateKey, paths.ServerCertificate, paths.ServerPrivateKey} {
		if _, err := os.Stat(path); err == nil {
			return paths, fmt.Errorf("refusing to overwrite existing PKI file %s", filepath.Base(path))
		} else if !errors.Is(err, os.ErrNotExist) {
			return paths, fmt.Errorf("inspect PKI path %s: %w", filepath.Base(path), err)
		}
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return paths, fmt.Errorf("generate root CA key: %w", err)
	}
	rootSerial, err := randomSerial()
	if err != nil {
		return paths, err
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName:   "NTAgentShield Enrollment Root",
			Organization: []string{"NTAgentShield"},
		},
		NotBefore:             options.Now.Add(-5 * time.Minute),
		NotAfter:              options.Now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return paths, fmt.Errorf("create root CA certificate: %w", err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return paths, fmt.Errorf("parse generated root CA certificate: %w", err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return paths, fmt.Errorf("generate gateway server key: %w", err)
	}
	serverSerial, err := randomSerial()
	if err != nil {
		return paths, err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:          serverSerial,
		Subject:               pkix.Name{CommonName: "NTAgentShield Gateway", Organization: []string{"NTAgentShield"}},
		NotBefore:             options.Now.Add(-5 * time.Minute),
		NotAfter:              options.Now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              append([]string(nil), options.DNSNames...),
		IPAddresses:           append([]net.IP(nil), options.IPAddresses...),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, rootCertificate, &serverKey.PublicKey, rootKey)
	if err != nil {
		return paths, fmt.Errorf("create gateway server certificate: %w", err)
	}
	rootKeyDER, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		return paths, fmt.Errorf("marshal root CA key: %w", err)
	}
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return paths, fmt.Errorf("marshal gateway server key: %w", err)
	}
	files := []struct {
		path    string
		content []byte
	}{
		{paths.RootCertificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})},
		{paths.RootPrivateKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: rootKeyDER})},
		{paths.ServerCertificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})},
		{paths.ServerPrivateKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})},
	}
	for _, file := range files {
		if err := writePrivateFile(file.path, file.content); err != nil {
			return paths, err
		}
	}
	return paths, nil
}

func LoadPKI(stateDir string) (*PKI, error) {
	paths := Paths(stateDir)
	rootPEM, err := os.ReadFile(paths.RootCertificate)
	if err != nil {
		return nil, fmt.Errorf("read root CA certificate: %w", err)
	}
	rootCertificates, err := parseCertificatePEM(rootPEM)
	if err != nil || len(rootCertificates) != 1 {
		return nil, errors.New("root CA file must contain exactly one certificate")
	}
	rootKey, err := readECPrivateKey(paths.RootPrivateKey)
	if err != nil {
		return nil, err
	}
	if err := publicKeysEqual(rootCertificates[0].PublicKey, &rootKey.PublicKey); err != nil {
		return nil, fmt.Errorf("root CA key mismatch: %w", err)
	}
	serverTLS, err := tls.LoadX509KeyPair(paths.ServerCertificate, paths.ServerPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load gateway server certificate: %w", err)
	}
	return &PKI{
		Paths:           paths,
		RootCertificate: rootCertificates[0],
		RootPrivateKey:  rootKey,
		RootPEM:         rootPEM,
		ServerTLS:       serverTLS,
	}, nil
}

func (p *PKI) IssueClientCertificate(csr *x509.CertificateRequest, tenantID, agentID string, ttl time.Duration, now time.Time) ([]byte, *x509.Certificate, error) {
	if p == nil || p.RootCertificate == nil || p.RootPrivateKey == nil {
		return nil, nil, errors.New("PKI signer is not initialized")
	}
	if csr == nil {
		return nil, nil, errors.New("certificate request is required")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("certificate request signature is invalid: %w", err)
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, nil, errors.New("endpoint certificate request must use ECDSA P-256")
	}
	identityURI, err := enrollment.SPIFFEURI(tenantID, agentID)
	if err != nil {
		return nil, nil, err
	}
	if ttl < time.Hour || ttl > 90*24*time.Hour {
		return nil, nil, errors.New("endpoint certificate TTL must be between 1h and 90d")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	notAfter := now.Add(ttl)
	if notAfter.After(p.RootCertificate.NotAfter) {
		notAfter = p.RootCertificate.NotAfter
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: agentID, Organization: []string{"NTAgentShield"}, OrganizationalUnit: []string{tenantID}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{identityURI},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.RootCertificate, csr.PublicKey, p.RootPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("issue endpoint certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse issued endpoint certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func readECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", filepath.Base(path), err)
	}
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("private key %s is not an EC private key", filepath.Base(path))
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key %s: %w", filepath.Base(path), err)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("private key %s must use ECDSA P-256", filepath.Base(path))
	}
	return key, nil
}

func parseCertificatePEM(content []byte) ([]*x509.Certificate, error) {
	certificates := make([]*x509.Certificate, 0)
	remaining := content
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, errors.New("certificate PEM contains no certificates")
	}
	return certificates, nil
}

func publicKeysEqual(left, right interface{}) error {
	leftDER, err := x509.MarshalPKIXPublicKey(left)
	if err != nil {
		return err
	}
	rightDER, err := x509.MarshalPKIXPublicKey(right)
	if err != nil {
		return err
	}
	if string(leftDER) != string(rightDER) {
		return errors.New("public keys do not match")
	}
	return nil
}

func writePrivateFile(path string, content []byte) error {
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure %s: %w", filepath.Base(path), err)
	}
	return nil
}
