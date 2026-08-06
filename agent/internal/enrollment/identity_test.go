package enrollment

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"runtime"
	"testing"
)

func TestEnsurePrivateKeyIsStableAndPrivate(t *testing.T) {
	directory := t.TempDir()
	first, paths, err := EnsurePrivateKey(directory)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := EnsurePrivateKey(directory)
	if err != nil {
		t.Fatal(err)
	}
	firstHash, err := PublicKeyHash(&first.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	secondHash, err := PublicKeyHash(&second.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash {
		t.Fatal("endpoint identity key changed between enrollment retries")
	}
	info, err := os.Stat(paths.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("endpoint identity key permissions are too broad: %o", info.Mode().Perm())
	}
}

func TestCreateCSRUsesEndpointKeyAndContainsNoTenantClaim(t *testing.T) {
	key, _, err := EnsurePrivateKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := CreateCSR(key, "agent-01")
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("CSR PEM is malformed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "agent-01" || len(csr.URIs) != 0 {
		t.Fatalf("CSR contains unexpected identity claims: %#v", csr)
	}
	csrHash, _ := PublicKeyHash(csr.PublicKey)
	keyHash, _ := PublicKeyHash(&key.PublicKey)
	if csrHash != keyHash {
		t.Fatal("CSR public key does not match endpoint key")
	}
}
