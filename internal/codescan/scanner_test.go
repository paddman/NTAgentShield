package codescan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScannerFindsAndRedactsHardcodedSecret(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.py")
	if err := os.WriteFile(path, []byte(`api_key = "super-secret-value"\nrequests.get(url, verify=False)\n`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := New().Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) < 2 {
		t.Fatalf("expected findings: %+v", result.Findings)
	}
	for _, finding := range result.Findings {
		if strings.Contains(finding.Excerpt, "super-secret-value") {
			t.Fatal("finding leaked the hard-coded secret")
		}
	}
}

func TestScannerFindsPHPWebShellChain(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "upload.php")
	content := `<?php $x = base64_decode($_POST['x']); eval($x); ?>`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := New().Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range result.Findings {
		if finding.RuleID == "NTS-CODE-008" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected PHP web-shell chain finding: %+v", result.Findings)
	}
}
