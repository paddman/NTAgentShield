package identity

import (
	"os"
	"runtime"
	"testing"
)

func TestEnsurePersistsSameIdentity(t *testing.T) {
	dataDir := t.TempDir()
	first, path, err := Ensure(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	second, secondPath, err := Ensure(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if path != secondPath || !first.Equal(second) {
		t.Fatal("identity key changed between loads")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("identity key permissions are too broad: %o", info.Mode().Perm())
	}
}
