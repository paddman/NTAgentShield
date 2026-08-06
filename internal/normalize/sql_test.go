package normalize

import "testing"

func TestSQLRemovesLiterals(t *testing.T) {
	got := SQL("SELECT * FROM users WHERE id = 42 AND email='alice@example.com'")
	want := "select * from users where id = ? and email=?"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSQLFingerprintStable(t *testing.T) {
	one := SQLFingerprint("SELECT * FROM users WHERE id=1")
	two := SQLFingerprint("select * from users where id=999")
	if one != two {
		t.Fatalf("fingerprints differ: %s %s", one, two)
	}
}
