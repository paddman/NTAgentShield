package inventory

import (
	"testing"
	"time"
)

func TestNewValidatesLimits(t *testing.T) {
	if _, err := New(Options{MaxItems: 0, CommandTimeout: 10 * time.Second}); err != nil {
		t.Fatalf("default options should be valid: %v", err)
	}
	if _, err := New(Options{MaxItems: 10001, CommandTimeout: 10 * time.Second}); err == nil {
		t.Fatal("expected max item validation error")
	}
	if _, err := New(Options{MaxItems: 10, CommandTimeout: 100 * time.Millisecond}); err == nil {
		t.Fatal("expected command timeout validation error")
	}
}

func TestCapItemsAndUniqueStrings(t *testing.T) {
	truncated := map[string]bool{}
	values := capItems([]int{1, 2, 3}, 2, truncated, "numbers")
	if len(values) != 2 || !truncated["numbers"] {
		t.Fatalf("unexpected cap result: values=%v truncated=%v", values, truncated)
	}
	unique := uniqueStrings([]string{"10.0.0.1", "10.0.0.1", "10.0.0.2"})
	if len(unique) != 2 || unique[0] != "10.0.0.1" || unique[1] != "10.0.0.2" {
		t.Fatalf("unexpected unique values: %#v", unique)
	}
}
