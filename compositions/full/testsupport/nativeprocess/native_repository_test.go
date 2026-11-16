package nativeprocess

import (
	"os"
	"path/filepath"
	"testing"
)

func nativeRepository(t *testing.T) string {
	t.Helper()
	path, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(path, "compositions", "full", "go.mod")); err == nil {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			t.Fatal("implementation root unavailable")
		}
		path = parent
	}
}
