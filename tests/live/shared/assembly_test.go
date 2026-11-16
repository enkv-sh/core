package core

import (
	"path/filepath"
	"testing"
)

// full_only: false
func TestLiveAssembly(t *testing.T) {
	if !liveFamily.Valid() {
		t.Fatal("missing provider family")
	}
	f := newFixture(t, 1, false, 1)
	if f.admission.admission == nil || f.session == nil {
		t.Fatal("private component fixture is unavailable")
	}
}

func liveTestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("canonical test directory unavailable")
	}
	return directory
}
