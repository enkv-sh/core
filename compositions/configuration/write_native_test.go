//go:build darwin || linux

package configuration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

// full_only: false
func TestEditNativeLock(t *testing.T) {
	if path := os.Getenv("ENKV_EDIT_LOCK_CHILD_PATH"); path != "" {
		s, err := BeginEdit(context.Background(), path, JSON)
		if s != nil {
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if !errors.Is(err, ErrEditLocked) {
			t.Fatal("child editor acquired held lock")
		}
		return
	}
	s, path := beginSourceEdit(t, JSON, false)
	check := func() {
		t.Helper()
		second, err := BeginEdit(context.Background(), path, JSON)
		if second != nil {
			if err := second.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if !errors.Is(err, ErrEditLocked) {
			t.Fatal("second editor acquired held lock")
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, executable, "-test.run=^TestEditNativeLock$")
		child.Env = append(os.Environ(), "ENKV_EDIT_LOCK_CHILD_PATH="+path)
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("lock child did not join: %v %s", err, output)
		}
	}
	check()
	c, _ := stageSourceEdit(t, s, sourceGeneratedJSON)
	if _, err := s.Commit(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	check()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := BeginEdit(context.Background(), path, JSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}
