//go:build (darwin || linux) && cgo

package manifesthost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// full_only: false
func TestNativeProcessStartPreservesHostErrors(t *testing.T) {
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := null.Close(); err != nil {
			t.Error("close parent descriptor", err)
		}
	})
	for _, tc := range []struct {
		name  string
		files []*os.File
	}{
		{"too-few", nil},
		{"too-many", make([]*os.File, 8)},
		{"nil-after-duplicate", []*os.File{null, nil, null}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child, err := startNativeChild(t.Context(), "", "", "", tc.files)
			if child != nil {
				killErr := child.Process.Kill()
				waitErr := child.Wait()
				t.Fatal("failed launch retained a child", errors.Join(err, killErr, waitErr))
			}
			if err != ErrAdmission {
				t.Fatal("launch admission changed host error identity", err)
			}
		})
	}
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		child, err := startNativeChild(ctx, "", "", "", []*os.File{null, null, null})
		if child != nil {
			killErr := child.Process.Kill()
			waitErr := child.Wait()
			t.Fatal("failed launch retained a child", errors.Join(err, killErr, waitErr))
		}
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrAdmission) || errors.Is(err, ErrProcess) {
			t.Fatal("cancelled launch changed its cause", err)
		}
	})
	t.Run("missing-executable", func(t *testing.T) {
		directory := t.TempDir()
		child, err := startNativeChild(t.Context(), filepath.Join(directory, "absent-executable"), directory, "unused", []*os.File{null, null, null})
		if child != nil {
			killErr := child.Process.Kill()
			waitErr := child.Wait()
			t.Fatal("failed launch retained a child", errors.Join(err, killErr, waitErr))
		}
		if !errors.Is(err, syscall.ENOENT) || errors.Is(err, ErrAdmission) || errors.Is(err, ErrProcess) {
			t.Fatal("failed native spawn changed its cause", err)
		}
	})
}
