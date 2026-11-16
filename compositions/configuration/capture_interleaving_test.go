package configuration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// captureStepContext performs a synchronous action at an existing read boundary.
// It controls capture's interleaving without depending on OS scheduling.
type captureStepContext struct {
	context.Context
	checks int
	at     int
	action func()
}

func (c *captureStepContext) Err() error {
	c.checks++
	if c.checks == c.at {
		c.action()
	}
	return c.Context.Err()
}

// full_only: false
func TestSourceCaptureChangesDuringIntakeRefuseOnce(t *testing.T) {
	for _, tc := range []struct {
		name       string
		at         int
		copied     int
		wantChecks int
	}{
		{"stable-same-size", 4, WindowBytes + 17, 7},
		{"path-replaced", 4, WindowBytes + 17, 6},
		{"same-length-rewrite", 4, WindowBytes + 17, 6},
		{"partial-read", 2, WindowBytes, 3},
		{"cancelled-after-intake", 4, WindowBytes + 17, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tmpDir := t.TempDir()
			t.Setenv("TMPDIR", tmpDir)
			path := filepath.Join(dir, "input")
			body := bytes.Repeat([]byte{'a'}, WindowBytes+17)
			wantSource := bytes.Clone(body)
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &captureStepContext{Context: parent, at: tc.at}
			var temporaryPath string
			ctx.action = func() {
				entries, err := os.ReadDir(tmpDir)
				if err != nil || len(entries) != 1 {
					t.Fatalf("capture must own one temporary image at the read boundary: %v, %v", entries, err)
				}
				temporaryPath = filepath.Join(tmpDir, entries[0].Name())
				copied, err := os.ReadFile(temporaryPath)
				if err != nil || !bytes.Equal(copied, body[:tc.copied]) {
					t.Fatalf("wrong intake boundary: copied %d bytes, want %d: %v", len(copied), tc.copied, err)
				}
				switch tc.name {
				case "path-replaced":
					replacement := filepath.Join(dir, "replacement")
					if err := os.WriteFile(replacement, body, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(replacement, path); err != nil {
						t.Fatal(err)
					}
				case "same-length-rewrite":
					f, err := os.OpenFile(path, os.O_WRONLY, 0)
					if err != nil {
						t.Fatal(err)
					}
					wantSource[WindowBytes] = 'b'
					n, writeErr := f.WriteAt([]byte{'b'}, WindowBytes)
					closeErr := f.Close()
					if n != 1 || writeErr != nil || closeErr != nil {
						t.Fatalf("same-length rewrite failed: %d, %v, %v", n, writeErr, closeErr)
					}
				case "partial-read":
					wantSource = wantSource[:WindowBytes+5]
					if err := os.Truncate(path, int64(len(wantSource))); err != nil {
						t.Fatal(err)
					}
				case "cancelled-after-intake":
					cancel()
				}
				after, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if same := os.SameFile(before, after); same != (tc.name != "path-replaced") {
					t.Fatal("source identity does not match the controlled change")
				}
				if after.Size() != int64(len(wantSource)) {
					t.Fatal("source size does not match the controlled change")
				}
			}

			image, err := capture(ctx, path, int64(len(body)))
			if image != nil {
				t.Cleanup(func() {
					if err := image.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			if ctx.checks != tc.wantChecks || temporaryPath == "" {
				t.Fatalf("capture repeated or missed its intended boundary: %d checks, want %d; temporary image %q", ctx.checks, tc.wantChecks, temporaryPath)
			}
			if tc.name == "stable-same-size" {
				if err != nil || image == nil {
					t.Fatalf("stable capture refused: %v", err)
				}
				var copied bytes.Buffer
				if _, err := image.CopyTo(&copied); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(copied.Bytes(), body) || image.Size() != int64(len(body)) || image.Digest() != sha256.Sum256(body) {
					t.Fatal("stable image bytes, length or digest differ")
				}
				if err := image.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if image != nil || !errors.Is(err, ErrCapture) {
					t.Fatalf("changed capture must return nil image and ErrCapture: image %v, error %v", image != nil, err)
				}
				if cancelled := errors.Is(err, context.Canceled); cancelled != (tc.name == "cancelled-after-intake") {
					t.Fatalf("wrong cancellation cause: %v", err)
				}
			}
			entries, err := os.ReadDir(tmpDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("capture retained a temporary image: %v, %v", entries, err)
			}
			if _, err := os.Stat(temporaryPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("temporary image still exists: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, wantSource) {
				t.Fatalf("capture changed the controlled source bytes: %v", err)
			}
		})
	}
}
