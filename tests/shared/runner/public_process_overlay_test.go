package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicOverlayClosureUsesBoundedContextualImages(t *testing.T) {
	for _, condition := range []string{"complete", "original-empty", "original-absent", "nil-context", "cancelled", "metadata-fifo", "original-fifo", "replacement-fifo", "replacement-absent", "wrong-mode", "wrong-digest", "metadata-limit", "original-limit", "replacement-limit"} {
		t.Run(condition, func(t *testing.T) {
			directory := sourceFixtureRoot(t)
			original, replacement := filepath.Join(directory, "original.go"), filepath.Join(directory, "replacement.go")
			if err := os.WriteFile(original, []byte("original"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(replacement, []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			hash := func(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
			source := nativeprocess.Source{Target: original, OriginalSHA256: hash([]byte("original")), Replacement: replacement, ReplacementSHA256: hash([]byte("replacement"))}
			if condition == "original-empty" || condition == "original-absent" {
				source.OriginalSHA256 = hash(nil)
				if condition == "original-empty" {
					if err := os.WriteFile(original, nil, 0644); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Remove(original); err != nil {
					t.Fatal(err)
				}
			}
			overlay := nativeprocess.Overlay{Path: filepath.Join(directory, "overlay.json"), Manifest: filepath.Join(directory, "sources.json")}
			for path, value := range map[string]any{overlay.Path: struct{ Replace map[string]string }{map[string]string{original: replacement}}, overlay.Manifest: []nativeprocess.Source{source}} {
				if err := records.WriteJSON(path, value, 0600); err != nil {
					t.Fatal(err)
				}
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if path == overlay.Path {
					overlay.SHA256 = hash(body)
				} else {
					overlay.ManifestSHA256 = hash(body)
				}
			}
			ctx := t.Context()
			switch condition {
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "metadata-fifo", "original-fifo", "replacement-fifo":
				path := map[string]string{"metadata-fifo": overlay.Path, "original-fifo": original, "replacement-fifo": replacement}[condition]
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "replacement-absent":
				if err := os.Remove(replacement); err != nil {
					t.Fatal(err)
				}
			case "metadata-limit", "original-limit", "replacement-limit":
				path := map[string]string{"metadata-limit": overlay.Path, "original-limit": original, "replacement-limit": replacement}[condition]
				if err := os.Truncate(path, records.MaximumJSONBytes+1); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				if ctx.Err() != nil {
					t.Fatal("size control context is not live")
				}
				body, identity, readErr := readPublicConfigurationFileContext(ctx, path, records.MaximumJSONBytes, info.Mode().Perm())
				if ctx.Err() != nil || readErr == nil || body != nil || identity != nil {
					t.Fatal("oversized regular image crossed its byte bound")
				}
			case "wrong-mode":
				if err := os.Chmod(overlay.Manifest, 0644); err != nil {
					t.Fatal(err)
				}
			case "wrong-digest":
				overlay.ManifestSHA256 = strings.Repeat("a", 64)
			}
			want := condition == "complete" || condition == "original-empty" || condition == "original-absent"
			if got := publicProcessOverlaySourcesValid(ctx, overlay); got != want {
				t.Fatalf("closure admission=%t, want %t", got, want)
			}
		})
	}
}
