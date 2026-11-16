package observability

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// full_only: false
func TestFileTransportCreationPreservesTrustedPathsAndExistingOutput(t *testing.T) {
	t.Run("trusted-existing-directory", func(t *testing.T) {
		base := t.TempDir()
		directory := filepath.Join(base, "telemetry")
		if err := os.Mkdir(directory, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o750); err != nil {
			t.Fatal(err)
		}
		sink := newFileTransport(base, "telemetry/nested", "logs")
		if err := sink.writeLine([]byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := sink.Close(); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(directory, "nested", "logs.jsonl")
		data, err := os.ReadFile(output)
		if err != nil || string(data) != "{}\n" {
			t.Fatalf("output=%q, error=%v", data, err)
		}
		info, err := os.Stat(filepath.Join(directory, "nested"))
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("created directory=%v, error=%v", info, err)
		}
		info, err = os.Stat(output)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("created file=%v, error=%v", info, err)
		}
	})

	for _, tc := range []struct {
		name, existing, signal string
	}{
		{"existing-output", "telemetry/logs.jsonl", "logs"},
		{"non-directory", "telemetry", "logs"},
		{"invalid-signal", "", "../outside"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			var existing string
			if tc.existing != "" {
				existing = filepath.Join(base, tc.existing)
				if err := os.MkdirAll(filepath.Dir(existing), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			sink := newFileTransport(base, "telemetry", tc.signal)
			if err := sink.writeLine([]byte(`{}`)); !errors.Is(err, errFileDelivery) {
				t.Fatalf("delivery error=%v", err)
			}
			if !sink.failed || sink.file != nil || sink.bytes != 0 {
				t.Fatalf("refused sink: failed=%t, open=%t, bytes=%d", sink.failed, sink.file != nil, sink.bytes)
			}
			if err := sink.Close(); err != nil {
				t.Fatal(err)
			}
			if existing != "" {
				data, err := os.ReadFile(existing)
				if err != nil || string(data) != "keep" {
					t.Fatalf("existing file=%q, error=%v", data, err)
				}
			} else if entries, err := os.ReadDir(base); err != nil || len(entries) != 0 {
				t.Fatalf("invalid signal created files: %v, error=%v", entries, err)
			}
		})
	}
}
