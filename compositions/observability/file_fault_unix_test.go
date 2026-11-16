//go:build darwin || linux

package observability

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// full_only: false
func TestFileTransportOSWriteFailureRetainsCompletePrefix(t *testing.T) {
	const childEnv = "ENKV_TEST_FILE_SIZE_LIMIT_CHILD"
	if os.Getenv(childEnv) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, executable, "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")
		command.Env = append(os.Environ(), childEnv+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("file-size-limit subprocess: %v\n%s", err, output)
		}
		return
	}

	// File-size limits and SIGXFSZ handling affect the whole process.
	// Only the isolated test child changes them.
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	for _, test := range []struct {
		name      string
		remaining int
	}{
		{name: "partial_write", remaining: 5},
		{name: "write_error", remaining: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			sink := newFileTransport(root, "telemetry", "logs")
			for _, line := range []string{`{"resourceLogs":[]}`, `{}`} {
				if err := sink.writeLine([]byte(line)); err != nil {
					t.Fatal(err)
				}
			}
			defer func() {
				if err := sink.Close(); err != nil {
					t.Errorf("close file after write failure: %v", err)
				}
			}()
			const prefix = "{\"resourceLogs\":[]}\n{}\n"
			const line = `{"resourceLogs":[{}]}`
			probe, err := os.Create(filepath.Join(root, "partial-write-probe"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := probe.Close(); err != nil {
					t.Errorf("close write probe: %v", err)
				}
			}()
			if _, err := io.WriteString(probe, prefix); err != nil {
				t.Fatal(err)
			}

			var original syscall.Rlimit
			if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
				t.Fatal(err)
			}
			limit := original
			limit.Cur = uint64(len(prefix) + test.remaining)
			if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
					t.Errorf("restore file-size limit: %v", err)
				}
			}()

			// Confirm the OS fault and exact partial bytes independently of
			// the transport's rollback and its much larger application quota.
			n, err := probe.Write([]byte(line + "\n"))
			if n != test.remaining || !errors.Is(err, syscall.EFBIG) {
				t.Fatalf("OS write = (%d, %v), want (%d, EFBIG)", n, err, test.remaining)
			}
			data, err := os.ReadFile(probe.Name())
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != prefix+line[:test.remaining] {
				t.Fatalf("OS fault wrote unexpected bytes: %q", data)
			}
			if sink.failed || sink.bytes != int64(len(prefix)) || len(prefix)+len(line)+1 >= fileQuotaBytes {
				t.Fatal("write fixture did not reach a healthy file below the quota")
			}
			if err := sink.writeLine([]byte(line)); !errors.Is(err, errFileDelivery) {
				t.Fatalf("write error = %v, want file delivery failure", err)
			}
			position, err := sink.file.Seek(0, io.SeekCurrent)
			if err != nil || position != int64(len(prefix)) {
				t.Fatalf("position after failed write = (%d, %v), want %d", position, err, len(prefix))
			}
			assertFailedFileTransportRetainsPrefix(t, sink, prefix)
		})
	}
}

// full_only: false
func TestFileTransportSyncFailureClosesHandleAndRetainsCompletePrefix(t *testing.T) {
	sink := newFileTransport(t.TempDir(), "telemetry", "logs")
	first := []byte(`{"resourceLogs":[]}`)
	if err := sink.writeLine(first); err != nil {
		t.Fatal(err)
	}
	if err := sink.file.Close(); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Errorf("close pipe reader: %v", err)
		}
		if err := writer.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("close pipe writer: %v", err)
		}
	}()
	// A pipe makes Sync fail while Close can still succeed. A closed
	// regular file would make both operations fail and hide a lost Sync error.
	if err := writer.Sync(); err == nil {
		t.Fatal("pipe Sync unexpectedly succeeded")
	}
	if n, err := writer.Write([]byte("open")); err != nil || n != 4 {
		t.Fatalf("pipe is not open after failed Sync: wrote %d bytes, error %v", n, err)
	}
	sink.file = writer
	if err := sink.Close(); !errors.Is(err, errFileDelivery) {
		t.Fatalf("shutdown error = %v, want file delivery failure", err)
	}
	if sink.file != nil {
		t.Fatal("shutdown retained the failed handle")
	}
	if _, err := writer.Write([]byte("closed")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after shutdown = %v, want closed file", err)
	}
	assertFailedFileTransportRetainsPrefix(t, sink, string(first)+"\n")
}
