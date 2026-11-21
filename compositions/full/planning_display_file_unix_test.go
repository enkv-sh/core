//go:build unix

package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"

	"enkv.sh/compositions/configuration"
	"os"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"golang.org/x/sys/unix"
)

// Darwin also returns write-history flags that F_SETFL cannot restore.
const planningRestorableFileFlags = unix.O_ACCMODE | unix.O_APPEND | unix.O_ASYNC | unix.O_NONBLOCK | unix.O_SYNC | unix.O_DSYNC

func planningFileFlags(t *testing.T, file *os.File) int {
	t.Helper()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var getErr error
	if err := raw.Control(func(fd uintptr) { flags, getErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); err != nil || getErr != nil {
		t.Fatal("descriptor status unavailable")
	}
	return flags
}

// full_only: false
func TestPlanningDisplayNativeStatusRestoredAfterEveryOutcome(t *testing.T) {
	for _, condition := range []string{"success", "write-error", "cancel", "restore-error"} {
		t.Run(condition, func(t *testing.T) {
			fds := make([]int, 2)
			if err := unix.Pipe(fds); err != nil {
				t.Fatal(err)
			}
			reader, writer := os.NewFile(uintptr(fds[0]), "display-read"), os.NewFile(uintptr(fds[1]), "display-write")
			readerClosed, writerClosed := false, false
			t.Cleanup(func() {
				if !readerClosed {
					if err := reader.Close(); err != nil {
						t.Error("display reader close failed", err)
					}
				}
				if !writerClosed {
					if err := writer.Close(); err != nil {
						t.Error("display writer close failed", err)
					}
				}
			})
			original := planningFileFlags(t, writer)
			if original&unix.O_NONBLOCK != 0 {
				t.Fatal("fixture is not inherited blocking output")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			factory, _ := NewPlanningDisplayFile(writer, false)
			sink, err := factory.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			sinkClosed := false
			defer func() {
				if !sinkClosed {
					if err := sink.Close(); err != nil {
						t.Error("display sink cleanup failed", err)
					}
				}
			}()
			if planningFileFlags(t, writer)&unix.O_NONBLOCK == 0 {
				t.Fatal("native pipe was not made cancellable")
			}
			value := []byte{1}
			if condition == "write-error" {
				readerClosed = true
				if err := reader.Close(); err != nil {
					t.Fatal("write-error fixture reader close failed", err)
				}
			}
			if condition == "cancel" {
				cancel()
			}
			err = sink.Accept(ctx, "binary", contract.PlanningSealed, value)
			if (err != nil) != (condition == "write-error" || condition == "cancel") {
				t.Fatal("native write result differs")
			}
			if condition == "restore-error" {
				writerClosed = true
				if err := writer.Close(); err != nil {
					t.Fatal("restore-error fixture writer close failed", err)
				}
			}
			sinkClosed = true
			closeErr := sink.Close()
			if condition == "restore-error" {
				if closeErr == nil {
					t.Fatal("restore failure discarded")
				}
				return
			}
			if closeErr != nil {
				t.Fatal("native close failed")
			}
			current := planningFileFlags(t, writer)
			if current&planningRestorableFileFlags != original&planningRestorableFileFlags {
				t.Fatalf("native mutable status was not restored: original=%#x current=%#x mask=%#x", original, current, planningRestorableFileFlags)
			}
			if condition != "write-error" {
				if n, err := writer.Write([]byte{'x'}); n != 1 || err != nil {
					t.Fatal("borrowed stdout descriptor closed")
				}
			}
		})
	}
}

// full_only: false
func TestPlanningDisplayRegularFileStaysOpenForSafeResult(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "result-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error("display result file close failed", err)
		}
	}()
	flags := planningFileFlags(t, file)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f, _ := NewPlanningDisplayFile(file, true)
	sink, err := f.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sinkClosed := false
	defer func() {
		if !sinkClosed {
			if err := sink.Close(); err != nil {
				t.Error("display sink cleanup failed", err)
			}
		}
	}()
	if err := sink.Accept(ctx, "", contract.PlanningRetained, nil); err != nil {
		t.Fatal(err)
	}
	sinkClosed = true
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if planningFileFlags(t, file)&planningRestorableFileFlags != flags&planningRestorableFileFlags {
		t.Fatal("regular-file status changed")
	}
	if _, err := file.Write([]byte("safe-result\n")); err != nil {
		t.Fatal("regular output closed")
	}
	body, err := os.ReadFile(file.Name())
	if err != nil || !bytes.HasSuffix(body, []byte("safe-result\n")) {
		t.Fatal("safe result not delivered after finalization")
	}
}

// full_only: false
func TestPlanningDisplayAcquisitionExcludesCapturedFiles(t *testing.T) {
	trusted := configurationReaderPair(t, "aws", configuration.JSON, configurationReaderWithoutOutputs)
	candidate := configurationReaderPair(t, "aws", configuration.JSON, configurationReaderWithoutOutputs)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, pair := range []configurationReaderSource{trusted, candidate} {
		for _, path := range []string{pair.path, pair.generated} {
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(t.TempDir(), "alias")
			if err := os.Link(path, alias); err != nil {
				t.Fatal(err)
			}
			for _, target := range []string{path, alias} {
				for _, mode := range []int{os.O_WRONLY, os.O_WRONLY | os.O_APPEND} {
					file, err := os.OpenFile(target, mode, 0)
					if err != nil {
						t.Fatal(err)
					}
					f, err := NewPlanningDisplayFile(file, true)
					if err != nil {
						t.Fatal(err)
					}
					guard := sourceBoundPlanningDisplay{PlanningDisplayFactory: f, trusted: trusted.pair, candidate: candidate.pair}
					sink, err := guard.Acquire(ctx)
					if sink != nil {
						t.Error("source accepted for native display")
						if err := sink.Close(); err != nil {
							t.Error(err)
						}
					}
					if !errors.Is(err, errPlanningDisplay) {
						t.Fatal("missing source separation failure", err)
					}
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("acquisition changed a source member", err)
			}
		}
	}
}

// full_only: false
func TestPlanningDisplayFinalRecordRequiresTheAdmittedFile(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	open := func() *os.File {
		f, err := os.CreateTemp(t.TempDir(), "output")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
		return f
	}
	admitted, other := open(), open()
	info, err := admitted.Stat()
	if err != nil {
		t.Fatal(err)
	}
	record := []byte("terminal\n")
	if err := writePlanningResult(ctx, other, record, info); !errors.Is(err, errPlanningDisplay) {
		t.Fatal("terminal output changed its destination", err)
	}
	if got, err := os.ReadFile(other.Name()); err != nil || len(got) != 0 {
		t.Fatal("changed destination received output", err)
	}
	empty := ConfigurationPlanningResult{}
	if err := empty.WriteDisplayResult(ctx, other, record); !errors.Is(err, errPlanningDisplay) {
		t.Fatal("unadmitted result wrote a terminal record", err)
	}
	if err := writePlanningResult(ctx, admitted, record, info); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(admitted.Name()); err != nil || !bytes.Equal(got, record) {
		t.Fatal("admitted terminal write changed", err)
	}
}
