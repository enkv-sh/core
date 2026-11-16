package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"syscall"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestGCFilePanicClosesCapturedDescriptors(t *testing.T) {
	for _, operation := range []string{"apply", "plan"} {
		t.Run(operation, func(t *testing.T) {
			source := configurationReaderPair(t, "aws", configuration.JSON, nil)
			// Keep the original os.File finalizers from masking missing explicit cleanup.
			previous := debug.SetGCPercent(-1)
			defer debug.SetGCPercent(previous)
			before := gcFileDescriptors(t)
			var captured map[int]syscall.Stat_t
			sentinel := new(int)
			ctx := gcFileDeadlineContext{Context: context.Background(), deadline: func() (time.Time, bool) {
				captured = gcFileCapturedDescriptors(t, before, source)
				panic(sentinel)
			}}
			var propagated any
			func() {
				defer func() { propagated = recover() }()
				gcFileExpiredInvocation(t, operation, ctx, source.path)
			}()
			if propagated != sentinel {
				t.Fatalf("panic = %v, want original sentinel", propagated)
			}
			gcFileAssertDescriptorsClosed(t, captured)
			source.assertUnchanged(t)
		})
	}
}

// full_only: false
func TestGCFileNormalReturnReportsCapturedCleanup(t *testing.T) {
	for _, operation := range []string{"apply", "plan"} {
		t.Run(operation, func(t *testing.T) {
			for _, closeBeforeReturn := range []bool{false, true} {
				name := "cleanup-succeeds"
				if closeBeforeReturn {
					name = "cleanup-fails"
				}
				t.Run(name, func(t *testing.T) {
					source := configurationReaderPair(t, "aws", configuration.JSON, nil)
					previous := debug.SetGCPercent(-1)
					defer debug.SetGCPercent(previous)
					before := gcFileDescriptors(t)
					var captured map[int]syscall.Stat_t
					ctx := &gcFileExpiringContext{gcFileDeadlineContext: gcFileDeadlineContext{Context: context.Background()}, done: make(chan struct{})}
					ctx.deadline = func() (time.Time, bool) {
						if captured != nil {
							t.Fatal("unexpected second deadline check")
						}
						captured = gcFileCapturedDescriptors(t, before, source)
						if closeBeforeReturn {
							// The expired-deadline branch performs no file opens before Pair.Close.
							// Its os.File owners therefore observe these exact failed closes.
							for fd := range captured {
								if err := syscall.Close(fd); err != nil {
									t.Fatal("preclose captured descriptor", err)
								}
							}
						}
						close(ctx.done)
						return time.Now().Add(-time.Second), true
					}
					if failed := gcFileExpiredInvocation(t, operation, ctx, source.path); failed != closeBeforeReturn {
						t.Errorf("CleanupFailed = %v, want %v", failed, closeBeforeReturn)
					}
					if len(captured) != 2 {
						t.Fatalf("captured descriptors = %d, want 2", len(captured))
					}
					gcFileAssertDescriptorsClosed(t, captured)
					source.assertUnchanged(t)
				})
			}
		})
	}
}

type gcFileDeadlineContext struct {
	context.Context
	deadline func() (time.Time, bool)
}

func (c gcFileDeadlineContext) Deadline() (time.Time, bool) { return c.deadline() }

type gcFileExpiringContext struct {
	gcFileDeadlineContext
	done chan struct{}
}

func (c *gcFileExpiringContext) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (c *gcFileExpiringContext) Done() <-chan struct{} { return c.done }

func gcFileExpiredInvocation(t *testing.T, operation string, ctx context.Context, path string) bool {
	t.Helper()
	if operation == "apply" {
		out := ApplyConfigurationGCFile(ctx, GCApplyRequest{RequestNonce: contract.ID{91}, OperationID: contract.ID{92}}, path, configuration.JSON)
		if out.Operation.Validate() != nil || out.Operation.StateResult != "refused" || out.Operation.Result.Outcome != core.AdmissionRefused || out.PreAdmission == nil || out.PreAdmission.Stage != "context" || out.PreAdmission.Code != string(contract.ReasonExpired) {
			t.Fatal("expired apply result lost refusal facts", out)
		}
		return out.Delivery.CleanupFailed
	}
	out := PlanConfigurationGCFile(ctx, GCPlanRequest{RequestNonce: contract.ID{93}, OperationID: contract.ID{94}, ArtifactPath: filepath.Join(filepath.Dir(path), "plan.bin")}, path, configuration.JSON)
	if out.Operation.Validate() != nil || out.Operation.StateResult != core.PublicQueryRefused || out.Operation.Result.Outcome != core.AdmissionRefused || out.Operation.FailureReason != contract.ReasonExpired || out.Operation.PreAdmission == nil || out.Operation.PreAdmission.Stage != "context" {
		t.Fatal("expired plan result lost refusal facts", out)
	}
	return out.Delivery.CleanupFailed
}

func gcFileDescriptors(t *testing.T) map[int]syscall.Stat_t {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal("enumerate file descriptors", err)
	}
	out := make(map[int]syscall.Stat_t)
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal("invalid descriptor name", err)
		}
		var stat syscall.Stat_t
		if err := syscall.Fstat(fd, &stat); errors.Is(err, syscall.EBADF) {
			continue // The enumeration directory descriptor has already closed.
		} else if err != nil {
			t.Fatal("inspect descriptor", err)
		}
		if uint32(stat.Mode)&syscall.S_IFMT == syscall.S_IFREG {
			out[fd] = stat
		}
	}
	return out
}

func gcFileCapturedDescriptors(t *testing.T, before map[int]syscall.Stat_t, source configurationReaderSource) map[int]syscall.Stat_t {
	t.Helper()
	out := make(map[int]syscall.Stat_t)
	matched := [2]bool{}
	for fd, stat := range gcFileDescriptors(t) {
		if prior, ok := before[fd]; ok && prior.Dev == stat.Dev && prior.Ino == stat.Ino {
			continue
		}
		if stat.Nlink != 0 {
			t.Fatal("new regular descriptor is not an unlinked snapshot", fd)
		}
		found := false
		for i, body := range [][]byte{source.editableBytes, source.generatedBytes} {
			if matched[i] || stat.Size != int64(len(body)) {
				continue
			}
			actual := make([]byte, len(body))
			n, err := syscall.Pread(fd, actual, 0)
			if err != nil || n != len(body) || !bytes.Equal(actual, body) {
				continue
			}
			matched[i], found = true, true
			break
		}
		if !found {
			t.Fatal("new descriptor does not contain an exact captured source image", fd)
		}
		out[fd] = stat
	}
	if len(out) != 2 || !matched[0] || !matched[1] {
		t.Fatalf("captured descriptors = %d, want exact editable and generated images", len(out))
	}
	return out
}

func gcFileAssertDescriptorsClosed(t *testing.T, descriptors map[int]syscall.Stat_t) {
	t.Helper()
	for fd, captured := range descriptors {
		var current syscall.Stat_t
		err := syscall.Fstat(fd, &current)
		if errors.Is(err, syscall.EBADF) {
			continue
		}
		if err == nil && current.Dev == captured.Dev && current.Ino == captured.Ino {
			t.Errorf("captured descriptor %d remains open", fd)
		} else {
			t.Errorf("captured descriptor %d closure is not established: stat=%+v err=%v", fd, current, err)
		}
	}
}
