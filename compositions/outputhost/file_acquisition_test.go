package outputhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/artifact/credentialroute"
	"golang.org/x/sys/unix"
)

// full_only: false
func TestBuildInfoFIFORefusesWithoutWriter(t *testing.T) {
	config := testArtifactAndConfig(t)
	if err := VerifyInstalledArtifact(t.Context(), config.ArtifactPath, config.Installation); err != nil {
		t.Fatal("actual native installation refused before FIFO check", err)
	}
	path := filepath.Join(t.TempDir(), "artifact.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() { done <- VerifyInstalledArtifact(t.Context(), path, config.Installation) == nil }()
	blocked := false
	select {
	case accepted := <-done:
		if accepted {
			t.Fatal("constructor accepted a FIFO")
		}
	case <-time.After(100 * time.Millisecond):
		blocked = true
		writer, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if accepted := <-done; accepted {
			t.Fatal("constructor accepted a FIFO")
		}
	}
	t.Logf("acquisition_joined=true refused=true blocked_before_writer=%t", blocked)
	if blocked {
		t.Fatal("constructor required a writer to refuse a FIFO")
	}
}

// full_only: false
func TestStageAndVerificationFIFORefuseWithoutWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.fifo")
	if err := unix.Mkfifo(path, 0500); err != nil {
		t.Fatal(err)
	}
	artifact := Artifact{Length: 1, SHA256: sha256.Sum256([]byte("x"))}
	for _, name := range []string{"stage", "verification", "source"} {
		t.Run(name, func(t *testing.T) {
			switch name {
			case "stage":
				if stage, _, err := stageArtifact(t.Context(), path, artifact); err == nil {
					defer func() {
						if err := stage.close(); err != nil {
							t.Error("stage cleanup failed", err)
						}
					}()
					t.Fatal("stage accepted FIFO")
				}
			case "verification":
				directory, err := os.Open(filepath.Dir(path))
				if err != nil {
					t.Fatal(err)
				}
				stage := &artifactStage{directory: directory, target: path}
				defer func() {
					if err := stage.close(); err != nil {
						t.Error("stage verification cleanup failed", err)
					}
				}()
				if err := stage.authenticate(t.Context(), artifact.SHA256, artifact.Length); err == nil {
					t.Fatal("verification accepted FIFO")
				}
			case "source":
				if source, _, err := acquireRegularFile(t.Context(), path); err == nil {
					if closeErr := source.close(); closeErr != nil {
						t.Error(closeErr)
					}
					t.Fatal("source accepted FIFO")
				}
			}
			t.Log("fifo_without_writer=true refused=true")
		})
	}
}

// full_only: false
func TestEnvironmentCaptureHasOneOwnedBufferAndExactSize(t *testing.T) {
	route := credentialroute.Route{Schema: 1, ContractID: [32]byte{1}, Mode: credentialroute.ModeEnvironment, Names: []string{"ENKV_OUTPUT_TEST_CREDENTIAL"}}
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", strings.Repeat("x", 1024))
	body, err := captureEnvironment(t.Context(), route)
	if err != nil || len(body) != 3+6+len(route.Names[0])+1024 || cap(body) != len(body) {
		t.Fatal("captured environment owner is not exact", err)
	}
	inputs, err := credentialroute.DecodeInputs(route, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 1 || len(inputs[0].Value) != 1024 {
		t.Fatal("captured value length changed")
	}
	clear(body)
	if !bytes.Equal(inputs[0].Value, make([]byte, 1024)) {
		t.Fatal("borrowed private bytes survived owner disposal")
	}
	if !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatal("owned capture disposal failed")
	}
}

// full_only: false
func TestNativeAcquisitionRetriesOnlyInterruptionsAndRejectsSubstitutedFIFO(t *testing.T) {
	for _, name := range []string{"interrupted-success", "interrupted-cancel", "other-error", "substituted-fifo"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(path, []byte("dummy"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			file, err := openNativeFileWith(ctx, path, unix.O_RDONLY, 0, func(path string, flags int, mode uint32) (int, error) {
				calls++
				required := unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_NOFOLLOW | unix.O_CLOEXEC
				if flags&required != required {
					t.Error("native acquisition omitted safe flags")
				}
				switch name {
				case "interrupted-cancel":
					cancel()
					return -1, unix.EINTR
				case "other-error":
					return -1, unix.EACCES
				case "substituted-fifo":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := unix.Mkfifo(path, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if name == "interrupted-success" && calls == 1 {
					return -1, unix.EINTR
				}
				return unix.Open(path, flags, mode)
			})
			if file != nil {
				defer func() {
					if err := file.Close(); err != nil {
						t.Error("close file", err)
					}
				}()
			}
			switch name {
			case "interrupted-success":
				if err != nil || file == nil || calls != 2 {
					t.Fatal("interruption lost success", calls, err)
				}
			case "interrupted-cancel":
				if !errors.Is(err, context.Canceled) || file != nil || calls != 1 {
					t.Fatal("interruption ignored cancellation", calls, err)
				}
			case "other-error":
				if !errors.Is(err, unix.EACCES) || file != nil || calls != 1 {
					t.Fatal("other failure was repeated or lost", calls, err)
				}
			case "substituted-fifo":
				if err != nil || file == nil {
					t.Fatal("nonblocking substitution did not return descriptor", err)
				}
				info, err := file.Stat()
				if err != nil || info.Mode().IsRegular() {
					t.Fatal("substitution lost special-file identity")
				}
			}
			t.Logf("acquisition_calls=%d fifo_without_writer=%t", calls, name == "substituted-fifo")
		})
	}
}
