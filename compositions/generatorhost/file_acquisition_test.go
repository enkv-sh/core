package generatorhost

import (
	"context"
	"crypto/sha256"
	"enkv.sh/sdk/artifact/credentialroute"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"golang.org/x/sys/unix"
)

// full_only: false
func TestBuildInfoFIFORefusesWithoutWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() {
		done <- verifyArtifactBuildInfo(t.Context(), path, &Installation{artifact: contract.GeneratorImplementation{ArtifactLength: 1, ArtifactSHA256: sha256.Sum256([]byte("x"))}}) == nil
	}()
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
	implementation := contract.GeneratorImplementation{ArtifactLength: 1, ArtifactSHA256: sha256.Sum256([]byte("x"))}
	for _, name := range []string{"stage", "verification"} {
		t.Run(name, func(t *testing.T) {
			switch name {
			case "stage":
				setup := &nativeSetup{removeLaunchDir: os.RemoveAll}
				defer func() {
					if err := setup.cleanup(); err != nil {
						t.Error("stage cleanup failed", err)
					}
				}()
				if _, err := (&NativeLauncher{config: Config{ArtifactPath: path, Artifact: implementation}}).sealedLaunchCopy(setup); err == nil {
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
				if err := stage.authenticate(t.Context(), implementation.ArtifactSHA256, implementation.ArtifactLength); err == nil {
					t.Fatal("verification accepted FIFO")
				}

			}
			t.Log("fifo_without_writer=true refused=true")
		})
	}
}

// full_only: false
func TestPrivateEnvironmentInputOwnsOneExactDisposedBuffer(t *testing.T) {
	route := credentialroute.Route{Schema: 1, ContractID: [32]byte{1}, Mode: credentialroute.ModeEnvironment, Names: []string{"ENKV_GENERATOR_TEST_TOKEN"}}
	t.Setenv(route.Names[0], strings.Repeat("x", 1024))
	body, err := readEnvironmentInputs(t.Context(), route)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := credentialroute.DecodeInputs(route, body)
	if err != nil || len(inputs) != 1 || len(inputs[0].Value) != 1024 {
		t.Fatal("input ownership changed", err)
	}
	if len(body) != 3+6+len(route.Names[0])+1024 || cap(body) != len(body) {
		t.Fatal("input allocation exceeds exact complete encoding")
	}
	clear(body[:cap(body)])
	if !allZero(inputs[0].Value) {
		t.Fatal("borrowed private input survived disposal")
	}
	t.Setenv(route.Names[0], strings.Repeat("x", credentialroute.MaxInputsBytes))
	if body, err := readEnvironmentInputs(t.Context(), route); body != nil || !errors.Is(err, ErrCredential) {
		t.Fatal("overflow returned private custody", err)
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

// full_only: false
func TestNativeAcquisitionCarriesItsOwnDisposalOutcome(t *testing.T) {
	for _, clean := range []bool{true, false} {
		t.Run(map[bool]string{true: "canceled-open-closed", false: "invalid-descriptor-close-refused"}[clean], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			file, failure := openNativeFileWith(ctx, os.DevNull, unix.O_RDONLY, 0, func(path string, flags int, mode uint32) (int, error) {
				if !clean {
					return -1, nil
				}
				fd, err := unix.Open(path, flags, mode)
				cancel()
				return fd, err
			})
			if file != nil || failure == nil || acquisitionSettled(failure) != clean {
				t.Fatal("native acquisition lost local disposal evidence", failure)
			}
			if clean && !errors.Is(failure, context.Canceled) || !clean && !errors.Is(failure, unix.EBADF) {
				t.Fatal("native acquisition lost original cause", failure)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "missing")
	if source, failure := acquireRegularFile(t.Context(), path); source != nil || !acquisitionSettled(failure) || !errors.Is(failure, os.ErrNotExist) {
		t.Fatal("clean source refusal lost disposal evidence", failure)
	}
}

// full_only: false
func TestFailedStageConstructionCarriesCompleteLocalDisposal(t *testing.T) {
	for _, closeFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean-collision", true: "root-close-refusal"}[closeFirst], func(t *testing.T) {
			path := t.TempDir()
			if err := os.Mkdir(filepath.Join(path, "existing"), 0700); err != nil {
				t.Fatal(err)
			}
			root, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if closeFirst {
				if err := root.Close(); err != nil {
					t.Fatal(err)
				}
			}
			stage, failure := newArtifactStage(t.Context(), root, "existing", "generator")
			if stage != nil || failure == nil || acquisitionSettled(failure) == closeFirst {
				t.Fatal("stage construction lost its exact disposal outcome", failure)
			}
			if _, err := root.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("failed stage retained root handle")
			}
			if closeFirst && !errors.Is(failure, os.ErrClosed) {
				t.Fatal("stage construction lost descriptor close cause", failure)
			}
		})
	}
}
