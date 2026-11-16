package generatorhost

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// full_only: false
func TestNativeProcessClosesCompleteDescriptorRangePreservesParent(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "fd-probe")
	build := exec.Command("go", "build", "-trimpath", "-o", artifact, "./testdata/fdprobe")
	build.Env = append(os.Environ(), "GOWORK=off")
	prepareNativeModule(t, "../..", build, artifact+".mod")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build descriptor probe: %v\n%s", err, output)
	}
	sentinel, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := sentinel.Close(); err != nil {
			t.Error("close sentinel", err)
		}
	}()
	high, err := unix.FcntlInt(sentinel.Fd(), unix.F_DUPFD, 512)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Close(high); err != nil {
			t.Error("close inherited descriptor", err)
		}
	}()
	flags, err := unix.FcntlInt(uintptr(high), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC != 0 {
		t.Fatal("non-close-on-exec sentinel absent")
	}
	for _, count := range []int{5, 7} {
		t.Run("assigned-"+strconv.Itoa(count), func(t *testing.T) {
			null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := null.Close(); err != nil {
					t.Error("close null", err)
				}
			}()
			files := []*os.File{null, null, null}
			var owned []*os.File
			defer func() {
				for _, file := range owned {
					if err := file.Close(); err != nil {
						t.Error("close owned pipe", err)
					}
				}
			}()
			for len(files) < count {
				read, write, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				owned = append(owned, read, write)
				files = append(files, read)
			}
			child, err := startNativeChild(t.Context(), artifact, filepath.Dir(artifact), strconv.Itoa(count), files)
			if err != nil {
				t.Fatal("descriptor setup refused", err)
			}
			waitErr := child.Wait()
			after, err := unix.FcntlInt(uintptr(high), unix.F_GETFD, 0)
			if err != nil || after != flags {
				t.Fatal("caller descriptor was closed or changed")
			}
			t.Logf("assigned_descriptors=%d inherited_high_descriptor_closed_in_child=true parent_descriptor_preserved=true child_joined=%t", count, child.ProcessState != nil)
			if waitErr != nil {
				t.Fatal("child received extra/missing descriptors", waitErr)
			}
		})
	}
}

// full_only: false
func TestNativePreSpawnFailureCarriesOnlyCleanNoChildProvenance(t *testing.T) {
	file, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, tc := range []struct {
		name      string
		files     []*os.File
		path      string
		qualified bool
	}{
		{"no descriptor vector", nil, "/not-used", true},
		{"partial descriptor acquisition", []*os.File{file, nil, file}, "/not-used", true},
		{"opaque spawn refusal", []*os.File{file, file, file}, filepath.Join(t.TempDir(), "missing"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child, failure := startNativeChild(context.Background(), tc.path, t.TempDir(), "generator-wire-v5", tc.files)
			if child != nil || failure == nil {
				t.Fatal("fixture did not refuse native launch")
			}
			_, qualified := failure.(*nativeStartFailure)
			if qualified != tc.qualified {
				t.Fatal("native refusal lost its exact creation provenance", qualified, failure)
			}
			if _, err := file.Stat(); err != nil {
				t.Fatal("borrowed descriptor was closed", err)
			}
			if tc.name == "opaque spawn refusal" && !errors.Is(failure, unix.ENOENT) {
				t.Fatal("native spawn cause lost", failure)
			}
		})
	}
}
