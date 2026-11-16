//go:build (darwin && arm64) || (linux && amd64)

package compositionfull

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

const manifestCutChild = "ENKV_TEST_NATIVE_MANIFEST_CUT"

// full_only: false
func TestManifestFileNativeProcessCuts(t *testing.T) {
	if cut := os.Getenv(manifestCutChild); cut != "" {
		manifestNativeCutChild(t, cut)
		return
	}
	for _, cut := range []string{"before-rename", "after-rename"} {
		t.Run(cut, func(t *testing.T) {
			parent := t.TempDir()
			subject := manifestNativeSubject(t, parent)
			t.Run(subject, func(t *testing.T) {
				path := filepath.Join(parent, "manifest.json")
				if os.WriteFile(path, []byte("old complete"), 0600) != nil {
					t.Fatal("old process fixture unavailable")
				}
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestManifestFileNativeProcessCuts$", "-test.count=1")
				cmd.Env = append(os.Environ(), manifestCutChild+"="+cut, "ENKV_TEST_NATIVE_MANIFEST_PATH="+path)
				cmd.Stderr = io.Discard
				cmd.WaitDelay = time.Second
				stdout, err := cmd.StdoutPipe()
				if err != nil {
					t.Fatal("process checkpoint pipe unavailable")
				}
				stdin, err := cmd.StdinPipe()
				if err != nil {
					t.Fatal("process cut barrier unavailable")
				}
				if err := cmd.Start(); err != nil {
					t.Fatal("native process did not start")
				}
				joined := false
				defer func() {
					if !joined {
						if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
							t.Error("failed native child could not be stopped")
						}
						waitErr := cmd.Wait()
						var exited *exec.ExitError
						if cmd.ProcessState == nil || waitErr != nil && !errors.As(waitErr, &exited) {
							t.Error("failed native child did not positively join")
						}
					}
					if err := stdin.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
						t.Error("process barrier close failed")
					}
				}()
				line, err := bufio.NewReader(stdout).ReadString('\n')
				if err != nil || line != "candidate-ready\n" {
					t.Fatal("native process did not reach exact cut checkpoint")
				}
				if err := cmd.Process.Kill(); err != nil {
					t.Fatal("native process cut failed")
				}
				err = cmd.Wait()
				joined = true
				status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
				if err == nil || !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("native interrupted process did not positively join")
				}
				want := "old complete"
				if cut == "after-rename" {
					want = "new complete"
				}
				manifestAssertBody(t, path, []byte(want))
				paths := manifestCandidates(t, parent)
				if cut == "before-rename" {
					if len(paths) != 1 {
						t.Fatal("interrupted invocation did not leave exactly one owned candidate")
					}
					info, err := os.Lstat(paths[0])
					if err != nil || !info.Mode().IsRegular() || info.Mode() != 0600 {
						t.Fatal("private process residue type or mode differs")
					}
					manifestAssertBody(t, paths[0], []byte("new complete"))
					// The exact child is joined and this private regular candidate is identified.
					if os.Remove(paths[0]) != nil {
						t.Fatal("identified process residue cleanup failed")
					}
				} else if len(paths) != 0 {
					t.Fatal("known rename retained a candidate name")
				}
				if _, err := os.Lstat(filepath.Join(parent, "completed")); !os.IsNotExist(err) {
					t.Fatal("interrupted native process claimed success")
				}
			})
		})
	}
}

func manifestNativeCutChild(t *testing.T, cut string) {
	t.Helper()
	path := os.Getenv("ENKV_TEST_NATIVE_MANIFEST_PATH")
	target := manifestTestTarget(t, path)
	rename := target.io.rename
	target.io.rename = func(from, to string) (ManifestReplacement, error) {
		replacement := ManifestNotReplaced
		var err error
		if cut == "after-rename" {
			replacement, err = rename(from, to)
			if err != nil {
				return replacement, err
			}
		} else if cut != "before-rename" {
			return replacement, syscall.EINVAL
		}
		if _, err := fmt.Fprintln(os.Stdout, "candidate-ready"); err != nil {
			return replacement, err
		}
		var release [1]byte
		if _, err := io.ReadFull(os.Stdin, release[:]); err != nil {
			return replacement, err
		}
		if cut == "before-rename" {
			return rename(from, to)
		}
		return replacement, nil
	}
	result := target.install(t.Context(), manifestTestArtifactIdentity(manifestTestFormat), []byte("new complete"), nil)
	if result.NativeCompletion == ManifestNativeComplete {
		if os.WriteFile(filepath.Join(filepath.Dir(path), "completed"), []byte("complete\n"), 0600) != nil {
			t.Fatal("completion marker failed")
		}
	}
}

func manifestNativeSubject(t *testing.T, path string) string {
	t.Helper()
	var filesystem syscall.Statfs_t
	if err := syscall.Statfs(path, &filesystem); err != nil {
		t.Fatal("native filesystem subject unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "df", "-P", path)
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	body, err := cmd.Output()
	if err != nil {
		t.Fatal("native mount subject unavailable")
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 {
		t.Fatal("native mount subject is not one exact filesystem")
	}
	fields := strings.Fields(lines[1])
	if len(fields) != 6 || len(fields[0]) > 160 || len(fields[5]) > 160 {
		t.Fatal("native mount subject is not bounded and unambiguous")
	}
	return fmt.Sprintf("os_%s_arch_%s_runtime_%s_filesystem_0x%x_source_%s_mount_%s_process-interruption", runtime.GOOS, runtime.GOARCH, runtime.Version(), filesystem.Type, url.PathEscape(fields[0]), url.PathEscape(fields[5]))
}

// full_only: false
func TestManifestFileNativeReservedDirectoryAliases(t *testing.T) {
	for _, reserved := range []string{".enkv", ".enkv-locks", ".enkv-pending", ".enkv-transactions"} {
		t.Run(reserved, func(t *testing.T) {
			parent, sources := manifestReservedSourceFixture(t)
			if reserved == ".enkv-locks" || reserved == ".enkv-transactions" {
				parent = filepath.Dir(sources[1])
			}
			directory := filepath.Join(parent, reserved)
			if err := os.MkdirAll(filepath.Join(directory, "nested"), 0700); err != nil {
				t.Fatal(err)
			}
			coordination := filepath.Join(directory, "coordination")
			if err := os.WriteFile(coordination, []byte("coordination original"), 0600); err != nil {
				t.Fatal(err)
			}
			original, err := os.Stat(directory)
			if err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(parent, strings.Replace(reserved, "k", "\u212a", 1))
			if err := os.MkdirAll(filepath.Join(alias, "nested"), 0700); err != nil {
				t.Fatal(err)
			}
			aliased, err := os.Stat(alias)
			if err != nil {
				t.Fatal(err)
			}
			same := os.SameFile(original, aliased)
			identity := "distinct-native-directory"
			if same {
				identity = "same-reserved-identity"
			}
			t.Run(identity, func(t *testing.T) {
				path := filepath.Join(alias, "nested", "manifest.json")
				if err := os.WriteFile(path, []byte("old complete"), 0600); err != nil {
					t.Fatal(err)
				}
				target, result := newManifestFileTarget(path, sources, nil)
				if target != nil {
					result = target.install(t.Context(), manifestTestArtifactIdentity(manifestTestFormat), []byte("new complete"), nil)
				}
				if same {
					if result.Failure == nil || result.Failure.Stage != ManifestPreflightStage || result.Failure.Reason != ManifestReservedPath || result.Replacement != ManifestReplacementNotAttempted || result.CandidateCleanup != ManifestCandidateNotCreated {
						t.Errorf("native reserved alias reached delivery: %+v", result)
					}
					manifestAssertBody(t, path, []byte("old complete"))
				} else {
					if result.NativeCompletion != ManifestNativeComplete || result.Failure != nil {
						t.Fatalf("distinct native directory inherited reservation: %+v", result)
					}
					manifestAssertBody(t, path, []byte("new complete"))
				}
				manifestAssertBody(t, coordination, []byte("coordination original"))
				manifestAssertReservedSources(t, sources)
				if len(manifestCandidates(t, filepath.Dir(path))) != 0 {
					t.Fatal("native alias operation retained a candidate")
				}
			})
		})
	}
	for _, name := range []string{"ordinary", ".enkv-locks"} {
		t.Run("unrelated-parent/"+name, func(t *testing.T) {
			_, sources := manifestReservedSourceFixture(t)
			parent := filepath.Join(t.TempDir(), name)
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "manifest.json")
			target := manifestTestTarget(t, path, sources...)
			result := target.install(t.Context(), manifestTestArtifactIdentity(manifestTestFormat), []byte("new complete"), nil)
			if result.NativeCompletion != ManifestNativeComplete || result.Failure != nil {
				t.Fatalf("unrelated native parent refused: %+v", result)
			}
			manifestAssertBody(t, path, []byte("new complete"))
			manifestAssertReservedSources(t, sources)
		})
	}
}

// full_only: false
func TestManifestFileNativeRechecksReservedDirectoryBeforeRename(t *testing.T) {
	parent, sources := manifestReservedSourceFixture(t)
	reserved, saved := filepath.Join(parent, ".enkv-locks"), filepath.Join(parent, "saved-locks")
	if err := os.Mkdir(reserved, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reserved, "coordination"), []byte("coordination original"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(reserved)
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	path := filepath.Join(output, "manifest.json")
	if err := os.WriteFile(path, []byte("old complete"), 0600); err != nil {
		t.Fatal(err)
	}
	target := manifestTestTarget(t, path, sources...)
	write := target.io.write
	changed := false
	target.io.write = func(file *os.File, body []byte) (int, error) {
		n, err := write(file, body)
		if err != nil || changed {
			return n, err
		}
		changed = true
		if err := os.Rename(reserved, saved); err != nil {
			return n, err
		}
		return n, os.Symlink(output, reserved)
	}
	renames := 0
	rename := target.io.rename
	target.io.rename = func(from, to string) (ManifestReplacement, error) { renames++; return rename(from, to) }
	result := target.install(t.Context(), manifestTestArtifactIdentity(manifestTestFormat), []byte("new complete"), nil)
	if !changed || renames != 0 || result.Failure == nil || result.Failure.Stage != ManifestPreflightStage || result.Failure.Reason != ManifestReservedPath || result.Replacement != ManifestNotReplaced || result.CandidateVerification != ManifestVerified || result.CandidateCleanup != ManifestCandidateRemoved || result.ResiduePath != "" {
		t.Errorf("late reserved directory change escaped replacement check: %+v renames=%d", result, renames)
	}
	manifestAssertBody(t, path, []byte("old complete"))
	manifestAssertBody(t, filepath.Join(saved, "coordination"), []byte("coordination original"))
	after, err := os.Stat(saved)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("original coordination directory identity changed")
	}
	manifestAssertReservedSources(t, sources)
	if len(manifestCandidates(t, output)) != 0 {
		t.Fatal("late refusal retained an owned candidate")
	}
}

func manifestReservedSourceFixture(t *testing.T) (string, []string) {
	t.Helper()
	root := t.TempDir()
	parent, generatedParent := filepath.Join(root, "editable"), filepath.Join(root, "generated")
	if os.Mkdir(parent, 0700) != nil || os.Mkdir(generatedParent, 0700) != nil {
		t.Fatal("source parent fixtures unavailable")
	}
	sources := []string{filepath.Join(parent, "source.yaml"), filepath.Join(generatedParent, "generated.json")}
	for _, source := range sources {
		if err := os.WriteFile(source, []byte("source original"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return parent, sources
}

func manifestAssertReservedSources(t *testing.T, sources []string) {
	t.Helper()
	for _, source := range sources {
		manifestAssertBody(t, source, []byte("source original"))
	}
}
