package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// full_only: false
func TestOverlayLifetimeRequiresEveryCommandJoined(t *testing.T) {
	for _, row := range []struct {
		name         string
		modules      []string
		unjoined     string
		wantRetained bool
		moduleCheck  bool
	}{
		{"joined-failure", []string{"core"}, "", false, false},
		{"unjoined-failure", []string{"core"}, "core", true, false},
		{"joined-first-unjoined-second", []string{"core", "crypto"}, "crypto", true, false},
		{"module-joined-failure", []string{"crypto"}, "", false, true},
		{"module-unjoined-failure", []string{"crypto"}, "crypto", true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if os.Getenv("ENKV_OVERLAY_LIFETIME_CHILD") != row.name {
				// The inner fixture intentionally returns an unjoined command,
				// then reaps it. Give it a separate process boundary so this
				// failure stays inside this fixture process lifetime.
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				command := exec.Command(executable, "-test.run=^TestOverlayLifetimeRequiresEveryCommandJoined$/^"+regexp.QuoteMeta(row.name)+"$")
				for _, item := range os.Environ() {
					name, _, _ := strings.Cut(item, "=")
					if name != "ENKV_OVERLAY_LIFETIME_CHILD" {
						command.Env = append(command.Env, item)
					}
				}
				command.Env = append(command.Env, "ENKV_OVERLAY_LIFETIME_CHILD="+row.name)
				var output limitedOutput
				command.Stdout, command.Stderr = &output, &output
				// The outer command remains supervised and positively joined.
				// The invocation guard also observes this fixture and its children.
				ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
				defer cancel()
				process := superviseProcess(ctx, command)
				if process.Status != "passed" || !process.Joined || output.overflow {
					t.Fatalf("overlay fixture failed: status=%s joined=%t cause=%v\n%s", process.Status, process.Joined, process.Cause, output.String())
				}
				return
			}
			root, _, _ := overlayFixture(t)
			for _, module := range row.modules {
				if module == "core" {
					writeLocalGoFixture(t, root, "tests/hermetic/hermetic.mod", "module "+componentPackage+"\n\ngo 1.27.0\n")
				} else {
					for _, name := range []string{"crypto/go.mod", "crypto/telemetry_test.mod"} {
						writeLocalGoFixture(t, root, name, "module "+modulePrefix+"crypto\n\ngo 1.27.0\n")
					}
				}
			}
			temporary, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			control := t.TempDir()
			binaryDirectory := t.TempDir()
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			realGo, err = filepath.EvalSymlinks(realGo)
			if err != nil {
				t.Fatal(err)
			}
			// Metadata commands have no overlay lifetime. Stop only when the
			// actual owned-overlay command reaches its inventory operation.
			fakeGo := `#!/bin/sh
overlay=
for argument in "$@"; do
 case "$argument" in
  -overlay=*) overlay=${argument#-overlay=} ;;
 esac
done
if [ -z "$overlay" ]; then
 exec '` + strings.ReplaceAll(realGo, "'", "'\"'\"'") + `' "$@"
fi
scope=$(pwd -P)
scope=${scope##*/}
printf '%s\n%s\n' "$$" "$overlay" > "$ENKV_UNIT_OVERLAY_FIXTURE/$scope.ready"
while [ ! -f "$ENKV_UNIT_OVERLAY_FIXTURE/$scope.release" ]; do
 /bin/sleep 0.01
done
printf 'controlled inventory failure\n' >&2
exit 1
`
			if err := os.WriteFile(filepath.Join(binaryDirectory, "go"), []byte(fakeGo), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TMPDIR", temporary)
			t.Setenv("PATH", binaryDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("ENKV_UNIT_OVERLAY_FIXTURE", control)
			ctx, cancel := context.WithTimeout(withExecutionCapacity(context.Background(), executionPolicy{Resolved: executionCapacity{Parallel: 2, MemoryLimitMiB: 4096}}), 30*time.Second)
			type result struct {
				evidence ordinaryStepEvidence
				err      error
			}
			done := make(chan result, 1)
			var helper *exec.Cmd
			helperReaped, invocationReturned := false, false
			// Reap our group member before waiting for the invocation during
			// emergency cleanup. Nothing is orphaned, including a failed test.
			t.Cleanup(func() {
				cancel()
				if helper != nil && helper.Process != nil && !helperReaped {
					if err := helper.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
						t.Errorf("owned group-member cleanup: %v", err)
					}
					_ = helper.Wait()
					helperReaped = true
				}
				if !invocationReturned {
					select {
					case <-done:
					case <-time.After(15 * time.Second):
						t.Error("unit invocation did not return after owned process cleanup")
					}
				}
			})
			selection := map[string][]string{}
			for _, module := range row.modules {
				selection[module] = []string{"."}
			}
			go func() {
				var evidence ordinaryStepEvidence
				var err error
				if row.moduleCheck {
					_, err = checkModule(ctx, root, "crypto")
				} else {
					err = runUnitProfileEvidence(ctx, root, selection, "full", io.Discard, &evidence)
				}
				done <- result{evidence: evidence, err: err}
			}()
			pids := map[string]int{}
			overlay := ""
			for _, module := range row.modules {
				deadline := time.Now().Add(10 * time.Second)
				for {
					body, readErr := os.ReadFile(filepath.Join(control, module+".ready"))
					fields := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
					if readErr == nil && len(fields) == 2 {
						pid, pidErr := strconv.Atoi(fields[0])
						if pidErr == nil && pid > 0 && fields[1] != "" {
							pids[module] = pid
							if overlay != "" && overlay != fields[1] {
								t.Fatal("unit commands did not share one overlay")
							}
							overlay = fields[1]
							break
						}
					}
					select {
					case got := <-done:
						invocationReturned = true
						t.Fatalf("unit invocation returned before %s inventory barrier: %v", module, got.err)
					default:
					}
					if !time.Now().Before(deadline) {
						t.Fatal("unit inventory barrier was not reached", module)
					}
					time.Sleep(10 * time.Millisecond)
				}
				if _, err := os.Stat(overlay); err != nil {
					t.Fatal("unit overlay was missing during inventory", err)
				}
				if row.unjoined == module {
					executable, err := os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					helper = exec.Command(executable, "-test.run=^TestProcessHelper$")
					helper.Env = environment(os.Environ(), map[string]string{"ENKV_PROCESS_HELPER": "exited"})
					helper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: pids[row.unjoined]}
					stdout, err := helper.StdoutPipe()
					if err != nil {
						t.Fatal(err)
					}
					if err := helper.Start(); err != nil {
						t.Fatal("owned helper could not join the inventory process group", err)
					}
					drained := make(chan error, 1)
					go func() {
						_, err := io.Copy(io.Discard, stdout)
						drained <- err
					}()
					select {
					case err := <-drained:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("owned helper did not exit before inventory release")
					}
					// EOF proves the helper exited. Delay Wait so its test-owned
					// zombie keeps this group unsettled beyond the join allowance.
				}
				if err := os.WriteFile(filepath.Join(control, module+".release"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			relative, pathErr := filepath.Rel(temporary, overlay)
			parts := strings.Split(relative, string(filepath.Separator))
			owned := pathErr == nil && len(parts) == 3 && strings.HasPrefix(parts[0], "enkv-invocation-artifacts-") && strings.HasPrefix(parts[1], "crypto-overlay-")
			if row.moduleCheck {
				owned = pathErr == nil && len(parts) == 2 && strings.HasPrefix(parts[0], "enkv-module-check-")
			}
			if !owned || filepath.Base(overlay) != "crypto-overlay.json" {
				t.Fatal("fixture did not observe the test-owned overlay", overlay, pathErr)
			}
			var got result
			select {
			case got = <-done:
				invocationReturned = true
			case <-ctx.Done():
				t.Fatal("unit invocation exceeded its fixture deadline")
			}
			if helper != nil {
				err := helper.Wait()
				helperReaped = true
				if err != nil {
					t.Fatal("owned exited helper was not reaped cleanly", err)
				}
			}
			if got.err == nil || got.evidence.Complete {
				t.Fatal("controlled inventory failure qualified the unit step")
			}
			var first *toolFailure
			if !errors.As(got.err, &first) || !first.process.Started {
				t.Fatal("controlled inventory failure lost its process result")
			}
			if row.name == "joined-first-unjoined-second" && !first.process.Joined {
				t.Fatal("fixture did not place the joined command first in the error tree")
			}
			unjoined := unitOverlayHasUnjoinedCommand(got.err)
			if unjoined != row.wantRetained {
				t.Fatalf("fixture settlement differs: unjoined=%t want=%t", unjoined, row.wantRetained)
			}
			_, overlayErr := os.Stat(overlay)
			_, directoryErr := os.Stat(filepath.Dir(overlay))
			if row.wantRetained {
				if overlayErr != nil || directoryErr != nil {
					t.Fatal("unit cleanup removed an overlay used by an unjoined command", overlayErr, directoryErr)
				}
			} else if !errors.Is(overlayErr, os.ErrNotExist) || !errors.Is(directoryErr, os.ErrNotExist) {
				t.Fatal("joined unit failure retained its disposable overlay", overlayErr, directoryErr)
			}
		})
	}
}

// Inspect every error branch; errors.As alone reports only the first matching
// command and would miss the second command in the two-module regression.
func unitOverlayHasUnjoinedCommand(err error) bool {
	if err == nil {
		return false
	}
	if failure, ok := err.(*toolFailure); ok && !failure.process.Joined {
		return true
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range wrapped.Unwrap() {
			if unitOverlayHasUnjoinedCommand(child) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return unitOverlayHasUnjoinedCommand(wrapped.Unwrap())
	}
	return false
}
