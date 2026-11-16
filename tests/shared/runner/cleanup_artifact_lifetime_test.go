package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestPreparedStandaloneCleanupReusesArtifactsAfterSourceEdit(t *testing.T) {
	for _, mode := range []string{"passed", "failed_cleanup"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ENKV_CONTROLLED_CLEANUP_FAILURE", "")

			ctx, root, bootstrap := localLivePreparationFixture(t, "gcp")
			ctx = testRaceContext(t, ctx)
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			oldRoot, original, _, request, _, _ := grantedRecoveryFixture(t)
			request.race = raceEnabled(ctx)
			request.Limits = filepath.Join(root, "cleanup-limits.json")
			allowance := testLimits()
			allowance.CleanupSeconds = 30
			if err := records.WriteJSON(request.Limits, allowance, 0600); err != nil {
				t.Fatal(err)
			}
			runs := filepath.Join(root, "tests/live/runs")
			if err := os.CopyFS(runs, os.DirFS(filepath.Join(oldRoot, "tests/live/runs"))); err != nil {
				t.Fatal("retained cleanup fixture unavailable", err)
			}
			if err := filepath.WalkDir(runs, func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				mode := os.FileMode(0600)
				if entry.IsDir() {
					mode = 0700
				}
				return os.Chmod(path, mode)
			}); err != nil {
				t.Fatal("retained cleanup fixture permissions unavailable", err)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			control := t.TempDir()
			cleanupCalls := filepath.Join(control, "cleanup-calls")
			worker := fmt.Sprintf(`package core
import ("os"; "os/exec"; "testing")
// full_only: false
func TestLiveRun(t *testing.T) { t.Fatal("cleanup replayed a Product writer") }
// full_only: false
func TestLiveChild(t *testing.T) { t.Fatal("cleanup replayed a Product reader") }
// full_only: false
func TestLiveCleanup(t *testing.T) {
 file, err := os.OpenFile(%q, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
 if err != nil { t.Fatal(err) }
 if _, err := file.WriteString("cleanup\n"); err != nil { t.Fatal(err) }
 if err := file.Close(); err != nil { t.Fatal(err) }
 command := exec.Command(%q, "-test.run=^TestLiveCleanup$", "-test.timeout=20s")
 command.Env, command.Stdout, command.Stderr = os.Environ(), os.Stdout, os.Stderr
 if %t { command.Env = append(command.Env, "ENKV_CONTROLLED_CLEANUP_FAILURE=1") }
 if err := command.Run(); err != nil { t.Fatal("controlled exact cleanup worker failed", err) }
}
`, cleanupCalls, binary, mode == "failed_cleanup")
			writeLocalGoFixture(t, root, "tests/live/runner/fixture_test.go", worker)
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			commands := filepath.Join(control, "go-commands")
			script := "#!/bin/sh\nprintf 'BEGIN\\n' >> " + shellQuote(commands) + "\nprintf '%s\\n' \"$PWD\" \"$@\" >> " + shellQuote(commands) + "\nprintf 'END\\n' >> " + shellQuote(commands) + "\nexec " + shellQuote(realGo) + " \"$@\"\n"
			if err := os.WriteFile(filepath.Join(control, "go"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", control+string(os.PathListSeparator)+os.Getenv("PATH"))
			if invocationArtifactsFrom(ctx) != nil {
				t.Fatal("standalone caller unexpectedly supplies a prepared artifact owner")
			}
			var preparationOutput bytes.Buffer
			prepared, err := prepareCleanup(ctx, root, bootstrap, request, &preparationOutput)
			if prepared != nil {
				defer func() {
					if err := prepared.close(ctx); err != nil {
						t.Error(err)
					}
				}()
			}
			if err != nil {
				diagnostic := preparationOutput.String()
				if len(diagnostic) > 16<<10 {
					diagnostic = diagnostic[:16<<10] + " [bounded diagnostic]"
				}
				t.Fatal("actual cleanup preparation failed", err, diagnostic)
			}
			before, err := os.ReadFile(commands)
			if err != nil {
				t.Fatal(err)
			}
			assemblies := 0
			for _, block := range strings.Split(string(before), "BEGIN\n")[1:] {
				if strings.Contains(block, "\n-c\n") {
					assemblies++
				}
			}
			if assemblies != 1 {
				t.Fatal("cleanup preparation did not construct one actual executable", assemblies)
			}
			writeLocalGoFixture(t, root, "tests/live/runner/fixture_test.go", "invalid source after completed cleanup preparation")
			result, err := runPreparedCleanupResult(ctx, root, bootstrap, prepared, io.Discard, suiteExecution{})
			if result.Record == nil || len(result.Record.Scenarios) != 1 || mode == "passed" && (err != nil || result.Record.Outcome != "passed") || mode == "failed_cleanup" && (err == nil || result.Record.Outcome != "failed") {
				t.Fatal("prepared cleanup rebuilt, lost its captured executable or changed the joined result", err)
			}
			after, err := os.ReadFile(commands)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("cleanup repeated compiler discovery or construction after preparation", err)
			}
			calls, err := os.ReadFile(cleanupCalls)
			if err != nil || string(calls) != "cleanup\n" {
				t.Fatal("cleanup did not execute exactly once", err)
			}
			resultCase := result.Record.Scenarios[0]
			if result.Record.RecoveryRunID != original.RunID || result.Record.Correctness.Passed || resultCase.Writer != nil || resultCase.Rerun != nil || len(resultCase.Children) != 0 || len(resultCase.PostExit) != 0 || resultCase.CleanupWorker == nil || !resultCase.CleanupWorker.Joined || mode == "passed" && !scenarioCleanupPassed(resultCase) || mode == "failed_cleanup" && (resultCase.CleanupWorker.Process != "process_failed" || scenarioCleanupPassed(resultCase)) {
				t.Fatal("cleanup lost exact ownership, settlement or no-replay behavior")
			}
			state := prepared.plan.Entries[0].State
			if _, err := os.Stat(filepath.Join(filepath.Dir(state), "gcp-cleanup-grant.json")); err != nil {
				t.Fatal("cleanup did not retain its consumed one-use grant", err)
			}

			if mode == "passed" {
				return
			}
			if result.Recovery == nil {
				t.Fatal("failed cleanup has no retained run owner")
			}
			if err := prepared.close(ctx); err != nil {
				t.Fatal("prepared cleanup cache did not close after all children joined", err)
			}
			retainedBuild := filepath.Join(result.Recovery.directory, "private/build")
			mapPath := filepath.Join(retainedBuild, "failure-sources.json")
			mapBody, err := os.ReadFile(mapPath)
			if err != nil || digestBytes(mapBody) != result.Record.BuildClosure.FailureSourcesSHA256 {
				t.Fatal("closed cached cleanup lost its exact retained assertion source map", err)
			}
			name, err := recordedCaseDirectory(resultCase.Entry)
			if err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(result.Recovery.directory, "private", name, "cleanup")
			var invocation records.Invocation
			if records.ReadJSON(filepath.Join(output, "invocation.json"), &invocation) != nil || invocation.FailureSources == nil || invocation.FailureSources.SHA256 != digestBytes(mapBody) {
				t.Fatal("retained cleanup map differs from the dispatched invocation")
			}
			originalBinding := invocation.FailureSources
			if _, err := os.Lstat(originalBinding.Path); !os.IsNotExist(err) {
				t.Fatal("controlled cache source map still exists after cache close", err)
			}
			invocation.FailureSources = &records.FailureSourceBinding{Path: mapPath, SHA256: digestBytes(mapBody)}
			assertions := records.InspectAssertions(invocation, resultCase.CleanupWorker.Process == "passed")
			if resultCase.CleanupWorker.Assertions == nil || !reflect.DeepEqual(assertions, *resultCase.CleanupWorker.Assertions) {
				t.Fatal("retained map cannot reopen the exact joined cleanup assertions")
			}
			if _, err := publicCleanupJoinedWorker(output, invocation, *resultCase.CleanupWorker, mapPath); err != nil {
				t.Fatal("closed cleanup assembly cannot reopen its exact worker join", err)
			}

		})
	}
}
