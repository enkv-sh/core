package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

type focusedNodeCancellationWriter struct{ cancel context.CancelFunc }

func (w focusedNodeCancellationWriter) Write(body []byte) (int, error) {
	if bytes.Contains(body, []byte("phase=test")) {
		w.cancel()
	}
	return len(body), nil
}

// full_only: false
func TestFocusedNodeUnavailableExecutionCannotClaimMissing(t *testing.T) {
	for _, owner := range []string{"component", "provider"} {
		for _, condition := range []string{"never-started", "unjoined-test", "unjoined-converter", "failed-converter", "available-missing", "malformed-empty", "truncated-empty", "prefix-child-failed"} {
			t.Run(owner+"/"+condition, func(t *testing.T) {
				if strings.HasPrefix(condition, "unjoined-") && os.Getenv("ENKV_FOCUSED_NODE_CHILD") != t.Name() {
					// This fixture deliberately returns before its group can join,
					// then reaps the held helper. Isolate that negative fact from
					// the outer fixture owner, as the overlay lifetime test does.
					executable, err := os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					command := exec.Command(executable, "-test.v", "-test.parallel=1", "-test.run=^TestFocusedNodeUnavailableExecutionCannotClaimMissing$/^"+regexp.QuoteMeta(owner)+"$/^"+regexp.QuoteMeta(condition)+"$")
					for _, item := range os.Environ() {
						name, _, _ := strings.Cut(item, "=")
						if name != "ENKV_FOCUSED_NODE_CHILD" {
							command.Env = append(command.Env, item)
						}
					}
					command.Env = append(command.Env, "ENKV_FOCUSED_NODE_CHILD="+t.Name())
					var output limitedOutput
					command.Stdout, command.Stderr = &output, &output
					ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
					defer cancel()
					// The existing native owner still monitors, stops and joins the
					// whole fixture process; the intentional join failure stays local.
					process := superviseProcess(ctx, command)
					if process.Status != "passed" || !process.Started || !process.Joined || output.overflow ||
						!strings.Contains(output.String(), "--- PASS: "+t.Name()+" (") {
						t.Fatalf("focused availability fixture did not pass its exact joined leaf: %+v\n%s", process, output.String())
					}
					return
				}
				root, bootstrap, build := overlayFixture(t)
				control := t.TempDir()
				ready, release := filepath.Join(control, "ready"), filepath.Join(control, "release")
				readyQuoted := "'" + strings.ReplaceAll(ready, "'", "'\"'\"'") + "'"
				releaseQuoted := "'" + strings.ReplaceAll(release, "'", "'\"'\"'") + "'"
				barrier := "printf '%s\\n' \"$$\" > " + readyQuoted + "\nwhile [ ! -f " + releaseQuoted + " ]; do /bin/sleep 0.01; done\n"
				inventory := append(ordinaryMemoryTestInventory(), "TestAlpha")
				if owner == "provider" {
					inventory = []string{"TestFreshProcessChild", "TestLiveInventoryFreshProcess", "TestAlpha"}
					for path, body := range map[string]string{
						"tests/live/providers/aws/provider_test.go": "package core\n// full_only: false\nfunc TestAlpha() {}\n",
						"tests/live/runner/worker_test.go":          "package core\n// full_only: false\nfunc TestLiveInventoryFreshProcess() {}\n",
						"tests/shared/process_fixture_test.go":      "package core\n// full_only: false\nfunc TestFreshProcessChild() {}\n",
					} {
						if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				script := "#!/bin/sh\ncase \"$*\" in\n *-test.list=^Test*) printf '%s\\n' " + strings.Join(inventory, " ") + "; exit 0 ;;\nesac\n"
				if condition == "unjoined-test" {
					script += barrier
				}
				script += "printf '%s\\n' '=== RUN   TestAlpha' '--- PASS: TestAlpha (0.01s)' PASS\n"
				binary := filepath.Join(build, "state.test")
				if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
				eventConverter := testEventConverterFixture(t, root)
				var value assembly
				if owner == "provider" {
					overlay, err := buildOverlay(root, "live", "aws", bootstrap, build)
					if err != nil {
						t.Fatal(err)
					}
					binaryDigest, err := assemblyFileSHA256(binary)
					if err != nil {
						t.Fatal(err)
					}
					overlayDigest, err := assemblyFileSHA256(overlay)
					if err != nil {
						t.Fatal(err)
					}
					value = assembly{root: root, Binary: binary, buildFlags: []string{"-overlay=" + overlay}, Closure: assemblyClosure{Suite: "live", Provider: "aws", BinarySHA256: binaryDigest, OverlaySHA256: overlayDigest}}
					bindAssemblyFailureSources(t, &value, build)
					value.converter = eventConverter
				}
				if condition == "unjoined-converter" || condition == "failed-converter" || condition == "malformed-empty" || condition == "truncated-empty" || condition == "prefix-child-failed" {
					realGo, err := exec.LookPath("go")
					if err != nil {
						t.Fatal(err)
					}
					realGo, err = filepath.EvalSymlinks(realGo)
					if err != nil {
						t.Fatal(err)
					}
					bin := t.TempDir()
					body := ordinaryEvents(ordinaryEvent{Action: "start", Package: componentPackage}, ordinaryEvent{Action: "run", Package: componentPackage, Test: "TestAlpha"}, ordinaryEvent{Action: "pass", Package: componentPackage, Test: "TestAlpha"}, ordinaryEvent{Action: "pass", Package: componentPackage})
					switch condition {
					case "malformed-empty":
						body = []byte("not-json\n")
					case "truncated-empty":
						body = []byte(`{"Action":"start"`)
					case "prefix-child-failed":
						body = append(ordinaryEvents(ordinaryEvent{Action: "start", Package: componentPackage}, ordinaryEvent{Action: "run", Package: componentPackage, Test: "TestAlpha"}, ordinaryEvent{Action: "run", Package: componentPackage, Test: "TestAlpha/missing"}, ordinaryEvent{Action: "fail", Package: componentPackage, Test: "TestAlpha/missing"}), []byte("not-json\n")...)
					}
					files := []string{"classification_test.go"}
					if owner == "provider" {
						files = nil
						var overlay struct{ Replace map[string]string }
						if err := records.ReadJSON(strings.TrimPrefix(value.buildFlags[0], "-overlay="), &overlay); err != nil {
							t.Fatal(err)
						}
						for target := range overlay.Replace {
							if filepath.Dir(target) == filepath.Join(root, "core") && strings.HasSuffix(target, "_test.go") {
								files = append(files, filepath.Base(target))
							}
						}
					}
					listed, err := json.Marshal(listedOrdinaryPackage{ImportPath: componentPackage, Dir: filepath.Join(root, "core"), TestGoFiles: files})
					if err != nil {
						t.Fatal(err)
					}
					converter := "#!/bin/sh\nif [ \"$1\" = list ]; then printf '%s\\n' '" + strings.ReplaceAll(string(listed), "'", "'\"'\"'") + "'; exit 0; fi\n"
					if condition == "unjoined-converter" {
						converter += barrier
					}
					converter += "printf '%s' '" + strings.ReplaceAll(string(body), "'", "'\"'\"'") + "'\n"
					if condition == "failed-converter" {
						converter += "exit 7\n"
					}
					goShim := `#!/bin/sh
if [ "$#" -eq 4 ] && [ "$1" = mod ] && [ "$2" = edit ] && [ "$3" = -json ]; then
 case "$4" in -modfile=?*) exec ` + shellQuote(realGo) + ` "$@" ;; esac
fi
` + strings.TrimPrefix(converter, "#!/bin/sh\n")
					if err := os.WriteFile(filepath.Join(bin, "go"), []byte(goShim), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(bin, "event-converter"), []byte(converter), 0700); err != nil {
						t.Fatal(err)
					}
					eventConverter = boundTestEventConverterFixture(t, filepath.Join(bin, "event-converter"))
					value.converter = eventConverter
					t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
				}
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				var output io.Writer = io.Discard
				if condition == "never-started" {
					output = focusedNodeCancellationWriter{cancel: cancel}
				}
				type result struct {
					process  processResult
					evidence checkEvidence
					err      error
				}
				done := make(chan result, 1)
				deadline := time.NewTimer(30 * time.Second)
				defer deadline.Stop()
				var helper *exec.Cmd
				reaped, returned := false, false
				t.Cleanup(func() {
					cancel()
					if helper != nil && helper.Process != nil && !reaped {
						if err := helper.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
							t.Error(err)
						}
						_ = helper.Wait()
						reaped = true
					}
					if !returned {
						select {
						case <-done:
						case <-time.After(15 * time.Second):
							t.Error("focused invocation did not join after owned helper cleanup")
						}
					}
				})
				go func() {
					if owner == "component" {
						p, e, _, _ := executeFixtureProfileComponentChecks(t, nil, ctx, root, binary, eventConverter, componentMetadataBuildFlags(t, root, componentFixtureClassifications(inventory)), os.Environ(), "dev", singleTestRequest("TestAlpha/missing"), 1, output, nil)
						done <- result{process: p, evidence: e}
					} else {
						err := checkLiveAssemblySelection(ctx, root, root, &value, "dev", false, "TestAlpha/missing", records.Source{Revision: strings.Repeat("a", 40)}, "go1.27.0", output)
						got := result{err: err}
						if value.Closure.LocalChecks != nil {
							got.evidence = *value.Closure.LocalChecks
						}
						done <- got
					}
				}()
				if strings.HasPrefix(condition, "unjoined-") {
					pid := 0
					deadline := time.Now().Add(10 * time.Second)
					for pid == 0 {
						body, err := os.ReadFile(ready)
						if err == nil {
							pid, _ = strconv.Atoi(strings.TrimSpace(string(body)))
						}
						if pid > 0 {
							break
						}
						select {
						case got := <-done:
							returned = true
							t.Fatal("focused invocation returned before its owned barrier", got.err)
						default:
						}
						if !time.Now().Before(deadline) {
							t.Fatal("focused process did not reach its barrier")
						}
						time.Sleep(10 * time.Millisecond)
					}
					executable, err := os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					helper = exec.Command(executable, "-test.run=^TestProcessHelper$")
					helper.Env = environment(os.Environ(), map[string]string{"ENKV_PROCESS_HELPER": "exited"})
					helper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: pid}
					stdout, err := helper.StdoutPipe()
					if err != nil {
						t.Fatal(err)
					}
					if err := helper.Start(); err != nil {
						t.Fatal(err)
					}
					drained := make(chan error, 1)
					go func() { _, err := io.Copy(io.Discard, stdout); drained <- err }()
					select {
					case err := <-drained:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("owned group member did not exit")
					}
					if err := os.WriteFile(release, nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
				var got result
				select {
				case got = <-done:
					returned = true
				case <-deadline.C:
					t.Fatal("focused availability fixture exceeded its deadline")
				}
				if helper != nil {
					err := helper.Wait()
					reaped = true
					if err != nil {
						t.Fatal(err)
					}
				}
				if got.evidence.Outcome == "passed" || got.evidence.TestsComplete || owner == "provider" && got.err == nil {
					t.Fatal("unavailable or missing node acquired passing evidence")
				}
				if got.evidence.Diagnostics == nil {
					t.Fatal("focused invocation lost its command facts")
				}
				testFacts := []checkCommandFacts{}
				for _, fact := range got.evidence.Diagnostics.Commands {
					if fact.Phase == "test" {
						testFacts = append(testFacts, fact)
					}
				}
				if len(testFacts) != 1 {
					t.Fatal("focused execution has no unique test command", testFacts)
				}
				want := "unavailable"
				if condition == "available-missing" {
					want = "missing"
				}
				if condition == "prefix-child-failed" {
					want = "failed"
				}
				if testFacts[0].RequestedNode != want {
					t.Error("unavailable execution was confused with an observed missing child", testFacts[0])
				}
				if condition == "never-started" && testFacts[0].Started {
					t.Fatal("never-started control actually executed its binary")
				}
				if condition == "never-started" {
					fact := testFacts[0]
					if !fact.Joined || fact.Process != "interrupted" || fact.Events != "not_run" || fact.RaceObservation != "unavailable" || fact.ToolCleanup != "not_required" {
						t.Error("refused dispatch lost its canceled command facts", fact)
					}
					if slices.ContainsFunc(got.evidence.Diagnostics.Commands, func(fact checkCommandFacts) bool { return fact.Phase == "conversion" }) {
						t.Error("refused dispatch acquired a conversion command")
					}
					cause := got.process.Cause
					if owner == "provider" {
						cause = got.err
					}
					if !errors.Is(cause, context.Canceled) {
						t.Error("refused dispatch lost its cancellation cause", cause)
					}
				}
				if condition == "unjoined-test" && (!testFacts[0].Started || testFacts[0].Joined) {
					t.Fatal("test control did not leave the owned group unjoined")
				}
				if condition == "unjoined-converter" {
					found := false
					for _, fact := range got.evidence.Diagnostics.Commands {
						if fact.Phase == "conversion" {
							found = !fact.Joined && fact.Started
						}
					}
					if !found {
						t.Fatal("converter control did not leave its owned group unjoined")
					}
				}
				if condition == "failed-converter" && !slices.ContainsFunc(got.evidence.Diagnostics.Commands, func(fact checkCommandFacts) bool {
					return fact.Phase == "conversion" && fact.Started && fact.Joined && fact.Process == "process_failed" && fact.Events == "valid"
				}) {
					t.Fatal("converter control did not retain its separate failure and valid events")
				}
				if condition == "available-missing" && (!testFacts[0].Started || !testFacts[0].Joined || !slices.ContainsFunc(got.evidence.Tests, func(test componentTest) bool { return test.Name == "TestAlpha" && test.Outcome == "passed" })) {
					t.Fatal("missing control did not provide an available passing parent stream")
				}
			})
		}
	}
}
