package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestComponentChecksRequirePackageCompletion(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "missing-package-terminal")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' '=== RUN   TestAlpha' '--- PASS: TestAlpha (0.01s)'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	process, evidence, _, _ := executeComponentChecks(context.Background(), root, binary, testEventConverterFixture(t, root), "^TestAlpha$", []string{"TestAlpha"}, os.Environ())
	if process.Status == "passed" || evidence.TestsComplete {
		t.Fatal("missing package terminal produced complete component evidence")
	}
}

// full_only: false
func TestComponentChecksRequireSuccessfulJoinedConverter(t *testing.T) {
	for _, spec := range []struct{ name, script string }{
		{"failed", "echo controlled-converter-failure >&2; exit 7"},
		{"malformed", "printf 'not-json\\n'"},
		{"truncated", `printf '{"Action":"start","Package":"enkv.sh/core"}'`},
		{"canceled", "sleep 30"},
		{"parent-canceled", `sleep 2
printf '%s\n' '{"Action":"start","Package":"enkv.sh/core"}' '{"Action":"run","Package":"enkv.sh/core","Test":"TestAlpha"}' '{"Action":"pass","Package":"enkv.sh/core","Test":"TestAlpha"}' '{"Action":"pass","Package":"enkv.sh/core"}'`},
	} {
		t.Run(spec.name, func(t *testing.T) {
			root := t.TempDir()
			binary := filepath.Join(root, "component")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' '=== RUN   TestAlpha' '--- PASS: TestAlpha (0.01s)' PASS\n"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "converter"), []byte("#!/bin/sh\n"+spec.script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			process, evidence, _, stderr := executeComponentChecks(ctx, root, binary, boundTestEventConverterFixture(t, filepath.Join(root, "converter")), "^TestAlpha$", []string{"TestAlpha"}, os.Environ())
			if process.Status == "passed" || !process.Joined || evidence.TestsComplete {
				t.Fatal("failed converter qualified or did not join", process, evidence)
			}
			if spec.name == "failed" && !strings.Contains(stderr.String(), "controlled-converter-failure") {
				t.Fatal("converter diagnostics were lost")
			}
			if strings.Contains(spec.name, "canceled") && !errors.Is(process.Cause, context.DeadlineExceeded) {
				t.Fatal("converter cancellation lost deadline cause", process)
			}
			checkRecordedCommand(t, evidence, "test", "passed", "not_run")
			converterStatus, events := "passed", "unavailable"
			switch spec.name {
			case "failed":
				converterStatus = "process_failed"
			case "malformed":
				events = "malformed"
			case "truncated":
				events = "truncated"
			case "canceled":
				converterStatus = "timed_out"
			case "parent-canceled":
				// Conversion has its own settlement context and finishes after
				// the parent deadline. Its success cannot qualify the whole run.
				events = "valid"
			}
			checkRecordedCommand(t, evidence, "conversion", converterStatus, events)
		})
	}
}

// full_only: false
func TestComponentConversionUsesRemainingWorkBudget(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ENKV_COMPONENT_CHECK_HELPER", "")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prepared := testEventConverterFixture(t, root)
	converterPath := filepath.Join(root, "delayed-converter")
	script := "#!/bin/sh\nset -eu\nsleep 6\nexec " + shellQuote(prepared.binary) + " \"$@\"\n"
	if err := os.WriteFile(converterPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	const name = "TestComponentCheckHelper"
	process, evidence, _, _ := executeComponentChecks(ctx, root, binary, boundTestEventConverterFixture(t, converterPath), literalTestSelection(name), []string{name}, os.Environ())
	if process.Status != "passed" || !process.Started || !process.Joined || !evidence.TestsComplete || evidence.Outcome != "passed" {
		t.Errorf("healthy conversion within the active work budget did not complete: process=%+v cause=%v evidence=%+v", process, process.Cause, evidence)
	}
	if len(evidence.Tests) != 1 || evidence.Tests[0].Name != name || evidence.Tests[0].Outcome != "passed" {
		t.Error("healthy conversion lost the exact actual test terminal", evidence.Tests)
	}
	checkRecordedCommand(t, evidence, "test", "passed", "not_run")
	checkRecordedCommand(t, evidence, "conversion", "passed", "valid")
	if evidence.Diagnostics == nil || len(evidence.Diagnostics.Commands) != 2 {
		t.Fatal("healthy conversion did not retain exactly one test and converter", evidence.Diagnostics)
	}
	conversion := evidence.Diagnostics.Commands[1]
	if conversion.WallSeconds == nil || *conversion.WallSeconds < 6 {
		t.Error("converter did not complete the controlled six-second work", conversion)
	}
}

// full_only: false
func TestComponentChecksRetainRowsAfterCancellation(t *testing.T) {
	for _, status := range []string{"interrupted", "timed_out"} {
		t.Run(status, func(t *testing.T) {
			root := t.TempDir()
			ready := filepath.Join(root, "ready")
			t.Setenv("ENKV_COMPONENT_CHECK_HELPER", "incomplete")
			t.Setenv("ENKV_COMPONENT_CHECK_READY", ready)
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			converter := testEventConverterFixture(t, root)
			ctx, cancel := context.WithTimeout(t.Context(), processGroupSettlementTimeout)
			defer cancel()
			watcherDone := make(chan struct{})
			go func() {
				defer close(watcherDone)
				ticker := time.NewTicker(processGroupPollInterval)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						if _, err := os.Stat(ready); err == nil && status == "interrupted" {
							cancel()
							return
						}
					}
				}
			}()
			const parent = "TestComponentCheckHelper"
			process, evidence, stdout, _ := executeComponentChecks(ctx, root, binary, converter, "^"+parent+"$", []string{parent}, os.Environ())
			cancel()
			<-watcherDone
			if process.Status != status || !process.Started || !process.Joined || evidence.TestsComplete || evidence.Outcome != status {
				t.Fatal("canceled execution status or join differs", process, evidence)
			}
			if _, err := os.Stat(ready); err != nil || !strings.Contains(stdout.String(), parent+"/waiting") {
				t.Fatal("control did not reach its in-flight child", err)
			}
			var got []string
			for _, test := range evidence.Tests {
				got = append(got, test.Name+":"+test.Outcome)
			}
			want := []string{parent + ":incomplete", parent + "/finished:passed", parent + "/failed:failed", parent + "/waiting:incomplete"}
			if !slices.Equal(got, want) {
				t.Fatalf("canceled execution lost structured rows: got %v want %v", got, want)
			}
		})
	}
}

// full_only: false
func TestComponentCheckHelper(t *testing.T) {
	mode := os.Getenv("ENKV_COMPONENT_CHECK_HELPER")
	if mode == "" {
		return
	}
	if mode == "incomplete" {
		t.Run("finished", func(t *testing.T) {})
		t.Run("failed", func(t *testing.T) {
			t.Error("controlled independent failure before cancellation")
		})
		t.Run("waiting", func(t *testing.T) {
			if err := os.WriteFile(os.Getenv("ENKV_COMPONENT_CHECK_READY"), []byte("ready"), 0600); err != nil {
				t.Fatal(err)
			}
			for {
				time.Sleep(time.Minute)
			}
		})
		return
	}
	if mode == "overflow" {
		// The test2json testing protocol redirects os.Stderr to os.Stdout.
		// Write the actual second descriptor to exercise both capture bounds.
		fd, err := syscall.Dup(2)
		if err != nil {
			t.Fatal(err)
		}
		stderr := os.NewFile(uintptr(fd), "component-stderr")
		defer stderr.Close()
		chunk := bytes.Repeat([]byte("x"), 64<<10)
		for i := 0; i < 513; i++ {
			if _, err := os.Stdout.Write(chunk); err != nil {
				t.Fatal(err)
			}
			if _, err := stderr.Write(chunk); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	if mode == "failed-middle" {
		t.Run("before", func(t *testing.T) {})
	}
	if strings.Contains(mode, "noisy") || mode == "failed-middle" {
		for i := 0; i < 8192; i++ {
			if _, err := fmt.Fprintln(os.Stdout, "controlled component setup noise before the terminal assertion"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := fmt.Fprintln(os.Stdout, "synthetic-secret component stdout"); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(os.Stderr, "synthetic-secret component stderr"); err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(mode, "child") {
		t.Run("child", func(t *testing.T) {
			t.Fatal("synthetic-secret component assertion")
		})
	} else if mode == "failed-middle" || mode == "failed-noisy-middle-parent" {
		t.Error("synthetic-secret component assertion")
	} else if mode == "failed-noisy-error-overflow" {
		for i := 0; i < 4096; i++ {
			t.Error("synthetic-secret controlled error output " + strings.Repeat("e", 128))
		}
		t.Error("synthetic-secret component assertion")
	} else if strings.HasPrefix(mode, "failed") {
		t.Fatal("synthetic-secret component assertion")
	}
	if mode == "failed-middle" || strings.Contains(mode, "noisy-middle") || mode == "failed-noisy-error-overflow" {
		// The real assertion is followed by unrelated output in this same
		// process group. Its package terminal remains a failure.
		t.Run("later-passing", func(t *testing.T) {
			for i := 0; i < 8192; i++ {
				if _, err := fmt.Fprintln(os.Stdout, "controlled passing output after the earlier terminal assertion"); err != nil {
					t.Fatal(err)
				}
			}
		})
		// Keep raw tail controls as well as the independently earlier error.
		if _, err := fmt.Fprintln(os.Stdout, "synthetic-secret component stdout"); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(os.Stderr, "synthetic-secret component stderr"); err != nil {
			t.Fatal(err)
		}
	}
}

func componentCheckFixture(t *testing.T, mode string) (*runState, string) {
	t.Helper()
	t.Setenv("ENKV_COMPONENT_CHECK_HELPER", mode)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, suite, environment := savedSelectionFixture(t)
	saveSelection(t, suite, suiteFixture("regression", catalog.RegressionNames()))
	request, err := parseRunRequest([]string{"run", "--suite", suite, "--environment", environment})
	if err != nil {
		t.Fatal(err)
	}
	s, err := newRunState(root, request, records.Source{}, "controlled toolchain")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	// Emit every selected synthetic root in its package process. The real
	// helper supplies the package terminal, diagnostics and overflow.
	quoted := "'" + strings.ReplaceAll(executable, "'", "'\"'\"'") + "'"
	binary := filepath.Join(root, "component-check")
	synthetic := append(ordinaryMemoryTestInventory(), maximumCapacityComponent)
	inventory := append(slices.Clone(synthetic), "TestComponentCheckHelper")
	script := "#!/bin/sh\n" +
		"case \"$*\" in\n" +
		" *-test.list=^Test*) printf '%s\\n' " + strings.Join(inventory, " ") + "; exit 0 ;;\n" +
		"esac\nfor name in " + strings.Join(synthetic, " ") + "; do\n" +
		" case \"$*\" in " + componentShellSelectedName + ")\n" +
		"  printf '%s\\n' \"=== RUN   $name\" \"--- PASS: $name (0.01s)\" ;; esac\ndone\n" +
		"name=TestComponentCheckHelper\ncase \"$*\" in " + componentShellSelectedName + ") exec " + quoted + " \"$@\" -test.run=^TestComponentCheckHelper$ ;; esac\n" +
		"printf '%s\\n' PASS\n"

	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return s, binary
}

// full_only: false
func TestComponentCheckFailuresKeepPublicEvidenceClosed(t *testing.T) {
	for _, mode := range []string{"failed-parent", "failed-child", "failed-noisy-parent", "failed-noisy-child", "failed-middle", "failed-noisy-middle-parent", "failed-noisy-middle-child", "failed-noisy-error-overflow"} {
		t.Run(mode, func(t *testing.T) {
			s, binary := componentCheckFixture(t, mode)
			inventory := append(ordinaryMemoryTestInventory(), maximumCapacityComponent, "TestComponentCheckHelper")
			flags := componentMetadataBuildFlags(t, s.root, componentFixtureClassifications(inventory))
			converter := testEventConverterFixture(t, s.root)
			owner := capturedComponentFixtureOwner(t, t.Context(), s.root, binary, converter, flags)
			checks, err := checkComponents(nil, t.Context(), s.root, s.directory, binary, converter, flags, nil, "full", singleTestRequest(""), 1, io.Discard, owner)
			t.Cleanup(func() {
				if t.Failed() {
					var diagnostics bytes.Buffer
					if err := writeCheckDiagnostics(&diagnostics, checks.Diagnostics); err != nil {
						t.Log("component diagnostic output failed", err)
					}
					body := diagnostics.Bytes()
					if len(body) > 8192 {
						body = body[len(body)-8192:]
					}
					t.Logf("component command facts (last at most 8192 bytes):\n%s", body)
				}
			})
			path := filepath.Join(s.private, "component-checks.log")
			if err == nil {
				t.Fatal("component failure returned success")
			}
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "synthetic-secret") {
				t.Error("component failure exposed raw output or its private diagnostics path")
			}
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) || exitError.ExitCode() == 0 {
				t.Error("safe component error lost its joined command failure")
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"TestComponentCheckHelper", "synthetic-secret component stdout", "synthetic-secret component stderr", "synthetic-secret component assertion", "Process: process_failed", "Joined: true", "exit status"} {
				if !bytes.Contains(body, []byte(want)) {
					t.Errorf("private component diagnostics lost %q", want)
				}
			}
			if len(body) > assemblyDiagnosticFileLimit {
				t.Fatal("private component diagnostics exceeded their existing file bound")
			}
			if strings.Contains(mode, "noisy") || mode == "failed-middle" {
				if !bytes.Contains(body, []byte("Raw capture middle omitted: true")) || !bytes.Contains(body, []byte("Stdout (truncated: true)")) {
					t.Error("bounded private diagnostic omissions were not explicit")
				}
			}
			if mode == "failed-middle" || strings.Contains(mode, "noisy-middle") || mode == "failed-noisy-error-overflow" {
				if !bytes.Contains(body, []byte("Private assertion output")) {
					t.Error("actual assertion output did not receive private diagnostic priority")
				}
				if !slices.ContainsFunc(checks.Tests, func(test componentTest) bool {
					return test.Name == "TestComponentCheckHelper/later-passing" && test.Outcome == "passed"
				}) {
					t.Error("same-group later noisy passing child was not retained")
				}
			}
			if mode == "failed-noisy-error-overflow" && !bytes.Contains(body, []byte("Private assertion output (truncated: true)")) {
				t.Error("private error-output overflow was not explicit")
			}
			failedNames := []string{"TestComponentCheckHelper"}
			if strings.HasSuffix(mode, "child") {
				failedNames = append(failedNames, "TestComponentCheckHelper/child")
			}
			for _, name := range failedNames {
				if !slices.ContainsFunc(checks.Tests, func(test componentTest) bool { return test.Name == name && test.Outcome == "failed" }) || !bytes.Contains(body, []byte("--- FAIL: "+name+" ")) {
					t.Error("exact failed terminal was lost", name)
				}
			}
			if mode == "failed-middle" && !slices.ContainsFunc(checks.Tests, func(test componentTest) bool {
				return test.Name == "TestComponentCheckHelper/before" && test.Outcome == "passed"
			}) {
				t.Error("same-package passing child before the failure was not retained")
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("component diagnostics permissions differ")
			}
			if checks.Outcome != "process_failed" {
				t.Fatal("component failure did not reach public status evidence")
			}
			encoded, err := json.Marshal(checks)
			if err != nil {
				t.Fatal(err)
			}
			var public map[string]any
			if json.Unmarshal(encoded, &public) != nil || public["event_time_source"] != "post_join_test2json" {
				t.Error("component conversion time was not distinguished from execution time", public["event_time_source"])
			}
			s.record.Correctness.ComponentRun = &componentRunRecord{Checks: &checks}
			s.finish()
			if err := s.save(); err != nil {
				t.Fatal(err)
			}
			current, err := json.Marshal(s.record)
			if err != nil || !bytes.Contains(current, []byte("TestComponentCheckHelper")) {
				t.Error("bounded component name missing from current result", err)
			}
			for _, private := range []string{"synthetic-secret", "exit status", path} {
				if bytes.Contains(current, []byte(private)) {
					t.Errorf("private component diagnostic %q entered closed current result", private)
				}
			}

		})
	}
}

// full_only: false
func TestComponentCheckCaptureBoundsBothStreamsAndFailsOnOverflow(t *testing.T) {
	t.Run("real-converter", func(t *testing.T) {
		s, binary := componentCheckFixture(t, "overflow")
		flags := componentMetadataBuildFlags(t, s.root, componentFixtureClassifications(append(ordinaryMemoryTestInventory(), maximumCapacityComponent, "TestComponentCheckHelper")))
		converter := testEventConverterFixture(t, s.root)
		owner := capturedComponentFixtureOwner(t, t.Context(), s.root, binary, converter, flags)
		checks, err := checkComponents(nil, t.Context(), s.root, s.directory, binary, converter, flags, nil, "full", singleTestRequest(""), 1, io.Discard, owner)
		if err == nil {
			t.Fatal("overflowing exit-zero component checks passed")
		}
		if checks.Outcome != "output_limit_exceeded" {
			t.Fatalf("component output overflow lost its failure status: outcome=%s diagnostics=%+v error=%v", checks.Outcome, checks.Diagnostics, err)
		}
		encoded, marshalErr := json.Marshal(checks)
		var saved struct {
			Diagnostics struct{ Commands []struct{ Events string } }
		}
		if marshalErr != nil || json.Unmarshal(encoded, &saved) != nil {
			t.Fatal("overflow facts could not be serialized", marshalErr)
		}
		observed := false
		for _, command := range saved.Diagnostics.Commands {
			observed = observed || command.Events == "overflow"
		}
		if !observed {
			t.Error("raw capture overflow was confused with complete or malformed event evidence")
		}
		body, err := os.ReadFile(filepath.Join(s.private, "component-checks.log"))
		if err != nil {
			t.Fatal(err)
		}
		if len(body) > (64<<20)+4096 {
			t.Fatal("component diagnostics exceeded both stream bounds")
		}
		for _, want := range []string{"Stdout (truncated: true)", "Stderr (truncated: true)", "component check output exceeds its bound"} {
			if !bytes.Contains(body, []byte(want)) {
				t.Errorf("component diagnostics lost %q", want)
			}
		}
	})
	t.Run("failed-converter", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("ENKV_COMPONENT_CHECK_HELPER", "overflow")
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		converterPath := filepath.Join(root, "failed-converter")
		if err := os.WriteFile(converterPath, []byte("#!/bin/sh\nexit 7\n"), 0700); err != nil {
			t.Fatal(err)
		}
		converter := boundTestEventConverterFixture(t, converterPath)
		const name = "TestComponentCheckHelper"
		process, evidence, stdout, stderr := executeComponentChecks(t.Context(), root, binary, converter, "^"+name+"$", []string{name}, os.Environ())
		if !stdout.overflow || !stderr.overflow || stdout.Len() != 32<<20 || stderr.Len() != 32<<20 {
			t.Fatal("actual component did not exceed both raw stream bounds", stdout.Len(), stderr.Len(), stdout.overflow, stderr.overflow)
		}
		checkRecordedCommand(t, evidence, "test", "passed", "not_run")
		checkRecordedCommand(t, evidence, "conversion", "process_failed", "overflow")
		var exit *exec.ExitError
		if !errors.As(process.Cause, &exit) || exit.ExitCode() != 7 {
			t.Error("overflow lost the joined converter's exact failure", process.Cause)
		}
		if process.Status != "output_limit_exceeded" || !process.Started || !process.Joined || evidence.Outcome != process.Status || evidence.TestsComplete {
			t.Error("later conversion failure replaced known raw capture overflow", process, evidence)
		}
	})
}

// full_only: false
func TestSuccessfulComponentChecksRetainNoDiagnostics(t *testing.T) {
	s, binary := componentCheckFixture(t, "passed")
	flags := componentMetadataBuildFlags(t, s.root, componentFixtureClassifications(append(ordinaryMemoryTestInventory(), maximumCapacityComponent, "TestComponentCheckHelper")))
	converter := testEventConverterFixture(t, s.root)
	owner := capturedComponentFixtureOwner(t, t.Context(), s.root, binary, converter, flags)
	checks, err := checkComponents(nil, t.Context(), s.root, s.directory, binary, converter, flags, nil, "full", singleTestRequest(""), 1, io.Discard, owner)
	if err != nil {
		t.Fatal(err)
	}
	if checks.Outcome != "passed" {
		t.Fatal("successful component status differs")
	}
	if _, err := os.Lstat(filepath.Join(s.private, "component-checks.log")); !os.IsNotExist(err) {
		t.Fatal("successful component checks retained output")
	}
}

// full_only: false
func TestComponentDiagnosticsRefuseSymlinkPaths(t *testing.T) {
	for _, mode := range []string{"file", "directory"} {
		t.Run(mode, func(t *testing.T) {
			s, binary := componentCheckFixture(t, "failed")
			outside := t.TempDir()
			target := filepath.Join(outside, "component-checks.log")
			if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.private, "component-checks.log")
			if mode == "directory" {
				if err := os.Remove(s.private); err != nil {
					t.Fatal(err)
				}
				path, target = s.private, outside
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			flags := componentMetadataBuildFlags(t, s.root, componentFixtureClassifications(append(ordinaryMemoryTestInventory(), maximumCapacityComponent, "TestComponentCheckHelper")))
			converter := testEventConverterFixture(t, s.root)
			owner := capturedComponentFixtureOwner(t, t.Context(), s.root, binary, converter, flags)
			_, err := checkComponents(nil, t.Context(), s.root, s.directory, binary, converter, flags, nil, "full", singleTestRequest(""), 1, io.Discard, owner)
			if err == nil || !strings.Contains(err.Error(), "diagnostics path refused") || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatalf("symlink diagnostics failure differs: %v", err)
			}
			body, err := os.ReadFile(filepath.Join(outside, "component-checks.log"))
			if err != nil || string(body) != "preserve" {
				t.Fatal("component diagnostics changed a symlink destination")
			}
		})
	}
}
