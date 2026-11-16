package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func fuzzOutput(t *testing.T, output string, passed bool) []byte {
	return fuzzOutputFor(t, fuzzSpecifications[0], output, passed)
}

func fuzzOutputFor(t *testing.T, spec fuzzSpecification, output string, passed bool) []byte {
	t.Helper()
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, line := range strings.SplitAfter(output, "\n") {
		if line == "" {
			continue
		}
		if err := encoder.Encode(map[string]string{"Action": "output", "Package": spec.importPath(), "Test": spec.Target, "Output": line}); err != nil {
			t.Fatal(err)
		}
	}
	if passed {
		if err := encoder.Encode(map[string]string{"Action": "pass", "Package": spec.importPath(), "Test": spec.Target}); err != nil {
			t.Fatal(err)
		}
	}
	return body.Bytes()
}

// full_only: false
func TestFuzzProgressCannotCrossTargetOwners(t *testing.T) {
	for _, actual := range fuzzSpecifications {
		body := fuzzOutputFor(t, actual, "fuzz: elapsed: 10m0s, execs: 1000 (1/sec), new interesting: 2 (total: 20)\n", true)
		for _, expected := range fuzzSpecifications {
			_, err := parseFuzzProgress(body, expected)
			if (err == nil) != (actual == expected) {
				t.Fatalf("fuzz evidence crossed from %s to %s: %v", actual.Name, expected.Name, err)
			}
		}
	}
}

// full_only: false
func TestFuzzCommandUsesFixedTargetAndOwnTimeout(t *testing.T) {
	for _, spec := range fuzzSpecifications {
		for _, parallel := range []int{1, 2, 3, 4} {
			cache := filepath.Join(t.TempDir(), "cache")
			want := []string{"-test.v=test2json", "-test.paniconexit0", "-test.run=^$", "-test.fuzz=^" + spec.Target + "$", "-test.fuzztime=10m", "-test.fuzzminimizetime=1m", fmt.Sprintf("-test.parallel=%d", parallel), "-test.timeout=15m", "-test.fuzzcachedir=" + filepath.Join(cache, "fuzz", spec.importPath())}
			if !reflect.DeepEqual(fuzzRuntimeArguments(spec, cache, parallel), want) || fuzzTimeout != 15*time.Minute {
				t.Fatal("native fuzz target, allocation or fixed budgets changed")
			}
		}
	}
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runCommand(ctx, root, "", []string{"fuzz"}, &bytes.Buffer{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled campaign entered work: %v", err)
	}
	if err := runCommand(context.Background(), root, "", []string{"fuzz", "-fuzztime=1s"}, &bytes.Buffer{}); err == nil {
		t.Fatal("caller replaced the fixed campaign")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused campaign created evidence or fixtures")
	}
}

// full_only: false
func TestFuzzPreparationRetainsExecutionCapacityBeforeDependencyRefusal(t *testing.T) {
	for _, row := range []struct {
		parallel int
		race     bool
	}{{1, false}, {1, true}, {3, false}, {3, true}} {
		parallel, race := row.parallel, row.race
		t.Run(fmt.Sprintf("parallel_%d/race_%t", parallel, race), func(t *testing.T) {
			root, _, _ := overlayFixture(t)
			writeLocalGoFixture(t, root, "tests/hermetic/hermetic.mod", "module enkv.sh/core\n\ngo 1.27.0\n")
			initializeWorkflowExecutionFixture(t, root)
			controls := t.TempDir()
			binaryDirectory := t.TempDir()
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			realGo, err = filepath.Abs(realGo)
			if err != nil {
				t.Fatal(err)
			}
			shim := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$ENKV_FUZZ_PREPARATION_FIXTURE/commands"
printf '%s\n' "$GORACE" >> "$ENKV_FUZZ_PREPARATION_FIXTURE/options"
if [ "$1" = version ]; then
 printf 'go version controlled-fuzz-fixture\n'
 exit 0
fi
if [ "$1" = env ] || { [ "$1" = mod ] && [ "$2" = edit ]; }; then
 exec ` + "'" + strings.ReplaceAll(realGo, "'", "'\"'\"'") + "'" + ` "$@"
fi
printf 'controlled fuzz dependency refusal\n' >&2
exit 7
`
			if err := os.WriteFile(filepath.Join(binaryDirectory, "go"), []byte(shim), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", binaryDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("ENKV_FUZZ_PREPARATION_FIXTURE", controls)
			t.Setenv("GORACE", "exitcode=0 halt_on_error=1 atexit_sleep_ms=0")
			memory := 4096
			policy := executionPolicy{Requested: executionRequest{Parallel: &parallel, MemoryLimitMiB: &memory}, Resolved: executionCapacity{Parallel: parallel, MemoryLimitMiB: 4096}}
			ctx, cancel := context.WithTimeout(withRacePolicy(withExecutionCapacity(t.Context(), policy), race), 10*time.Second)
			defer cancel()
			source, err := sourceRevision(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			record, err := runFuzzTarget(ctx, root, fuzzSpecifications[0], source, policy, &output)
			if err == nil {
				t.Fatal("controlled dependency refusal was ignored")
			}
			var failure *toolFailure
			if !errors.As(err, &failure) || !failure.process.Started || !failure.process.Joined || failure.process.Status != "process_failed" {
				t.Fatal("dependency refusal lost positive process join", err)
			}
			commands, err := os.ReadFile(filepath.Join(controls, "commands"))
			lines := strings.Split(strings.TrimSpace(string(commands)), "\n")
			if err != nil || len(lines) != 3 || !strings.HasPrefix(lines[0], "env ") || !strings.HasPrefix(lines[1], "mod edit -json -modfile=") || !strings.HasPrefix(lines[2], "list ") {
				t.Fatal("fixture crossed dependency refusal", string(commands), err)
			}
			wantOptions := ""
			if race {
				wantOptions = "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000"
			}
			options, err := os.ReadFile(filepath.Join(controls, "options"))
			if err != nil || string(options) != strings.Repeat(wantOptions+"\n", 3) {
				t.Fatalf("preparation child runtime options differ from accepted race=%t: %q, %v", race, options, err)
			}
			discoveryRaceFlags := 0
			for _, flag := range strings.Fields(lines[2]) {
				if flag == "-race" {
					discoveryRaceFlags++
				}
			}
			wantRaceFlags := 0
			if race {
				wantRaceFlags = 1
			}
			if discoveryRaceFlags != wantRaceFlags {
				t.Fatalf("dependency source mode differs from accepted race=%t: %s", race, lines[1])
			}
			if record.Outcome != "failed" || record.Failure == nil || record.Failure.Class != "fuzz_campaign_failed" || record.Failure.Stage != "dependencies" || record.Process != "not_started" || record.Joined || record.FinishedAt == nil || len(record.Progress) != 0 || record.Closure != nil {
				t.Fatalf("preparation crossed campaign boundary or lost refusal: %+v", record)
			}
			private, _, found := strings.Cut(strings.TrimPrefix(record.Arguments[len(record.Arguments)-1], "-test.fuzzcachedir="), string(filepath.Separator)+"cache"+string(filepath.Separator)+"fuzz"+string(filepath.Separator))
			if !found {
				t.Fatal("native fuzz cache lost execution owner")
			}
			want := fuzzRuntimeArguments(fuzzSpecifications[0], filepath.Join(private, "cache"), parallel)
			if record.Module != "core" || record.Package != "./format" || record.Target != "FuzzCanonicalRecords" || record.TimeoutSeconds != 900 || !strings.HasPrefix(record.Toolchain, "go version go") || !reflect.DeepEqual(record.Arguments, want) {
				t.Fatal("native fuzz owner or fixed arguments differ", record)
			}
			if record.Execution == nil || record.Execution.Resolved.Parallel != parallel || record.Execution.Resolved.MemoryLimitMiB != 4096 {
				t.Fatal("fuzz current outcome lost accepted capacity")
			}
			if _, err := os.Lstat(filepath.Dir(private)); !os.IsNotExist(err) {
				t.Error("joined failed fuzz preparation retained current files", err)
			}

		})
	}
}

// full_only: false
func TestFuzzSelectionPreservesOrderAndRequiresUniqueKnownTargets(t *testing.T) {
	for _, names := range [][]string{nil, {"crypto", "format"}} {
		selected, err := selectFuzzTargets(names)
		if err != nil {
			t.Fatal(err)
		}
		var actual []string
		for _, target := range selected {
			actual = append(actual, target.Name)
		}
		want := names
		if names == nil {
			want = []string{"format", "contract", "crypto"}
		}
		if !reflect.DeepEqual(actual, want) {
			t.Fatalf("selected targets = %v, want %v", actual, want)
		}
		selected[0].Name = "changed"
		if fuzzSpecifications[0].Name != "format" || fuzzSpecifications[2].Name != "crypto" {
			t.Fatal("selection changed the target catalog")
		}
	}
	for _, names := range [][]string{{}, {"unknown"}, {"contract", "contract"}} {
		if _, err := selectFuzzTargets(names); err == nil {
			t.Fatalf("accepted targets %v", names)
		}
	}
}

// full_only: false
func TestFuzzProgressRequiresTargetPassAndMonotonicGeneratedEvidence(t *testing.T) {
	progress := "fuzz: elapsed: 3s, execs: 100 (33/sec), new interesting: 1 (total: 20)\n" +
		"fuzz: elapsed: 10m0s, execs: 12000 (20/sec), new interesting: 2 (total: 21)\n"
	got, err := parseFuzzProgress(fuzzOutput(t, progress, true), fuzzSpecifications[0])
	if err != nil || len(got) != 2 || got[1] != (fuzzProgress{600, 12000, 2, 21}) {
		t.Fatalf("generated evidence: %v, %v", got, err)
	}
	for _, body := range [][]byte{
		fuzzOutput(t, progress, false),
		fuzzOutput(t, progress+"fuzz: elapsed: 3s, execs: 99 (33/sec), new interesting: 1 (total: 20)\n", true),
		fuzzOutput(t, "fuzz: elapsed: 600s, execs: 100 (1/sec), new interesting: 21 (total: 20)\n", true),
		fuzzOutput(t, "fuzz: elapsed: 600s, execs: 100 (1/sec), new interesting: 20 (total: 20)\n", true),
		fuzzOutput(t, "fuzz: elapsed: 600s, execs: 19 (1/sec), new interesting: 0 (total: 20)\n", true),
		fuzzOutput(t, "fuzz: elapsed: 600s, execs: 21 (1/sec), new interesting: 2 (total: 22)\n", true),
		fuzzOutput(t, progress+"fuzz: elapsed: 601s, execs: 12001 (1/sec), new interesting: 2 (total: 22)\n", true),
		fuzzOutput(t, progress+"fuzz: elapsed: 601s, execs: 12001 (1/sec), new interesting: 1 (total: 20)\n", true),
		fuzzOutput(t, strings.Repeat("fuzz: elapsed: 600s, execs: 21 (1/sec), new interesting: 0 (total: 20)\n", 401), true),
		[]byte("invalid JSON"),
	} {
		if _, err := parseFuzzProgress(body, fuzzSpecifications[0]); err == nil {
			t.Fatal("invalid or nonmonotonic campaign evidence accepted")
		}
	}
}

// full_only: false
func TestFuzzProcessFixture(t *testing.T) {
	mode := os.Getenv("ENKV_FUZZ_PROCESS_FIXTURE")
	if mode == "" {
		return
	}
	if mode == "timeout" {
		time.Sleep(time.Minute)
		return
	}
	if mode == "failed" {
		os.Exit(7)
	}
	progress := ""
	switch mode {
	case "complete":
		progress = "fuzz: elapsed: 10m0s, execs: 1000 (1/sec), new interesting: 2 (total: 20)\n"
	case "baseline-only":
		progress = "fuzz: elapsed: 10m0s, execs: 20 (0/sec), new interesting: 0 (total: 20)\n"
	case "baseline-plus-one":
		progress = "fuzz: elapsed: 10m0s, execs: 21 (0/sec), new interesting: 0 (total: 20)\n"
	}
	if _, err := fmt.Fprintf(os.Stdout, "=== RUN   %s\n%s--- PASS: %s (0.00s)\nPASS\n", fuzzTarget, progress, fuzzTarget); err != nil {
		os.Exit(8)
	}
	os.Exit(0)
}

// full_only: false
func TestFuzzProcessPropagatesFailureTimeoutAndSeedOnly(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	converter := testEventConverterFixture(t, workflowExecutionFixture(t))
	for _, test := range []struct {
		mode                string
		passed              bool
		baseline, generated uint64
	}{
		{"complete", true, 18, 982},
		{"failed", false, 0, 0},
		{"timeout", false, 0, 0},
		{"seed-only", false, 0, 0},
		{"baseline-only", false, 20, 0},
		{"baseline-plus-one", true, 20, 1},
	} {
		t.Run(test.mode, func(t *testing.T) {
			mode := test.mode
			directory := t.TempDir()
			command := exec.Command(exe, "-test.run=^TestFuzzProcessFixture$")
			command.Env = environment(os.Environ(), map[string]string{"ENKV_FUZZ_PROCESS_FIXTURE": mode})
			timeout := 10 * time.Second
			if mode == "timeout" {
				timeout = 100 * time.Millisecond
			}
			record := fuzzEvidence{Module: "core", Package: "./format", Target: fuzzTarget}
			err := executeFuzz(context.Background(), command, converter, timeout, directory, &record)
			if (err == nil) != test.passed || !record.Joined {
				t.Fatalf("process result: %+v, %v", record, err)
			}
			if record.BaselineExecutions != test.baseline || record.GeneratedExecutions != test.generated {
				t.Fatalf("baseline and generated counts not retained: %+v", record)
			}
			if mode == "timeout" && record.Process != "timed_out" {
				t.Fatal("timeout was not propagated")
			}
			if mode == "failed" && (record.ExitCode == nil || *record.ExitCode != 7) {
				t.Fatal("exit status was not retained")
			}
			info, err := os.Stat(filepath.Join(directory, "fuzz.log"))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("private diagnostics missing or exposed")
			}
		})
	}
}

// full_only: false
func TestFuzzCorpusIdentityBindsNamesAndBytes(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "seed")
	if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	first, count, err := fuzzCorpusIdentity(directory)
	if err != nil || count != 1 {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	second, _, err := fuzzCorpusIdentity(directory)
	if err != nil || first == second {
		t.Fatal("corpus bytes were not bound")
	}
	if err := os.Rename(path, filepath.Join(directory, "other")); err != nil {
		t.Fatal(err)
	}
	third, _, err := fuzzCorpusIdentity(directory)
	if err != nil || second == third {
		t.Fatal("corpus names were not bound")
	}
	if err := os.Symlink("other", path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fuzzCorpusIdentity(directory); err == nil {
		t.Fatal("corpus symlink accepted")
	}
}
