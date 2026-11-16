package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// full_only: false
func TestAssemblyFailureRetainsPrivateWrapperContext(t *testing.T) {
	permission := &os.PathError{Op: "open", Path: "/private/controlled-source.go", Err: os.ErrPermission}
	exitCause := errors.New("controlled lint exit")
	lint := fmt.Errorf("lint core stdout: SYNTHETIC_LINT_STDOUT stderr: SYNTHETIC_LINT_STDERR %s: %w", strings.Repeat("bounded-lint-context ", 4096), exitCause)
	for _, spec := range []struct {
		name            string
		cause, original error
		want            []string
	}{
		{"path-error", permission, os.ErrPermission, []string{"open", "/private/controlled-source.go", "permission denied"}},
		{"lint-context", lint, exitCause, []string{"lint core", "SYNTHETIC_LINT_STDOUT", "SYNTHETIC_LINT_STDERR", "controlled lint exit", "truncated: true"}},
	} {
		t.Run(spec.name, func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			s := &runState{directory: directory}
			public := s.retainAssemblyFailure(spec.cause)
			if public == nil || !errors.Is(public, spec.original) {
				t.Fatal("safe wrapper lost the original cause")
			}
			for _, forbidden := range []string{"/private/controlled-source.go", "SYNTHETIC_LINT_STDOUT", "SYNTHETIC_LINT_STDERR", directory} {
				if strings.Contains(public.Error(), forbidden) {
					t.Error("private wrapper context reached public output", forbidden)
				}
			}
			body, err := os.ReadFile(filepath.Join(directory, "private", assemblyDiagnosticName))
			if err != nil {
				t.Fatal(err)
			}
			if len(body) > assemblyDiagnosticFileLimit {
				t.Fatal("private wrapper context exceeded the diagnostic bound")
			}
			for _, want := range spec.want {
				if !bytes.Contains(body, []byte(want)) {
					t.Error("private wrapper context was erased", want)
				}
			}
		})
	}
}

// full_only: false
func TestAssemblyFailurePrioritizesLateFailedGoTestOutput(t *testing.T) {
	var stdout bytes.Buffer
	emit := func(event ordinaryEvent) {
		body, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		stdout.Write(body)
		stdout.WriteByte('\n')
	}
	const pkg = "example.invalid/diagnostic"
	emit(ordinaryEvent{Action: "output", Package: pkg, Test: "TestPassing", Output: strings.Repeat("passing noise\n", assemblyDiagnosticOutputLimit/4)})
	emit(ordinaryEvent{Action: "pass", Package: pkg, Test: "TestPassing"})
	emit(ordinaryEvent{Action: "output", Package: pkg, Test: "TestFailed", Output: "controlled_test.go:42: exact late assertion\n"})
	emit(ordinaryEvent{Action: "fail", Package: pkg, Test: "TestFailed"})
	failure := &toolFailure{operation: "go test", process: processResult{Status: "process_failed", Started: true, Joined: true}, stdout: stdout.Bytes()}
	var retained bytes.Buffer
	if err := writeAssemblyDiagnosticBody(&retained, failure); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"TestFailed", "controlled_test.go:42: exact late assertion", "Raw stdout prefix:", "truncated: true"} {
		if !strings.Contains(retained.String(), want) {
			t.Error("private diagnostic lost", want)
		}
	}
	if retained.Len() > assemblyDiagnosticFileLimit {
		t.Fatal("private diagnostic exceeded its existing file limit")
	}
	stdout.WriteString("{interrupted event")
	failure.stdout = stdout.Bytes()
	retained.Reset()
	if err := writeAssemblyDiagnosticBody(&retained, failure); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(retained.String(), "controlled_test.go:42: exact late assertion") || !strings.Contains(retained.String(), "Non-event stdout excluded from failed-test selection: true") {
		t.Fatal("incomplete event discarded an earlier assertion or its exclusion marker")
	}
}

// full_only: false
func TestAssemblyFailureRetainsBoundedPrivateDiagnostics(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(directory, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	s := &runState{directory: directory, private: private}
	failure := &toolFailure{
		operation: "go test",
		process:   processResult{Status: "process_failed", Started: true, Joined: true, Cause: errors.New("exit status 1")},
		stdout:    bytes.Repeat([]byte("private-source-path\n"), assemblyDiagnosticOutputLimit),
		stderr:    []byte("compiler-secret-sentinel\n"),
	}

	err = s.retainAssemblyFailure(failure)
	if err == nil || !strings.Contains(err.Error(), "diagnostics:") {
		t.Fatalf("private diagnostic reference missing: %v", err)
	}
	if strings.Contains(err.Error(), "private-source-path") || strings.Contains(err.Error(), "compiler-secret-sentinel") {
		t.Fatal("private assembly output reached the public error")
	}
	path := filepath.Join(private, assemblyDiagnosticName)
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0600 || info.Size() > assemblyDiagnosticFileLimit {
		t.Fatalf("private diagnostic bounds differ: mode=%o size=%d", info.Mode().Perm(), info.Size())
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, want := range []string{"Operation: go test", "Process: process_failed", "Joined: true", "compiler-secret-sentinel", "truncated: true"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("diagnostic missing %q", want)
		}
	}
}

// full_only: false
func TestAssemblyFailureKeepsCommandAndCleanupFacts(t *testing.T) {
	cleanupFailure := errors.New("directory cleanup failed: synthetic-cleanup-secret /private/controlled-overlay")
	failure := &toolFailure{
		operation: "go vet",
		process:   processResult{Status: "passed", Started: true, Joined: true},
		cleanup:   cleanupFailure,
	}
	if !strings.Contains(failure.Error(), "cleanup") {
		t.Fatal("cleanup failure was flattened")
	}
	if !errors.Is(&toolFailure{operation: "go test", process: processResult{Status: "interrupted", Joined: true, Cause: context.Canceled}}, context.Canceled) {
		t.Fatal("command cause is not retained")
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(directory, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	s := &runState{directory: directory, private: private}
	public := s.retainAssemblyFailure(failure)
	if public == nil {
		t.Fatal("cleanup failure returned success")
	}
	for _, forbidden := range []string{"synthetic-cleanup-secret", "/private/controlled-overlay", private} {
		if strings.Contains(public.Error(), forbidden) {
			t.Error("public assembly error exposed a private cause or path", forbidden)
		}
	}
	var retained *toolFailure
	if !errors.Is(public, cleanupFailure) || !errors.As(public, &retained) || retained != failure {
		t.Error("safe assembly error lost its original command and cleanup causes")
	}
	body, err := os.ReadFile(filepath.Join(private, assemblyDiagnosticName))
	if err != nil || !bytes.Contains(body, []byte(cleanupFailure.Error())) || !bytes.Contains(body, []byte("Process: passed")) || !bytes.Contains(body, []byte("Joined: true")) {
		t.Error("private diagnostic lost independent passed-command and failed-cleanup facts", err)
	}
}

// full_only: false
func TestAssemblyFailureRefusesExistingDiagnostic(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(directory, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, assemblyDiagnosticName)
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &runState{directory: directory, private: private}
	err = s.retainAssemblyFailure(errors.New("synthetic private compiler output"))
	if err == nil || !strings.Contains(err.Error(), "private diagnostics could not be created") || strings.Contains(err.Error(), "synthetic private compiler output") {
		t.Fatalf("existing diagnostic handling differs: %v", err)
	}
}

// full_only: false
func TestAssemblyFailureBoundsArbitraryCauses(t *testing.T) {
	var output bytes.Buffer
	if err := writeAssemblyDiagnosticBody(&output, errors.New(strings.Repeat("x", assemblyDiagnosticFileLimit))); err != nil {
		t.Fatal(err)
	}
	if output.Len() > assemblyDiagnosticFileLimit || !strings.Contains(output.String(), "truncated: true") {
		t.Fatal("arbitrary assembly cause was not bounded")
	}
}

// full_only: false
func TestAssemblyFailureBoundsFailedGoTestOutputTail(t *testing.T) {
	const assertion = "controlled_test.go:99: final assertion\n"
	small := strings.Repeat("earlier failed-test log\n", 64)
	chunks := make([]string, assemblyDiagnosticOutputLimit/len(small)+2)
	for i := range chunks {
		chunks[i] = small
	}
	chunks = append(chunks, assertion)
	for _, tc := range []struct {
		name   string
		chunks []string
	}{
		{"single oversized event", []string{strings.Repeat("earlier failed-test log\n", assemblyDiagnosticOutputLimit) + assertion}},
		{"many small events", chunks},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []ordinaryEvent
			for _, chunk := range tc.chunks {
				events = append(events, ordinaryEvent{Action: "output", Package: "p", Test: "TestFailed", Output: chunk})
			}
			events = append(events, ordinaryEvent{Action: "fail", Package: "p", Test: "TestFailed"})
			var body bytes.Buffer
			for _, event := range events {
				line, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				body.Write(line)
				body.WriteByte('\n')
			}
			var retained bytes.Buffer
			if err := writeAssemblyOutput(&retained, "Stdout", prioritizeFailedGoTestOutput(body.Bytes()), false); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(retained.String(), assertion) || !strings.Contains(retained.String(), "Failed test output tail truncated: true") {
				t.Fatal("bounded failed-test tail lost the assertion or truncation signal")
			}
			if retained.Len() > assemblyDiagnosticOutputLimit+len("\nStdout (truncated: true):\n") {
				t.Fatal("stdout exceeded its existing diagnostic limit")
			}
		})
	}
	for _, raw := range [][]byte{[]byte("compiler error\n"), []byte("{invalid\n"), []byte("{\"Action\":\"pass\",\"Package\":\"p\",\"Test\":\"TestPass\"}\n")} {
		if !bytes.Equal(prioritizeFailedGoTestOutput(raw), raw) {
			t.Fatal("raw or passing diagnostic fallback changed")
		}
	}
}
