package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestNativeTestDeadlineKeepsRootBudgetsAndBounds(t *testing.T) {
	normal, full := false, true
	artifact := preparedOrdinaryArtifact{unit: true, ordinaryArtifact: ordinaryArtifact{Package: "example.test/unit", Tests: []string{"TestNormal", "TestFull", "TestHelper", "TestParent"}, Classifications: []testClassification{{Name: "TestNormal", FullOnly: &normal}, {Name: "TestFull", FullOnly: &full}, {Name: "TestHelper", FullOnly: &full}, {Name: "TestParent", FullOnly: &normal}}}}
	helpers := map[string]string{"example.test/unit\x00TestHelper": "TestParent/leaf"}
	budgets, idle, err := ordinaryRootTimeouts(artifact, ordinaryProcessGroup{fullOnly: true}, helpers)
	if err != nil || budgets["TestNormal"] != 10*time.Minute || budgets["TestFull"] != 30*time.Minute || budgets["TestHelper"] != 30*time.Minute || budgets["TestParent"] != 30*time.Minute || idle != 30*time.Minute {
		t.Fatal("full-only membership changed an unrelated root or lost its helper closure", budgets, idle, err)
	}
	artifact.TestFlags = []string{"-timeout=100ms"}
	budgets, idle, err = ordinaryRootTimeouts(artifact, ordinaryProcessGroup{fullOnly: true}, helpers)
	if err != nil || idle != time.Minute {
		t.Fatal("short root limit removed finite race-exit grace", idle, err)
	}
	for name, budget := range budgets {
		if budget != 100*time.Millisecond {
			t.Fatal("explicit shorter root limit was lost", name, budget)
		}
	}
	if backstop, err := nativeTestBackstop(map[string]time.Duration{"TestA": time.Second, "TestB": 2 * time.Second}, 2*time.Second); err != nil || backstop != 13*time.Second {
		t.Fatal("package safety alarm omitted root or no-active allowances", backstop, err)
	}
	for _, budgets := range []map[string]time.Duration{{"TestA": 0}, {"TestA": -1}, {"TestA/child": time.Second}, {"TestA": time.Duration(math.MaxInt64)}} {
		if _, err := nativeTestBackstop(budgets, time.Second); err == nil {
			t.Fatal("invalid or overflowing allowance was admitted", budgets)
		}
	}
}

// full_only: false
func TestNativeTestDeadlineUsesOnlyAdmittedRootTransitions(t *testing.T) {
	newOwner := func(t *testing.T, names map[string]time.Duration, idle time.Duration) *nativeTestDeadline {
		t.Helper()
		owner, err := newNativeTestDeadline(t.Context(), names, idle, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { owner.joined(processResult{Status: "passed", Joined: true}); owner.cancel(context.Canceled) })
		return owner
	}
	write := func(owner *nativeTestDeadline, text string) { _, _ = io.WriteString(owner, text) }
	t.Run("parallel-wait-retains-remaining-budget", func(t *testing.T) {
		owner := newOwner(t, map[string]time.Duration{"TestA": 150 * time.Millisecond, "TestB": time.Second}, time.Second)
		write(owner, "\x16=== RUN   TestA\n")
		time.Sleep(30 * time.Millisecond)
		write(owner, "\x16=== PAUSE TestA\n\x16=== RUN   TestB\n")
		time.Sleep(180 * time.Millisecond)
		write(owner, "\x16--- PASS: TestB (0.18s)\n\x16=== CONT  TestA\n")
		time.Sleep(30 * time.Millisecond)
		write(owner, "\x16--- PASS: TestA (0.06s)\n")
		if owner.ctx.Err() != nil {
			t.Fatal("scheduler pause consumed root budget", context.Cause(owner.ctx))
		}
	})
	t.Run("subtests-and-output-do-not-renew-parent", func(t *testing.T) {
		owner := newOwner(t, map[string]time.Duration{"TestA": 80 * time.Millisecond}, time.Second)
		write(owner, "\x16=== RUN   TestA\n\x16=== RUN   TestA/child\n\x16=== PAUSE TestA/child\n")
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for owner.ctx.Err() == nil {
			select {
			case <-ticker.C:
				write(owner, "log output\n\x16=== NAME  TestA\n")
			case <-owner.ctx.Done():
			}
		}
		if !errors.Is(owner.ctx.Err(), context.DeadlineExceeded) || !errors.Is(context.Cause(owner.ctx), context.DeadlineExceeded) {
			t.Fatal("active parent did not expire while its child paused and logged", owner.ctx.Err())
		}
	})
	t.Run("resume-does-not-grant-new-allowance", func(t *testing.T) {
		owner := newOwner(t, map[string]time.Duration{"TestA": 500 * time.Millisecond, "TestB": 2 * time.Second}, 2*time.Second)
		write(owner, "\x16=== RUN   TestA\n")
		time.Sleep(300 * time.Millisecond)
		write(owner, "\x16=== PAUSE TestA\n\x16=== RUN   TestB\n")
		time.Sleep(600 * time.Millisecond)
		if owner.ctx.Err() != nil {
			t.Fatal("paused root consumed its remaining allowance", context.Cause(owner.ctx))
		}
		write(owner, "\x16--- PASS: TestB (0.60s)\n\x16=== CONT  TestA\n")
		select {
		case <-owner.ctx.Done():
		case <-time.After(350 * time.Millisecond):
			t.Fatal("resume granted a fresh root allowance")
		}
		if !errors.Is(owner.ctx.Err(), context.DeadlineExceeded) {
			t.Fatal("resumed root lost its deadline cause", context.Cause(owner.ctx))
		}
	})
	for _, phase := range []string{"startup", "all-paused", "teardown"} {
		t.Run(phase, func(t *testing.T) {
			owner := newOwner(t, map[string]time.Duration{"TestA": time.Second}, 40*time.Millisecond)
			if phase != "startup" {
				write(owner, "\x16=== RUN   TestA\n")
				if phase == "all-paused" {
					write(owner, "\x16=== PAUSE TestA\n")
				} else {
					write(owner, "\x16--- PASS: TestA (0.00s)\n")
				}
			}
			select {
			case <-owner.ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("no-active phase was not bounded")
			}
			if !errors.Is(owner.ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("idle expiry lost its cause", owner.ctx.Err())
			}
		})
	}
	for _, control := range []string{"\x16=== RUN   TestUnknown\n", "\x16=== RUN   TestA\n\x16=== RUN   TestA\n", "\x16=== CONT  TestA\n", "\x16--- PASS: TestA (invalids)\n"} {
		t.Run(fmt.Sprintf("invalid-%x", []byte(control)), func(t *testing.T) {
			owner := newOwner(t, map[string]time.Duration{"TestA": time.Second}, time.Second)
			write(owner, control)
			if owner.ctx.Err() == nil || errors.Is(owner.ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("invalid lifecycle changed clock authority", context.Cause(owner.ctx))
			}
		})
	}
	t.Run("split-escaped-markers-and-long-names", func(t *testing.T) {
		name := "Test" + strings.Repeat("Long", 2048)
		var capture bytes.Buffer
		owner := newOwner(t, map[string]time.Duration{name: time.Second}, time.Second)
		owner.capture = &capture
		body := "plain-no-newline\x1b\x16=== RUN   TestUnknown\n\x16=== RUN   " + name + "\n" + strings.Repeat("log", 2048) + "\n\x16--- PASS: " + name + " (0.00s)\n"
		for _, b := range []byte(body) {
			_, _ = owner.Write([]byte{b})
		}
		if owner.ctx.Err() != nil || capture.String() != body {
			t.Fatal("chunking, escaped marker or long valid root changed capture/clock", context.Cause(owner.ctx))
		}
	})
	t.Run("parent-cause", func(t *testing.T) {
		parent, cancel := context.WithCancelCause(t.Context())
		owner, err := newNativeTestDeadline(parent, map[string]time.Duration{"TestA": time.Second}, time.Second, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		cause := errors.New("controlled parent cancellation")
		cancel(cause)
		process := owner.joined(processResult{Status: "interrupted", Started: true, Joined: true})
		owner.cancel(context.Canceled)
		if !errors.Is(process.Cause, cause) || owner.ctx.Err() != context.Canceled {
			t.Fatal("parent cancellation cause was replaced", process.Cause, owner.ctx.Err())
		}
	})
}

// full_only: false
func TestNativeTestDeadlineSupervisesAggregateAndHungRoots(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"aggregate", "parallel", "hung-cleanup"} {
		t.Run(mode, func(t *testing.T) {
			capture := &limitedOutput{}
			budgets := map[string]time.Duration{"TestNativeDeadlineFirstHelper": 250 * time.Millisecond, "TestNativeDeadlineSecondHelper": 500 * time.Millisecond}
			if mode == "aggregate" {
				budgets["TestNativeDeadlineSecondHelper"] = 250 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			owner, err := newNativeTestDeadline(ctx, budgets, 3*time.Second, capture)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.cancel(context.Canceled)
			command := exec.Command(binary, "-test.v=test2json", "-test.count=1", "-test.parallel=1", "-test.run=^TestNativeDeadline(First|Second)Helper$", "-test.timeout="+owner.backstop.String())
			command.Env = environment(goEnvironment(), map[string]string{"ENKV_NATIVE_DEADLINE_HELPER": mode})
			command.Stdout, command.Stderr = owner, &limitedOutput{}
			process := owner.joined(superviseProcess(owner.ctx, command))
			if !process.Started || !process.Joined {
				t.Fatal("deadline lost native process custody", process)
			}
			if mode == "hung-cleanup" {
				if process.Status != "timed_out" || !errors.Is(process.Cause, context.DeadlineExceeded) || !bytes.Contains(capture.Bytes(), []byte("--- PASS: TestNativeDeadlineFirstHelper")) || bytes.Contains(capture.Bytes(), []byte("--- PASS: TestNativeDeadlineSecondHelper")) {
					t.Fatal("logging cleanup escaped root deadline or lost earlier pass", process, string(capture.Bytes()))
				}
			} else if process.Status != "passed" || process.Cause != nil || !bytes.Contains(capture.Bytes(), []byte("--- PASS: TestNativeDeadlineSecondHelper")) {
				t.Fatal("healthy aggregate or parallel scheduler wait exhausted one root allowance", process, string(capture.Bytes()))
			}
		})
	}
	t.Run("component-observer-wiring", func(t *testing.T) {
		root := t.TempDir()
		converter := testEventConverterFixture(t, root)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		const admitted = "TestNativeDeadlineSecondHelper"
		process, evidence, _, _ := executeComponentChecks(ctx, root, binary, converter, literalTestSelection("TestNativeDeadlineFirstHelper"), []string{admitted}, environment(goEnvironment(), map[string]string{"ENKV_NATIVE_DEADLINE_HELPER": "unlisted-stall"}))
		if !process.Started || !process.Joined || process.Status != "process_failed" || process.Cause == nil || !strings.Contains(process.Cause.Error(), "native test deadline control has no admitted root") || ctx.Err() != nil || evidence.TestsComplete {
			t.Fatal("component caller did not stop an unadmitted native root before parent expiry", process, evidence, ctx.Err())
		}
	})
}

// full_only: false
func TestNativeDeadlineFirstHelper(t *testing.T) {
	switch os.Getenv("ENKV_NATIVE_DEADLINE_HELPER") {
	case "aggregate":
		time.Sleep(160 * time.Millisecond)
	case "parallel":
		t.Parallel()
		time.Sleep(60 * time.Millisecond)
	case "unlisted-stall":
		time.Sleep(10 * time.Second)
	}
}

// full_only: false
func TestNativeDeadlineSecondHelper(t *testing.T) {
	switch os.Getenv("ENKV_NATIVE_DEADLINE_HELPER") {
	case "aggregate":
		time.Sleep(160 * time.Millisecond)
	case "parallel":
		time.Sleep(300 * time.Millisecond)
	case "hung-cleanup":
		t.Cleanup(func() {
			for {
				t.Log("controlled cleanup remains active")
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}
