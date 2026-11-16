package main

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// full_only: false
func TestLocalFailedEventsKeepStructuralChecks(t *testing.T) {
	t.Run("retained-relation", func(t *testing.T) {
		child := retainedSecretMaterialOwner + "/false"
		body := ordinaryEvents(
			ordinaryEvent{Action: "start", Package: componentPackage},
			ordinaryEvent{Action: "run", Package: componentPackage, Test: retainedSecretMaterialOwner},
			ordinaryEvent{Action: "run", Package: componentPackage, Test: child},
			ordinaryEvent{Action: "output", Package: componentPackage, Test: child, Output: retainedSecretMaterialMarker + " expected=0 actual=1\n"},
			ordinaryEvent{Action: "pass", Package: componentPackage, Test: child},
			ordinaryEvent{Action: "fail", Package: componentPackage, Test: retainedSecretMaterialOwner},
			ordinaryEvent{Action: "fail", Package: componentPackage},
		)
		rows, _, err := parseOrdinaryEvents(body, map[string][]string{componentPackage: {retainedSecretMaterialOwner}}, nil)
		if len(rows) != 2 || err == nil || !strings.Contains(err.Error(), "contradicts a passing terminal") {
			t.Fatal("failed package hid contradictory relation evidence", err, rows)
		}
		if containedCheckFailure(context.Background(), containTestFailure(context.Background(), localTestExit(), err)) {
			t.Fatal("native child failure contained contradictory relation evidence")
		}
	})
	t.Run("helper-skip", func(t *testing.T) {
		const pkg = "example.org/local"
		body := ordinaryEvents(
			ordinaryEvent{Action: "start", Package: pkg},
			ordinaryEvent{Action: "run", Package: pkg, Test: "TestHelper"},
			ordinaryEvent{Action: "skip", Package: pkg, Test: "TestHelper"},
			ordinaryEvent{Action: "run", Package: pkg, Test: "TestFailure"},
			ordinaryEvent{Action: "fail", Package: pkg, Test: "TestFailure"},
			ordinaryEvent{Action: "fail", Package: pkg},
		)
		rows, _, err := parseOrdinaryEvents(body, map[string][]string{pkg: {"TestHelper", "TestFailure"}}, nil)
		if len(rows) != 2 || err == nil || !strings.Contains(err.Error(), "skipped without exact helper invocation proof") {
			t.Fatal("failed package hid missing helper proof", err, rows)
		}
		if containedCheckFailure(context.Background(), containTestFailure(context.Background(), localTestExit(), err)) {
			t.Fatal("native child failure contained missing helper proof")
		}
		proved := ordinaryEvents(
			ordinaryEvent{Action: "start", Package: pkg},
			ordinaryEvent{Action: "run", Package: pkg, Test: "TestHelper"},
			ordinaryEvent{Action: "skip", Package: pkg, Test: "TestHelper"},
			ordinaryEvent{Action: "run", Package: pkg, Test: "TestProof"},
			ordinaryEvent{Action: "pass", Package: pkg, Test: "TestProof"},
			ordinaryEvent{Action: "run", Package: pkg, Test: "TestFailure"},
			ordinaryEvent{Action: "fail", Package: pkg, Test: "TestFailure"},
			ordinaryEvent{Action: "fail", Package: pkg},
		)
		rows, _, err = parseOrdinaryEvents(proved, map[string][]string{pkg: {"TestHelper", "TestProof", "TestFailure"}}, map[string]string{pkg + "\x00TestHelper": "TestProof"})
		if len(rows) != 3 || !containedCheckFailure(context.Background(), containTestFailure(context.Background(), localTestExit(), err)) {
			t.Fatal("valid helper proof blocked a settled child failure", err, rows)
		}
	})
}

func localTestExit() error {
	return &toolFailure{process: processResult{Status: "process_failed", Started: true, Joined: true, Cause: &exec.ExitError{}}}
}

// full_only: false
func TestLocalFailedEventPrefixesRequireSettledChild(t *testing.T) {
	const pkg = "example.org/local"
	want := map[string][]string{pkg: {"TestParent", "TestUnstarted"}}
	prefix := []ordinaryEvent{
		{Action: "start", Package: pkg},
		{Action: "run", Package: pkg, Test: "TestParent"},
		{Action: "run", Package: pkg, Test: "TestParent/failed"},
		{Action: "fail", Package: pkg, Test: "TestParent/failed"},
		{Action: "run", Package: pkg, Test: "TestParent/waiting"},
	}
	for _, spec := range []struct {
		name      string
		tail      []ordinaryEvent
		raw       string
		unstarted string
		contained bool
	}{
		{name: "valid-prefix", unstarted: "not_run", contained: true},
		{name: "failed-terminals", tail: []ordinaryEvent{{Action: "fail", Package: pkg, Test: "TestParent/waiting"}, {Action: "fail", Package: pkg, Test: "TestParent"}, {Action: "fail", Package: pkg}}, unstarted: "not_run", contained: true},
		{name: "malformed", raw: "not-json\n", unstarted: "incomplete"},
		{name: "truncated", raw: `{"Action":"fail"`, unstarted: "incomplete"},
		{name: "unexpected-test", tail: []ordinaryEvent{{Action: "run", Package: pkg, Test: "TestOther"}}, unstarted: "incomplete"},
		{name: "duplicate-terminal", tail: []ordinaryEvent{{Action: "fail", Package: pkg, Test: "TestParent/failed"}}, unstarted: "incomplete"},
		{name: "passing-package", tail: []ordinaryEvent{{Action: "pass", Package: pkg}}, unstarted: "not_run"},
		{name: "passing-parent", tail: []ordinaryEvent{{Action: "pass", Package: pkg, Test: "TestParent"}, {Action: "fail", Package: pkg}}, unstarted: "not_run"},
	} {
		t.Run(spec.name, func(t *testing.T) {
			body := ordinaryEvents(append(append([]ordinaryEvent{}, prefix...), spec.tail...)...)
			body = append(body, spec.raw...)
			rows, _, eventErr := parseOrdinaryEvents(body, want, nil)
			if eventErr == nil || len(rows) != 4 {
				t.Fatal("failed prefix lost its incomplete outcome or rows", eventErr, rows)
			}
			unstarted := rows[len(rows)-1]
			if unstarted.Package != pkg || unstarted.Name != "TestUnstarted" || unstarted.Outcome != spec.unstarted ||
				unstarted.StartedAt != nil || unstarted.FinishedAt != nil || unstarted.ElapsedSeconds != nil {
				t.Fatal("failed prefix lost unstarted selection or invented execution", unstarted)
			}
			processErr := localTestExit()
			result := containTestFailure(context.Background(), processErr, eventErr)
			if containedCheckFailure(context.Background(), result) != spec.contained || !errors.Is(result, processErr) || !errors.Is(result, eventErr) {
				t.Fatal("event validation changed settlement classification or original errors", result)
			}
			if spec.name == "valid-prefix" {
				outcomes := make(map[string]string, len(rows))
				for _, row := range rows {
					outcomes[row.Name] = row.Outcome
				}
				if !reflect.DeepEqual(outcomes, map[string]string{"TestParent": "incomplete", "TestParent/failed": "fail", "TestParent/waiting": "incomplete", "TestUnstarted": "not_run"}) {
					t.Fatal("prefix changed completed or unfinished selections", outcomes)
				}
				for _, passed := range []error{nil, &toolFailure{process: processResult{Status: "passed", Started: true, Joined: true}}} {
					if containedCheckFailure(context.Background(), containTestFailure(context.Background(), passed, eventErr)) {
						t.Fatal("missing terminals were contained without a native failed child")
					}
				}
				cancelled, cancel := context.WithCancel(context.Background())
				cancel()
				if containedCheckFailure(cancelled, containTestFailure(cancelled, processErr, eventErr)) {
					t.Fatal("cancelled parent permitted continuation")
				}
				unknown := errors.New("converter fault")
				mixed := containTestFailure(context.Background(), processErr, errors.Join(eventErr, unknown))
				if containedCheckFailure(context.Background(), mixed) || !errors.Is(mixed, unknown) {
					t.Fatal("valid failed prefix hid an unknown completion branch")
				}
			}
		})
	}
	t.Run("failed-focus-keeps-subtree-check", func(t *testing.T) {
		rows, _, eventErr := parseOrdinaryEvents(ordinaryEvents(prefix...), map[string][]string{pkg: {"TestParent"}}, nil)
		for _, requested := range []string{"TestParent", "TestParent/failed"} {
			focusErr := ordinaryFocusEventError(rows, ordinaryFocus{Package: pkg, Tests: singleTestRequest(requested)}, eventErr)
			result := containTestFailure(context.Background(), localTestExit(), focusErr)
			if containedCheckFailure(context.Background(), result) != (requested == "TestParent") {
				t.Fatal("failed focus hid an out-of-subtree result", requested, result)
			}
		}
	})
}
