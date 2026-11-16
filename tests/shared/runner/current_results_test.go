package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// full_only: false
func TestWorkflowCurrentResultsPublishInventoryAndTerminals(t *testing.T) {
	ordinary := &ordinaryStepEvidence{Profile: "dev", Race: raceSetting(false), Packages: []ordinaryPackage{{Name: "example.org/selected", Tests: []string{"TestSelected"}, Inventory: []string{"TestSelected", "TestDeferred"}, Classifications: []testClassification{{Name: "TestSelected", FullOnly: boolPointer(false)}, {Name: "TestDeferred", FullOnly: boolPointer(true)}}}}, Tests: []ordinaryTest{{Package: "example.org/selected", Name: "TestSelected", Outcome: "pass"}}}
	component := &componentRunRecord{Outcome: "passed", Checks: &checkEvidence{Profile: "dev", Inventory: []string{"TestComponent", "TestMaximum"}, Classifications: []testClassification{{Name: "TestComponent", FullOnly: boolPointer(false)}, {Name: "TestMaximum", FullOnly: boolPointer(true)}}, Tests: []componentTest{{Name: "TestComponent", Outcome: "passed"}}}}
	for _, row := range []struct {
		activity, field string
		execution       workflowStepExecution
	}{
		{"unit", "ordinary", workflowStepExecution{Ordinary: ordinary}},
		{"component-tests", "component", workflowStepExecution{Component: component}},
		{"assembly-checks", "assembly", workflowStepExecution{Assembly: &offlineEvidence{Outcome: "passed"}}},
		{"fuzz", "fuzz", workflowStepExecution{Fuzz: []*fuzzEvidence{{Outcome: "passed", Joined: true}}}},
		{"run", "suite", workflowStepExecution{Suite: &runRecord{Outcome: "passed"}}},
	} {
		t.Run(row.field, func(t *testing.T) {
			plan := workflowPlan{SchemaVersion: 1, Name: "current-results", Profile: "dev", Execution: defaultExecutionPolicy(), Steps: []resolvedWorkflowStep{{ID: "selected", Kind: row.activity, Selected: true}}}
			var output bytes.Buffer
			result, err := executeWorkflow(t.Context(), sourceFixtureRoot(t), plan, &output, nil, nil, func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error) {
				return row.execution, nil
			})
			if err != nil || result.Outcome != "passed" {
				t.Fatal("controlled current result execution failed", err, result.Outcome)
			}
			var records []map[string]json.RawMessage
			for _, line := range strings.Split(output.String(), "\n") {
				var record map[string]json.RawMessage
				if json.Unmarshal([]byte(line), &record) == nil && string(record["type"]) == `"test_result"` {
					records = append(records, record)
				}
			}
			if len(records) != 1 || string(records[0]["step"]) != `"selected"` || string(records[0]["activity"]) != `"`+row.activity+`"` || string(records[0]["outcome"]) != `"passed"` || len(records[0][row.field]) == 0 {
				t.Fatalf("current selected result is not observable: %s", output.String())
			}
			if row.field == "ordinary" {
				var got ordinaryStepEvidence
				if json.Unmarshal(records[0][row.field], &got) != nil || len(got.Packages) != 1 || len(got.Packages[0].Inventory) != 2 || got.Packages[0].Inventory[1] != "TestDeferred" || len(got.Tests) != 1 || got.Tests[0].Name != "TestSelected" || got.Tests[0].Outcome != "pass" {
					t.Fatal("ordinary inventory or terminal was lost", string(records[0][row.field]))
				}
			}
			if row.field == "component" {
				var got componentRunRecord
				if json.Unmarshal(records[0][row.field], &got) != nil || got.Checks == nil || len(got.Checks.Classifications) != 2 || !*got.Checks.Classifications[1].FullOnly || len(got.Checks.Tests) != 1 || got.Checks.Tests[0].Name != "TestComponent" {
					t.Fatal("component compiled classification or terminal was lost", string(records[0][row.field]))
				}
			}
		})
	}
}

type currentResultFailureWriter struct{ cause error }

func (writer currentResultFailureWriter) Write(body []byte) (int, error) {
	if bytes.Contains(body, []byte(`"type":"test_result"`)) {
		return 0, writer.cause
	}
	return len(body), nil
}

// full_only: false
func TestWorkflowCurrentResultOutputFailureStopsDispatch(t *testing.T) {
	failure := errors.New("controlled result output failure")
	plan := workflowPlan{SchemaVersion: 1, Name: "current-result-failure", Profile: "dev", Execution: defaultExecutionPolicy(), Steps: []resolvedWorkflowStep{{ID: "first", Kind: "unit", Selected: true}, {ID: "later", Kind: "unit", Selected: true}}}
	calls := 0
	result, err := executeWorkflow(t.Context(), sourceFixtureRoot(t), plan, currentResultFailureWriter{cause: failure}, nil, nil, func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error) {
		calls++
		return workflowStepExecution{Ordinary: &ordinaryStepEvidence{Tests: []ordinaryTest{{Package: "example.org/selected", Name: "TestSelected", Outcome: "pass"}}}}, nil
	})
	if !errors.Is(err, failure) || calls != 1 || result.Outcome != "failed" || result.Steps[0].Outcome != "failed" || result.Steps[1].Outcome != "not_run" {
		t.Fatal("current result output failure was lost or later work started", calls, result.Outcome, result.Steps, err)
	}
}
