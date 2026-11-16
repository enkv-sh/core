package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// full_only: false
func TestWorkflowPreparationCauseUsesBoundedLocalOutput(t *testing.T) {
	for _, refuseOutput := range []bool{false, true} {
		t.Run(map[bool]string{false: "bounded-cause", true: "output-failure"}[refuseOutput], func(t *testing.T) {
			cause := errors.New("original local preparation refusal")
			failure := &toolFailure{
				operation: "go list",
				process:   processResult{Status: "process_failed", Started: true, Joined: true, Cause: cause},
				stdout:    []byte("original local stdout\n" + strings.Repeat("x", assemblyDiagnosticOutputLimit) + "excluded stdout tail"),
				stderr:    []byte("original local stderr\n"),
			}
			plan := workflowPlan{SchemaVersion: 1, Name: "preparation-diagnostics", Profile: "dev", Execution: defaultExecutionPolicy(), Steps: []resolvedWorkflowStep{
				{ID: "unit", Kind: "unit", Selected: true},
				{ID: "unstarted", Kind: "lint", Selected: true},
			}}
			prepared := &preparedWorkflow{plan: plan, joined: true}
			var output bytes.Buffer
			var writer io.Writer = &output
			outputErr := errors.New("local preparation diagnostic output refused")
			if refuseOutput {
				writer = assemblyGroupFailureOutput{cause: outputErr}
			}
			admissions := 0
			ctx := context.WithValue(t.Context(), rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, _ rootAdmission) (context.Context, error) {
				admissions++
				return ctx, nil
			}))
			result, err := executeCommandWorkflow(ctx, "", "", prepared, failure, writer)
			if !errors.Is(err, cause) || admissions != 0 || !prepared.closed {
				t.Fatal("fatal preparation lost its cause or entered execution", err, admissions)
			}
			if len(result.Steps) != 2 {
				t.Fatal("fatal preparation lost the selected steps", result.Steps)
			}
			for _, step := range result.Steps {
				if step.Outcome != "not_run" || step.StartedAt != nil || step.FinishedAt != nil {
					t.Fatal("preparation failure invented a test terminal", step)
				}
			}
			if refuseOutput {
				if !errors.Is(err, outputErr) {
					t.Fatal("diagnostic delivery failure was discarded", err)
				}
				return
			}
			for _, want := range []string{"Operation: go list", "Started: true", "Joined: true", cause.Error(), "Stdout (truncated: true)", "original local stdout", "original local stderr"} {
				if !strings.Contains(output.String(), want) {
					t.Error("local preparation diagnostic lost a required fact", want)
				}
			}
			if strings.Count(output.String(), cause.Error()) != 1 || strings.Contains(output.String(), "excluded stdout tail") || output.Len() > assemblyDiagnosticFileLimit {
				t.Fatal("local preparation cause was duplicated or exceeded its bound", output.Len())
			}
		})
	}
}
