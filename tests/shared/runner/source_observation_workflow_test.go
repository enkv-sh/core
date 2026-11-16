package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestWorkflowSourceObservationSurvivesCommandContext(t *testing.T) {
	t.Run("retained_live_result", func(t *testing.T) {
		root := assemblyGroupExecutionRoot(t)
		source, err := sourceIdentity(t.Context(), root)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.WithValue(t.Context(), sourceObservationContextKey{}, source)
		plan := liveGroupPlan(1)
		plan.Steps = plan.Steps[:1]
		plan.Steps[0].ParallelGroup = ""
		var output strings.Builder
		failure := errors.New("controlled contained assertion failure")
		result, err := executeWorkflow(ctx, root, plan, &output, nil, nil,
			func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error) {
				if err := os.WriteFile(filepath.Join(root, "core", "observed.go"), []byte("package core\n"), 0600); err != nil {
					return workflowStepExecution{}, err
				}
				return workflowStepExecution{}, &liveCheckFailure{cause: failure}
			})
		if !errors.Is(err, failure) || result.Outcome != "failed" || !result.SourceChanged {
			t.Fatal("cached command observation was not finished in the workflow", result.Outcome, result.SourceChanged, err)
		}
		relative, err := records.RunRelative(result.RunID, result.StartedAt)
		if err != nil {
			t.Fatal(err)
		}
		var saved workflowResult
		if err := records.ReadJSON(filepath.Join(root, "tests", "workflows", "runs", relative, "workflow.json"), &saved); err != nil || !saved.SourceChanged || saved.Outcome != "failed" {
			t.Fatal("durable workflow lost its informational source change", saved.SourceChanged, saved.Outcome, err)
		}
		if strings.Count(output.String(), "Source changed during execution; prepared builds remain in use") != 1 {
			t.Fatal("workflow source observation was missing or repeated", output.String())
		}
	})
	t.Run("command_reports_once", func(t *testing.T) {
		ctx, root, bootstrap, marker, workflow, _ := completePreparationFixture(t, "")
		ctx = testRaceContext(t, ctx)
		t.Setenv("ENKV_SOURCE_OBSERVATION_EDIT", filepath.Join(root, "core", "go.mod"))
		writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", `package witness
import ("os"; "testing")
// full_only: false
func TestNormal(t *testing.T) {
 f, err := os.OpenFile(os.Getenv("ENKV_SOURCE_OBSERVATION_EDIT"), os.O_APPEND|os.O_WRONLY, 0600)
 if err != nil { t.Fatal(err) }
 if _, err := f.WriteString("\n"); err != nil { f.Close(); t.Fatal(err) }
 if err := f.Close(); err != nil { t.Fatal(err) }
 if err := os.WriteFile(os.Getenv("ENKV_PREPARATION_WITNESS"), []byte("ran"), 0600); err != nil { t.Fatal(err) }
}
`)
		var output strings.Builder
		if err := runCommand(ctx, root, bootstrap, []string{"run", "--workflow", workflow}, &output); err != nil {
			t.Fatal("command did not complete selected work", err, output.String())
		}
		body, err := os.ReadFile(marker)
		if err != nil || string(body) != "ran" || strings.Count(output.String(), "Source changed during execution; prepared builds remain in use") != 1 {
			t.Fatal("command lost execution or repeated its final source observation", string(body), err, output.String())
		}
	})
}
