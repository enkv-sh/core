package main

import (
	"context"
	catalog "enkv.sh/core/internal/testcatalog"
	"path/filepath"
	"reflect"
	"testing"
)

// full_only: false
func TestPublicReplacementSavedWorkflowHasExactFiftyFourCells(t *testing.T) {
	path := savedWorkflowPath(t, "keys-replacement-live")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	var file workflowFile
	if err := readSelectionFile(path, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Steps) != 54 {
		t.Fatal("exact finite workflow inventory differs", len(file.Steps))
	}
	var canonical workflowFile
	if err := readSelectionFile(savedWorkflowPath(t, "canonical"), &canonical); err != nil {
		t.Fatal(err)
	}
	canonicalByID := map[string]workflowStep{}
	for _, step := range canonical.Steps {
		canonicalByID[step.ID] = step
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, step := range file.Steps {
		t.Run(step.ID, func(t *testing.T) {
			if !reflect.DeepEqual(canonicalByID[step.ID], step) {
				t.Fatal("focused activity missing or changed in canonical inventory")
			}
			if seen[step.ID] || len(step.Scenarios) != 1 || step.Limits != "../live/limits/authority-operator.json" {
				t.Fatal("duplicate, broad selection or wrong capacity allowance")
			}
			seen[step.ID] = true
			plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: step.ID})
			if err != nil {
				t.Fatal(err)
			}
			selected := 0
			for _, resolved := range plan.Steps {
				if !resolved.Selected {
					continue
				}
				selected++
				run := resolved.Run
				if run == nil || run.Race || run.Schedule.SmokePolicy != catalog.SmokePublicConfiguration || len(run.Schedule.Entries) != 1 || !run.Schedule.Entries[0].Smoke || run.Schedule.Entries[0].Scenario != step.Scenarios[0] {
					t.Fatal("smoke must reuse exactly the selected public case")
				}
				row, ok := catalog.PublicConfiguration(step.Scenarios[0])
				kind := "admin"
				if ok {
					if row.Replacement == nil {
						t.Fatal("unrelated public case entered replacement selection")
					}
					kind = "replacement"
					if row.Replacement.Operator {
						kind = "operator"
						if step.RecoveryMode != "disabled" {
							t.Fatal("operator qualification multiplied Recovery modes")
						}
					}
				}
				counts[kind]++
			}
			if selected != 1 {
				t.Fatal("single cell focus differs", selected)
			}
		})
	}
	if counts["replacement"] != 42 || counts["admin"] != 8 || counts["operator"] != 4 {
		t.Fatal("provider/admin/operator partition differs", counts)
	}
}
