package main

import (
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestPublicManifestSavedWorkflowHasFourProviderRecoveryCells(t *testing.T) {
	path := savedWorkflowPath(t, "public-configuration-manifest-live")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	var focused workflowFile
	if err := readSelectionFile(path, &focused); err != nil || focused.Name != "public-configuration-manifest-live" || len(focused.Steps) != 4 {
		t.Fatal("manifest workflow unavailable", err)
	}
	var suite suiteFile
	if err := readSelectionFile(filepath.Join(root, "tests/suites/public-configuration-manifest.json"), &suite); err != nil || suite.SchemaVersion != 2 || suite.Name != "public-configuration-manifest" ||
		!slices.Equal(suite.RequiredRoles, []string{"authority", "apply", "reader", "cleanup"}) ||
		!slices.Equal(suite.Scenarios, []string{"public-configuration.manifest/atomic_public_file"}) {
		t.Fatal("manifest suite changed exact roles or case", err)
	}
	for i, step := range focused.Steps {
		provider := []string{"aws", "gcp"}[i%2]
		mode := []string{"disabled", "enabled"}[i/2]
		environment, names := savedWorkflowRunInputs(t, root, path, step)
		if step.ID != "public-manifest-"+provider+"-"+mode || step.Kind != "run" || step.RecoveryMode != mode ||
			step.Environment != "../environments/public-manifest-"+provider+".example.json" || !environment.PublicConfiguration || environment.Provider != provider || len(step.AdditionalProviders) != 0 ||
			!slices.Equal(step.Suites, []string{"../suites/public-configuration-manifest.json"}) || !slices.Equal(names, suite.Scenarios) || step.Limits != "../live/limits/public-manifest.json" || step.TelemetryConfig != "../telemetry/local.json" {
			t.Fatal("manifest provider cell changed", i)
		}
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
			if resolved.Run == nil || resolved.Limits == nil || !resolved.Limits.valid() || resolved.Run.Provider != provider || resolved.Run.RecoveryMode != mode || resolved.Run.Race ||
				!slices.Equal(resolved.Run.Schedule.Selected, suite.Scenarios) || len(resolved.Run.Entries) != 1 || !resolved.Run.Entries[0].Smoke {
				t.Fatal("manifest focus changed finite execution selection")
			}
			cloud := "aws-secrets-manager"
			if provider == "gcp" {
				cloud = "gcp-secret-manager"
			}
			if len(resolved.Run.Outputs) != 1 || resolved.Run.Outputs[0].Scope != cloud {
				t.Fatal("manifest setup admitted a GitHub or cross-cloud effect")
			}
		}
		if selected != 1 {
			t.Fatal("manifest focus selected another activity")
		}
	}
	for _, name := range []string{"canonical", "live"} {
		var file workflowFile
		if err := readSelectionFile(savedWorkflowPath(t, name), &file); err != nil {
			t.Fatal(err)
		}
		var cells []workflowStep
		for _, step := range file.Steps {
			if strings.HasPrefix(step.ID, "public-manifest-") {
				cells = append(cells, step)
			}
		}
		if !reflect.DeepEqual(cells, focused.Steps) {
			t.Fatal("manifest cells differ from canonical live inventory", name)
		}
	}
}

// full_only: false
func TestSavedPublicOutputLimitsCoverCompleteSelectedWorkload(t *testing.T) {
	for _, workload := range []struct {
		workflow, stepPrefix, suite, limitFile string
		cases                                  []string
		work                                   records.BudgetReservation
		cleanupRequests, cleanupBytes          uint64
	}{
		{
			"public-output-live", "public-output-", "public-configuration-output", "public-output",
			[]string{"public-configuration.output-standalone/output_standalone", "public-configuration.output-combined/output_combined"},
			records.BudgetReservation{Requests: 11332, BodyBytes: 1274 << 20, Objects: 8736, ObjectBytes: 324 << 20},
			171008, 410880 << 20,
		},
		{
			"public-configuration-manifest-live", "public-manifest-", "public-configuration-manifest", "public-manifest",
			[]string{"public-configuration.manifest/atomic_public_file"},
			records.BudgetReservation{Requests: 11148, BodyBytes: 10998 << 20, Objects: 4496, ObjectBytes: 178 << 20},
			91624, 220740 << 20,
		},
	} {
		path := savedWorkflowPath(t, workload.workflow)
		root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
		var workflow workflowFile
		if err := readSelectionFile(path, &workflow); err != nil || len(workflow.Steps) != 4 {
			t.Fatal("public output workflow lost a provider or Recovery mode", err)
		}
		for index, step := range workflow.Steps {
			t.Run(step.ID, func(t *testing.T) {
				provider, mode := []string{"aws", "gcp"}[index%2], []string{"disabled", "enabled"}[index/2]
				if step.ID != workload.stepPrefix+provider+"-"+mode || step.Kind != "run" || step.RecoveryMode != mode ||
					step.Limits != "../live/limits/"+workload.limitFile+".json" || !slices.Equal(step.Suites, []string{"../suites/" + workload.suite + ".json"}) {
					t.Fatal("public output cell changed its complete workload or limits owner")
				}
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
					if resolved.Run == nil || resolved.Limits == nil || !resolved.Limits.valid() || resolved.Run.Provider != provider || resolved.Run.RecoveryMode != mode ||
						!slices.Equal(resolved.Run.Schedule.Selected, workload.cases) || len(resolved.Run.Entries) != len(workload.cases) || resolved.Run.Schedule.Repetitions != 1 {
						t.Fatal("saved output bounds no longer describe the selected complete workload")
					}
					// Output: two eight-command cases with two publication/service
					// pairs each. Manifest: nineteen work commands and two pairs;
					// its extra apply reserves another 128 objects. Both include
					// preflight, fresh readers and the whole selected suite.
					// Cleanup: four commands and one publication/service pair per
					// case, plus the admitted 4096-object inventory and two scans.
					// Each manifest direct selected-state reader has at most 340
					// logical reads with three attempts: 2040 requests/5100 MiB.
					// There are two work readers and three cleanup readers.
					limits := resolved.Limits
					if limits.Requests < workload.work.Requests || limits.BodyBytes < workload.work.BodyBytes || limits.Objects < workload.work.Objects || limits.ObjectBytes < workload.work.ObjectBytes ||
						limits.CleanupRequests < workload.cleanupRequests || limits.CleanupBytes < workload.cleanupBytes {
						t.Errorf("configured bounds cannot cover complete output workload: work=%+v cleanup_requests=%d cleanup_bytes=%d configured=%+v", workload.work, workload.cleanupRequests, workload.cleanupBytes, *limits)
					}
				}
				if selected != 1 {
					t.Fatal("public output focus selected another activity")
				}
			})
		}
	}
}

// full_only: false
func TestPublicManifestKeepsExistingPublicWorkflowInventoriesSeparate(t *testing.T) {
	const manifest = "public-configuration.manifest/atomic_public_file"
	if publicConfigurationWorkflowCase(manifest) {
		t.Fatal("manifest entered broad public workflow classification")
	}
	for _, name := range []string{"public-configuration", "public-configuration-functional", "public-configuration-operator", "public-configuration-replacement"} {
		path := savedWorkflowPath(t, "public-configuration-manifest-live")
		var suite suiteFile
		if err := readSelectionFile(filepath.Join(filepath.Dir(filepath.Dir(path)), "suites", name+".json"), &suite); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(suite.Scenarios, manifest) {
			t.Fatal("manifest entered an existing public suite", name)
		}
	}
}
