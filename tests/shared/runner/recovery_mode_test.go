package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func recoveryModeWorkflowFixture(t *testing.T, root, provider string) (string, workflowFile) {
	t.Helper()
	environment, _ := replacementEnvironmentFixture(t, provider, "enabled")
	// Planning must use public references without opening any credentials.
	access := accessReference{CredentialsFile: "missing-operator.json"}
	if provider == "aws" {
		access.Profile = "operator"
	}
	environment.Participants["operator"] = participantReference{Access: access}
	saveSelection(t, filepath.Join(root, "environment.json"), environment)
	saveSelection(t, filepath.Join(root, "suite.json"), suiteFixture("replacement-modes", []string{"access.normal-signer-k2-zero-material/plain1_no_current_secret", "access.recovery-combined-k2-zero-material/plain1_no_current_secret"}))
	saveSelection(t, filepath.Join(root, "limits.json"), testLimits())
	file := workflowFile{SchemaVersion: 1, Name: "modes", Steps: []workflowStep{{ID: provider, Kind: "run", RecoveryMode: "both", Suites: []string{"suite.json"}, Environment: "environment.json", Limits: "limits.json"}}}
	path := filepath.Join(root, "workflow.json")
	saveSelection(t, path, file)
	return path, file
}

// full_only: false
func TestWorkflowCloudRecoveryModesUseOneEnvironment(t *testing.T) {
	for _, provider := range []string{"gcp", "aws"} {
		t.Run(provider, func(t *testing.T) {
			root, _, _ := savedSelectionFixture(t)
			path, _ := recoveryModeWorkflowFixture(t, root, provider)
			before, err := os.ReadFile(filepath.Join(root, "environment.json"))
			if err != nil {
				t.Fatal(err)
			}
			plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: provider})
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Steps) != 2 {
				t.Fatal("both did not expand into two runs")
			}
			for i, mode := range []string{"enabled", "disabled"} {
				step := plan.Steps[i]
				if step.ID != provider+"-"+mode || step.ConfiguredStep != provider || !step.Selected || step.Run.RecoveryMode != mode || step.Run.Schedule.RecoveryMode != mode {
					t.Fatal("mode missing from plan", step)
				}
				if !reflect.DeepEqual(step.request.Resolved, step.Run) || !reflect.DeepEqual(step.request.Schedule, step.Run.Schedule) || step.request.Allowance != step.Limits {
					t.Fatal("planned and executed mode or limits differ")
				}
				settings, err := step.request.environment.settingsFor("operator")
				if err != nil || settings["recovery_mode"] != mode {
					t.Fatal("worker settings differ", err)
				}
				if mode == "disabled" {
					if !slices.Equal(step.Run.Schedule.Selected, []string{"access.normal-signer-k2-zero-material/plain1_no_current_secret"}) || !slices.Equal(step.Run.Schedule.NotApplicable, []string{"access.recovery-combined-k2-zero-material/plain1_no_current_secret"}) {
						t.Fatal("unsupported cases were not accounted for", step.Run.Schedule)
					}
					for field := range settings {
						if strings.HasPrefix(field, "recovery_") && field != "recovery_mode" {
							t.Fatal("disabled worker received recovery resources", field)
						}
					}
					for role := range step.request.environment.RoleBindings {
						if role == "recovery" || replacementRoles[role] {
							t.Fatal("disabled worker received a recovery route", role)
						}
					}
				} else if len(step.Run.Schedule.Selected) != 2 || len(step.Run.Schedule.NotApplicable) != 0 || settings["recovery_key_id"] == "" {
					t.Fatal("enabled coverage or resource was lost")
				}
				args := []string{"run", "--suite", filepath.Join(root, "suite.json"), "--environment", filepath.Join(root, "environment.json"), "--limits", filepath.Join(root, "limits.json"), "--recovery-mode", mode}
				request, err := parseRunRequest(args)
				if err != nil || !reflect.DeepEqual(request.Resolved, step.Run) {
					t.Fatal("standalone mode differs from workflow", err)
				}
			}
			if plan.Steps[0].Limits == plan.Steps[1].Limits || plan.Steps[0].Limits.Requests != plan.Steps[1].Limits.Requests {
				t.Fatal("mode allowances are not separate")
			}
			after, err := os.ReadFile(filepath.Join(root, "environment.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("selection changed the environment file", err)
			}
			var out bytes.Buffer
			if err := json.NewEncoder(&out).Encode(plan); err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{root, "credentials_file", "public_key_pem", "missing-operator"} {
				if strings.Contains(out.String(), private) {
					t.Fatal("plan exposed private input")
				}
			}
		})
	}
}

// full_only: false
func TestWorkflowRecoveryModesRefuseIncompleteSelectionsBeforeExecution(t *testing.T) {
	for _, condition := range []string{"missing-resources", "no-applicable-cases", "expanded-id-conflict"} {
		t.Run(condition, func(t *testing.T) {
			root, _, _ := savedSelectionFixture(t)
			path, file := recoveryModeWorkflowFixture(t, root, "gcp")
			switch condition {
			case "missing-resources":
				environment, _ := replacementEnvironmentFixture(t, "gcp", "disabled")
				saveSelection(t, filepath.Join(root, "environment.json"), environment)
			case "no-applicable-cases":
				saveSelection(t, filepath.Join(root, "suite.json"), suiteFixture("recovery-only", []string{"access.recovery-combined-k2-zero-material/plain1_no_current_secret"}))
			case "expanded-id-conflict":
				file.Steps = append(file.Steps, workflowStep{ID: "gcp-enabled", Kind: "lint"})
				saveSelection(t, path, file)
			}
			var out bytes.Buffer
			want := map[string]string{
				"missing-resources":    "enabled recovery requires its participant",
				"no-applicable-cases":  "case selection has no cases for the recovery mode",
				"expanded-id-conflict": "expanded step ID gcp-enabled conflicts with a configured step",
			}[condition]
			if err := runCommand(context.Background(), root, "must-not-build", []string{"run", "--workflow", path}, &out); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatal("invalid mode selection lost its exact refusal", err, out.String())
			}
			if out.String() != "" && out.String() != "Source observation incomplete; prepared builds remain in use\n" {
				t.Fatal("invalid mode selection emitted execution output", out.String())
			}
			if _, err := os.Stat(filepath.Join(root, "tests")); !os.IsNotExist(err) {
				t.Fatal("refused selection created run state")
			}
		})
	}
}

// full_only: false
func TestWorkflowRecoveryModesKeepSeparateResultsAndStopOnFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "passed", true: "failed"}[fail], func(t *testing.T) {
			root := workflowExecutionFixture(t)
			if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("tests/workflows/runs/\ntests/hermetic/runs/\ntests/live/runs/\n"), 0600); err != nil {
				t.Fatal(err)
			}
			path, _ := recoveryModeWorkflowFixture(t, root, "aws")
			plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: "aws"})
			if err != nil {
				t.Fatal(err)
			}
			var calls []string
			evidencePaths := map[string]string{}
			cleanupErr := errors.New("run cleanup failed")
			result, err := executeWorkflow(context.Background(), root, plan, io.Discard, nil, nil, func(ctx context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
				calls = append(calls, step.Run.RecoveryMode)
				source, err := sourceIdentity(ctx, root)
				if err != nil {
					return workflowStepExecution{}, err
				}
				child, err := newRunState(root, step.request, source, "controlled")
				if err != nil {
					return workflowStepExecution{}, err
				}
				if fail {
					child.fail("cleanup_failed", "cleanup")
				}
				child.finish()
				if err := child.save(); err != nil {
					return workflowStepExecution{}, err
				}
				relative, err := filepath.Rel(root, filepath.Join(child.directory, "run.json"))
				if err != nil {
					return workflowStepExecution{}, err
				}
				evidence := filepath.ToSlash(relative)
				evidencePaths[step.Run.RecoveryMode] = evidence
				if fail {
					return workflowStepExecution{Evidence: evidence}, cleanupErr
				}
				return workflowStepExecution{Evidence: evidence}, nil
			})
			if (err != nil) != fail {
				t.Fatal("unexpected workflow result", err)
			}
			if fail && !errors.Is(err, cleanupErr) {
				t.Fatal("workflow lost cleanup failure or refused fixture ownership", err)
			}
			want := []string{"enabled", "disabled"}
			if fail {
				want = want[:1]
			}
			if !slices.Equal(calls, want) {
				t.Fatal("mode order or failure handling changed", calls)
			}
			if evidencePaths["enabled"] == "" || result.Steps[0].Evidence != evidencePaths["enabled"] {
				t.Fatal("enabled evidence missing")
			}
			if fail {
				if result.Steps[1].Outcome != "not_run" || result.Steps[1].Evidence != "" {
					t.Fatal("failed cleanup did not stop next mode")
				}
			} else if evidencePaths["disabled"] == "" || result.Steps[1].Evidence != evidencePaths["disabled"] || result.Steps[0].Evidence == result.Steps[1].Evidence {
				t.Fatal("mode evidence was overwritten")
			}
		})
	}
}

// full_only: false
func TestCleanupUsesRecordedRecoveryModeWithFullEnvironment(t *testing.T) {
	root, request, entries := recoveryFixture(t, 1)
	settings := maps.Clone(entries[0].Input.Settings)
	recovery := firstFlowConfigurationFixture(t, "gcp", "enabled")
	for field, value := range recovery {
		if strings.HasPrefix(field, "recovery_") {
			settings[field] = value
		}
	}
	environment := environmentFor(settings)
	environment.Participants["recovery"] = participantReference{Access: accessReference{CredentialsFile: "missing-recovery.json"}}
	environment.RoleBindings["recovery"] = "recovery"
	request.Environment = filepath.Join(root, "environment.json")
	saveSelection(t, request.Environment, environment)
	plan, err := prepareRecovery(root, request)
	if err != nil || plan.Settings["recovery_mode"] != "disabled" || !sameResources(plan.Settings, entries[0].Input.Settings) {
		t.Fatal("cleanup did not use retained run mode", err)
	}
	if environment.Resource.Settings["recovery_mode"] != "enabled" {
		t.Fatal("cleanup changed available resources")
	}
}
