package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/compositions/observability"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

func savedWorkflowPath(t *testing.T, name string) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		path := filepath.Join(directory, "tests/workflows", name+".json")
		if _, err := os.Stat(path); err == nil {
			return path
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("saved workflow was not found", name)
		}
		directory = parent
	}
}

// Saved cloud environments can contain private operator inputs. Classification
// reads the checked-in public examples and catalog memberships instead.
func savedWorkflowRunInputs(t *testing.T, root, path string, step workflowStep) (environmentFile, []string) {
	t.Helper()
	environmentPath := filepath.Join(filepath.Dir(path), step.Environment)
	switch filepath.Base(environmentPath) {
	case "aws.json":
		environmentPath = filepath.Join(root, "tests/environments/aws.example.json")
	case "gcp.json":
		environmentPath = filepath.Join(root, "tests/environments/gcp.example.json")
	}
	var environment environmentFile
	if err := readSelectionFile(environmentPath, &environment); err != nil {
		t.Fatal("saved environment facts unavailable", step.ID, err)
	}
	names := slices.Clone(step.Scenarios)
	for _, path := range step.Suites {
		var suite suiteFile
		if err := readSelectionFile(filepath.Join(root, "tests/workflows", path), &suite); err != nil {
			t.Fatal("saved suite facts unavailable", step.ID, err)
		}
		names = append(names, suite.Scenarios...)
	}
	return environment, names
}

func workflowCaseFacts(names []string) (generated, operator, publication bool) {
	for _, name := range names {
		generated = generated || catalog.HasFixtureCapability(name, catalog.FixtureGeneratedProcess)
		if row, known := catalog.PublicConfiguration(name); known {
			generated = generated || row.Generated
		}
		operator = operator || slices.Contains(catalog.AuthorityOperatorLiveNames(), name)
		_, livePublication := catalog.LivePublication(name)
		publication = publication || livePublication
	}
	return
}

// full_only: false
func TestOrdinaryCurrentResultsRequireSelectedCompletion(t *testing.T) {
	if err := validateOrdinaryStepResult(ordinaryStepEvidence{Complete: true}); err == nil {
		t.Fatal("ordinary command without accepted race results passed")
	}
}

// full_only: false
func TestSavedWorkflowSelections(t *testing.T) {
	for _, test := range []struct {
		name, step        string
		selected, entries int
	}{
		{"check", "", 134, 134},
		{"dev", "scenarios", 134, 134},
		{"canonical", "scenarios", 134, 134},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := savedWorkflowPath(t, test.name)
			root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
			var file workflowFile
			if err := readSelectionFile(path, &file); err != nil || strings.TrimSpace(file.Description) == "" {
				t.Fatal("saved workflow needs a description", err)
			}
			plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: test.step})
			if err != nil {
				var diagnostic bytes.Buffer
				diagnosticErr := writeAssemblyDiagnosticBody(&diagnostic, err)
				t.Fatalf("saved workflow resolution failed: %v\n%s", errors.Join(err, diagnosticErr), diagnostic.String())
			}
			if test.name == "check" {
				if err := validateCheckWorkflow(plan); err != nil {
					t.Fatal(err)
				}
			}
			var run *resolvedRequest
			for _, step := range plan.Steps {
				if step.Selected && step.Kind == "run" {
					run = step.Run
				}
			}
			if run == nil {
				t.Fatal("saved workflow has no selected scenario run")
			}
			if len(run.Schedule.Selected) != test.selected || len(run.Entries) != test.entries || !run.Entries[0].Smoke {
				t.Fatal("saved workflow scope changed", run.Schedule)
			}
			body, err := json.Marshal(run)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("resolved local inventory %s: %s", test.name, body)
			if len(run.Suites) != 13 || !slices.Equal(run.Suites[len(run.Suites)-4:], []string{
				"configuration-recovery", "configuration-recovery-aws-owner", "configuration-recovery-generated", "publication",
			}) {
				t.Fatal("local workflow must select all three recovery suites and publication", run.Suites)
			}
			var responsibilities []string
			var assemblyIDs []string
			for _, step := range plan.Steps {
				if step.Kind == "assembly-checks" {
					responsibilities = append(responsibilities, step.Responsibility)
					assemblyIDs = append(assemblyIDs, step.ID)
				}
			}
			if !slices.Equal(responsibilities, []string{"common", "gcp", "aws"}) || !slices.Equal(assemblyIDs, []string{"assembly-common", "assemblies-gcp", "assemblies-aws"}) {
				t.Fatal("saved workflow must retain the exact common, GCP and AWS responsibility order", responsibilities, assemblyIDs)
			}
			if test.name == "canonical" {
				modules, targets, kinds := map[string]int{}, map[string]int{}, map[string]int{}
				runs := map[string]int{}
				for i, step := range file.Steps {
					kinds[step.Kind]++
					switch step.Kind {
					case "unit":
						if len(step.Packages) == 0 {
							t.Fatal("canonical reference must list unit modules explicitly")
						}
						for _, module := range step.Packages {
							if !slices.Contains(moduleRoots, module) {
								t.Fatal("canonical reference must cover complete unit modules", module)
							}
							modules[module]++
						}
					case "fuzz":
						if len(step.Targets) == 0 {
							t.Fatal("canonical reference must list fuzz targets explicitly")
						}
						for _, target := range step.Targets {
							targets[target]++
						}
					case "run":
						file.Steps[i].TelemetryConfig = filepath.Join(root, "tests/telemetry/local.json")
						environment, names := savedWorkflowRunInputs(t, root, path, step)
						if step.ID == "state-point-diagnostics" {
							diagnostic, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: step.ID})
							if err != nil {
								t.Fatal("canonical point diagnostic plan failed", err)
							}
							for _, selected := range diagnostic.Steps {
								if !selected.Selected {
									continue
								}
								run := selected.Run
								if run == nil || run.Mode != "hermetic" || run.Race || run.RecoveryMode != "both" || run.Schedule.SmokePolicy != catalog.SmokeFirstSelectedPoint || run.Schedule.Repetitions != 1 || len(run.Entries) != 64 || len(run.Schedule.Selected) != 64 || run.Schedule.FullCoverage {
									t.Fatal("canonical point diagnostics changed scope")
								}
								for i, entry := range run.Entries {
									want := fmt.Sprintf("state.single-value-update-preserves-other-values/members_%d", i+1)
									if entry.Scenario != want || run.Schedule.Selected[i] != want || entry.Smoke != (i == 0) || entry.Fixture.Members != i+1 {
										t.Fatal("canonical point diagnostics lost a fixed fixture", i)
									}
								}
							}
							continue
						}
						generated, operator, publication := workflowCaseFacts(names)
						if environment.Mode == "live" && (generated || operator || publication || environment.PublicConfiguration) {
							continue
						}
						provider := environment.Provider
						if len(step.Suites) == 0 {
							t.Fatal("canonical reference must list the supported provider runs")
						}
						runs[provider]++
						if environment.Mode == "hermetic" && step.RecoveryMode != "both" ||
							environment.Mode == "live" && step.RecoveryMode != "enabled" && step.RecoveryMode != "disabled" {
							t.Fatal("canonical reference has a mismatched recovery mode", step.ID)
						}
						for j, suite := range step.Suites {
							if filepath.Base(suite) == "canonical.json" {
								t.Fatal("canonical reference must list separate suites", step.ID)
							}
							file.Steps[i].Suites[j] = filepath.Join(filepath.Dir(path), suite)
						}
						// Plan against public examples so this test never depends on
						// the operator's local cloud files or opens credentials.
						environmentName := "hermetic.json"
						if provider != "memory" {
							environmentName = provider + ".example.json"
							file.Steps[i].Limits = filepath.Join(filepath.Dir(path), step.Limits)
						}
						file.Steps[i].Environment = filepath.Join(root, "tests/environments", environmentName)
					}
				}
				for _, module := range moduleRoots {
					if modules[module] != 1 {
						t.Fatal("canonical reference must select every unit module once", module)
					}
				}
				for _, target := range fuzzSpecifications {
					if targets[target.Name] != 1 {
						t.Fatal("canonical reference must select every fuzz target once", target.Name)
					}
				}
				for _, kind := range []string{"lint", "runner-tests", "component-tests"} {
					if kinds[kind] != 1 {
						t.Fatal("canonical reference must select each fixed check once", kind)
					}
				}
				publicDirectory, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				publicPath := filepath.Join(publicDirectory, "canonical.json")
				saveSelection(t, publicPath, file)
				for _, provider := range []string{"memory", "gcp", "aws"} {
					ids := []string{"scenarios"}
					if provider != "memory" {
						ids = []string{provider + "-recovery-disabled", provider + "-recovery-enabled"}
					}
					if runs[provider] != len(ids) {
						t.Fatal("canonical reference must select every provider mode", provider)
					}
					var modes []string
					for _, id := range ids {
						resolved, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: publicPath, SelectedStep: id})
						if err != nil {
							t.Fatal("canonical reference provider plan failed", provider, err)
						}
						for _, step := range resolved.Steps {
							if step.Selected {
								modes = append(modes, step.Run.RecoveryMode)
								var want []string
								for _, name := range catalog.OrdinaryNames() {
									definition, _ := catalog.DefinitionFor(name)
									_, public := catalog.PublicConfiguration(name)
									// Cloudflare generated cases need a separate credential and
									// artifact; their exact cells are checked by the
									// qualification manifest, not the base cloud runs.
									separateLive := provider != "memory" && (slices.Contains(catalog.GeneratedLiveNames(), definition.Name) ||
										slices.Contains(catalog.AuthorityOperatorLiveNames(), definition.Name) || slices.Contains(catalog.LivePublicationNames(), definition.Name) || public)
									if slices.Contains(definition.Providers, provider) && !separateLive && len(definition.RolesForRecovery(step.Run.RecoveryMode)) != 0 {
										want = append(want, definition.Name)
									}
								}
								slices.Sort(want)
								selected := slices.Clone(step.Run.Schedule.Selected)
								slices.Sort(selected)
								if !slices.Equal(selected, want) {
									t.Fatal("canonical reference does not cover every supported case", provider)
								}
							}
						}
					}
					wantModes := []string{"disabled", "enabled"}
					if provider == "memory" {
						wantModes = []string{"both"}
					}
					if !slices.Equal(modes, wantModes) {
						t.Fatal("canonical reference lost a recovery mode", provider, modes)
					}
				}
			}
		})
	}
	t.Run("public-inspection-receipts-local", func(t *testing.T) {
		var file workflowFile
		path := savedWorkflowPath(t, "public-inspection-receipts-local")
		if err := readSelectionFile(path, &file); err != nil {
			t.Fatal(err)
		}
		want := []workflowStep{
			{ID: "selection-1", Kind: "runner-tests", Tests: singleTestRequest("TestPublicConfigurationCatalogRequiresExactLiveRolesAndBoundaries")},
			{ID: "selection-2", Kind: "runner-tests", Tests: singleTestRequest("TestSavedSuitesUseConcreteScenarios")},
			{ID: "selection-3", Kind: "runner-tests", Tests: singleTestRequest("TestExpectedScheduleProjections")},
			{ID: "selection-4", Kind: "runner-tests", Tests: singleTestRequest("TestCurrentCaseProjectionPreservesHistoricalSemantics")},
			{ID: "selection-5", Kind: "runner-tests", Tests: singleTestRequest("TestCurrentCaseDirectoryBindingsAreFiniteAndDistinct")},
			{ID: "selection-6", Kind: "runner-tests", Tests: singleTestRequest("TestCurrentFamilyListsPreserveOrdinaryCoverage")},
			{ID: "selection-7", Kind: "runner-tests", Tests: singleTestRequest("TestCurrentCaseSmokePoliciesPreserveExactCardinality")},
			{ID: "selection-8", Kind: "runner-tests", Tests: singleTestRequest("TestCurrentCaseRepetitionsPreserveSmokeCardinality")},
			{ID: "selection-9", Kind: "runner-tests", Tests: singleTestRequest("TestSavedWorkflowSelections")},
			{ID: "selection-10", Kind: "runner-tests", Tests: singleTestRequest("TestSavedFuzzAndLiveWorkflowsMatchCanonical")},
			{ID: "selection-11", Kind: "runner-tests", Tests: singleTestRequest("TestSavedAssemblyFocusRequiresExactProviderTest")},
			{ID: "native-public-reads", Kind: "unit", Tests: singleTestRequest("TestPublicNativeInspectionAndReceiptsUseOnlyObjectReads"), Packages: []string{"compositions/full"}, Package: "compositions/full/testsupport/nativeprocess"},
			{ID: "gcp-capture", Kind: "assembly-checks", Tests: singleTestRequest("TestPublicInspectionReceiptCaptureRequiresJoinedGETOnly"), Responsibility: "gcp"},
			{ID: "gcp-payload", Kind: "assembly-checks", Tests: singleTestRequest("TestPublicInspectionReceiptPayloadRequiresCompleteFacts"), Responsibility: "gcp"},
			{ID: "aws-capture", Kind: "assembly-checks", Tests: singleTestRequest("TestPublicInspectionReceiptCaptureRequiresJoinedGETOnly"), Responsibility: "aws"},
			{ID: "aws-payload", Kind: "assembly-checks", Tests: singleTestRequest("TestPublicInspectionReceiptPayloadRequiresCompleteFacts"), Responsibility: "aws"},
			{ID: "gcp-allowance", Kind: "assembly-checks", Tests: singleTestRequest("TestPublicConfigurationSuccessorReservesMutationAllowance"), Responsibility: "gcp"},
			{ID: "gcp-fresh-pair", Kind: "assembly-checks", Tests: singleTestRequest("TestPublicFreshPairSourceAdmitsPortableWriterFacts"), Responsibility: "gcp"},
			{ID: "gcp-fixture", Kind: "assembly-checks", Tests: singleTestRequest("TestPublicInspectionReceiptExpectedFactsMatchInstalledQueries"), Responsibility: "gcp"},
			{ID: "aws-fixture", Kind: "assembly-checks", Tests: singleTestRequest("TestPublicInspectionReceiptExpectedFactsMatchInstalledQueries"), Responsibility: "aws"},
		}
		if file.Profile != "full" || !reflect.DeepEqual(file.Steps, want) {
			t.Fatal("local inspection/receipt workflow lost exact checks or admitted a live run")
		}
		root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
		plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path})
		if err != nil || len(plan.Steps) != len(want) {
			t.Fatal("local inspection/receipt workflow cannot resolve", err)
		}
	})

}

// full_only: false
func TestSavedFuzzAndLiveWorkflowsMatchCanonical(t *testing.T) {
	path := savedWorkflowPath(t, "canonical")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	var canonical, live, fuzz workflowFile
	for name, value := range map[string]*workflowFile{"canonical": &canonical, "live": &live, "fuzz": &fuzz} {
		if err := readSelectionFile(savedWorkflowPath(t, name), value); err != nil {
			t.Fatal(name, err)
		}
	}
	var liveSteps, fuzzSteps []workflowStep
	for _, step := range canonical.Steps {
		if step.Kind == "fuzz" {
			fuzzSteps = append(fuzzSteps, step)
		} else if step.Kind == "run" {
			environment, _ := savedWorkflowRunInputs(t, root, path, step)
			if environment.Mode == "live" {
				liveSteps = append(liveSteps, step)
			}
		}
	}
	liveEqual, fuzzEqual := reflect.DeepEqual(live.Steps, liveSteps), reflect.DeepEqual(fuzz.Steps, fuzzSteps)
	if len(liveSteps) != 114 || len(fuzzSteps) != 3 || !liveEqual || !fuzzEqual {
		t.Fatalf("focused live or fuzz workflow differs from the canonical inventory: canonical_live=%d focused_live=%d expected_live=114 live_equal=%t canonical_fuzz=%d focused_fuzz=%d expected_fuzz=3 fuzz_equal=%t",
			len(liveSteps), len(live.Steps), liveEqual, len(fuzzSteps), len(fuzz.Steps), fuzzEqual)
	}
	for _, name := range []string{"canonical", "live", "publication-live", "github-publication-live"} {
		var file workflowFile
		if err := readSelectionFile(savedWorkflowPath(t, name), &file); err != nil {
			t.Fatal(name, err)
		}
		var grouped, want []string
		for i, step := range file.Steps {
			if step.Kind != "run" || step.ParallelGroup == "" {
				continue
			}
			grouped = append(grouped, step.ParallelGroup+":"+step.ID)
			if strings.HasPrefix(step.ID, "aws-recovery-") && (i == 0 ||
				file.Steps[i-1].ID != "gcp-recovery-"+step.RecoveryMode || file.Steps[i-1].ParallelGroup != step.ParallelGroup) {
				t.Fatal("saved recovery pair must be contiguous", name, step.ID)
			}
		}
		if name == "canonical" || name == "live" {
			want = []string{"recovery-disabled:gcp-recovery-disabled", "recovery-disabled:aws-recovery-disabled",
				"recovery-enabled:gcp-recovery-enabled", "recovery-enabled:aws-recovery-enabled"}
		}
		if !slices.Equal(grouped, want) {
			t.Fatal("saved live groups must contain only the base GCP/AWS recovery pairs", name, grouped)
		}
	}
	for i, target := range []string{"format", "contract", "crypto"} {
		if fuzz.Steps[i].Kind != "fuzz" || !slices.Equal(fuzz.Steps[i].Targets, []string{target}) {
			t.Fatal("fuzz workflow includes a wrong target or activity")
		}
	}
	fixtureDirectory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	generatorPath := filepath.Join(fixtureDirectory, "cloudflare.json")
	saveSelection(t, generatorPath, generatorConfiguration{SchemaVersion: 1, Provider: "cloudflare", Generator: generatorReference{
		Account: strings.Repeat("a", 32), PermissionGroup: strings.Repeat("b", 32),
		Artifact: filepath.Join(fixtureDirectory, "artifact")}})
	generatorPublicPath := filepath.Join(fixtureDirectory, "cloudflare-public.json")
	saveSelection(t, generatorPublicPath, generatorConfiguration{SchemaVersion: 1, Provider: "cloudflare", Generator: generatorReference{Account: strings.Repeat("a", 32), PermissionGroup: strings.Repeat("b", 32), Artifact: filepath.Join(fixtureDirectory, "artifact")}})
	for i := range live.Steps {
		step := &live.Steps[i]
		step.TelemetryConfig = filepath.Join(root, "tests/telemetry/local.json")
		environment, names := savedWorkflowRunInputs(t, root, savedWorkflowPath(t, "live"), *step)
		provider := environment.Provider
		generated, operator, publication := workflowCaseFacts(names)
		replacement := false
		if len(step.Scenarios) == 1 {
			row, known := catalog.PublicConfiguration(step.Scenarios[0])
			replacement = environment.PublicConfiguration && known && row.Replacement != nil &&
				slices.Equal(step.Suites, []string{"../suites/public-configuration-replacement.json"})
		}
		if len(step.Scenarios) != 0 && !operator && !replacement {
			t.Fatal("live workflow inline selection is not an operator or exact replacement case", step.ID)
		}
		var recoverySuites []string
		for _, suite := range step.Suites {
			if slices.Contains([]string{"configuration-recovery.json", "configuration-recovery-aws-owner.json", "configuration-recovery-generated.json"}, filepath.Base(suite)) {
				recoverySuites = append(recoverySuites, filepath.Base(suite))
			}
		}
		var wantRecoverySuites []string
		if generated && !environment.PublicConfiguration {
			wantRecoverySuites = []string{"configuration-recovery-generated.json"}
		} else if !operator && !publication && !environment.PublicConfiguration {
			wantRecoverySuites = []string{"configuration-recovery.json"}
			if provider == "aws" {
				wantRecoverySuites = append(wantRecoverySuites, "configuration-recovery-aws-owner.json")
			}
		}
		if !slices.Equal(recoverySuites, wantRecoverySuites) {
			t.Fatal("live workflow recovery suites differ", step.ID, recoverySuites, wantRecoverySuites)
		}
		if step.Kind != "run" || step.Limits == "" ||
			(provider != "gcp" && provider != "aws") {
			t.Fatal("live workflow has an invalid activity", step.ID)
		}
		for j, suite := range step.Suites {
			step.Suites[j] = filepath.Join(root, "tests/workflows", suite)
		}
		step.Limits = filepath.Join(root, "tests/workflows", step.Limits)
		if len(step.AdditionalProviders) != 0 {
			if environment.PluginAcceptance != nil {
				if !environment.PublicConfiguration || !generated || step.RecoveryMode != "enabled" ||
					len(step.AdditionalProviders) != 1 || step.AdditionalProviders["cloudflare"] != "../environments/cloudflare-stock-plugin.example.json" ||
					!slices.Equal(step.Suites, []string{filepath.Join(root, "tests/suites/stock-plugin-acceptance.json")}) ||
					step.Environment != "../environments/stock-plugin-"+provider+".example.json" {
					t.Fatal("stock plugin cell changed its fixture or credential route", step.ID)
				}
				step.AdditionalProviders["cloudflare"] = filepath.Join(root, "tests/environments/cloudflare-stock-plugin.example.json")
			} else if environment.PublicConfiguration && generated {
				if len(step.AdditionalProviders) != 1 || step.AdditionalProviders["cloudflare"] != "../environments/cloudflare-public-environment.json" || !slices.Equal(step.Suites, []string{filepath.Join(root, "tests/suites/public-generated.json")}) || step.Environment != "../environments/public-aws-assume-role.example.json" && step.Environment != "../environments/public-gcp-impersonated.example.json" {
					t.Fatal("public generated live cell changed its environment credential route", step.ID)
				}
				step.AdditionalProviders["cloudflare"] = generatorPublicPath
			} else {
				if !generated || step.RecoveryMode != "enabled" && step.RecoveryMode != "disabled" ||
					len(step.AdditionalProviders) != 1 || step.AdditionalProviders["cloudflare"] != "../environments/cloudflare.json" ||
					step.Environment != "../environments/"+provider+".json" ||
					generated && !slices.Equal(step.Suites, []string{filepath.Join(root, "tests/suites/generated-lifecycle.json"), filepath.Join(root, "tests/suites/configuration-recovery-generated.json")}) {
					t.Fatal("generated or operator live cell selection changed", step.ID)
				}
				step.AdditionalProviders["cloudflare"] = generatorPath
			}
		}
		if environment.PublicConfiguration {
			step.Environment = filepath.Join(root, "tests/environments", filepath.Base(step.Environment))
		} else {
			step.Environment = filepath.Join(root, "tests/environments", provider+".example.json")
		}
		if publication {
			path, raw := mixedOutputInput(t, provider)
			var public environmentFile
			if readSelectionFile(step.Environment, &public) != nil {
				t.Fatal("public State example unavailable")
			}
			var outputEnvironment environmentFile
			body, marshalErr := json.Marshal(raw)
			if marshalErr != nil || json.Unmarshal(body, &outputEnvironment) != nil {
				t.Fatal("public output fixture unavailable")
			}
			public.OutputTargets, public.GitHubOutputTargets = outputEnvironment.OutputTargets, outputEnvironment.GitHubOutputTargets
			for namespace, target := range public.OutputTargets {
				if provider == "aws" {
					target.Region = public.Resource.Settings["region"]
				} else {
					target.Project = public.Resource.Settings["project"]
				}
				public.OutputTargets[namespace] = target
			}
			saveSelection(t, path, public)
			step.Environment = path
		}
	}
	selection := filepath.Join(fixtureDirectory, "live.json")
	saveSelection(t, selection, live)
	plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: selection})
	if err != nil || len(plan.Steps) != 114 {
		t.Fatalf("live workflow did not resolve every provider cell: resolved_steps=%d expected_steps=114 resolve_error=%v", len(plan.Steps), err)
	}
	want := []string{}
	for _, mode := range []string{"disabled", "enabled"} {
		want = append(want, "gcp-recovery-"+mode, "aws-recovery-"+mode)
		for _, provider := range []string{"gcp", "aws"} {
			want = append(want, provider+"-generated-lifecycle-"+mode, "admin-"+provider+"-abandon-"+mode)
			condition := "replacement-refusal"
			if mode == "enabled" {
				condition = "replace-authority"
			}
			want = append(want, "admin-"+provider+"-"+condition+"-"+mode)
		}
		for _, base := range []string{"gcp-state-output-publication-positive", "gcp-state-output-publication-later-member-refusal", "aws-state-output-publication-positive", "aws-state-output-publication-later-member-refusal"} {
			want = append(want, base+"-"+mode)
		}
	}
	want = append(want, "public-aws-disabled", "public-gcp-disabled", "public-aws-enabled", "public-gcp-enabled",
		"public-functional-aws-disabled", "public-functional-gcp-disabled", "public-functional-aws-enabled", "public-functional-gcp-enabled")
	for _, recovery := range []string{"disabled", "enabled"} {
		for _, mode := range []string{"gcp-user-adc", "gcp-service-account-adc", "aws-shared-credentials", "aws-sso"} {
			want = append(want, "public-operator-"+mode+"-"+recovery)
		}
	}
	want = append(want,
		"keys-gcp-authority-signing-by-authority-disabled",
		"keys-gcp-authority-encryption-by-authority-disabled",
		"keys-gcp-authority-both-by-authority-disabled",
		"keys-gcp-authority-signing-by-authority-enabled",
		"keys-gcp-authority-signing-by-recovery-enabled",
		"keys-gcp-authority-encryption-by-authority-enabled",
		"keys-gcp-authority-encryption-by-recovery-enabled",
		"keys-gcp-authority-both-by-authority-enabled",
		"keys-gcp-authority-both-by-recovery-enabled",
		"keys-gcp-recovery-signing-by-authority-enabled",
		"keys-gcp-recovery-signing-by-recovery-enabled",
		"keys-gcp-recovery-encryption-by-authority-enabled",
		"keys-gcp-recovery-encryption-by-recovery-enabled",
		"keys-gcp-recovery-both-by-authority-enabled",
		"keys-gcp-recovery-both-by-recovery-enabled",
		"keys-gcp-recipient-enabled",
		"keys-gcp-required-public-denied-enabled",
		"keys-gcp-normal-signing-denied-enabled",
		"keys-gcp-authority-private-denied-enabled",
		"keys-gcp-recovery-signing-denied-enabled",
		"keys-gcp-recovery-private-denied-enabled",
		"keys-aws-authority-signing-by-authority-disabled",
		"keys-aws-authority-encryption-by-authority-disabled",
		"keys-aws-authority-both-by-authority-disabled",
		"keys-aws-authority-signing-by-authority-enabled",
		"keys-aws-authority-signing-by-recovery-enabled",
		"keys-aws-authority-encryption-by-authority-enabled",
		"keys-aws-authority-encryption-by-recovery-enabled",
		"keys-aws-authority-both-by-authority-enabled",
		"keys-aws-authority-both-by-recovery-enabled",
		"keys-aws-recovery-signing-by-authority-enabled",
		"keys-aws-recovery-signing-by-recovery-enabled",
		"keys-aws-recovery-encryption-by-authority-enabled",
		"keys-aws-recovery-encryption-by-recovery-enabled",
		"keys-aws-recovery-both-by-authority-enabled",
		"keys-aws-recovery-both-by-recovery-enabled",
		"keys-aws-recipient-enabled",
		"keys-aws-required-public-denied-enabled",
		"keys-aws-normal-signing-denied-enabled",
		"keys-aws-authority-private-denied-enabled",
		"keys-aws-recovery-signing-denied-enabled",
		"keys-aws-recovery-private-denied-enabled",
		"keys-operator-gcp-user-adc",
		"keys-operator-gcp-service-account-adc",
		"keys-operator-aws-shared-credentials",
		"keys-operator-aws-sso",
	)
	want = append(want, "public-generated-aws-disabled", "public-generated-gcp-disabled", "public-generated-aws-enabled", "public-generated-gcp-enabled")
	want = append(want, "public-output-aws-disabled", "public-output-gcp-disabled", "public-output-aws-enabled", "public-output-gcp-enabled")
	want = append(want, "public-inspection-receipts-aws-disabled", "public-inspection-receipts-gcp-disabled", "public-inspection-receipts-aws-enabled", "public-inspection-receipts-gcp-enabled")
	want = append(want, "capacity-gc-aws-disabled", "capacity-gc-gcp-disabled", "capacity-gc-aws-enabled", "capacity-gc-gcp-enabled")
	want = append(want, "public-materialization-aws-enabled", "public-materialization-gcp-enabled")
	want = append(want, "public-manifest-aws-disabled", "public-manifest-gcp-disabled", "public-manifest-aws-enabled", "public-manifest-gcp-enabled")
	want = append(want, "public-prepare-aws-disabled", "public-prepare-gcp-disabled", "public-prepare-aws-enabled", "public-prepare-gcp-enabled")
	want = append(want, "stock-plugin-aws-enabled", "stock-plugin-gcp-enabled")
	if len(plan.Steps) != len(want) {
		t.Fatalf("resolved live cells differ from the complete expected identities: resolved_steps=%d expected_identities=%d", len(plan.Steps), len(want))
	}
	for i, step := range plan.Steps {
		if step.Run == nil {
			t.Fatal("live provider cell has no resolved selection", want[i])
		}
		generated, operator, publication := workflowCaseFacts(step.Run.Schedule.Selected)
		if step.ID != want[i] || step.Kind != "run" || !step.Selected || step.Run == nil || step.Run.Mode != "live" ||
			step.Run.Provider != step.request.environment.Provider || step.Limits == nil || (step.Run.Generator != nil) != generated {
			t.Fatal("live provider cell lost its selection or configuration", want[i])
		}

		body, err := json.Marshal(step)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("resolved live inventory %s: cases=%d entries=%d serialized_bytes=%d", step.ID, len(step.Run.Schedule.Selected), len(step.Run.Entries), len(body))
		if !generated && !operator && !publication && !step.request.environment.PublicConfiguration {
			var actual, want []string
			for _, name := range step.Run.Schedule.Selected {
				if _, known := catalog.ConfigurationRecovery(name); known {
					actual = append(actual, name)
				}
			}
			for _, name := range catalog.ConfigurationRecoveryNames() {
				row, known := catalog.ConfigurationRecovery(name)
				if !known {
					t.Fatal("recovery case missing")
				}
				if row.Generated || row.EnabledOnly && step.Run.RecoveryMode == "disabled" || row.AWSOnly && step.Run.Provider != "aws" {
					continue
				}
				want = append(want, name)
			}
			slices.Sort(actual)
			slices.Sort(want)
			if !slices.Equal(actual, want) {
				t.Fatal("base provider recovery applicability differs", step.ID, actual, want)
			}
		}
		if strings.HasPrefix(step.ID, "public-inspection-receipts-") {
			wantRoles := []string{"authority", "apply", "reader", "cleanup"}
			if !step.request.environment.PublicConfiguration || !slices.Equal(step.Run.Schedule.Selected, []string{"public-configuration.inspection-receipts/inspection_receipts"}) ||
				len(step.Run.Entries) != 1 || !step.Run.Entries[0].Smoke || step.Run.Schedule.SmokePolicy != catalog.SmokePublicConfiguration ||
				!slices.Equal(catalog.RolesForScenarios(step.Run.Schedule.Selected, step.Run.RecoveryMode), wantRoles) || step.Run.Generator != nil {
				t.Fatal("inspection/receipt cell lost its isolated public GET-only fixture", step.ID)
			}
		}
		if step.request.environment.PluginAcceptance != nil {
			if !generated || !step.request.environment.PublicConfiguration || step.Run.RecoveryMode != "enabled" ||
				!slices.Equal(step.Run.Schedule.Selected, []string{"public-configuration.plugin-contracts/plugin_contracts"}) ||
				len(step.Run.Entries) != 1 || !step.Run.Entries[0].Smoke || step.Run.Schedule.SmokePolicy != catalog.SmokePublicConfiguration ||
				step.Limits.GeneratorCreates != 9 || step.Limits.GeneratorRetires != 24 {
				t.Fatal("stock plugin cell lost finite isolated lifecycle selection", step.ID)
			}
		} else if generated && step.request.environment.PublicConfiguration {
			if len(step.Run.Schedule.Selected) != 2 || len(step.Run.Entries) != 2 || step.Run.Schedule.SmokePolicy != catalog.SmokePublicConfiguration || !step.Run.Entries[0].Smoke || step.Limits.GeneratorCreates != 6 || step.Limits.GeneratorRetires != 22 {
				t.Fatal("public generated cell lost finite isolated lifecycle selection", step.ID)
			}
		} else if generated {
			if len(step.Run.Schedule.Selected) != 8 || len(step.Run.Entries) != 9 {
				t.Fatal("generated cell must retain smoke plus exactly eight applicable cases", step.ID)
			}
			if step.Limits.GeneratorCreates != 16 || step.Limits.GeneratorRetires != 32 {
				t.Fatal("generated live cell lost finite limits", want[i])
			}
			selected := slices.Clone(step.Run.Schedule.Selected)
			wantScenarios := catalog.GeneratedLiveNames()
			slices.Sort(selected)
			slices.Sort(wantScenarios)
			if !slices.Equal(selected, wantScenarios) {
				t.Fatal("generated live scenario selection changed", want[i])
			}
		} else if operator {
			if !step.request.environment.PublicConfiguration || len(step.Run.Schedule.Selected) != 1 || len(step.Run.Entries) != 1 ||
				step.Run.Schedule.SmokePolicy != catalog.SmokePublicConfiguration || !step.Run.Entries[0].Smoke {
				t.Fatal("administrative cell lost its isolated public fixture", step.ID)
			}
		}
	}
	var inspection workflowFile
	if err := readSelectionFile(savedWorkflowPath(t, "public-inspection-receipts-live"), &inspection); err != nil {
		t.Fatal(err)
	}
	var inspectionSteps []workflowStep
	for _, step := range liveSteps {
		if strings.HasPrefix(step.ID, "public-inspection-receipts-") {
			inspectionSteps = append(inspectionSteps, step)
		}
	}
	if len(inspectionSteps) != 4 || !reflect.DeepEqual(inspection.Steps, inspectionSteps) {
		t.Fatal("focused inspection/receipt workflow differs from canonical provider/Recovery cells")
	}
	checkPublicationWorkflowViews(t, root, fixtureDirectory, live, liveSteps, plan)
}

func checkPublicationWorkflowViews(t *testing.T, root, directory string, publicLive workflowFile, savedLive []workflowStep, aggregate workflowPlan) {
	t.Helper()
	var savedPublication []workflowStep
	publicByID := map[string]workflowStep{}
	resolvedByID := map[string]resolvedWorkflowStep{}
	for _, step := range savedLive {
		_, names := savedWorkflowRunInputs(t, root, savedWorkflowPath(t, "live"), step)
		_, _, publication := workflowCaseFacts(names)
		if publication {
			savedPublication = append(savedPublication, step)
		}
	}
	for _, step := range publicLive.Steps {
		publicByID[step.ID] = step
	}
	wantCells := map[string]struct{ provider, condition, namespace string }{
		"aws-state-output-publication-positive":             {"aws", "plain-secret-lifecycle", "positive"},
		"gcp-state-output-publication-positive":             {"gcp", "plain-secret-lifecycle", "positive"},
		"aws-state-output-publication-later-member-refusal": {"aws", "later-member-refusal", "ambiguity"},
		"gcp-state-output-publication-later-member-refusal": {"gcp", "later-member-refusal", "ambiguity"},
	}
	selected, smokes := 0, 0
	for _, step := range aggregate.Steps {
		_, _, publication := workflowCaseFacts(step.Run.Schedule.Selected)
		if !publication {
			continue
		}
		resolvedByID[step.ID] = step
		selected += len(step.Run.Schedule.Selected)
		for _, entry := range step.Run.Entries {
			if entry.Smoke {
				smokes++
			}
		}
		// These literal rows preserve the publication case and destination
		// selection independently of the suites and catalog derivation.
		cell, known := wantCells[strings.TrimSuffix(step.ID, "-"+step.Run.RecoveryMode)]
		if !known || step.Run.Provider != cell.provider {
			t.Fatal("aggregate publication State backend changed", step.ID)
		}
		cloud := "aws-secrets-manager"
		if cell.provider == "gcp" {
			cloud = "gcp-secret-manager"
		}
		condition, namespace := cell.condition, cell.namespace
		wantCases := map[string][]string{
			"publication." + cloud + ".later-member-refusal/plain1_secret1_first_target_ack_later_not_sent":       {cloud},
			"publication.github-repository.later-member-refusal/plain1_secret1_first_target_ack_later_not_sent":   {"github-repository"},
			"publication.github-organization.later-member-refusal/plain1_secret1_first_target_ack_later_not_sent": {"github-organization"},
			"publication.github-environment.later-member-refusal/plain1_secret1_first_target_ack_later_not_sent":  {"github-environment"},
		}
		if condition == "plain-secret-lifecycle" {
			wantCases = map[string][]string{
				"publication." + cloud + ".plain-secret-lifecycle/plain1_secret1_create_value_delete":                       {cloud},
				"publication.github-repository.plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete":  {"github-repository"},
				"publication.github-organization.plain-secret-lifecycle/plain1_secret1_create_value_policy_delete":          {"github-organization"},
				"publication.github-environment.plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete": {"github-environment"},
				"publication.mixed-destinations/plain1_secret1_initial_noop_delete_mixed4":                                  {cloud, "github-repository", "github-organization", "github-environment"},
			}
		}
		var want []string
		for name := range wantCases {
			want = append(want, name)
		}
		slices.Sort(want)
		actual := slices.Clone(step.Run.Schedule.Selected)
		slices.Sort(actual)
		if !slices.Equal(actual, want) || step.Run.Race || step.Run.Schedule.Repetitions != 1 ||
			(step.Run.RecoveryMode != "enabled" && step.Run.RecoveryMode != "disabled") {
			t.Fatal("aggregate publication case/backend/mode/race tuple changed", step.ID, actual, want)
		}
		scopes := []string{cloud, "github-repository", "github-organization", "github-environment"}
		for _, name := range actual {
			row, known := catalog.LivePublication(name)
			wantScopes := wantCases[name]
			if !known || row.Namespace != namespace || !slices.Equal(row.OutputScopes(step.Run.Provider), wantScopes) {
				t.Fatal("publication destination/fixture tuple changed", step.ID, name, row)
			}
		}
		var actualScopes []string
		for _, output := range step.Run.Outputs {
			if output.Namespace != namespace {
				t.Fatal("resolved publication fixture namespace changed", step.ID, output)
			}
			actualScopes = append(actualScopes, output.Scope)
		}
		slices.Sort(scopes)
		slices.Sort(actualScopes)
		if !slices.Equal(actualScopes, scopes) {
			t.Fatal("resolved publication destinations changed", step.ID, actualScopes)
		}
	}
	if len(savedPublication) != 8 || len(resolvedByID) != 8 || selected != 36 || smokes != 8 {
		t.Fatal("aggregate publication cells, cases or smokes changed", len(savedPublication), len(resolvedByID), selected, smokes)
	}
	for _, name := range []string{"publication-live", "github-publication-live"} {
		t.Run(name, func(t *testing.T) {
			path := savedWorkflowPath(t, name)
			var view workflowFile
			if err := readSelectionFile(path, &view); err != nil || strings.TrimSpace(view.Description) == "" {
				t.Fatal("focused publication view unavailable", err)
			}
			if len(view.Steps) != len(savedPublication) {
				t.Fatal("focused publication view changed aggregate cells")
			}
			for index, step := range view.Steps {
				want := savedPublication[index]
				if name == "github-publication-live" {
					want.Suites = nil
					for _, suite := range savedPublication[index].Suites {
						if filepath.Base(suite) == "publication-github-positive.json" || filepath.Base(suite) == "publication-github-later-member-refusal.json" {
							want.Suites = append(want.Suites, suite)
						}
					}
				}
				if !reflect.DeepEqual(step, want) {
					t.Fatal("focused publication view changed aggregate inputs", step.ID)
				}
				public := publicByID[step.ID]
				public.Suites = nil
				for _, suite := range step.Suites {
					public.Suites = append(public.Suites, filepath.Join(filepath.Dir(path), suite))
				}
				view.Steps[index] = public
			}
			publicPath := filepath.Join(directory, name+".json")
			saveSelection(t, publicPath, view)
			plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: publicPath})
			if err != nil || len(plan.Steps) != 8 {
				t.Fatal("focused publication view did not resolve all existing cells", err)
			}
			for _, step := range plan.Steps {
				original, known := resolvedByID[step.ID]
				if !known || step.Run.Provider != original.Run.Provider || step.Run.RecoveryMode != original.Run.RecoveryMode ||
					step.Run.Race != original.Run.Race || !reflect.DeepEqual(step.Limits, original.Limits) {
					t.Fatal("focused publication view changed execution tuple", step.ID)
				}
				want := slices.Clone(original.Run.Schedule.Selected)
				if name == "github-publication-live" {
					want = slices.DeleteFunc(want, func(name string) bool { return !strings.HasPrefix(name, "publication.github-") })
				}
				slices.Sort(want)
				actual := slices.Clone(step.Run.Schedule.Selected)
				slices.Sort(actual)
				if !slices.Equal(actual, want) || len(step.Run.Entries) != len(actual)+1 || !step.Run.Entries[0].Smoke {
					t.Fatal("focused publication view is not the exact checked subset", step.ID, actual, want)
				}
				wantOutputs := slices.Clone(original.Run.Outputs)
				if name == "github-publication-live" {
					wantOutputs = slices.DeleteFunc(wantOutputs, func(output resolvedOutputScope) bool {
						return output.Scope != "github-repository" && output.Scope != "github-organization" && output.Scope != "github-environment"
					})
				}
				if !reflect.DeepEqual(step.Run.Outputs, wantOutputs) {
					t.Fatal("focused publication destinations or fixture namespaces changed", step.ID)
				}
			}
		})
	}
}

// full_only: false
func TestWorkflowDescriptionsDoNotChangeSelection(t *testing.T) {
	root, suite, env := savedSelectionFixture(t)
	path := filepath.Join(root, "workflow.json")
	saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "work", Steps: []workflowStep{
		{ID: "state", Kind: "run", RecoveryMode: "both", Suites: []string{suite}, Environment: env},
	}})
	before, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{suite, path} {
		var file map[string]any
		if err := readSelectionFile(filename, &file); err != nil {
			t.Fatal(err)
		}
		file["description"] = "Read the selected state after a fresh process starts."
		saveSelection(t, filename, file)
		after, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path})
		if err != nil {
			t.Fatal("description changed workflow selection", filename, err)
		}
		current, previous := after, before
		if !reflect.DeepEqual(previous, current) {
			t.Fatal("description changed workflow selection", filename)
		}
		before = after
	}
}

func writeTelemetryConfigs(t *testing.T, root string) {
	t.Helper()
	for name, body := range map[string]string{
		"local.json": `{"schema_version":1,"metrics":{"exporters":["local"]},"exporters":{"local":{"type":"otlp_file","directory":"telemetry"}}}`,
		"noop.json":  `{"schema_version":1}`,
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// full_only: false
func TestRemovedWorkflowFieldsAreRejected(t *testing.T) {
	root, suite, environment := savedSelectionFixture(t)
	for _, field := range []string{`"telemetry":true`, `"diagnostics":true`, `"members":[32]`, `"members":[]`} {
		t.Run(field, func(t *testing.T) {
			path := filepath.Join(root, "workflow.json")
			body := `{"schema_version":1,"name":"work","steps":[{"id":"state","kind":"run","recovery_mode":"disabled","suites":["` + filepath.Base(suite) + `"],"environment":"` + filepath.Base(environment) + `",` + field + `}]}`
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path}); err == nil {
				t.Fatal("removed workflow field was accepted")
			}
		})
	}
}

// full_only: false
func TestWorkflowPlanCombinesSuitesWithOneScheduleAndBudget(t *testing.T) {
	root, suite, _ := savedSelectionFixture(t)
	writeTelemetryConfigs(t, root)
	ctx, bootstrap, _ := copyPreparationAssemblyFixture(t, root)
	ctx = withRacePolicy(ctx, false)
	second := filepath.Join(root, "second.json")
	saveSelection(t, second, suiteFixture("history", []string{"state.historical-bytes-get-new-identities/members_32_three_generations"}))
	steps := []workflowStep{{ID: "unit", Kind: "unit", Packages: []string{"core/contract", "crypto/internal/custody"}}, {ID: "fuzz", Kind: "fuzz", Targets: []string{"crypto"}}}
	for _, provider := range []string{"gcp", "aws"} {
		_, settings := configurationFixture(t, provider)
		settings["credentials_file"] = "missing-credentials"
		env := provider + ".json"
		saveSelection(t, filepath.Join(root, env), environmentFor(settings))
		allowance := limits{Requests: 200, BodyBytes: 4096, Objects: 20, ObjectBytes: 4096, GeneratorCreates: 20, GeneratorRetires: 20, ElapsedSeconds: 60, CleanupRequests: 200, CleanupBytes: 4096, CleanupSeconds: 60}
		enabled := provider == "gcp"
		repetitions := 1
		if provider == "aws" {
			allowance.Requests = 400
			repetitions = 2
		}
		saveSelection(t, filepath.Join(root, provider+"-limits.json"), allowance)
		steps = append(steps, workflowStep{ID: provider, Kind: "run", RecoveryMode: "disabled", Suites: []string{filepath.Base(suite), "second.json"}, Environment: env, Limits: provider + "-limits.json", Repetitions: &repetitions, TelemetryConfig: map[bool]string{true: "local.json", false: "noop.json"}[enabled]})
	}
	path := filepath.Join(root, "workflow.json")
	saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "work", Steps: steps})
	var output bytes.Buffer
	if err := runCommand(ctx, root, bootstrap, []string{"plan", "--workflow", path}, &output); err != nil {
		t.Fatal(err)
	}
	var preview workflowPreview
	if err := json.Unmarshal(output.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Kind != "selection_preview" || len(preview.Unresolved) != 4 || len(preview.Steps) != 4 || !slices.Equal(preview.Steps[0].Packages, steps[0].Packages) || !slices.Equal(preview.Steps[1].Targets, []string{"crypto"}) {
		t.Fatal("preview lost requested activities or claimed compiled scope", preview)
	}
	for index, step := range preview.Steps {
		if !step.Selected || !reflect.DeepEqual(step.workflowStep, steps[index]) {
			t.Fatal("preview changed an input reference or execution request", step)
		}
	}
	if preview.Steps[2].LimitsConfiguration == nil || preview.Steps[2].LimitsConfiguration.Requests != 200 || preview.Steps[3].LimitsConfiguration == nil || preview.Steps[3].LimitsConfiguration.Requests != 400 {
		t.Fatal("preview lost explicit finite allowance inputs", preview)
	}
	resolved, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.Steps) != 4 || len(resolved.Steps[0].Packages) != 2 || resolved.Steps[1].FuzzSeconds != 600 {
		t.Fatal("resolved workflow activities were lost")
	}
	gcp, aws := resolved.Steps[2], resolved.Steps[3]
	if gcp.Run == nil || aws.Run == nil || gcp.Limits == nil || aws.Limits == nil || len(gcp.Run.Suites) != 2 || len(gcp.Run.Schedule.Entries) != 2 || len(aws.Run.Schedule.Entries) != 4 || gcp.Limits.Requests != 200 || aws.Limits.Requests != 400 || len(gcp.Run.Preparation) != 2 {
		t.Fatal("resolved provider settings, schedule or shared allowance changed")
	}
	if !reflect.DeepEqual(gcp.request.Schedule, gcp.Run.Schedule) || gcp.request.Allowance.Requests != 200 || !reflect.DeepEqual(aws.request.Schedule, aws.Run.Schedule) || aws.request.Allowance.Requests != 400 {
		t.Fatal("execution request differs from its resolved scope or budget")
	}
	var public bytes.Buffer
	if err := json.NewEncoder(&public).Encode(resolved); err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{root, "credentials_file", "missing-credentials", "public_key_pem"} {
		if strings.Contains(public.String(), private) {
			t.Fatal("resolved public metadata exposes private configuration")
		}
	}
	for _, directory := range []string{"tests/live/runs", "tests/hermetic/runs", "tests/workflows/runs", "tests/qualification"} {
		if _, err := os.Stat(filepath.Join(root, directory)); !os.IsNotExist(err) {
			t.Fatal("planning created execution state", directory, err)
		}
	}
}

// full_only: false
func TestWorkflowRejectsInvalidInputsBeforeExecution(t *testing.T) {
	for _, condition := range []string{"empty", "duplicate-id", "unknown-kind", "wrong-fields", "missing-mode", "unknown-mode", "non-run-mode", "run-race", "non-run-race", "non-component-profile", "additional-provider-on-hermetic", "additional-provider-on-unit", "unknown-additional-provider", "empty-additional-provider", "unknown-target", "duplicate-target", "empty-targets", "empty-packages", "zero-repetitions", "negative-repetitions", "unknown-package", "unknown-step", "duplicate-scenario", "unknown-field"} {
		t.Run(condition, func(t *testing.T) {
			root, suite, env := savedSelectionFixture(t)
			writeWorkflowUnitPackages(t, root)
			file := workflowFile{SchemaVersion: 1, Name: "work", Steps: []workflowStep{{ID: "unit", Kind: "unit", Packages: []string{"core/contract"}}, {ID: "state", Kind: "run", RecoveryMode: "both", Suites: []string{suite}, Environment: env}}}
			selected := ""
			switch condition {
			case "empty":
				file.Steps = nil
			case "duplicate-id":
				file.Steps[1].ID = "unit"
			case "unknown-kind":
				file.Steps[1].Kind = "shell"
			case "wrong-fields":
				file.Steps[0].Suites = []string{suite}
			case "missing-mode":
				file.Steps[1].RecoveryMode = ""
			case "unknown-mode":
				file.Steps[1].RecoveryMode = "auto"
			case "non-run-mode":
				file.Steps[0].RecoveryMode = "both"
			case "non-component-profile":
				file.Steps[1].Profile = "dev"
			case "additional-provider-on-hermetic":
				file.Steps[1].AdditionalProviders = map[string]string{"cloudflare": "missing.json"}
			case "additional-provider-on-unit":
				file.Steps[0].AdditionalProviders = map[string]string{"cloudflare": "missing.json"}
			case "unknown-additional-provider":
				file.Steps[1].AdditionalProviders = map[string]string{"unknown": "missing.json"}
			case "empty-additional-provider":
				file.Steps[1].AdditionalProviders = map[string]string{"cloudflare": ""}
			case "unknown-target":
				file.Steps[0] = workflowStep{ID: "fuzz", Kind: "fuzz", Targets: []string{"absent"}}
			case "duplicate-target":
				file.Steps[0] = workflowStep{ID: "fuzz", Kind: "fuzz", Targets: []string{"format", "format"}}
			case "empty-targets":
				file.Steps[0] = workflowStep{ID: "fuzz", Kind: "fuzz", Targets: []string{"format"}}
			case "zero-repetitions", "negative-repetitions":
				repetitions := 0
				if condition == "negative-repetitions" {
					repetitions = -1
				}
				file.Steps[1].Repetitions = &repetitions
			case "unknown-package":
				file.Steps[0].Packages = []string{"other/module"}
			case "unknown-step":
				selected = "absent"
			case "duplicate-scenario":
				other := filepath.Join(root, "other.json")
				saveSelection(t, other, suiteFixture("other", []string{"state.single-value-update-preserves-other-values/members_32"}))
				file.Steps[1].Suites = append(file.Steps[1].Suites, other)
			}
			path := filepath.Join(root, "workflow.json")
			saveSelection(t, path, file)
			if condition == "run-race" || condition == "non-run-race" || condition == "unknown-field" || condition == "empty-packages" || condition == "empty-targets" {
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				switch condition {
				case "run-race":
					body = bytes.Replace(body, []byte(`"id":"state"`), []byte(`"id":"state","race":true`), 1)
				case "non-run-race":
					body = bytes.Replace(body, []byte(`"id":"unit"`), []byte(`"id":"unit","race":true`), 1)
				case "unknown-field":
					body = bytes.Replace(body, []byte(`"name":"work"`), []byte(`"name":"work","retry":5`), 1)
				case "empty-packages":
					body = bytes.Replace(body, []byte(`"packages":["core/contract"]`), []byte(`"packages":[]`), 1)
				case "empty-targets":
					body = bytes.Replace(body, []byte(`"targets":["format"]`), []byte(`"targets":[]`), 1)
				}
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: selected}); err == nil {
				t.Fatal("invalid workflow resolved")
			}
			args := []string{"run", "--workflow", path}
			if selected != "" {
				args = append(args, "--step", selected)
			}
			if err := runCommand(context.Background(), root, "must-not-build", args, &bytes.Buffer{}); err == nil {
				t.Fatal("invalid workflow accepted")
			}
			if _, err := os.Stat(filepath.Join(root, "tests")); !os.IsNotExist(err) {
				t.Fatal("invalid workflow caused effects")
			}
		})
	}
}

func writeWorkflowUnitPackages(t *testing.T, root string) {
	t.Helper()
	for _, module := range []string{"core", "crypto"} {
		writeLocalGoFixture(t, root, module+"/go.mod", "module "+modulePrefix+module+"\n\ngo 1.27.0\n")
	}
	for _, path := range []string{"core/contract", "crypto/internal/custody"} {
		writeLocalGoFixture(t, root, path+"/fixture.go", "package fixture\n")
	}
}

// full_only: false
func TestWorkflowRejectsUnmatchedUnitPackagesBeforeExecution(t *testing.T) {
	for _, condition := range []string{"missing", "empty-pattern", "mixed-patterns"} {
		t.Run(condition, func(t *testing.T) {
			root := workflowExecutionFixture(t)
			writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePrefix+"telemetry\n\ngo 1.27.0\n")
			writeLocalGoFixture(t, root, "telemetry/valid/fixture.go", "package fixture\nfunc init() { panic(\"package discovery executed code\") }\n")
			writeLocalGoFixture(t, root, "telemetry/empty/sentinel", "no Go package\n")
			packages := []string{"telemetry/missing"}
			if condition == "empty-pattern" {
				packages = []string{"telemetry/empty/..."}
			}
			if condition == "mixed-patterns" {
				packages = []string{"telemetry/valid", "telemetry/empty/..."}
			}
			path := filepath.Join(root, "workflow.json")
			saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "work", Steps: []workflowStep{
				{ID: "lint", Kind: "lint"},
				{ID: "unit", Kind: "unit", Packages: packages},
			}})
			var previewOutput bytes.Buffer
			if err := runCommand(t.Context(), root, "must-not-build", []string{"plan", "--workflow", path}, &previewOutput); err != nil {
				t.Fatal("preview tried to resolve actual package existence", err)
			}
			var preview workflowPreview
			if json.Unmarshal(previewOutput.Bytes(), &preview) != nil || preview.Kind != "selection_preview" || len(preview.Unresolved) != 4 || len(preview.Steps) != 2 || !slices.Equal(preview.Steps[1].Packages, packages) {
				t.Fatal("preview lost the unresolved literal package request", previewOutput.String())
			}
			var refused bytes.Buffer
			if err := runCommand(t.Context(), root, "must-not-build", []string{"run", "--workflow", path}, &refused); err == nil || !strings.Contains(err.Error(), "step unit:") {
				t.Fatalf("run did not reject the later unit before activities: output=%q err=%v", refused.String(), err)
			}
			if refused.String() != "" && refused.String() != "Source observation incomplete; prepared builds remain in use\n" {
				t.Fatal("unmatched workflow selection emitted activity output", refused.String())
			}
			var output bytes.Buffer
			err := runCommand(context.Background(), root, "must-not-build", append([]string{"unit"}, packages...), &output)
			var preparation *checkFailure
			if err == nil || !strings.Contains(err.Error(), "matches no packages") && (!errors.As(err, &preparation) || preparation.phase != "preparation" || preparation.Unwrap() == nil) {
				t.Fatalf("direct unit command did not reject the selection before execution: output=%q err=%v", output.String(), err)
			}
			var failure *toolFailure
			if errors.As(err, &failure) {
				if failure.operation != "go list" || !failure.process.Started || !failure.process.Joined || failure.process.Status != "process_failed" || len(bytes.TrimSpace(failure.stderr)) == 0 || !bytes.Contains(output.Bytes(), bytes.TrimSpace(failure.stderr)) || output.Len() > 1<<20 {
					t.Fatalf("unit membership failure lost its bounded diagnostic or positive join: output=%q err=%v", output.String(), err)
				}
			} else if output.String() != "" && output.String() != "Source observation incomplete; prepared builds remain in use\n" {
				t.Errorf("semantic selection refusal produced tool diagnostics: %q", output.String())
			}
			if _, err := os.Stat(filepath.Join(root, "tests/workflows/runs")); !os.IsNotExist(err) {
				t.Fatal("invalid package selection started the workflow")
			}
		})
	}
	t.Run("private-go-diagnostic", func(t *testing.T) {
		root := workflowExecutionFixture(t)
		writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePrefix+"telemetry\n\ngo 1.27.0\n")
		realGo, err := exec.LookPath("go")
		if err != nil {
			t.Fatal(err)
		}
		realGo, err = filepath.EvalSymlinks(realGo)
		if err != nil {
			t.Fatal(err)
		}
		bin := t.TempDir()
		trace := filepath.Join(bin, "calls")
		t.Setenv("ENKV_ADMISSION_TRACE", trace)
		script := `#!/bin/sh
set -eu
printf '%s\000' "$@" '' >> "$ENKV_ADMISSION_TRACE"
if [ "$#" -eq 4 ] && [ "$1" = mod ] && [ "$2" = edit ] && [ "$3" = -json ]; then
 case "$4" in -modfile=?*) exec ` + shellQuote(realGo) + ` "$@" ;; esac
fi
if [ "$1" = list ]; then
 printf '%s\n' 'SYNTHETIC_ADMISSION_SECRET /private/controlled-admission-source' >&2
 exit 8
fi
printf '%s\n' 'unexpected Go command in admission diagnostics fixture' >&2
exit 97
`
		if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		path := filepath.Join(root, "workflow.json")
		saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "admission", Steps: []workflowStep{{ID: "unit", Kind: "unit", Packages: []string{"telemetry"}}}})
		var preview bytes.Buffer
		if err := runCommand(t.Context(), root, "must-not-build", []string{"plan", "--workflow", path}, &preview); err != nil {
			t.Fatal("preview performed package membership discovery", err)
		}
		if _, err := os.Stat(trace); !os.IsNotExist(err) {
			t.Fatal("preview dispatched a Go command", err)
		}
		for _, args := range [][]string{{"unit", "telemetry"}, {"run", "--workflow", path}} {
			if err := os.WriteFile(trace, nil, 0600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err := runCommand(t.Context(), root, "must-not-build", args, &output)
			var exit *exec.ExitError
			var failure *toolFailure
			if err == nil || !errors.As(err, &exit) || exit.ExitCode() != 8 || !errors.As(err, &failure) || failure.operation != "go list" || !failure.process.Started || !failure.process.Joined || failure.process.Status != "process_failed" {
				t.Fatal("admission failure lost its original cause or positive join", args, err)
			}
			calls, traceErr := os.ReadFile(trace)
			commands := strings.Split(strings.TrimSuffix(string(calls), "\x00\x00"), "\x00\x00")
			if traceErr != nil || !strings.HasSuffix(string(calls), "\x00\x00") || len(commands) != 2 {
				t.Fatalf("rejected admission did not run one metadata parser and membership discovery: args=%v calls=%q err=%v", args, calls, traceErr)
			}
			metadata, membership := strings.Split(commands[0], "\x00"), strings.Split(commands[1], "\x00")
			if len(metadata) != 4 || !slices.Equal(metadata[:3], []string{"mod", "edit", "-json"}) || !strings.HasPrefix(metadata[3], "-modfile=") {
				t.Fatalf("admission module parser arguments changed: %q", metadata)
			}
			modfile := strings.TrimPrefix(metadata[3], "-modfile=")
			if !filepath.IsAbs(modfile) || filepath.Base(modfile) != "local.mod" || len(membership) != 7 || membership[0] != "list" || !slices.Contains([]string{"-p=1", "-p=2", "-p=3", "-p=4"}, membership[1]) || !slices.Equal(membership[2:], []string{metadata[3], "-mod=readonly", "-find", "-json=Match", "./..."}) {
				t.Fatalf("rejected admission changed its private module input or membership discovery: args=%v calls=%q", args, calls)
			}
			if args[0] == "unit" {
				if !strings.Contains(output.String(), "SYNTHETIC_ADMISSION_SECRET /private/controlled-admission-source") || output.Len() > 1<<20 {
					t.Errorf("bare unit lost bounded hermetic admission diagnostics: %q", output.String())
				}
			} else if output.String() != "" && output.String() != "Source observation incomplete; prepared builds remain in use\n" {
				t.Errorf("shared workflow admission exposed private compiler output: args=%v output=%q", args, output.String())
			}
			if strings.Contains(err.Error(), "SYNTHETIC_ADMISSION_SECRET") || strings.Contains(err.Error(), "/private/controlled-admission-source") {
				t.Error("shared package admission exposed private compiler output", args)
			}
		}
		if _, err := os.Stat(filepath.Join(root, "tests/workflows/runs")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("rejected package admission acquired an execution owner", err)
		}
	})
}

// full_only: false
func TestUnitPackageValidationAcceptsExactAndRecursiveMatches(t *testing.T) {
	root := t.TempDir()
	writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePrefix+"telemetry\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "telemetry/valid/fixture.go", "package fixture\nfunc init() { panic(\"package discovery executed code\") }\n")
	for _, packages := range [][]string{{"telemetry"}, {"telemetry/valid", "telemetry/valid/..."}} {
		selection, err := resolveUnitPackages(packages)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateUnitPackages(context.Background(), root, selection); err != nil {
			t.Fatal("valid package selection refused", err)
		}
	}
}

// full_only: false
func TestWorkflowStepSelectionDoesNotLoadOtherEnvironments(t *testing.T) {
	root, suite, env := savedSelectionFixture(t)
	writeTelemetryConfigs(t, root)
	path := filepath.Join(root, "workflow.json")
	saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "work", Steps: []workflowStep{
		{ID: "state", Kind: "run", RecoveryMode: "both", Suites: []string{suite}, Environment: env, SmokePolicy: "first-selected-point", TelemetryConfig: "local.json"},
		{ID: "cloud", Kind: "run", RecoveryMode: "enabled", Suites: []string{suite}, Environment: "missing-environment.json", Limits: "missing-limits.json"},
		{ID: "other-unit", Kind: "unit", Packages: []string{"core/missing"}},
	}})
	plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path, SelectedStep: "state"})
	if err != nil || !plan.Steps[0].Selected || plan.Steps[1].Selected || plan.Steps[1].Run != nil {
		t.Fatal("unselected environment blocked focused work", err)
	}
	run := plan.Steps[0].Run
	if run == nil || len(run.Schedule.Selected) != 1 || len(run.Entries) != 1 || !run.Entries[0].Smoke || run.Entries[0].Members != 0 || run.Entries[0].Fixture.Members != 32 {
		t.Fatal("focused smoke selection changed", run)
	}
	if _, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path}); err == nil {
		t.Fatal("full workflow ignored missing environment")
	}
}

func workflowExecutionFixture(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initializeWorkflowExecutionFixture(t, root)
	return root
}

func initializeWorkflowExecutionFixture(t *testing.T, root string) {
	t.Helper()
	copyModuleInventoryFixture(t, root)
	publicSourceFixtureOwners(t, root)
	initializePublicSourceGitFixture(t, root)
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("tests/workflows/runs/\ntests/hermetic/runs/\ntests/live/runs/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "--quiet"}, {"add", ".gitignore"}, {"-c", "user.name=Local Test", "-c", "user.email=local@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		if body, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture: %v\n%s", err, body)
		}
	}
}

// full_only: false
func TestBareOrdinaryCommandsExposeHermeticFailureDetails(t *testing.T) {
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		command, phase string
		refuseOutput   bool
	}{
		{"unit", "membership", false},
		{"unit", "env", false},
		{"unit", "inventory", false},
		{"runner-tests", "env", false},
		{"runner-tests", "inventory", false},
		{"runner-tests", "env", true},
	} {
		name := row.command + "/" + row.phase
		if row.refuseOutput {
			name += "/refused-output"
		}
		t.Run(name, func(t *testing.T) {
			root, bootstrap, _ := overlayFixture(t)
			module, err := os.ReadFile(filepath.Join(root, "core/go.mod"))
			if err != nil {
				t.Fatal(err)
			}
			writeLocalGoFixture(t, root, "tests/hermetic/hermetic.mod", string(module))
			initializeWorkflowExecutionFixture(t, root)
			bin := t.TempDir()
			fakeGo := `#!/bin/sh
set -eu
fail() {
 echo 'hermetic compiler assertion expected 7 observed 9' >&2
 exit 7
}
case "$1" in
 version) echo 'go version go1.27.0 local'; exit 0 ;;
 mod)
  if [ "$#" -eq 4 ] && [ "$2" = edit ] && [ "$3" = -json ]; then
   case "$4" in -modfile=?*) exec ` + shellQuote(realGo) + ` "$@" ;; esac
  fi
  ;;
 env)
  if [ "$ENKV_BARE_FAILURE_PHASE" = env ]; then fail; fi
  exec ` + shellQuote(realGo) + ` "$@"
  ;;
 list)
  case "$*" in
   *-json=Match*)
    if [ "$ENKV_BARE_FAILURE_PHASE" = membership ]; then fail; fi
    echo '{"Match":["./contract"]}'
    exit 0
    ;;
  esac
  if [ "$ENKV_BARE_FAILURE_PHASE" = inventory ]; then fail; fi
  ;;
esac
echo 'unexpected Go command in bare diagnostics fixture' >&2
exit 97
`
			if err := os.WriteFile(filepath.Join(bin, "go"), []byte(fakeGo), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("ENKV_BARE_FAILURE_PHASE", row.phase)
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			args := []string{row.command}
			if row.command == "unit" {
				args = append(args, "core/contract")
			}
			var output bytes.Buffer
			var writer io.Writer = &output
			outputErr := errors.New("controlled bare diagnostic output refusal")
			if row.refuseOutput {
				writer = assemblyGroupFailureOutput{cause: outputErr}
			}
			ctx := withResourceLocks(t.Context(), resourceLockFixture(t))
			commandErr := runCommand(ctx, root, bootstrap, args, writer)
			var failure *toolFailure
			var exit *exec.ExitError
			operation := "go list"
			if row.phase == "env" {
				operation = "go env"
			}
			if !errors.As(commandErr, &failure) || failure.operation != operation || !failure.process.Started || !failure.process.Joined || failure.process.Status != "process_failed" || !errors.As(commandErr, &exit) || exit.ExitCode() != 7 {
				t.Fatal("controlled Go failure lost its operation, exit or positive join", commandErr)
			}
			if row.refuseOutput {
				if !errors.Is(commandErr, outputErr) {
					t.Error("diagnostic output refusal was not propagated", commandErr)
				}
			} else {
				commands := 1
				if row.command == "runner-tests" && row.phase == "inventory" {
					commands = 2
				}
				if strings.Count(output.String(), "Operation: "+operation+"\n") != commands || strings.Count(output.String(), "Stderr (truncated: false):\nhermetic compiler assertion expected 7 observed 9\n") != commands {
					t.Error("terminal lost or repeated a failing command body", commandErr, output.String())
				}
			}
			if _, err := os.Stat(filepath.Join(root, "tests/workflows/runs")); !os.IsNotExist(err) {
				t.Error("ordinary failure created old result state", err)
			}
		})
	}
}

// full_only: false
func TestWorkflowCurrentResultsKeepOrderAndFailure(t *testing.T) {
	for _, condition := range []string{"passed", "failed", "cancelled", "selected"} {
		t.Run(condition, func(t *testing.T) {
			root := workflowExecutionFixture(t)
			plan := workflowPlan{Execution: defaultExecutionPolicy(), SchemaVersion: 1, Name: "work", Steps: []resolvedWorkflowStep{{ID: "first", Kind: "unit", Selected: true}, {ID: "second", Kind: "unit", Selected: true}}}
			if condition == "selected" {
				plan.Steps[0].Selected = false
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var output bytes.Buffer
			var calls []string
			cause := errors.New("controlled private failure")
			result, err := executeWorkflow(ctx, root, plan, &output, nil, nil, func(_ context.Context, step resolvedWorkflowStep, out io.Writer, _ string) (workflowStepExecution, error) {
				calls = append(calls, step.ID)
				if _, err := io.WriteString(out, "current step output\n"); err != nil {
					return workflowStepExecution{}, err
				}
				if condition == "failed" {
					return workflowStepExecution{}, cause
				}
				if condition == "cancelled" {
					cancel()
					return workflowStepExecution{}, context.Canceled
				}
				return workflowStepExecution{}, nil
			})
			wantPass := condition == "passed" || condition == "selected"
			if (err == nil) != wantPass || (result.Outcome == "passed") != wantPass || result.FinishedAt == nil || len(result.Steps) != 2 {
				t.Fatal("current workflow completion differs", result.Outcome, err)
			}
			if condition == "failed" && !errors.Is(err, cause) {
				t.Error("current outcome lost its cause")
			}
			want := []string{"first"}
			if condition == "passed" {
				want = append(want, "second")
			}
			if condition == "selected" {
				want = []string{"second"}
			}
			if !slices.Equal(calls, want) {
				t.Error("wrong current step order", calls)
			}
			if !wantPass && result.Steps[1].Outcome != "not_run" {
				t.Error("unexecuted step acquired a result")
			}
			if condition == "selected" && result.Steps[0].Outcome != "not_selected" {
				t.Error("selection outcome missing")
			}
			if _, err := os.Stat(filepath.Join(root, "tests/workflows/runs")); !os.IsNotExist(err) {
				t.Error("current result was persisted", err)
			}
		})
	}
}

// full_only: false
func TestWorkflowPanicRetainsUncertainCurrentFiles(t *testing.T) {
	for _, panicStep := range []string{"first", "second"} {
		t.Run(panicStep, func(t *testing.T) {
			root := workflowExecutionFixture(t)
			plan := workflowPlan{Execution: defaultExecutionPolicy(), SchemaVersion: 1, Name: "panic", Steps: []resolvedWorkflowStep{{ID: "first", Kind: "unit", Selected: true}, {ID: "second", Kind: "unit", Selected: true}, {ID: "later", Kind: "unit", Selected: true}}}
			var output bytes.Buffer
			var scratch string
			var calls []string
			cause := errors.New("controlled panic")
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				_, _ = executeWorkflow(t.Context(), root, plan, &output, nil, nil, func(_ context.Context, step resolvedWorkflowStep, _ io.Writer, directory string) (workflowStepExecution, error) {
					scratch = directory
					calls = append(calls, step.ID)
					if step.ID == panicStep {
						panic(cause)
					}
					return workflowStepExecution{}, nil
				})
			}()
			if recovered != cause {
				t.Fatal("original panic was lost", recovered)
			}
			if slices.Contains(calls, "later") {
				t.Error("panic admitted later work")
			}
			if _, err := os.Stat(scratch); err != nil {
				t.Error("uncertain consumers lost scratch", err)
			}
			if !strings.Contains(output.String(), "Workflow failed") || strings.Contains(output.String(), cause.Error()) {
				t.Error("panic terminal outcome differs", output.String())
			}
		})
	}
}

// full_only: false
func TestWorkflowProtectsCurrentFixturesUntilConsumersFinish(t *testing.T) {
	root := workflowExecutionFixture(t)
	plan := workflowPlan{Execution: defaultExecutionPolicy(), SchemaVersion: 1, Name: "fixtures", Steps: []resolvedWorkflowStep{{ID: "first", Kind: "unit", Selected: true}, {ID: "second", Kind: "unit", Selected: true}}}
	var directory string
	var output bytes.Buffer
	result, err := executeWorkflow(t.Context(), root, plan, &output, nil, nil, func(ctx context.Context, step resolvedWorkflowStep, _ io.Writer, scratch string) (workflowStepExecution, error) {
		fixtures, ok := ctx.Value(protectedFixtureContextKey{}).(string)
		if !ok || fixtures != filepath.Join(scratch, "private/protected-fixtures") {
			t.Fatal("current fixture route missing")
		}
		if directory != "" && directory != scratch {
			t.Fatal("current fixture owner changed between steps")
		}
		directory = scratch
		path := filepath.Join(fixtures, "sentinel")
		if step.ID == "first" {
			if err := os.WriteFile(path, []byte("current fixture"), 0600); err != nil {
				t.Fatal(err)
			}
		} else if body, err := os.ReadFile(path); err != nil || string(body) != "current fixture" {
			t.Fatal("fixture disappeared before its last consumer", err)
		}
		return workflowStepExecution{}, nil
	})
	if err != nil || result.Outcome != "passed" {
		t.Fatal("current fixture workflow failed", err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Error("joined fixture owner retained scratch", err)
	}
}

// full_only: false
func TestUnitPackageSelectionStaysInsideModules(t *testing.T) {
	all, err := resolveUnitPackages(nil)
	if err != nil || len(all) != len(moduleRoots) {
		t.Fatal("omitted unit selection did not select all modules", all, err)
	}
	if _, err := resolveUnitPackages([]string{}); err == nil {
		t.Fatal("empty unit selection accepted")
	}
	selected, err := resolveUnitPackages([]string{"core/contract", "crypto/internal/custody", "providers/gcp"})
	if err != nil || !reflect.DeepEqual(selected, map[string][]string{"core": {"./contract"}, "crypto": {"./internal/custody"}, "providers/gcp": {"./..."}}) {
		t.Fatal("unit scope differs", selected, err)
	}
	for _, path := range []string{"../core", "/core", "core/../crypto", "-run=TestFoo", "external/module", "core/*", "core/./contract"} {
		if _, err := resolveUnitPackages([]string{path}); err == nil {
			t.Errorf("accepted %q", path)
		}
	}
	if _, err := resolveUnitPackages([]string{"core", "core/..."}); err == nil {
		t.Fatal("duplicate package scope accepted")
	}
}

// full_only: false
func TestSavedWorkflowTelemetryUsesCommonLocalPolicy(t *testing.T) {
	for _, name := range []string{"check", "dev", "canonical", "diagnostics", "smoke", "live", "publication-live", "github-publication-live"} {
		t.Run(name, func(t *testing.T) {
			path := savedWorkflowPath(t, name)
			root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
			var file workflowFile
			if err := readSelectionFile(path, &file); err != nil {
				t.Fatal(err)
			}
			runs := 0
			for _, step := range file.Steps {
				if step.Kind != "run" {
					continue
				}
				runs++
				t.Run(step.ID, func(t *testing.T) {
					configuration := step.TelemetryConfig
					if configuration != "" && !filepath.IsAbs(configuration) {
						configuration = filepath.Join(filepath.Dir(path), configuration)
					}
					// Resolve only the public telemetry file, without opening
					// the workflow's cloud environment or starting exporters.
					settings, err := observability.Load(configuration, observability.Options{LogLevel: step.LogLevel})
					if err != nil {
						t.Fatal("saved telemetry configuration did not resolve", err)
					}
					if settings.LogLevel != observability.Warn {
						t.Error("saved workflow changed the common WARN collection threshold")
					}
					if configuration != filepath.Join(root, "tests/telemetry/local.json") {
						t.Error("instrumented workflow must select the one maintained local configuration", step.TelemetryConfig)
					}
					if !slices.Equal(settings.LogExporters, []string{"local"}) || !slices.Equal(settings.MetricExporters, []string{"local"}) || !slices.Equal(settings.TraceExporters, []string{"local"}) || settings.TraceSampleRatio != 1 {
						t.Errorf("saved workflow must collect all three signals with sample ratio 1: logs=%v metrics=%v traces=%v sample_ratio=%v", settings.LogExporters, settings.MetricExporters, settings.TraceExporters, settings.TraceSampleRatio)
					}
					if settings.Console || !reflect.DeepEqual(settings.ActiveExporters, map[string]observability.Exporter{"local": {Type: "otlp_file", Directory: "telemetry"}}) {
						t.Error("saved workflow must use the common local file route")
					}
				})
			}
			if runs == 0 {
				t.Fatal("saved workflow has no run steps to check")
			}
		})
	}
}

// full_only: false
func TestWorkflowSelectedTelemetryConfigAndLevel(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	t.Setenv("ENKV_LOG_LEVEL", "debug")
	root, suite, env := savedSelectionFixture(t)
	writeTelemetryConfigs(t, root)
	path := filepath.Join(root, "workflow.json")
	file := workflowFile{SchemaVersion: 1, Name: "telemetry", Steps: []workflowStep{{ID: "state", Kind: "run", RecoveryMode: "both", Suites: []string{suite}, Environment: env, TelemetryConfig: "local.json", LogLevel: "error"}}}
	saveSelection(t, path, file)
	plan, err := resolveWorkflow(context.Background(), root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if step.request.telemetrySettings == nil || len(step.request.telemetrySettings.MetricExporters) != 1 || step.request.telemetrySettings.LogLevel != 17 {
			t.Fatal("workflow configuration was not resolved once", step.ID)
		}
		if step.Run == nil {
			t.Fatal("missing planned run")
		}
	}
	file.Steps[0].TelemetryConfig = "noop.json"
	file.Steps[0].LogLevel = ""
	saveSelection(t, path, file)
	plan, err = resolveWorkflow(context.Background(), root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if len(step.request.telemetrySettings.MetricExporters) != 0 || step.request.telemetrySettings.LogLevel != 5 {
			t.Fatal("noop or environment level ignored")
		}
	}
}

// full_only: false
func TestRunTelemetrySettingsDoNotChangeParentEnvironment(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	t.Setenv("ENKV_LOG_LEVEL", "")
	root, suite, env := savedSelectionFixture(t)
	writeTelemetryConfigs(t, root)
	for _, name := range []string{"noop.json", "local.json"} {
		request, err := resolveSavedRun([]string{suite}, env, "", "", "both", filepath.Join(root, name), "", "", 1, true)
		if err != nil {
			t.Fatal(err)
		}
		state, err := newRunState(root, request, records.Source{}, "test")
		if err != nil || state.record.Telemetry.Enabled != (name == "local.json") {
			t.Fatal("run ignored selected routes", err)
		}
		if state.telemetrySettings == nil || len(state.telemetrySettings.MetricExporters) != len(request.telemetrySettings.MetricExporters) {
			t.Fatal("settings handoff differs")
		}
		if os.Getenv("ENKV_TELEMETRY") != "1" {
			t.Fatal("parent environment changed")
		}
	}
	t.Run("manual_default", func(t *testing.T) {
		t.Setenv("ENKV_LOG_LEVEL", "fatal")
		state, err := newRunState(root, runRequest{Suite: "hermetic"}, records.Source{}, "test")
		if err != nil {
			t.Fatal(err)
		}
		if state.telemetrySettings.LogLevel != observability.Warn || !state.telemetrySettings.Console || len(state.telemetrySettings.ActiveExporters) != 0 {
			t.Fatal("manual run did not use no-config defaults")
		}
		body, err := json.Marshal(state.record)
		if err != nil {
			t.Fatal(err)
		}
		checkEffectiveTelemetryJSON(t, body, `{"configuration_source":"none","level_override_source":"none","log_level":13,"trace_sample_ratio":1,"logs":["console"],"metrics":[],"traces":[]}`)
	})
	t.Run("owned_settings_snapshot", func(t *testing.T) {
		request, err := parseRunRequest([]string{"plan", "--suite", suite, "--environment", env, "--telemetry-config", filepath.Join(root, "local.json"), "--log-level", "error"})
		if err != nil {
			t.Fatal(err)
		}
		request.telemetrySettings.LogLevel = observability.Warn
		request.telemetrySettings.Console = false
		request.telemetrySettings.LogExporters = []string{"local"}
		request.telemetrySettings.TraceExporters = []string{"local"}
		request.telemetrySettings.TraceSampleRatio = 0.5
		t.Setenv("ENKV_LOG_LEVEL", "fatal")
		state, err := newRunState(root, request, records.Source{}, "test")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(state.telemetrySettings, request.telemetrySettings) {
			t.Fatal("run did not clone its effective worker settings")
		}
		body, err := json.Marshal(state.record)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"configuration_source":"command","level_override_source":"command","log_level":13,"trace_sample_ratio":0.5,"logs":["file"],"metrics":["file"],"traces":["file"]}`
		checkEffectiveTelemetryJSON(t, body, want)
		request.effectiveTelemetry.Metrics[0] = "private-summary-mutation"
		request.effectiveTelemetry.ConfigurationSource = "workflow"
		request.telemetrySettings.TraceExporters[0] = "private-settings-mutation"
		body, err = json.Marshal(state.record)
		if err != nil {
			t.Fatal(err)
		}
		checkEffectiveTelemetryJSON(t, body, want)
		if !slices.Equal(state.telemetrySettings.TraceExporters, []string{"local"}) {
			t.Fatal("run retained an alias to mutable request settings")
		}
		cloned := state.record.EffectiveTelemetry.clone()
		*cloned.LogLevel = observability.Fatal
		*cloned.TraceSampleRatio = 0
		body, err = json.Marshal(state.record)
		if err != nil {
			t.Fatal(err)
		}
		checkEffectiveTelemetryJSON(t, body, want)
	})
}

// full_only: false
func TestWorkerEnvironmentDoesNotInheritDiagnostics(t *testing.T) {
	t.Setenv("ENKV_DIAGNOSTICS", "synthetic-secret")
	t.Setenv("GORACE", "halt_on_error=1 exitcode=0")
	raceValues := 0
	for _, variable := range workerEnvironment("invocation") {
		if strings.HasPrefix(variable, "ENKV_DIAGNOSTICS=") {
			t.Fatal("worker inherited ambient diagnostics selection")
		}
		if value, ok := strings.CutPrefix(variable, "GORACE="); ok {
			raceValues++
			if value != "" {
				t.Fatal("worker inherited ambient race settings")
			}
		}
	}
	if raceValues != 1 {
		t.Fatal("worker lacks one empty base race setting")
	}
}

func checkEffectiveTelemetryJSON(t *testing.T, document []byte, wantJSON string) {
	t.Helper()
	var public map[string]json.RawMessage
	if err := json.Unmarshal(document, &public); err != nil {
		t.Fatal("public telemetry document did not decode", err)
	}
	var got, want map[string]any
	if err := json.Unmarshal(public["effective_telemetry"], &got); err != nil {
		t.Error("public document lacks effective telemetry", err)
		return
	}
	if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
		t.Fatal("invalid expected telemetry facts", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("effective telemetry differs: got %s, want %s", public["effective_telemetry"], wantJSON)
	}
}

// full_only: false
func TestWorkflowCommandTelemetryOverridesUseInvocationPaths(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	for _, test := range []struct {
		name, environment, stepLevel string
		flags                        []string
		wantLevel                    observability.Severity
		wantService                  string
		wantMetrics                  int
		configuration                string
		wantSummary                  string
	}{
		{"workflow", "debug", "error", nil, observability.Error, "workflow", 1, "settings.json", `{"configuration_source":"workflow","level_override_source":"workflow","log_level":17,"trace_sample_ratio":1,"logs":["console"],"metrics":["file"],"traces":[]}`},
		{"command_file", "debug", "error", []string{"--telemetry-config=settings.json"}, observability.Error, "command", 0, "settings.json", `{"configuration_source":"command","level_override_source":"workflow","log_level":17,"trace_sample_ratio":1,"logs":["console"],"metrics":[],"traces":[]}`},
		{"command_level", "debug", "error", []string{"--log-level", "off"}, observability.Off, "workflow", 1, "settings.json", `{"configuration_source":"workflow","level_override_source":"command","log_level":0,"trace_sample_ratio":1,"logs":[],"metrics":["file"],"traces":[]}`},
		{"command_file_and_level", "invalid", "invalid", []string{"--telemetry-config", "settings.json", "--log-level=17"}, observability.Error, "command", 0, "settings.json", `{"configuration_source":"command","level_override_source":"command","log_level":17,"trace_sample_ratio":1,"logs":["console"],"metrics":[],"traces":[]}`},
		{"environment_level", "debug", "", nil, observability.Debug, "workflow", 1, "settings.json", `{"configuration_source":"workflow","level_override_source":"environment","log_level":5,"trace_sample_ratio":1,"logs":["console"],"metrics":["file"],"traces":[]}`},
		{"configuration_level", "", "", nil, observability.Info, "workflow", 1, "settings.json", `{"configuration_source":"workflow","level_override_source":"none","log_level":9,"trace_sample_ratio":1,"logs":["console"],"metrics":["file"],"traces":[]}`},
		{"no_configuration", "", "", nil, observability.Warn, "enkv", 0, "", `{"configuration_source":"none","level_override_source":"none","log_level":13,"trace_sample_ratio":1,"logs":["console"],"metrics":[],"traces":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("ENKV_LOG_LEVEL", test.environment)
			ctx, root, bootstrap := componentRepetitionAssemblyFixture(t)
			ctx = withRacePolicy(ctx, false)
			suite, environment := filepath.Join(root, "suite.json"), filepath.Join(root, "environment.json")
			saveSelection(t, suite, suiteFixture("smoke", []string{"state.single-value-update-preserves-other-values/members_32"}))
			saveSelection(t, environment, memoryEnvironment())
			entered := filepath.Join(t.TempDir(), "worker-entered")
			writeLocalGoFixture(t, root, "tests/hermetic/workflow_telemetry_plan_test.go", fmt.Sprintf(`package core
import (
 "os"
 "testing"
)
func init() {
 if os.Getenv("ENKV_TEST_INVOCATION") != "" {
  if err := os.WriteFile(%[1]q, []byte("entered"), 0600); err != nil { panic(err) }
 }
}
func failWorkflowTelemetryPlanWorker(t *testing.T) {
 t.Helper()
 if err := os.WriteFile(%[1]q, []byte("entered"), 0600); err != nil { t.Fatal(err) }
 t.Fatal("workflow telemetry planning must not execute a scenario worker")
}
// full_only: false
func TestHermeticRun(t *testing.T) { failWorkflowTelemetryPlanWorker(t) }
// full_only: false
func TestHermeticChild(t *testing.T) { failWorkflowTelemetryPlanWorker(t) }
`, entered))
			workflowDirectory, invocationDirectory := filepath.Join(root, "workflows"), filepath.Join(root, "invocation")
			for _, directory := range []string{workflowDirectory, invocationDirectory} {
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Chdir(invocationDirectory)
			for directory, body := range map[string]string{
				workflowDirectory:   `{"schema_version":1,"logs":{"level":"info"},"resource":{"attributes":{"service.name":"workflow","workflow.only":true}},"metrics":{"exporters":["local"]},"exporters":{"local":{"type":"otlp_file","directory":"telemetry"}}}`,
				invocationDirectory: `{"schema_version":1,"logs":{"level":"info"},"resource":{"attributes":{"service.name":"command"}}}`,
			} {
				if err := os.WriteFile(filepath.Join(directory, "settings.json"), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(workflowDirectory, "workflow.json")
			step := workflowStep{ID: "first", Kind: "run", RecoveryMode: "both", Suites: []string{suite}, Environment: environment, TelemetryConfig: test.configuration, LogLevel: test.stepLevel}
			other := step
			other.ID = "second"
			saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "work", Steps: []workflowStep{step, other}})
			args := append([]string{"plan", "--workflow=" + path}, test.flags...)
			var output bytes.Buffer
			if err := runCommand(ctx, root, bootstrap, args, &output); err != nil {
				t.Fatal("workflow command refused selected settings", err)
			}
			var preview workflowPreview
			if json.Unmarshal(output.Bytes(), &preview) != nil || preview.Kind != "selection_preview" || len(preview.Steps) != 2 || len(preview.Unresolved) != 4 || bytes.Contains(output.Bytes(), []byte("effective_telemetry")) {
				t.Fatal("workflow preview lost requests or claimed effective telemetry")
			}
			wantLevel := test.stepLevel
			if test.name == "command_level" {
				wantLevel = "off"
			} else if test.name == "command_file_and_level" {
				wantLevel = "17"
			}
			for _, selected := range preview.Steps {
				if !selected.Selected || selected.TelemetryConfig != test.configuration || selected.LogLevel != wantLevel || !slices.Equal(selected.Suites, []string{suite}) || selected.Environment != environment {
					t.Fatal("preview changed requested input paths or level override", selected)
				}
			}
			request, err := workflowArguments(args)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := resolveWorkflow(context.Background(), root, request)
			if err != nil || len(plan.Steps) != 2 {
				t.Fatal("workflow settings resolution differs", err)
			}
			for _, selected := range plan.Steps {
				settings := selected.request.telemetrySettings
				if !selected.Selected || settings == nil || settings.LogLevel != test.wantLevel || settings.Resource["service.name"] != test.wantService || len(settings.MetricExporters) != test.wantMetrics {
					t.Fatal("selected step did not receive the effective settings", selected.ID, settings)
				}
				if _, retained := settings.Resource["workflow.only"]; retained != (test.wantService == "workflow") || len(settings.ActiveExporters) != test.wantMetrics || len(settings.LogExporters) != 0 || len(settings.TraceExporters) != 0 {
					t.Fatal("configuration replacement merged fields or enabled other routes", selected.ID)
				}
				authority, err := json.Marshal(selected)
				if err != nil || bytes.Contains(authority, []byte("effective_telemetry")) {
					t.Fatal("display metadata entered resolved workflow selection", err)
				}
			}
			prepared := &preparedWorkflow{plan: plan}
			var retained workflowResult
			if err := prepared.retainWorkflowPreparation(&retained, nil, io.Discard); err != nil {
				t.Fatal(err)
			}
			var public bytes.Buffer
			if err := json.NewEncoder(&public).Encode(retained); err != nil {
				t.Fatal(err)
			}
			var document struct {
				Steps []json.RawMessage `json:"steps"`
			}
			if err := json.Unmarshal(public.Bytes(), &document); err != nil || len(document.Steps) != 2 {
				t.Fatal("resolved public metadata lost step documents", err)
			}
			for _, step := range document.Steps {
				checkEffectiveTelemetryJSON(t, step, test.wantSummary)
			}
			if strings.Contains(public.String(), root) {
				t.Fatal("resolved workflow metadata exposed a configuration path")
			}
			for _, directory := range []string{"tests/live/runs", "tests/hermetic/runs", "tests/workflows/runs", "tests/qualification"} {
				if _, err := os.Stat(filepath.Join(root, directory)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("planning created execution evidence", directory, err)
				}
			}
			if _, err := os.Stat(filepath.Join(invocationDirectory, "telemetry")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("planning activated a telemetry output")
			}
			if _, err := os.Stat(entered); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("workflow telemetry planning executed a scenario worker", err)
			}
		})
	}
}

// full_only: false
func TestWorkflowTelemetrySummaryStaysOutsideSelectionAuthority(t *testing.T) {
	t.Setenv("ENKV_LOG_LEVEL", "")
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	root := workflowExecutionFixture(t)
	_, suite, environment := savedSelectionFixture(t)
	writeTelemetryConfigs(t, root)
	path := filepath.Join(root, "workflow.json")
	saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "telemetry", Steps: []workflowStep{{ID: "state", Kind: "run", RecoveryMode: "both", Suites: []string{suite}, Environment: environment, TelemetryConfig: "local.json"}}})
	plan, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	result, err := executeWorkflow(t.Context(), root, plan, &output, nil, nil, func(context.Context, resolvedWorkflowStep, io.Writer, string) (workflowStepExecution, error) {
		return workflowStepExecution{}, nil
	})
	if err != nil || len(result.Steps) != 1 {
		t.Fatal("current telemetry result missing", err)
	}
	body, err := json.Marshal(result.Steps[0])
	if err != nil {
		t.Fatal(err)
	}
	checkEffectiveTelemetryJSON(t, body, `{"configuration_source":"workflow","level_override_source":"none","log_level":13,"trace_sample_ratio":1,"logs":["console"],"metrics":["file"],"traces":[]}`)
	var step map[string]json.RawMessage
	if err := json.Unmarshal(body, &step); err != nil || bytes.Contains(step["run"], []byte("effective_telemetry")) {
		t.Fatal("display metadata entered resolved identity", err)
	}
}

// full_only: false
func TestWorkflowCommandReplacesUnreadableOrInvalidTelemetryReference(t *testing.T) {
	t.Setenv("ENKV_LOG_LEVEL", "")
	for _, condition := range []string{"missing", "directory", "invalid"} {
		t.Run(condition, func(t *testing.T) {
			root, suite, environment := savedSelectionFixture(t)
			ctx, bootstrap, _ := copyPreparationAssemblyFixture(t, root)
			ctx = withRacePolicy(ctx, false)
			admissions := 0
			ctx = context.WithValue(ctx, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, _ rootAdmission) (context.Context, error) {
				admissions++
				return ctx, errors.New("invalid telemetry requested execution admission")
			}))
			writeTelemetryConfigs(t, root)
			reference := filepath.Join(root, "replaced.json")
			switch condition {
			case "directory":
				if err := os.Mkdir(reference, 0700); err != nil {
					t.Fatal(err)
				}
			case "invalid":
				if err := os.WriteFile(reference, []byte(`{"schema_version":2}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(root, "workflow.json")
			saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "work", Steps: []workflowStep{{ID: "state", Kind: "run", RecoveryMode: "both", Suites: []string{suite}, Environment: environment, TelemetryConfig: filepath.Base(reference)}}})
			args := []string{"plan", "--workflow", path}
			var output bytes.Buffer
			if err := runCommand(ctx, root, bootstrap, args, &output); err != nil {
				t.Fatal("preview tried to load a telemetry reference", err)
			}
			var preview workflowPreview
			if json.Unmarshal(output.Bytes(), &preview) != nil || preview.Kind != "selection_preview" || len(preview.Steps) != 1 || preview.Steps[0].TelemetryConfig != filepath.Base(reference) {
				t.Fatal("preview changed its unresolved telemetry reference", output.String())
			}
			var refused bytes.Buffer
			if err := runCommand(ctx, root, bootstrap, []string{"run", "--workflow", path}, &refused); err == nil {
				t.Fatal("invalid effective telemetry reached execution")
			}
			if admissions != 0 {
				t.Fatal("invalid effective telemetry crossed execution admission", admissions)
			}
			if refused.String() != "" && refused.String() != "Source observation incomplete; prepared builds remain in use\n" {
				t.Fatal("invalid effective telemetry emitted execution output", refused.String())
			}
			args = append(args, "--telemetry-config", filepath.Join(root, "noop.json"))
			output.Reset()
			if err := runCommand(ctx, root, bootstrap, args, &output); err != nil {
				t.Fatal("preview refused the replacement reference", err)
			}
			request, err := workflowArguments(args)
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := resolveWorkflow(ctx, root, request)
			if err != nil || len(resolved.Steps) != 1 || resolved.Steps[0].request.telemetrySettings == nil || len(resolved.Steps[0].request.telemetrySettings.MetricExporters) != 0 {
				t.Fatal("execution settings loaded the replaced workflow reference", err)
			}
			for _, directory := range []string{"tests/live/runs", "tests/hermetic/runs", "tests/workflows/runs"} {
				if _, err := os.Stat(filepath.Join(root, directory)); !os.IsNotExist(err) {
					t.Fatal("telemetry resolution created execution evidence", directory, err)
				}
			}
		})
	}
}

// full_only: false
func TestWorkflowCommandLoadsTelemetryOnlyForSelectedRuns(t *testing.T) {
	t.Setenv("ENKV_LOG_LEVEL", "")
	root, suite, environment := savedSelectionFixture(t)
	ctx, bootstrap, _ := copyPreparationAssemblyFixture(t, root)
	ctx = withRacePolicy(ctx, false)
	var mapping struct{ Replace map[string]string }
	if err := records.ReadJSON(bootstrap, &mapping); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "tests/shared/runner"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			mapping.Replace[filepath.Join(root, "core/internal/testmain", entry.Name())] = filepath.Join(root, "tests/shared/runner", entry.Name())
		}
	}
	if err := records.WriteJSON(bootstrap, mapping, 0600); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"tests/scripts/bootstrap.go", "tests/scripts/bootstrap_test.go"} {
		body, err := os.ReadFile(filepath.Join(testRepositoryRoot(t), relative))
		if err != nil {
			t.Fatal(err)
		}
		writeLocalGoFixture(t, root, relative, string(body))
	}
	writeTelemetryConfigs(t, root)
	path := filepath.Join(root, "workflow.json")
	saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "work", Steps: []workflowStep{
		{ID: "state", Kind: "run", RecoveryMode: "both", Suites: []string{suite}, Environment: environment, TelemetryConfig: "local.json"},
		{ID: "unused", Kind: "run", RecoveryMode: "both", Suites: []string{"missing-suite.json"}, Environment: "missing-environment.json", TelemetryConfig: "missing-telemetry.json", LogLevel: "invalid"},
		{ID: "runner", Kind: "runner-tests"},
	}})
	for _, test := range []struct {
		step, configuration, level string
	}{
		{"state", filepath.Join(root, "noop.json"), "error"},
		{"runner", filepath.Join(root, "missing-override.json"), "invalid"},
	} {
		t.Run(test.step, func(t *testing.T) {
			args := []string{"plan", "--workflow", path, "--step", test.step, "--telemetry-config", test.configuration, "--log-level", test.level}
			var output bytes.Buffer
			if err := runCommand(ctx, root, bootstrap, args, &output); err != nil {
				t.Fatal("unselected run inputs blocked the selected step", err)
			}
			request, err := workflowArguments(args)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := resolveWorkflow(context.Background(), root, request)
			if err != nil || len(plan.Steps) != 3 {
				t.Fatal("workflow scope changed", err)
			}
			for _, step := range plan.Steps {
				if step.Selected != (step.ID == test.step) {
					t.Fatal("override changed the selected scope", step.ID)
				}
				if !step.Selected || step.Kind != "run" {
					if step.Run != nil || step.request.telemetrySettings != nil {
						t.Fatal("unused run settings were loaded", step.ID)
					}
				} else if settings := step.request.telemetrySettings; settings == nil || settings.LogLevel != observability.Error || len(settings.MetricExporters) != 0 {
					t.Fatal("selected run ignored its overrides")
				}
			}
		})
	}
}

// full_only: false
func TestWorkflowCommandRejectsInvalidEffectiveTelemetryBeforeExecution(t *testing.T) {
	t.Setenv("ENKV_LOG_LEVEL", "")
	root, suite, environment := savedSelectionFixture(t)
	writeTelemetryConfigs(t, root)
	admissions := 0
	ctx := context.WithValue(t.Context(), rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, _ rootAdmission) (context.Context, error) {
		admissions++
		return ctx, errors.New("invalid telemetry requested execution admission")
	}))
	invalid := filepath.Join(root, "invalid.json")
	if err := os.WriteFile(invalid, []byte(`{"schema_version":1,"metrics":{"exporters":["missing"]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "workflow.json")
	saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "work", Steps: []workflowStep{{ID: "state", Kind: "run", RecoveryMode: "both", Suites: []string{suite}, Environment: environment, TelemetryConfig: "noop.json"}}})
	for _, flags := range [][]string{
		{"--telemetry-config", invalid},
		{"--telemetry-config", filepath.Join(root, "missing.json")},
		{"--log-level", "invalid"},
		{"--telemetry-config"},
		{"--log-level"},
		{"--telemetry=true"},
		{"--diagnostics=true"},
	} {
		var output bytes.Buffer
		args := append([]string{"run", "--workflow", path}, flags...)
		if err := runCommand(ctx, root, "must-not-build", args, &output); err == nil {
			t.Fatal("invalid effective telemetry passed execution admission", flags)
		}
		if admissions != 0 {
			t.Fatal("invalid effective telemetry crossed execution admission", flags, admissions)
		}
		if output.String() != "" && output.String() != "Source observation incomplete; prepared builds remain in use\n" {
			t.Fatal("invalid effective telemetry emitted execution output", flags, output.String())
		}
		if _, err := os.Stat(filepath.Join(root, "tests")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid configuration created execution evidence")
		}
	}
}

// full_only: false
func TestWorkflowOrdinaryFocusArguments(t *testing.T) {
	for _, command := range []string{"plan", "run"} {
		for _, flags := range [][]string{
			{"--step=unit", "--package=core/contract"},
			{"--step", "unit", "--package", "core/contract", "--test", "TestTokenValidation/valid"},
			{"--step=runner", "--test=TestGoEnvironmentPreservesExplicitTelemetry"},
			{"--step=runner", "--test=Example"},
			{"--step=runner", "--test=FuzzDecode/seed#0"},
			{"--step=runner", "--test=TestParent/a(b)?"},
			{"--step=runner", "--test=TestParent/" + strings.Repeat("x", 300)},
		} {
			if _, err := workflowArguments(append([]string{command, "--workflow=dev.json"}, flags...)); err != nil {
				t.Fatal("valid ordinary focus refused", flags, err)
			}
		}
		for _, flags := range [][]string{
			{"--package=core/contract"}, {"--step=unit", "--package="},
			{"--step=unit", "--package=core/contract", "--package=core/contract"},
			{"--step=unit", "--package=core/contract/..."}, {"--step=unit", "--package=./core/contract"},
			{"--step=unit", "--package=core/../crypto"}, {"--step=unit", "--package=/core/contract"},
			{"--step=unit", "--package=unknown/package"}, {"--step=", "--package=core/contract"},
			{"--step=unit", "--package=core/contract", "--resume=0123456789abcdef0123456789abcdef"},
			{"--step=runner", "--test=TestAlpha//child"}, {"--step=runner", "--test=TestAlpha/"},
		} {
			if _, err := workflowArguments(append([]string{command, "--workflow=dev.json"}, flags...)); err == nil {
				t.Fatal("invalid ordinary focus accepted", flags)
			}
		}
	}
	path := savedWorkflowPath(t, "check")
	root := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	for _, request := range []workflowRequest{
		{Path: path, SelectedStep: "unit", Test: "TestTokenValidation"},
		{Path: path, SelectedStep: "runner", Package: "core/contract", Test: "TestAlpha"},
		{Path: path, SelectedStep: "components", Package: "core/contract", Test: "TestAlpha"},
		{Path: path, SelectedStep: "components", Test: "Example"},
		{Path: path, SelectedStep: "assemblies-aws", Package: "core/contract"},
	} {
		if _, err := resolveWorkflow(t.Context(), root, request); err == nil {
			t.Fatal("direct resolver accepted invalid ordinary focus", request)
		}
	}
	plan, err := resolveWorkflow(t.Context(), root, workflowRequest{Path: path, SelectedStep: "runner", Test: "TestAlpha/child"})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if step.Selected && (step.OrdinaryFocus == nil || step.OrdinaryFocus.Tests[0] != "TestAlpha/child") || !step.Selected && step.OrdinaryFocus != nil {
			t.Fatal("ordinary selection differs", step)
		}
	}
}

// full_only: false
func TestWorkflowOrdinaryPackageUsesConfiguredMembership(t *testing.T) {
	root := t.TempDir()
	for path, body := range map[string]string{
		"core/go.mod":               "module example.org/core\n\ngo 1.27.0\n",
		"core/contract/contract.go": "package contract\n",
		"core/other/other.go":       "package other\n",
	} {
		writeLocalGoFixture(t, root, path, body)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "checkout")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name     string
		patterns []string
		path     string
		valid    bool
	}{
		{"exact", []string{"./contract"}, "core/contract", true},
		{"recursive", []string{"./..."}, "core/contract", true},
		{"outside-exact", []string{"./contract"}, "core/other", false},
		{"missing", []string{"./..."}, "core/missing", false},
		{"module-is-not-recursive-focus", []string{"./..."}, "core", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			for name, directory := range map[string]string{"original": root, "canonical": canonical, "symlink": alias} {
				t.Run(name, func(t *testing.T) {
					got, err := resolveOrdinaryUnitPackage(t.Context(), directory, map[string][]string{"core": row.patterns}, row.path)
					if (err == nil) != row.valid {
						t.Fatal("package admission differs", got, err)
					}
					if row.valid && (len(got.Artifacts) != 1 || got.Artifacts[0].Owner != "core/contract" || !slices.Equal(got.Artifacts[0].Patterns, []string{"./contract"})) {
						t.Fatal("exact focus became module scope", got)
					}
					if row.name == "recursive" && !slices.Equal(got.AdmittedPackages, []string{"core/contract", "core/other"}) {
						t.Fatal("unselected package membership was lost", got)
					}
				})
			}
		})
	}
	t.Run("outside-root", func(t *testing.T) {
		escaped := t.TempDir()
		writeLocalGoFixture(t, escaped, "outside.go", "package outside\n")
		if err := os.Symlink(escaped, filepath.Join(root, "core/outside")); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveOrdinaryUnitPackage(t.Context(), canonical, map[string][]string{"core": {"./outside"}}, "core/outside"); err == nil {
			t.Fatal("package outside the repository was admitted through a symlink")
		}
	})
}

// full_only: false
func TestOrdinarySelectedFailureCannotClaimCompletion(t *testing.T) {
	focus := ordinaryFocus{PackagePath: "core/contract", Tests: singleTestRequest("TestParent/missing"), Package: "example.org/contract", Artifact: "core/contract"}
	current := ordinaryStepEvidence{RaceOptions: raceOptions, Focus: &focus, Preparation: &ordinaryPreparation{Artifacts: []ordinaryArtifact{{Owner: "core/contract", Package: focus.Package, Tests: []string{"TestParent"}}}}, Execution: []ordinaryExecution{{Artifact: focus.Artifact, Package: focus.Package, Tests: []string{"TestParent"}}}, Packages: []ordinaryPackage{{Name: focus.Package, Tests: []string{"TestParent"}}}, Tests: []ordinaryTest{{Package: focus.Package, Name: "TestParent", Outcome: "pass"}}}
	if err := validateOrdinaryStepResult(current); err == nil {
		t.Fatal("missing requested child acquired successful completion")
	}
}

func testRepositoryRoot(t *testing.T) string {
	t.Helper()
	return filepath.Clean(filepath.Join(filepath.Dir(savedWorkflowPath(t, "dev")), "../.."))
}

func testRaceContext(t *testing.T, ctx context.Context) context.Context {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	race, err := binaryRace(binary)
	if err != nil {
		t.Fatal(err)
	}
	return withRacePolicy(ctx, race)
}

func workflowTestContext(t *testing.T, root string) context.Context {
	t.Helper()
	// These real-checkout checks are one job in the outer test invocation.
	// They call common execution directly and retain its one assigned slot.
	return withExecutionParallel(testRaceContext(t, t.Context()), 1)
}
