package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/compositions/observability"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

func memoryEnvironment() environmentFile {
	e := environmentFile{
		SchemaVersion: 1, Name: "memory", Mode: "hermetic", Provider: "memory", Resource: environmentResource{Alias: "state"},
		Participants: map[string]participantReference{"operator": {}, "reader": {}, "recovery": {}, "denied-reader": {}},
		RoleBindings: map[string]string{"authority": "operator", "reader": "reader", "recovery": "recovery", "denied-reader": "denied-reader"},
	}
	for _, role := range []string{"reader-successor", "replacement-store", "normal-signer-0", "normal-signer-1", "normal-signer-2", "denied-observer", "authority-decrypter-0", "authority-decrypter-1", "authority-decrypter-2", "recovery-signer-0", "recovery-signer-1", "recovery-decrypter-0", "recovery-decrypter-1", "recovery-decrypter-2"} {
		e.Participants[role] = participantReference{}
		e.RoleBindings[role] = role
	}
	return e
}

func suiteFixture(name string, scenarios []string) suiteFile {
	return suiteFile{SchemaVersion: 2, Name: name, RequiredRoles: catalog.RolesForScenarios(scenarios, "both"), Scenarios: scenarios}
}

func savedSelectionFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	suite, environment := filepath.Join(root, "suite.json"), filepath.Join(root, "environment.json")
	saveSelection(t, suite, suiteFixture("smoke", []string{"state.single-value-update-preserves-other-values/members_32"}))
	saveSelection(t, environment, memoryEnvironment())
	return root, suite, environment
}
func saveSelection(t *testing.T, path string, value any) {
	t.Helper()
	if records.WriteJSON(path, value, 0600) != nil {
		t.Fatal("selection fixture unavailable")
	}
}
func environmentFor(settings liveSettings) environmentFile {
	resource := resourceIdentity(settings)
	delete(resource, "provider")
	return environmentFile{SchemaVersion: 1, Name: "cloud", Mode: "live", Provider: settings["provider"], Resource: environmentResource{Alias: "state", Settings: resource}, Participants: map[string]participantReference{"operator": {Access: accessReference{CredentialsFile: settings["credentials_file"], Profile: settings["profile"], CredentialExpires: settings["credential_expires"]}}}, RoleBindings: map[string]string{"authority": "operator"}}
}

// full_only: false
func TestSavedPreviewKeepsRequestedRunSelection(t *testing.T) {
	root, suite, environment := savedSelectionFixture(t)
	ctx := withRacePolicy(t.Context(), true)
	compiles := observePreparationCompiles(t)
	admissions := 0
	ctx = context.WithValue(ctx, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, _ rootAdmission) (context.Context, error) {
		admissions++
		return ctx, errors.New("selection preview requested execution admission")
	}))
	args := []string{"plan", "--race", "--suite", suite, "--environment", environment}
	var output bytes.Buffer
	if err := runCommand(ctx, root, "must-not-build", args, &output); err != nil {
		t.Fatal(err)
	}
	if admissions != 0 {
		t.Fatal("selection preview crossed execution admission", admissions)
	}
	if _, err := os.Stat(compiles); !os.IsNotExist(err) {
		t.Fatal("selection preview compiled an executable", err)
	}
	var planned workflowPreview
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&planned); err != nil {
		t.Fatal("invalid public plan JSON", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("public plan has trailing output", err)
	}
	expected, err := json.MarshalIndent(planned, "", "  ")
	if err != nil || !bytes.Equal(output.Bytes(), append(expected, '\n')) {
		t.Fatal("successful plan changed its exact JSON output", err)
	}
	if planned.Kind != "selection_preview" || !planned.Race || planned.Profile != "full" || len(planned.Steps) != 1 || len(planned.Unresolved) != 4 {
		t.Fatal("preview lost requested scope or claimed compiled facts", planned)
	}
	step := planned.Steps[0]
	if !step.Selected || step.Kind != "run" || !slices.Equal(step.Suites, []string{suite}) || step.Environment != environment || step.RecoveryMode != "both" {
		t.Fatal("preview changed the requested input references", step)
	}
	assertPublicExecutionCapacity(t, output.Bytes(), map[string]int{}, 4, 8192)
	args[0] = "run"
	request, err := parseRunRequest(args)
	if err != nil || request.Resolved == nil {
		t.Fatal("requested run selection did not resolve", err)
	}
	selection := request.Resolved
	if len(selection.Entries) != 1 || !selection.Entries[0].Smoke || selection.Entries[0].Repetition != 1 || selection.Entries[0].Members != 0 || selection.Entries[0].Fixture.Members != 32 || selection.Schedule.FullCoverage || !reflect.DeepEqual(selection.Participants, []string{"operator", "recovery"}) {
		t.Fatal("smoke selection must include authority and enabled recovery qualification")
	}
	for _, secret := range []string{"credentials_file", "public_key_pem"} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("plan exposes private input")
		}
	}
	for _, directory := range []string{"tests/hermetic/runs", "tests/live/runs", "tests/workflows/runs"} {
		if _, err := os.Stat(filepath.Join(root, directory)); !os.IsNotExist(err) {
			t.Fatal("selection preview created durable execution state", directory, err)
		}
	}
}

// full_only: false
func TestRemovedRunFlagsAreRejected(t *testing.T) {
	_, suite, environment := savedSelectionFixture(t)
	for _, flag := range []string{"--telemetry=true", "--diagnostics=true", "--members=32", "--members=1,2"} {
		t.Run(flag, func(t *testing.T) {
			if _, err := parseRunRequest([]string{"plan", "--suite", suite, "--environment", environment, flag}); err == nil {
				t.Fatal("removed run flag was accepted")
			}
		})
	}
}

// full_only: false
func TestCloudflareGeneratorInputsStayOutOfResolvedAndEvidenceRecords(t *testing.T) {
	root, suite, environment := savedSelectionFixture(t)
	saveSelection(t, suite, suiteFixture("generated", catalog.GeneratedLiveNames()))
	env := configurationRecoverySelectionEnvironment(t, "gcp", "disabled")
	operator := env.Participants["operator"]
	operator.Access.CredentialsFile = filepath.Join(root, "domain-credentials.json")
	env.Participants["operator"] = operator
	if err := selectRecoveryMode(&env, "disabled"); err != nil {
		t.Fatal(err)
	}
	account := strings.Repeat("a", 32)
	credential := filepath.Join(root, "cloudflare-api-token")
	artifact := filepath.Join(root, "enkv-generator-cloudflare")
	env.Generator = &generatorReference{Account: account, PermissionGroup: strings.Repeat("d", 32), Artifact: artifact}
	saveSelection(t, environment, env)
	request, err := parseRunRequest([]string{"plan", "--suite", suite, "--environment", environment})
	if err != nil || request.Resolved.Generator == nil || request.Resolved.Generator.Provider != "cloudflare" || request.Resolved.Generator.CredentialContract != "environment:CLOUDFLARE_API_TOKEN" {
		t.Fatal("generator plan was not resolved", err)
	}
	body, err := json.Marshal(struct {
		Resolved *resolvedRequest `json:"resolved"`
		Record   runRecord        `json:"record"`
	}{Resolved: request.Resolved, Record: runRecord{Resolved: request.Resolved}})
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{account, credential, artifact, filepath.Base(credential), filepath.Base(artifact)} {
		if bytes.Contains(body, []byte(private)) {
			t.Fatal("resolved or evidence record retained a private generator input")
		}
	}
	if request.environment == nil || request.environment.Generator == nil || request.environment.Generator.Account != account || request.environment.Generator.CredentialsFile != "" || request.environment.Generator.Artifact != artifact {
		t.Fatal("private execution request lost its generator inputs")
	}
}

// full_only: false
func TestCloudflareGeneratorInputValidationIsSeparateFromDomainProvider(t *testing.T) {
	root, suite, environment := savedSelectionFixture(t)
	saveSelection(t, suite, suiteFixture("generated", catalog.GeneratedLiveNames()))
	env := configurationRecoverySelectionEnvironment(t, "aws", "disabled")
	operator := env.Participants["operator"]
	operator.Access.CredentialsFile = filepath.Join(root, "domain-credentials")
	env.Participants["operator"] = operator
	if err := selectRecoveryMode(&env, "disabled"); err != nil {
		t.Fatal(err)
	}
	env.Generator = &generatorReference{Account: strings.Repeat("b", 32), PermissionGroup: strings.Repeat("d", 32), Artifact: "cloudflare-artifact"}
	saveSelection(t, environment, env)
	request, err := parseRunRequest([]string{"plan", "--suite", suite, "--environment", environment})
	if err != nil || request.Provider != "aws" || request.Resolved.Provider != "aws" || request.Resolved.Generator == nil || request.Resolved.Generator.Provider != "cloudflare" || request.Resolved.Generator.CredentialContract != "environment:CLOUDFLARE_API_TOKEN" {
		t.Fatal("generator changed the Store/Trust provider", err)
	}
	if request.environment.Generator.CredentialsFile != "" || request.environment.Generator.Artifact != filepath.Join(root, "cloudflare-artifact") {
		t.Fatal("generator paths did not resolve beside the environment")
	}
	env.Generator.CredentialsFile = "cloudflare-token"
	saveSelection(t, environment, env)
	if _, err := parseRunRequest([]string{"plan", "--suite", suite, "--environment", environment}); err == nil {
		t.Fatal("fresh generator admitted file credential recipe")
	}
	env.Generator.CredentialsFile = ""
	env.Generator.Account = "not-an-account"
	saveSelection(t, environment, env)
	if _, err := parseRunRequest([]string{"plan", "--suite", suite, "--environment", environment}); err == nil {
		t.Fatal("invalid generator account admitted")
	}
	hermetic := memoryEnvironment()
	hermetic.Generator = &generatorReference{Account: strings.Repeat("c", 32), PermissionGroup: strings.Repeat("d", 32), CredentialsFile: "token", Artifact: "artifact"}
	saveSelection(t, environment, hermetic)
	if _, err := parseRunRequest([]string{"plan", "--suite", suite, "--environment", environment}); err == nil {
		t.Fatal("hermetic environment admitted live generator inputs")
	}
}

// full_only: false
func TestScenarioRolesResolveBeforeEffects(t *testing.T) {
	for _, test := range []struct {
		name, scenario            string
		observer, reuse, accepted bool
		aliasRole                 string
	}{
		{name: "authority only", scenario: "state.historical-bytes-get-new-identities/members_32_three_generations", accepted: true},
		{name: "several participants", scenario: "access.observer-sees-selected-state/members_32_observer", observer: true, accepted: true},
		{name: "missing participant", scenario: "access.observer-sees-selected-state/members_32_observer"},
		{name: "role reuse", scenario: "access.observer-sees-selected-state/members_32_observer", observer: true, reuse: true, accepted: true},
		{name: "distinct roles", scenario: "access.distinct-observer-sees-selected-state/members_32_distinct_observer", observer: true, accepted: true},
		{name: "distinct role reuse refused", scenario: "access.distinct-observer-sees-selected-state/members_32_distinct_observer", observer: true, reuse: true},
		{name: "recovery role reuse refused", scenario: "genesis.empty-domain-reopens/empty_genesis", aliasRole: "recovery"},
		{name: "reader role reuse refused", scenario: "secret.shared-reader-survives-restart/plain_neighbor_shared_secret", aliasRole: "reader"},
		{name: "denied reader role reuse refused", scenario: "secret.provider-refuses-reader/plain_neighbor_denied_reader", aliasRole: "denied-reader"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, suite, path := savedSelectionFixture(t)
			env := memoryEnvironment()
			if test.observer {
				env.Participants["auditor"] = participantReference{}
				env.RoleBindings["observer"] = "auditor"
			}
			if test.reuse {
				env.RoleBindings["observer"] = "operator"
			}
			if test.aliasRole != "" {
				env.RoleBindings[test.aliasRole] = "operator"
			}
			saveSelection(t, suite, suiteFixture("case", []string{test.scenario}))
			saveSelection(t, path, env)
			req, err := parseRunRequest([]string{"run", "--suite", suite, "--environment", path})
			if (err == nil) != test.accepted {
				t.Fatal("scenario participant admission differs", err)
			}
			if test.accepted {
				count := 2
				if test.observer && !test.reuse {
					count = 3
				}
				if len(req.Resolved.Participants) != count {
					t.Fatal("wrong selected participants")
				}
				if _, err := req.Resolved.scenarioParticipants(test.scenario); err != nil {
					t.Fatal("resolved participants differ from admitted selection", err)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "tests")); !os.IsNotExist(err) {
				t.Fatal("resolution created fixture state")
			}
		})
	}
}

// full_only: false
func TestExpectedResultsBelongToScenarios(t *testing.T) {
	env := memoryEnvironment()
	env.Participants["auditor"] = participantReference{}
	env.RoleBindings["observer"] = "auditor"
	env.Participants["denied-auditor"] = participantReference{}
	env.RoleBindings["denied-observer"] = "denied-auditor"
	for _, scenario := range []string{"access.observer-sees-selected-state/members_32_observer", "access.provider-refuses-observer/members_32_denied_observer"} {
		request := runRequest{Suite: "hermetic", Provider: "memory"}
		if err := resolveSelection(&request, catalog.Request{Include: []string{scenario}, Repetitions: 1}, "witness", env); err != nil {
			t.Fatal(err)
		}
		steps := request.Resolved.Entries[len(request.Resolved.Entries)-1].Steps
		want := "success"
		if scenario == "access.provider-refuses-observer/members_32_denied_observer" {
			want = "access-refused"
		}
		if steps[len(steps)-1].Expected != want {
			t.Fatal("environment changed scenario expectation")
		}
	}
}

// full_only: false
func TestSavedSelectionRejectsBeforeFixtureEffects(t *testing.T) {
	for _, test := range []struct{ name, file, before, after string }{
		{"unknown field", "suite", `"name":"smoke"`, `"unexpected":32`},
		{"duplicate key", "suite", `"name":"smoke"`, `"name":"smoke","name":"other"`},
		{"noncanonical field", "suite", `"name":"smoke"`, `"NAME":"smoke"`},
		{"null members", "suite", `"name":"smoke"`, `"name":null`},
		{"unknown scenario", "suite", `state.single-value-update-preserves-other-values`, `synthetic-secret`},
		{"empty members", "suite", `"name":"smoke"`, `"members":[]`},
		{"unsupported repetitions", "suite", `"name":"smoke"`, `"name":"smoke","repetitions":2`},
		{"missing authority", "environment", `"authority":"operator"`, `"authority":"absent"`},
		{"environment outcome", "environment", `"schema_version":1`, `"schema_version":1,"reader_outcome":"access-refused"`},
		{"null participant", "environment", `"operator":{"access":{}}`, `"operator":null`},
		{"unknown mode", "environment", `"hermetic"`, `"e2e"`},
		{"unknown access field", "environment", `"operator":{"access":{}}`, `"operator":{"access":{"token":"synthetic-secret"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, suite, environment := savedSelectionFixture(t)
			path := suite
			if test.file == "environment" {
				path = environment
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(string(body), test.before, test.after, 1)
			if changed == string(body) {
				t.Fatal("test did not change input")
			}
			if os.WriteFile(path, []byte(changed), 0600) != nil {
				t.Fatal("fixture write failed")
			}
			if err := runCommand(context.Background(), root, "absent", []string{"run", "--suite", suite, "--environment", environment}, &bytes.Buffer{}); err == nil || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("invalid selection admitted or exposed", err)
			}
			if _, err := os.Stat(filepath.Join(root, "tests")); !os.IsNotExist(err) {
				t.Fatal("rejection followed fixture effects")
			}
		})
	}
}

// full_only: false
func TestLivePlanDoesNotReadCredentialsAndRunKeepsLimits(t *testing.T) {
	for _, provider := range []string{"gcp", "aws"} {
		t.Run(provider, func(t *testing.T) {
			_, suite, path := savedSelectionFixture(t)
			ctx, root, bootstrap := localLivePreparationFixture(t, provider)
			ctx = withRacePolicy(ctx, false)
			_, settings := configurationFixture(t, provider)
			settings["credentials_file"] = "missing-credentials"
			saveSelection(t, path, environmentFor(settings))
			args := []string{"plan", "--suite", suite, "--environment", path}
			var output bytes.Buffer
			if err := runCommand(ctx, root, bootstrap, args, &output); err != nil {
				t.Fatalf("%v\n%s", err, output.Bytes())
			}
			args[0] = "run"
			if _, err := parseRunRequest(args); err == nil {
				t.Fatal("live run accepted missing limits")
			}
			args = append(args, "--limits", "limits.json")
			if _, err := parseRunRequest(args); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// full_only: false
func TestLiveStateRegressionExcludesHermeticGeneratedHistoryRoutes(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, mode := range []string{"disabled", "enabled"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				root, _, path := savedSelectionFixture(t)
				env := configurationRecoverySelectionEnvironment(t, provider, mode)
				saveSelection(t, path, env)
				workflowPath := savedWorkflowPath(t, "canonical")
				var workflow workflowFile
				if err := readSelectionFile(workflowPath, &workflow); err != nil {
					t.Fatal(err)
				}
				var suites []string
				for _, step := range workflow.Steps {
					if step.ID == provider+"-recovery-"+mode {
						if len(step.Scenarios) != 0 {
							t.Fatal("canonical base cell must select suites without inline scenarios")
						}
						for _, suite := range step.Suites {
							suites = append(suites, filepath.Join(filepath.Dir(workflowPath), suite))
						}
						break
					}
				}
				if len(suites) == 0 {
					t.Fatal("canonical base cell selection missing")
				}
				request, err := resolveSavedRun(suites, path, "", "", mode, "", "", "", 1, false)
				if err != nil {
					t.Fatal("live state regression required a hermetic generated route", err)
				}
				for _, name := range request.Resolved.Schedule.Selected {
					if _, generated := catalog.GeneratedHistory(name); generated || slices.Contains(catalog.GeneratedLiveNames(), name) {
						t.Fatal("live state regression retained generated history dispatch", name)
					}
				}
				if _, err := os.Stat(filepath.Join(root, "tests")); !os.IsNotExist(err) {
					t.Fatal("selection created fixture state")
				}
			})
		}
	}
}

// full_only: false
func TestEnvironmentCopyKeepsAbsoluteCredentialReferences(t *testing.T) {
	for _, provider := range []string{"gcp", "aws"} {
		t.Run(provider, func(t *testing.T) {
			root, suite, environment := savedSelectionFixture(t)
			config, settings := configurationFixture(t, provider)
			credential := filepath.Join(filepath.Dir(config), settings["credentials_file"])
			settings["credentials_file"] = credential
			saveSelection(t, environment, environmentFor(settings))
			other := t.TempDir()
			copied := filepath.Join(other, "environment.json")
			body, err := os.ReadFile(environment)
			if err != nil || os.WriteFile(copied, body, 0600) != nil {
				t.Fatal("copy failed")
			}
			alias := filepath.Join(root, "copied-directory")
			if os.Symlink(other, alias) != nil {
				t.Fatal("directory alias failed")
			}
			for _, path := range []string{environment, copied, filepath.Join(alias, "environment.json")} {
				request, err := parseRunRequest([]string{"plan", "--suite", suite, "--environment", path})
				if err != nil {
					t.Fatal(err)
				}
				loaded, _, err := loadRunSettings(request)
				authority, observer := loaded["authority"], loaded["observer"]
				if err != nil || authority["credentials_file"] != credential || observer != nil {
					t.Fatal("copied environment changed credential route", err)
				}
			}
		})
	}
}

// full_only: false
func TestCheckRejectsNarrowedRegressionBeforeTools(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"tests/suites", "tests/environments", "tests/workflows"} {
		if os.MkdirAll(filepath.Join(root, directory), 0700) != nil {
			t.Fatal("fixture directory failed")
		}
	}
	saveSelection(t, filepath.Join(root, "tests/environments/hermetic.json"), memoryEnvironment())
	saveSelection(t, filepath.Join(root, "tests/suites/narrow.json"), suiteFixture("narrow", []string{"state.single-value-update-preserves-other-values/members_32"}))
	saveSelection(t, filepath.Join(root, "tests/workflows/check.json"), workflowFile{SchemaVersion: 1, Name: "check", Steps: []workflowStep{{ID: "state", Kind: "run", RecoveryMode: "both", Suites: []string{"../suites/narrow.json"}, Environment: "../environments/hermetic.json"}}})
	var output bytes.Buffer
	_, err = runLocalWorkflow(context.Background(), root, "must-not-build", "check", executionRequest{}, &output)
	if err == nil || err.Error() != "local verification requires the complete hermetic catalog and its declared execution profile" || output.Len() != 0 {
		t.Fatal("partial check reached tools or passed", err)
	}
}

// full_only: false
func TestCheckRequiresEveryActivityAndAllProductPackages(t *testing.T) {
	complete := func() workflowPlan {
		packages, err := resolveUnitPackages(nil)
		if err != nil {
			t.Fatal(err)
		}
		var hermetic []string
		for _, name := range catalog.OrdinaryNames() {
			definition, _ := catalog.DefinitionFor(name)
			if slices.Contains(definition.Modes, "hermetic") {
				hermetic = append(hermetic, definition.Name)
			}
		}
		return workflowPlan{Execution: defaultExecutionPolicy(), Steps: []resolvedWorkflowStep{
			{ID: "lint", Kind: "lint", Selected: true},
			{ID: "runner", Kind: "runner-tests", Selected: true},
			{ID: "unit", Kind: "unit", Selected: true, Packages: packages},
			{ID: "assembly-common", Kind: "assembly-checks", Responsibility: "common", Selected: true},
			{ID: "assemblies-gcp", Kind: "assembly-checks", Responsibility: "gcp", Selected: true},
			{ID: "assemblies-aws", Kind: "assembly-checks", Responsibility: "aws", Selected: true},
			{ID: "components", Kind: "component-tests", Selected: true, Profile: "full"},
			{ID: "state", Kind: "run", Selected: true, Run: &resolvedRequest{Profile: "full", Race: false, Mode: "hermetic", Schedule: catalog.Schedule{FullCoverage: true, Selected: hermetic}}},
		}}
	}
	if err := validateCheckWorkflow(complete()); err != nil {
		t.Fatal("complete check refused", err)
	}
	for _, index := range []int{1, 2, 6} {
		t.Run("repeated-focused-"+complete().Steps[index].Kind, func(t *testing.T) {
			plan := complete()
			selected := plan.Steps[index]
			if selected.Kind == "component-tests" {
				selected.Focus = &componentFocus{Tests: singleTestRequest("TestParent/leaf")}
				selected.Preparation = &componentPreparation{Inventory: []string{"TestParent"}}
			} else {
				selected.OrdinaryFocus = &ordinaryFocus{Tests: singleTestRequest("TestParent/leaf")}
				selected.OrdinarySelection = []ordinaryExecution{{Artifact: "selected", Package: "example.org/selected"}}
			}
			repeated := expandWorkflowRepetitions(selected, 3)
			plan.Steps = append(append(slices.Clone(plan.Steps[:index]), repeated...), plan.Steps[index+1:]...)
			if err := validateCheckWorkflow(plan); err == nil {
				t.Fatal("focused repetitions claimed complete check coverage")
			}
			// Removing the focus and repetition labels must not erase the
			// actual selected execution evidence from an otherwise full plan.
			selected.Focus, selected.OrdinaryFocus = nil, nil
			selected.ConfiguredStep, selected.Repetition, selected.Repetitions = "", 0, 0
			plan = complete()
			plan.Steps[index] = selected
			if err := validateCheckWorkflow(plan); err == nil {
				t.Fatal("removed repetition labels hid partial selection evidence")
			}
			selected.Preparation, selected.OrdinarySelection = nil, nil
			plan.Steps[index] = selected
			if err := validateCheckWorkflow(plan); err != nil {
				t.Fatal("restored complete activity refused", err)
			}
		})
	}
	for index, step := range complete().Steps {
		t.Run("missing-"+step.Kind, func(t *testing.T) {
			plan := complete()
			plan.Steps = append(plan.Steps[:index], plan.Steps[index+1:]...)
			if err := validateCheckWorkflow(plan); err == nil {
				t.Fatal("check accepted a missing activity")
			}
		})
	}
	for _, condition := range []string{"missing-module", "narrowed-package", "unselected-activity", "missing-observers", "missing-accepted-work", "diagnostic-widening", "diagnostic-replacement", "components-after-scenarios", "focused-runner", "focused-unit", "focused-component", "removed-focus", "removed-focus-and-preparation", "duplicate-responsibility", "unknown-responsibility", "empty-responsibility", "unselected-responsibility", "focused-assembly", "removed-assembly-focus"} {
		t.Run(condition, func(t *testing.T) {
			plan := complete()
			switch condition {
			case "duplicate-responsibility":
				plan.Steps[4].Responsibility = "common"
			case "unknown-responsibility":
				plan.Steps[4].Responsibility = "other"
			case "empty-responsibility":
				plan.Steps[4].Responsibility = ""
			case "unselected-responsibility":
				plan.Steps[4].Selected = false
			case "focused-assembly":
				plan.Steps[4].AssemblyFocus = &assemblyFocus{Requested: "TestParent"}
			case "removed-assembly-focus":
				plan.Steps[4].AssemblyPreparation = &assemblyPreparation{Selection: "^TestParent$"}
			case "focused-runner":
				plan.Steps[1].OrdinaryFocus = &ordinaryFocus{Tests: singleTestRequest("TestParent")}
			case "focused-unit":
				plan.Steps[2].OrdinaryFocus = &ordinaryFocus{PackagePath: "core/contract"}
			case "focused-component":
				plan.Steps[6].Focus = &componentFocus{Tests: singleTestRequest("TestParent")}
			case "removed-focus":
				plan.Steps[1].OrdinaryPreparation = &ordinaryPreparation{Artifacts: []ordinaryArtifact{{Owner: "tests/shared/runner", Package: "example.org/runner", Tests: []string{"TestParent"}}}}
			case "removed-focus-and-preparation":
				plan.Steps[1].OrdinarySelection = []ordinaryExecution{{Artifact: "tests/shared/runner", Package: "example.org/runner"}}
			case "missing-module":
				delete(plan.Steps[2].Packages, "crypto")
			case "narrowed-package":
				plan.Steps[2].Packages["core"] = []string{"./contract"}
			case "unselected-activity":
				plan.Steps[0].Selected = false
			case "diagnostic-widening":
				plan.Steps[7].Run.Schedule.Selected = append(slices.Clone(plan.Steps[7].Run.Schedule.Selected), "state.single-value-update-preserves-other-values/members_1")
			case "diagnostic-replacement":
				names := slices.Clone(plan.Steps[7].Run.Schedule.Selected)
				for i, name := range names {
					if name == "state.single-value-update-preserves-other-values/members_32" {
						names[i] = "state.single-value-update-preserves-other-values/members_1"
					}
				}
				plan.Steps[7].Run.Schedule.Selected = names
			case "missing-observers":
				plan.Steps[7].Run.Schedule.Selected = catalog.RegressionNames()
			case "missing-accepted-work":
				plan.Steps[7].Run.Schedule.Selected = slices.DeleteFunc(slices.Clone(plan.Steps[7].Run.Schedule.Selected), func(name string) bool {
					_, accepted := catalog.GeneratedHistory(name)
					return accepted
				})
			case "components-after-scenarios":
				plan.Steps[6], plan.Steps[7] = plan.Steps[7], plan.Steps[6]
			}
			if err := validateCheckWorkflow(plan); err == nil {
				t.Fatal("check accepted incomplete activity coverage")
			}
		})
	}
}

// full_only: false
func TestFirstFlowEnvironmentRequiresExplicitRecoveryParticipant(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, mode := range []string{"disabled", "enabled"} {
			settings := firstFlowConfigurationFixture(t, provider, mode)
			env := environmentFor(settings)
			if mode == "enabled" {
				env.RoleBindings["recovery"] = "recovery"
				env.Participants["recovery"] = participantReference{Access: accessReference{CredentialsFile: "not-opened.json", Profile: settings["profile"]}}
			}
			if err := validateEnvironment(&env, t.TempDir()); err != nil {
				t.Fatal(err)
			}
			if mode == "enabled" {
				delete(env.RoleBindings, "recovery")
			} else {
				env.RoleBindings["recovery"] = "operator"
			}
			if err := validateEnvironment(&env, t.TempDir()); err == nil {
				t.Fatalf("%s/%s recovery mismatch accepted", provider, mode)
			}
		}
	}
}

// full_only: false
func TestRecoveryRoleResolutionKeepsAllSteps(t *testing.T) {
	definition := catalog.Definition{
		RecoveryModes: []string{"disabled", "enabled"},
		Roles:         []string{"authority", "reader", "recovery", "denied-reader"},
		RolesByRecovery: map[string][]string{
			"disabled": {"authority", "reader", "denied-reader"},
			"enabled":  {"authority", "reader", "recovery", "denied-reader"},
			"both":     {"authority", "reader", "recovery", "denied-reader"},
		},
		Steps: []catalog.Step{{Name: "initialize", Role: "authority", Expected: "success"}, {Name: "verification", Role: "reader", Expected: "success"}},
	}
	for _, mode := range []string{"enabled", "disabled", "both"} {
		roles := definition.RolesForRecovery(mode)
		want := []string{"authority", "reader", "recovery", "denied-reader"}
		if mode == "disabled" {
			want = []string{"authority", "reader", "denied-reader"}
		}
		if !reflect.DeepEqual(roles, want) || len(definition.Steps) != 2 {
			t.Fatalf("mode changed steps or wrong actors: %s", mode)
		}
	}
	if definition.RolesForRecovery("") != nil || definition.RolesForRecovery("automatic") != nil {
		t.Fatal("implicit recovery profile admitted")
	}
}

// full_only: false
func TestDirectRunCommandKeepsTelemetrySelectionAndLevelPrecedence(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	for _, test := range []struct {
		name, environment, configuration string
		flags                            []string
		wantSummary                      string
	}{
		{"no_configuration", "", "", nil, `{"configuration_source":"none","level_override_source":"none","log_level":13,"trace_sample_ratio":1,"logs":["console"],"metrics":[],"traces":[]}`},
		{"environment_level", "debug", "", nil, `{"configuration_source":"none","level_override_source":"environment","log_level":5,"trace_sample_ratio":1,"logs":["console"],"metrics":[],"traces":[]}`},
		{"configuration_level", "", `{"schema_version":1,"logs":{"level":"info"},"resource":{"attributes":{"service.name":"private-service-sentinel"}}}`, []string{"--telemetry-config", "settings.json"}, `{"configuration_source":"command","level_override_source":"none","log_level":9,"trace_sample_ratio":1,"logs":["console"],"metrics":[],"traces":[]}`},
		{"command_level", "invalid", `{"schema_version":1,"logs":{"level":"invalid"}}`, []string{"--telemetry-config", "settings.json", "--log-level", "error"}, `{"configuration_source":"command","level_override_source":"command","log_level":17,"trace_sample_ratio":1,"logs":["console"],"metrics":[],"traces":[]}`},
		{"explicit_metrics", "", `{"schema_version":1,"metrics":{"exporters":["private-file-route"]},"exporters":{"private-file-route":{"type":"otlp_file","directory":"private-directory-sentinel"}}}`, []string{"--telemetry-config", "settings.json"}, `{"configuration_source":"command","level_override_source":"none","log_level":13,"trace_sample_ratio":1,"logs":["console"],"metrics":["file"],"traces":[]}`},
		{"three_signals_both", "", `{"schema_version":1,"logs":{"exporters":["private-http-route","private-file-route"]},"metrics":{"exporters":["private-http-route","private-file-route"]},"traces":{"exporters":["private-http-route","private-file-route"],"sample_ratio":0.25},"exporters":{"private-file-route":{"type":"otlp_file","directory":"private-directory-sentinel"},"private-http-route":{"type":"otlp_http","endpoint":"https://127.0.0.1:4318","api_key_env":"PRIVATE_API_KEY_SENTINEL"}}}`, []string{"--telemetry-config", "settings.json"}, `{"configuration_source":"command","level_override_source":"none","log_level":13,"trace_sample_ratio":0.25,"logs":["file","http"],"metrics":["file","http"],"traces":["file","http"]}`},
		{"logs_off", "", "", []string{"--log-level", "off"}, `{"configuration_source":"none","level_override_source":"command","log_level":0,"trace_sample_ratio":1,"logs":[],"metrics":[],"traces":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("ENKV_LOG_LEVEL", test.environment)
			ctx, root, bootstrap := componentRepetitionAssemblyFixture(t)
			ctx = withRacePolicy(ctx, false)
			compiles := observePreparationCompiles(t)
			suite, environment := filepath.Join(root, "suite.json"), filepath.Join(root, "environment.json")
			saveSelection(t, suite, suiteFixture("smoke", []string{"state.single-value-update-preserves-other-values/members_32"}))
			saveSelection(t, environment, memoryEnvironment())
			entered := filepath.Join(t.TempDir(), "worker-entered")
			writeLocalGoFixture(t, root, "tests/hermetic/direct_telemetry_plan_test.go", fmt.Sprintf(`package core
import (
 "os"
 "testing"
)
func init() {
 if os.Getenv("ENKV_TEST_INVOCATION") != "" {
  if err := os.WriteFile(%[1]q, []byte("entered"), 0600); err != nil { panic(err) }
 }
}
func failDirectTelemetryPlanWorker(t *testing.T) {
 t.Helper()
 if err := os.WriteFile(%[1]q, []byte("entered"), 0600); err != nil { t.Fatal(err) }
 t.Fatal("direct telemetry planning must not execute a scenario worker")
}
// full_only: false
func TestHermeticRun(t *testing.T) { failDirectTelemetryPlanWorker(t) }
// full_only: false
func TestHermeticChild(t *testing.T) { failDirectTelemetryPlanWorker(t) }
`, entered))
			admissions := 0
			ctx = context.WithValue(ctx, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, _ rootAdmission) (context.Context, error) {
				admissions++
				return ctx, errors.New("telemetry preview requested execution admission")
			}))
			t.Chdir(root)
			if test.configuration != "" {
				if err := os.WriteFile("settings.json", []byte(test.configuration), 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := append([]string{"plan", "--suite", suite, "--environment", environment}, test.flags...)
			var output bytes.Buffer
			if err := runCommand(ctx, root, bootstrap, args, &output); err != nil {
				t.Fatal("direct command refused effective telemetry settings", err)
			}
			if _, err := os.Stat(entered); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("direct telemetry planning executed a scenario worker", err)
			}
			if admissions != 0 {
				t.Fatal("telemetry preview crossed execution admission", admissions)
			}
			if _, err := os.Stat(compiles); !os.IsNotExist(err) {
				t.Fatal("telemetry preview compiled an executable", err)
			}
			assertPublicExecutionCapacity(t, output.Bytes(), map[string]int{}, 4, 8192)
			var plan workflowPreview
			decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&plan); err != nil {
				t.Fatal("invalid public telemetry plan JSON", err)
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				t.Fatal("public telemetry plan has trailing output", err)
			}
			if plan.Kind != "selection_preview" || len(plan.Steps) != 1 || len(plan.Unresolved) != 4 {
				t.Fatal("telemetry preview lost requested scope or claimed resolved facts", plan)
			}
			step := plan.Steps[0]
			wantConfig := ""
			if test.configuration != "" {
				wantConfig = "settings.json"
			}
			wantLevel := ""
			if test.name == "command_level" {
				wantLevel = "error"
			} else if test.name == "logs_off" {
				wantLevel = "off"
			}
			if !step.Selected || step.Kind != "run" || !slices.Equal(step.Suites, []string{suite}) || step.Environment != environment || step.TelemetryConfig != wantConfig || step.LogLevel != wantLevel {
				t.Fatal("telemetry preview changed requested references or overrides", step)
			}
			for _, private := range []string{"private-service-sentinel", "private-file-route", "private-http-route", "private-directory-sentinel", "https://127.0.0.1:4318", "PRIVATE_API_KEY_SENTINEL"} {
				if strings.Contains(output.String(), private) {
					t.Error("public plan exposed private telemetry configuration", private)
				}
			}
			request, err := parseRunRequest(args)
			if err != nil || request.Resolved == nil || request.Resolved.Mode != "hermetic" || request.telemetrySettings == nil {
				t.Fatal("direct request changed resolved selection or lost telemetry settings", err)
			}
			if test.name == "command_level" {
				settings := request.telemetrySettings
				if settings.LogLevel != observability.Error || !settings.Console || len(settings.ActiveExporters) != 0 || len(settings.LogExporters) != 0 || len(settings.MetricExporters) != 0 || len(settings.TraceExporters) != 0 {
					t.Fatal("direct request changed the selected level or enabled export", settings)
				}
			}
			for _, directory := range []string{"tests/hermetic/runs", "tests/live/runs", "tests/workflows/runs"} {
				if _, err := os.Stat(filepath.Join(root, directory)); !os.IsNotExist(err) {
					t.Fatal("direct planning created durable execution state", directory, err)
				}
			}
			t.Setenv("ENKV_LOG_LEVEL", "fatal")
			output.Reset()
			if err := json.NewEncoder(&output).Encode(runRecord{Resolved: request.Resolved, Execution: recordExecutionPolicy(request.execution), EffectiveTelemetry: request.effectiveTelemetry}); err != nil {
				t.Fatal(err)
			}
			checkEffectiveTelemetryJSON(t, output.Bytes(), test.wantSummary)
			state, err := newRunState(root, request, records.Source{}, "test")
			if err != nil {
				t.Fatal("run record did not preserve resolved telemetry", err)
			}
			t.Cleanup(func() {
				if err := state.current.remove(true); err != nil {
					t.Error("remove telemetry record fixture without consumers", err)
				}
			})
			body, err := json.Marshal(state.record)
			if err != nil {
				t.Fatal(err)
			}
			checkEffectiveTelemetryJSON(t, body, test.wantSummary)
			authority, err := json.Marshal(request.Resolved)
			if err != nil || bytes.Contains(authority, []byte("effective_telemetry")) {
				t.Fatal("display metadata entered resolved request authority", err)
			}
		})
	}
}

func configurationRecoverySelectionEnvironment(t *testing.T, provider, mode string) environmentFile {
	t.Helper()
	environment, _ := replacementEnvironmentFixture(t, provider, mode)
	environment.Resource.Settings["normal_successor_2_key_id"] = "public-key-normal-successor-2"
	environment.Resource.Settings["normal_successor_2_public_key_pem"] = "-----BEGIN PUBLIC KEY-----\nsynthetic-normal-successor-2\n-----END PUBLIC KEY-----"
	for _, role := range []string{"normal-signer-2", "reader", "denied-reader", "observer", "denied-observer"} {
		access := accessReference{CredentialsFile: role + ".json"}
		if provider == "aws" {
			access.Profile = "enkv-" + role
		}
		environment.Participants[role] = participantReference{Access: access}
		environment.RoleBindings[role] = role
	}
	return environment
}

// full_only: false
func TestExecutionRecordsOwnRequestedSettings(t *testing.T) {
	root, suite, environment := savedSelectionFixture(t)
	request, err := parseRunRequest([]string{"run", "--suite", suite, "--environment", environment, "--parallel=2", "--memory-limit-mib=512"})
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRunState(root, request, records.Source{}, "controlled")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.current.remove(true); err != nil {
			t.Error("remove execution settings fixture without consumers", err)
		}
	})
	ctx := withExecutionCapacity(context.Background(), request.execution)
	*request.execution.Requested.Parallel = 4
	*request.execution.Requested.MemoryLimitMiB = 4096
	request.execution.Resolved = executionCapacity{Parallel: 4, MemoryLimitMiB: 4096}
	if got := executionCapacityFromContext(ctx); got != (executionCapacity{Parallel: 2, MemoryLimitMiB: 512}) {
		t.Fatalf("context borrowed mutable request: %+v", got)
	}
	if err := state.save(); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(state.record)
	if err != nil {
		t.Fatal(err)
	}
	assertPublicExecutionCapacity(t, body, map[string]int{"parallel": 2, "memory_limit_mib": 512}, 2, 512)
	resolved, err := json.Marshal(state.record.Resolved)
	if err != nil || bytes.Contains(resolved, []byte("execution")) || bytes.Contains(resolved, []byte("memory_limit_mib")) || bytes.Contains(resolved, []byte("parallel")) {
		t.Fatal("execution capacity became scenario selection authority", err)
	}
}

// full_only: false
func TestSavedExecutionCapacityPlanRunParity(t *testing.T) {
	cases := []struct {
		name             string
		flags            []string
		requested        map[string]int
		parallel, memory int
		refused          bool
	}{
		{name: "defaults", requested: map[string]int{}, parallel: 4, memory: 8192},
		{name: "parallel_one", flags: []string{"--parallel=1"}, requested: map[string]int{"parallel": 1}, parallel: 1, memory: 8192},
		{name: "parallel_two", flags: []string{"--parallel=2"}, requested: map[string]int{"parallel": 2}, parallel: 2, memory: 8192},
		{name: "parallel_three", flags: []string{"--parallel=3"}, requested: map[string]int{"parallel": 3}, parallel: 3, memory: 8192},
		{name: "parallel_four_memory_minimum", flags: []string{"--parallel=4", "--memory-limit-mib=1"}, requested: map[string]int{"parallel": 4, "memory_limit_mib": 1}, parallel: 4, memory: 1},
		{name: "memory_maximum", flags: []string{"--memory-limit-mib=24576"}, requested: map[string]int{"memory_limit_mib": 24576}, parallel: 4, memory: 8192},
		{name: "parallel_zero", flags: []string{"--parallel=0"}, refused: true},
		{name: "parallel_negative", flags: []string{"--parallel=-1"}, refused: true},
		{name: "parallel_over_maximum", flags: []string{"--parallel=5"}, refused: true},
		{name: "parallel_fraction", flags: []string{"--parallel=1.5"}, refused: true},
		{name: "parallel_null", flags: []string{"--parallel=null"}, refused: true},
		{name: "parallel_duplicate", flags: []string{"--parallel=1", "--parallel=1"}, refused: true},
		{name: "memory_zero", flags: []string{"--memory-limit-mib=0"}, refused: true},
		{name: "memory_negative", flags: []string{"--memory-limit-mib=-1"}, refused: true},
		{name: "memory_over_maximum", flags: []string{"--memory-limit-mib=24577"}, refused: true},
		{name: "memory_fraction", flags: []string{"--memory-limit-mib=1.5"}, refused: true},
		{name: "memory_null", flags: []string{"--memory-limit-mib=null"}, refused: true},
		{name: "memory_duplicate", flags: []string{"--memory-limit-mib=512", "--memory-limit-mib=512"}, refused: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root, suite, environment := savedSelectionFixture(t)
			var firstPlan []byte
			for _, command := range []string{"plan", "run"} {
				args := append([]string{command, "--suite", suite, "--environment", environment}, test.flags...)
				request, err := parseRunRequest(args)
				if test.refused {
					if err == nil {
						t.Fatalf("%s accepted invalid capacity", command)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s refused valid capacity: %v", command, err)
				}
				var output bytes.Buffer
				if err := json.NewEncoder(&output).Encode(runRecord{Resolved: request.Resolved, Execution: recordExecutionPolicy(request.execution), EffectiveTelemetry: request.effectiveTelemetry}); err != nil {
					t.Fatal(err)
				}
				assertPublicExecutionCapacity(t, output.Bytes(), test.requested, test.parallel, test.memory)
				if firstPlan == nil {
					firstPlan = append([]byte(nil), output.Bytes()...)
				} else if !bytes.Equal(firstPlan, output.Bytes()) {
					t.Fatal("plan and run resolved different public capacity or selection")
				}
			}
			if _, err := os.Stat(filepath.Join(root, "tests")); !os.IsNotExist(err) {
				t.Fatal("capacity resolution created execution state")
			}
		})
	}
}
