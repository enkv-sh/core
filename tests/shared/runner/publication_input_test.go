package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	protocol "enkv.sh/sdk/protocols/output"
)

func publicationParentFixture(t *testing.T, provider, scenario string) ([]selectedOutputProfile, assemblyClosure, string, string) {
	t.Helper()
	path, raw := mixedOutputInput(t, provider)
	environment, err := loadOutputEnvironment(t, path, raw)
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := catalog.Resolve(catalog.Request{Include: []string{scenario}, Repetitions: 1})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := selectPublicationOutputs(schedule, environment)
	if err != nil {
		t.Fatal(err)
	}
	runID := strings.Repeat("a", 32)
	bindings, err := publicationAssemblyBindings(runID, selected)
	if err != nil {
		t.Fatal(err)
	}
	closure := assemblyClosure{Suite: "live", Provider: provider, Race: true}
	for _, binding := range bindings {
		// This fixture supplies complete structural metadata, without claiming
		// on-disk source or executable verification.
		closure.OutputArtifacts = append(closure.OutputArtifacts, testOutputClosure(t, binding.StoredProfileID, false))
	}
	owner, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(owner, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	build := filepath.Join(private, "build")
	if err := os.Mkdir(build, 0700); err != nil {
		t.Fatal(err)
	}
	return selected, closure, private, build
}

func publicationCaseState(t *testing.T, private string) string {
	t.Helper()
	state := filepath.Join(private, "0000-publication-case")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	return state
}

// full_only: false
func TestPublicationInputPreparationAndProjections(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			scenario := "publication.mixed-destinations/plain1_secret1_initial_noop_delete_mixed4"
			selected, closure, private, build := publicationParentFixture(t, provider, scenario)
			state := publicationCaseState(t, private)
			parent, err := preparePublicationInput(state, strings.Repeat("a", 32), "case-writer", scenario, selected, build, closure)
			if err != nil {
				t.Fatal(err)
			}
			if parent.Scope.RunID != strings.Repeat("a", 32) || parent.Scope.Scenario != scenario || parent.Scope.WriterID != "case-writer" || len(parent.Scope.DomainID) != 64 || parent.Scope.DomainID == strings.Repeat("0", 64) || len(parent.Profiles) != 4 {
				t.Fatal("scope or complete selected profile set changed")
			}
			inventory, err := records.ReadOutputFixtureInventory(parent.InventoryPath, parent.Scope)
			if err != nil || len(inventory.Rows) != 8 || len(inventory.Actors) != 0 {
				t.Fatal("initial exclusive inventory unavailable", err)
			}
			if _, err := os.Lstat(parent.JoinedPath); !os.IsNotExist(err) {
				t.Fatal("prelaunch join proof created")
			}
			suffix := strings.ToUpper(parent.Scope.DomainID[:32])
			cloudScope := "aws-secrets-manager"
			cloudSlot := "arn:aws:secretsmanager:example-region:123456789012:secret:enkv-output-positive-"
			if provider == "gcp" {
				cloudScope = "gcp-secret-manager"
				cloudSlot = "projects/123456789012/secrets/enkv-output-positive-"
			}
			wantScopes := []string{cloudScope, "github-repository", "github-organization", "github-environment"}
			wantPrefixes := []string{cloudSlot, "repos/example-owner/example-repository/actions/secrets/ENKV_", "orgs/example-owner/actions/secrets/ENKV_", "repos/example-owner/example-repository/environments/production/secrets/ENKV_"}
			for i, p := range parent.Profiles {
				if p.Scope != wantScopes[i] || p.Namespace != "positive" || p.ProfileID != "ENKV/OUTPUT/"+strings.ToUpper(wantScopes[i])+"/v3" {
					t.Fatal("selected profile mapping changed")
				}
				for j, end := range []string{"_P", "_S"} {
					target := p.Targets[j]
					want := wantPrefixes[i] + suffix + end
					consumer := want
					if i == 0 {
						if provider == "aws" {
							consumer += "?stage=AWSCURRENT"
						} else {
							consumer += "/versions/latest"
						}
					}
					if target.Index != uint32(2*i+j) || target.PlannedSlot != want || target.ConsumerLocator != consumer {
						t.Fatalf("target %d/%d coordinate changed", i, j)
					}
					row := inventory.Rows[2*i+j]
					if row.ProfileID != p.ProfileID || row.PlannedSlot != want || row.ExclusiveNamespaceDigest != target.ExclusiveNamespaceDigest || len(row.Attempts) != 0 || row.Cleanup != nil || row.BirthAttemptID != "" || row.OwnedInstance != "" {
						t.Fatal("initial row acquired effect or lost reservation")
					}
				}
				if p.Targets[0].ExclusiveNamespaceDigest != p.Targets[1].ExclusiveNamespaceDigest {
					t.Fatal("profile reservation digest diverged")
				}
				if _, err := os.Stat(p.Native.CredentialPath); !os.IsNotExist(err) {
					t.Fatal("preparation opened native credential route")
				}
				for _, actor := range []*records.OutputFixtureActor{p.Writer, p.Cleaner, p.ConsumerA, p.ConsumerB} {
					if actor != nil {
						if _, err := os.Stat(actor.CredentialsFile); !os.IsNotExist(err) {
							t.Fatal("preparation opened actor credentials")
						}
					}
				}
			}
			writer, err := parent.WriterProjection()
			if err != nil {
				t.Fatal(err)
			}
			cleaner, err := parent.CleanerProjection()
			if err != nil {
				t.Fatal(err)
			}
			for i, p := range writer.Profiles {
				if p.Cleaner != nil || p.Writer == nil || p.Native == nil || cleaner.Profiles[i].Cleaner == nil || cleaner.Profiles[i].Writer != nil || cleaner.Profiles[i].Native != nil || cleaner.Profiles[i].ConsumerA != nil || cleaner.Profiles[i].ConsumerB != nil {
					t.Fatal("child projection exceeded role")
				}
			}
			before, _ := json.Marshal(parent)
			writer.Profiles[0].Targets[0].PlannedSlot = "changed"
			cleaner.Profiles[1].GitHub.Owner = "changed"
			after, _ := json.Marshal(parent)
			if string(before) != string(after) {
				t.Fatal("projection borrowed parent memory")
			}
			prior, err := os.ReadFile(parent.InventoryPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := preparePublicationInput(state, strings.Repeat("a", 32), "case-writer", scenario, selected, build, closure); err == nil {
				t.Fatal("existing inventory replaced")
			}
			now, _ := os.ReadFile(parent.InventoryPath)
			if string(prior) != string(now) {
				t.Fatal("failed reservation replaced original inventory")
			}
		})
	}
}

// full_only: false
func TestPublicationInputAllScopesAndNamespaces(t *testing.T) {
	for _, scope := range []string{"aws-secrets-manager", "gcp-secret-manager", "github-repository", "github-organization", "github-environment"} {
		for _, condition := range []string{"plain-secret-lifecycle", "later-member-refusal"} {
			t.Run(scope+"/"+condition, func(t *testing.T) {
				provider := "aws"
				if scope == "gcp-secret-manager" {
					provider = "gcp"
				}
				child := "plain1_secret1_create_value_delete"
				if scope == "github-organization" {
					child = "plain1_secret1_create_value_policy_delete"
				}
				if scope == "github-repository" || scope == "github-environment" {
					child = "plain1_secret1_create_value_inherited_policy_delete"
				}
				if condition == "later-member-refusal" {
					child = "plain1_secret1_first_target_ack_later_not_sent"
				}
				scenario := "publication." + scope + "." + condition + "/" + child
				selected, closure, private, build := publicationParentFixture(t, provider, scenario)
				state := publicationCaseState(t, private)
				input, err := preparePublicationInput(state, strings.Repeat("a", 32), "case-writer", scenario, selected, build, closure)
				if err != nil || len(input.Profiles) != 1 {
					t.Fatal("scope reservation refused", err)
				}
				want := "positive"
				if condition == "later-member-refusal" {
					want = "ambiguity"
				}
				if input.Profiles[0].Namespace != want {
					t.Fatal("wrong fixture namespace")
				}
				second := filepath.Join(private, "second")
				if os.Mkdir(second, 0700) != nil {
					t.Fatal("directory")
				}
				again, err := preparePublicationInput(second, strings.Repeat("a", 32), "case-writer", scenario, selected, build, closure)
				if err != nil || input.Scope.DomainID == again.Scope.DomainID || input.Profiles[0].Targets[0].PlannedSlot == again.Profiles[0].Targets[0].PlannedSlot {
					t.Fatal("case reused a Domain or slot", err)
				}
			})
		}
	}
	for _, namespace := range []string{"positive", "ambiguity"} {
		for _, tc := range []struct {
			prefixLength int
			entryLength  int
			admitted     bool
		}{
			{222, 256, true},
			{223, 257, false},
		} {
			t.Run(fmt.Sprintf("aws-prefix-entry-bound/%s/prefix-%d-entry-%d", namespace, tc.prefixLength, tc.entryLength), func(t *testing.T) {
				path, input := outputEnvironmentInput(t, "aws")
				suffix := "-output-" + namespace + "-"
				prefix := strings.Repeat("A", tc.prefixLength-len(suffix)) + suffix
				for _, roleSuffix := range []string{"_P", "_S"} {
					name := prefix + strings.Repeat("A", 32) + roleSuffix
					if len(prefix) != tc.prefixLength || len(name) != tc.entryLength {
						t.Fatal("independent AWS allocation width differs")
					}
				}
				target := input["output_targets"].(map[string]any)[namespace].(map[string]any)
				target["secret_name_prefix"] = prefix
				environment, err := loadOutputEnvironment(t, path, input)
				if (err == nil) != tc.admitted {
					t.Fatalf("AWS %s prefix length %d admitted=%t want=%t: %v", namespace, tc.prefixLength, err == nil, tc.admitted, err)
				}
				if tc.admitted && environment.OutputTargets[namespace].SecretNamePrefix != prefix {
					t.Fatal("environment changed independently fixed AWS prefix")
				}
				for _, role := range []string{"writer", "cleaner", "consumer_a", "consumer_b"} {
					credential := filepath.Join(filepath.Dir(path), "output-"+namespace+"-"+role)
					if _, err := os.Stat(credential); !os.IsNotExist(err) {
						t.Fatal("AWS prefix admission opened or created credentials", credential, err)
					}
				}
			})
		}
	}
}

// full_only: false
func TestPublicationInputRefusesChangedNativeBindingBeforeInventory(t *testing.T) {
	for _, damage := range []string{"missing", "duplicate", "descriptor", "config", "namespace", "actor", "bounds"} {
		t.Run(damage, func(t *testing.T) {
			scenario := "publication.github-repository.plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete"
			selected, closure, private, build := publicationParentFixture(t, "aws", scenario)
			state := publicationCaseState(t, private)
			switch damage {
			case "missing":
				closure.OutputArtifacts = nil
			case "duplicate":
				closure.OutputArtifacts = append(closure.OutputArtifacts, closure.OutputArtifacts[0])
			case "descriptor":
				closure.OutputArtifacts[0].Artifact.DescriptorID = protocol.ID(sha256.Sum256([]byte("other-permission")))
			case "config":
				closure.OutputArtifacts[0].Artifact.ConfigContractID = "different/config/v1"
			case "namespace":
				selected[0].Namespace = "ambiguity"
			case "actor":
				selected[0].GitHub.Cleaner.CredentialsFile = selected[0].GitHub.Writer.CredentialsFile
			case "bounds":
				selected[0].GitHub.SecretNamePrefix = strings.Repeat("A", 67)
			}
			if _, err := preparePublicationInput(state, strings.Repeat("a", 32), "case-writer", scenario, selected, build, closure); err == nil {
				t.Fatal("changed input admitted")
			}
			if _, err := os.Stat(filepath.Join(state, "output-inventory.json")); !os.IsNotExist(err) {
				t.Fatal("refused input initialized inventory")
			}
		})
	}
}

// full_only: false
func TestPublicationJoinedRequiresStartedExactSettledWriterGroup(t *testing.T) {
	for _, condition := range []string{"prelaunch", "unjoined", "group-unjoined", "wrong-worker", "wrong-run", "wrong-scenario", "wrong-state", "failed-joined", "passed-joined", "marker-save-failed"} {
		t.Run(condition, func(t *testing.T) {
			scenario := "publication.github-repository.plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete"
			selected, closure, private, build := publicationParentFixture(t, "aws", scenario)
			state := publicationCaseState(t, private)
			parent, err := preparePublicationInput(state, strings.Repeat("a", 32), "case-writer", scenario, selected, build, closure)
			if err != nil {
				t.Fatal(err)
			}
			writer, err := parent.WriterProjection()
			if err != nil {
				t.Fatal(err)
			}
			inv := records.Invocation{RunID: parent.Scope.RunID, Scenario: scenario, Worker: "case-writer", Role: "writer", StateDir: state}
			process := processResult{Status: "passed", Started: true, Joined: true}
			group := true
			switch condition {
			case "prelaunch":
				process.Started = false
			case "unjoined":
				process.Joined = false
			case "group-unjoined":
				group = false
			case "wrong-worker":
				inv.Worker = "other-writer"
			case "wrong-run":
				inv.RunID = strings.Repeat("b", 32)
			case "wrong-scenario":
				inv.Scenario = "publication.github-repository.later-member-refusal/plain1_secret1_first_target_ack_later_not_sent"
			case "wrong-state":
				inv.StateDir = private
			case "failed-joined":
				process.Status = "process_failed"
			case "marker-save-failed":
				if os.Mkdir(writer.JoinedPath, 0700) != nil {
					t.Fatal("joined marker obstruction unavailable")
				}
			}
			route := writer.Profiles[0].Native.CredentialPath
			if os.WriteFile(route, []byte("local-test-route"), 0600) != nil {
				t.Fatal("route")
			}
			if removePublicationRoutes(writer) == nil {
				t.Fatal("route removed before marker")
			}
			err = writePublicationJoined(writer, inv, process, group)
			want := condition == "failed-joined" || condition == "passed-joined"
			if (err == nil) != want {
				t.Fatal("join qualification changed", err)
			}
			if want {
				if records.ReadOutputFixtureJoined(writer.JoinedPath, writer.Scope) != nil {
					t.Fatal("exact joined marker missing")
				}
				if removePublicationRoutes(writer) != nil {
					t.Fatal("joined route removal refused")
				}
				if _, err := os.Stat(route); !os.IsNotExist(err) {
					t.Fatal("joined route retained")
				}
				if writePublicationJoined(writer, inv, process, group) == nil {
					t.Fatal("joined marker replaced")
				}
			} else {
				if condition == "marker-save-failed" {
					cleaner, err := parent.CleanerProjection()
					if err != nil || records.ReadOutputFixtureJoined(writer.JoinedPath, writer.Scope) == nil || removePublicationRoutes(writer) == nil || validateRecordedPublicationInventory(cleaner, true) == nil {
						t.Fatal("failed join publication admitted route disposal or cleanup")
					}
				} else if _, err := os.Stat(writer.JoinedPath); !os.IsNotExist(err) {
					t.Fatal("unqualified marker created")
				}
				if _, err := os.Stat(route); err != nil {
					t.Fatal("unjoined route removed")
				}
			}
		})
	}
}

// full_only: false
func TestPublicationRetainedEvidenceRefusesInputInventoryAndJoinDamage(t *testing.T) {
	for _, identity := range []string{"current", "historical"} {
		t.Run(identity, func(t *testing.T) {
			for _, damage := range []string{"none", "writer-source", "cleaner-source", "target", "route", "inventory", "join", "namespace-digest", "original-run"} {
				t.Run(damage, func(t *testing.T) {
					scenario := "publication.github-repository.plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete"
					selected, closure, private, build := publicationParentFixture(t, "aws", scenario)
					state := publicationCaseState(t, private)
					if identity == "historical" {
						oldState := filepath.Join(private, "0000-publication-github-repository-plain-secret-lifecycle")
						if os.Rename(state, oldState) != nil {
							t.Fatal("historical state unavailable")
						}
						state = oldState
					}
					parent, err := preparePublicationInput(state, strings.Repeat("a", 32), "case-writer", scenario, selected, build, closure)
					if err != nil {
						t.Fatal(err)
					}
					w, _ := parent.WriterProjection()
					c, _ := parent.CleanerProjection()
					if identity == "historical" {
						inventory, readErr := records.ReadOutputFixtureInventory(w.InventoryPath, w.Scope)
						if readErr != nil {
							t.Fatal("historical inventory fixture unavailable", readErr)
						}
						scenario = "publication.github-repository.plain-secret-lifecycle"
						w.Scope.Scenario, c.Scope.Scenario = scenario, scenario
						inventory.Scope.Scenario = scenario
						if records.WriteJSON(w.InventoryPath, inventory, 0600) != nil {
							t.Fatal("historical inventory scope unavailable")
						}
					}
					writer := workerInput{RunID: parent.Scope.RunID, Scenarios: []string{scenario}, Repetitions: 1, Participants: map[string]string{"authority": "authority"}, Outputs: w}
					cleaner := writer.authorityOnly()
					cleaner.Outputs = c
					digest, _ := publicationEvidenceDigest(w, c)
					result := scenarioResult{Entry: catalog.Entry{Scenario: scenario}, Writer: &workerEvidence{Worker: "case-writer", Joined: true}, OutputsSHA256: digest}
					record := runRecord{RunID: parent.Scope.RunID, BuildClosure: &closure}
					if records.WriteOutputFixtureJoined(w.JoinedPath, w.Scope) != nil {
						t.Fatal("join")
					}
					// Preserve uncertain birth history. Validation may read it but must not replay it.
					attempt := strings.Repeat("c", 64)
					if records.BeginOutputFixtureAction(w.InventoryPath, w.Scope, 0, attempt, 1) != nil {
						t.Fatal("intent")
					}
					prior, _ := os.ReadFile(w.InventoryPath)
					switch damage {
					case "writer-source":
						writer.Prefix = "changed"
					case "cleaner-source":
						cleaner.Prefix = "changed"
					case "target":
						c.Profiles[0].Targets[0].PlannedSlot += "changed"
					case "route":
						w.Profiles[0].Native.CredentialRouteID = strings.Repeat("d", 64)
					case "inventory":
						if os.Remove(w.InventoryPath) != nil {
							t.Fatal("remove")
						}
					case "join":
						if os.Remove(w.JoinedPath) != nil {
							t.Fatal("remove")
						}
					case "namespace-digest":
						for i := range w.Profiles[0].Targets {
							w.Profiles[0].Targets[i].ExclusiveNamespaceDigest = strings.Repeat("d", 64)
							c.Profiles[0].Targets[i].ExclusiveNamespaceDigest = strings.Repeat("d", 64)
						}
						digest, _ = publicationEvidenceDigest(w, c)
						result.OutputsSHA256 = digest
					case "original-run":
						record.RunID = strings.Repeat("b", 32)
					}
					if records.WriteJSON(filepath.Join(state, "input.json"), writer, 0400) != nil || records.WriteJSON(filepath.Join(state, "cleanup-input.json"), cleaner, 0400) != nil {
						t.Fatal("input")
					}
					err = validateRetainedPublication(state, record, result)
					if (err == nil) != (damage == "none") {
						t.Fatal("retained evidence qualification changed", err)
					}
					if damage != "inventory" {
						now, _ := os.ReadFile(w.InventoryPath)
						if string(now) != string(prior) {
							t.Fatal("validation changed prior output evidence")
						}
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicationParentAuthorityAndContinuationNarrowing(t *testing.T) {
	scenario := "publication.github-repository.plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete"
	selected, closure, private, build := publicationParentFixture(t, "aws", scenario)
	parent, err := preparePublicationInput(publicationCaseState(t, private), strings.Repeat("a", 32), "case-writer", scenario, selected, build, closure)
	if err != nil {
		t.Fatal(err)
	}
	writer, _ := parent.WriterProjection()
	input := workerInput{Outputs: writer, Participants: map[string]string{"authority": "a", "reader": "b"}}
	if input.authorityOnly().Outputs != nil || input.freshAfterInput().Outputs != nil {
		t.Fatal("stripped input retained output authority")
	}
	before, _ := json.Marshal(input)
	_ = input.authorityOnly()
	_ = input.freshAfterInput()
	after, _ := json.Marshal(input)
	if string(before) != string(after) {
		t.Fatal("stripping changed retained writer")
	}
	retained, err := retainedOutputBindings(closure.OutputArtifacts)
	if err != nil {
		t.Fatal("structural retained bindings", err)
	}
	later, err := publicationAssemblyBindings(strings.Repeat("b", 32), selected)
	if err != nil {
		t.Fatal("later public bindings", err)
	}
	if !samePublicationBindings(later, retained) || !reflect.DeepEqual(later, retained) {
		t.Fatal("continuation changed the exact descriptor or credential route")
	}
	changed := append([]outputProfileBinding(nil), later...)
	changed[0].DescriptorID = protocol.ID(sha256.Sum256([]byte("different-location")))
	if samePublicationBindings(changed, retained) {
		t.Fatal("changed public location admitted")
	}
	original := closure
	changedClosure := closure
	changedClosure.OutputArtifacts = append([]*outputArtifactClosure(nil), closure.OutputArtifacts...)
	copy := *changedClosure.OutputArtifacts[0]
	copy.Artifact.CredentialRouteID = protocol.ID(sha256.Sum256([]byte("different-route")))
	changedClosure.OutputArtifacts[0] = &copy
	original.BinarySHA256 = "binary"
	original.OverlaySHA256 = "overlay"
	changedClosure.BinarySHA256 = "binary"
	changedClosure.OverlaySHA256 = "overlay"
	if sameAssemblyBuild(changedClosure, original) {
		t.Fatal("continuation ignored changed installed output binding")
	}
	if hex.EncodeToString(closure.OutputArtifacts[0].Artifact.CredentialRouteID[:]) != writer.Profiles[0].Native.CredentialRouteID {
		t.Fatal("parent input lost installed route")
	}
}

// full_only: false
func TestPublicationParentRetainsSuccessfulPrivateEvidence(t *testing.T) {
	root := workflowExecutionFixture(t)
	scenario := "publication.github-repository.plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete"
	selected, closure, _, _ := publicationParentFixture(t, "gcp", scenario)
	schedule, err := catalog.Resolve(catalog.Request{Include: []string{scenario}, Repetitions: 1})
	if err != nil {
		t.Fatal(err)
	}
	wantEntries := []catalog.Entry{
		{Scenario: "state.single-value-update-preserves-other-values/members_32", Smoke: true},
		{Scenario: scenario, Sequence: 1, Repetition: 1},
	}
	if !reflect.DeepEqual(schedule.Entries, wantEntries) {
		t.Fatal("publication retention fixture has an unexpected schedule", schedule.Entries)
	}
	var publicationEntry catalog.Entry
	for _, entry := range schedule.Entries {
		if entry.Scenario == scenario {
			publicationEntry = entry
		}
	}
	plan := workflowPlan{Execution: defaultExecutionPolicy(), SchemaVersion: 1, Name: "publication-owner-lifetime", Steps: []resolvedWorkflowStep{
		{ID: "publication", Kind: "run", Selected: true, request: runRequest{Suite: "live"}},
		{ID: "later", Kind: "run", Selected: true, request: runRequest{Suite: "live"}},
	}}
	laterFailure := errors.New("controlled later sibling failure")
	var child *runState
	var packet map[string][]byte
	result, err := executeWorkflow(t.Context(), root, plan, io.Discard, nil, nil, func(_ context.Context, step resolvedWorkflowStep, _ io.Writer, _ string) (workflowStepExecution, error) {
		if step.ID == "later" {
			assertPrivateRecoveryUnchanged(t, packet)
			if err := validatePublicationRunEvidence(root, child.directory, child.record); err != nil {
				t.Fatal("successful publication evidence was not retained for its later sibling", err)
			}
			return workflowStepExecution{}, laterFailure
		}
		owner := step.request.workflowRunID
		var enclosing workflowResult
		directory, err := records.ResolveRun(filepath.Join(root, "tests/workflows/runs"), owner)
		if err == nil {
			err = records.ReadJSON(filepath.Join(directory, "workflow.json"), &enclosing)
		}
		if err != nil || !records.ValidRunID(owner) || enclosing.RunID != owner {
			t.Fatal("publication child began without its actual enclosing workflow", err)
		}
		child, err = newRunState(root, runRequest{Suite: "live", Provider: "gcp", Target: "gcp", Schedule: schedule, workflowRunID: owner}, enclosing.Source, "controlled")
		if err != nil {
			t.Fatal(err)
		}
		build := filepath.Join(child.private, "build")
		if err := os.Mkdir(build, 0700); err != nil {
			t.Fatal(err)
		}
		name, err := recordedCaseDirectory(publicationEntry)
		if err != nil {
			t.Fatal(err)
		}
		state := filepath.Join(child.private, name)
		if err := os.Mkdir(state, 0700); err != nil {
			t.Fatal(err)
		}
		parent, err := preparePublicationInput(state, child.record.RunID, "case-writer", scenario, selected, build, closure)
		if err != nil {
			t.Fatal(err)
		}
		writer, err := parent.WriterProjection()
		if err != nil {
			t.Fatal(err)
		}
		cleaner, err := parent.CleanerProjection()
		if err != nil {
			t.Fatal(err)
		}
		input := workerInput{RunID: child.record.RunID, Scenarios: []string{scenario}, Repetitions: 1, Participants: map[string]string{"authority": "authority"}, Outputs: writer}
		cleanup := input.authorityOnly()
		cleanup.Outputs = cleaner
		if err := records.WriteJSON(filepath.Join(state, "input.json"), input, 0400); err != nil {
			t.Fatal(err)
		}
		if err := records.WriteJSON(filepath.Join(state, "cleanup-input.json"), cleanup, 0400); err != nil {
			t.Fatal(err)
		}
		if err := records.WriteOutputFixtureJoined(writer.JoinedPath, writer.Scope); err != nil {
			t.Fatal(err)
		}
		digest, err := publicationEvidenceDigest(writer, cleaner)
		if err != nil {
			t.Fatal(err)
		}
		child.record.BuildClosure = &closure
		for _, entry := range schedule.Entries {
			shape, err := recordedFixture(entry.Scenario, entry.Members)
			if err != nil {
				t.Fatal(err)
			}
			result := scenarioResult{Entry: entry, Fixture: shape, Outcome: "passed", CorrectnessPassed: true,
				Writer:  &workerEvidence{Worker: "smoke-writer", Role: "writer", Outcome: "passed", Process: "passed", Started: true, Joined: true},
				Cleanup: records.Cleanup{Outcome: "passed", RemainingOwnedObjects: new(int64), UnknownEffects: new(int64)}}
			if entry == publicationEntry {
				result.Writer.Worker = "case-writer"
				result.OutputsSHA256 = digest
			}
			child.record.Scenarios = append(child.record.Scenarios, result)
		}
		child.finish()
		if child.record.Outcome != "passed" || !runCleanupPassed(child.record) || !runProcessesJoined(child.record) {
			t.Fatal("completed publication lost successful cleanup or joins")
		}
		if err := validatePublicationRunEvidence(root, child.directory, child.record); err != nil {
			t.Fatal("publication packet did not qualify before finalization", err)
		}
		packet = map[string][]byte{}
		for _, path := range []string{filepath.Join(state, "input.json"), filepath.Join(state, "cleanup-input.json"), writer.InventoryPath, writer.JoinedPath} {
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			packet[path] = body
		}
		if err := child.finishCurrentRun(io.Discard, nil); err != nil {
			t.Fatal("successful publication finalization failed", err)
		}
		assertPrivateRecoveryUnchanged(t, packet)
		path := filepath.Join(child.directory, "run.json")
		var saved runRecord
		if err := records.ReadJSON(path, &saved); err != nil || saved.RunID != child.record.RunID || saved.ContinuationRootRunID != owner || !sameSource(saved.Source, enclosing.Source) || saved.Outcome != "passed" {
			t.Fatal("successful publication lost its persisted source and workflow binding", err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		packet[path] = body
		return workflowStepExecution{Suite: &child.record, Recovery: child.recovery}, nil
	})
	if !errors.Is(err, laterFailure) || result.Outcome != "failed" || len(result.Steps) != 2 || result.Steps[0].Outcome != "passed" || result.Steps[1].Outcome != "failed" {
		t.Fatal("controlled later sibling did not keep the enclosing obligation open", err)
	}
	if child == nil || child.record.Outcome != "passed" || child.record.ContinuationRootRunID != result.RunID || !sameSource(child.record.Source, result.Source) {
		t.Fatal("successful publication lost its enclosing source and workflow binding")
	}
	assertPrivateRecoveryUnchanged(t, packet)
	if err := validatePublicationRunEvidence(root, child.directory, child.record); err != nil {
		t.Fatal("enclosing failure discarded qualified publication evidence", err)
	}
}

// full_only: false
func TestPublicationNamespaceDigestUsesFixedLengthDelimitedPublicReservation(t *testing.T) {
	p := records.OutputFixtureProfile{ProfileID: "ENKV/OUTPUT/GITHUB-REPOSITORY/v3", Namespace: "positive", GitHub: &records.OutputFixtureGitHub{Owner: "example-owner", Repository: "example-repository", SecretNamePrefix: "ENKV_"}, Targets: []records.OutputFixtureTarget{{PlannedSlot: "repos/example-owner/example-repository/actions/secrets/ENKV_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_P"}, {PlannedSlot: "repos/example-owner/example-repository/actions/secrets/ENKV_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_S"}}}
	// Independent SHA-256 of the fixed domain prefix and six big-endian u32
	// length-prefixed fields, including the v3 profile ID and literal public location JSON.
	want := "9dc5dfbfb258f97d5cb1c16a406c018002d6fb65bdaeb9453e274c9f03bce01e"
	got, err := publicationNamespaceDigest(strings.Repeat("a", 64), p)
	if err != nil || got != want {
		t.Fatal("reservation digest changed", err)
	}
	p.Targets[1].PlannedSlot += "changed"
	changed, err := publicationNamespaceDigest(strings.Repeat("a", 64), p)
	if err != nil || changed == want {
		t.Fatal("reservation failed to bind both slots")
	}
}

// full_only: false
func TestPublicationScheduledCompletionRequiresExactBirthRowsAndJoin(t *testing.T) {
	for _, condition := range []string{"scheduled", "scheduled-empty-inventory", "store-cleanup-failure", "missing-join", "wrong-birth", "wrong-count", "unknown-before-delete", "missing-input", "changed-private-source", "missing-actors", "changed-actors", "missing-cleaner-output", "wrong-worker-count", "false-zero", "unknown-effects", "missing-count", "missing-phase", "failed-phase", "wrong-worker-actor", "unjoined-process", "wrong-cleanup-input", "unresolved-worker"} {
		t.Run(condition, func(t *testing.T) {
			scenario := "publication.aws-secrets-manager.plain-secret-lifecycle/plain1_secret1_create_value_delete"
			selected, closure, private, build := publicationParentFixture(t, "aws", scenario)
			ownedPrivate := filepath.Join(filepath.Dir(private), "runs", strings.Repeat("a", 32), "private")
			if os.MkdirAll(filepath.Dir(ownedPrivate), 0700) != nil || os.Rename(private, ownedPrivate) != nil {
				t.Fatal("controlled publication owner")
			}
			private, build = ownedPrivate, filepath.Join(ownedPrivate, "build")
			name, _ := catalog.Name(scenario)
			token, err := catalog.CaseDirectoryToken(name)
			if err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(private, "0000-"+token)
			if os.Mkdir(state, 0700) != nil {
				t.Fatal("state")
			}
			parent, err := preparePublicationInput(state, strings.Repeat("a", 32), "case-writer", scenario, selected, build, closure)
			if err != nil {
				t.Fatal(err)
			}
			w, _ := parent.WriterProjection()
			c, _ := parent.CleanerProjection()
			input := workerInput{Outputs: w, RunID: parent.Scope.RunID, Scenarios: []string{scenario}, Repetitions: 1, Settings: liveSettings{"test_mode": "publication_scheduled"}, Participants: map[string]string{"authority": "authority"}}
			if condition == "scheduled-empty-inventory" {
				input.Settings["test_mode"] = "publication_scheduled_empty"
			}
			if condition == "store-cleanup-failure" {
				input.Settings["test_mode"] = "publication_scheduled_store_failure"
			}
			cleanupInput := input.authorityOnly()
			cleanupInput.Outputs = c
			if condition == "missing-cleaner-output" {
				cleanupInput.Outputs = nil
			}
			digest, _ := publicationEvidenceDigest(w, c)
			remaining, zero := int64(1), int64(0)
			result := scenarioResult{Entry: catalog.Entry{Scenario: scenario}, OutputsSHA256: digest, OutputScheduled: 1, Outcome: "passed", Writer: &workerEvidence{Worker: "case-writer", Role: "writer", Joined: true}, Cleanup: records.Cleanup{Outcome: "passed", RemainingOwnedObjects: &remaining, UnknownEffects: &zero}}
			record := runRecord{RunID: parent.Scope.RunID, BuildClosure: &closure, Scenarios: []scenarioResult{result}, Cleanup: result.Cleanup}
			actors := publicationCapturedActors(w.Profiles[0])
			if condition == "changed-actors" {
				actors.ReaderA = "arn:aws:iam::123456789012:user/wrong-reader"
			}
			if records.SetOutputFixtureActors(w.InventoryPath, w.Scope, actors) != nil {
				t.Fatal("actors")
			}
			create, del := strings.Repeat("c", 64), strings.Repeat("d", 64)
			if records.BeginOutputFixtureAction(w.InventoryPath, w.Scope, 0, create, contract.PublicationCreateWithValue) != nil {
				t.Fatal("create intent")
			}
			owned := w.Profiles[0].Targets[0].PlannedSlot + "-Ab123Z"
			if condition == "wrong-birth" {
				owned = w.Profiles[0].Targets[0].PlannedSlot + "-ABCDE/"
			}
			deleteAction := uint8(contract.PublicationDeleteOwned)
			outcome, instance := "acknowledged", owned
			if condition == "unknown-before-delete" {
				outcome, instance = "unknown", ""
				deleteAction = contract.PublicationDeleteReservedSlot
			}
			if records.RecordOutputFixtureAction(w.InventoryPath, w.Scope, 0, create, outcome, instance) != nil {
				t.Fatal("create receipt")
			}
			if records.BeginOutputFixtureAction(w.InventoryPath, w.Scope, 0, del, deleteAction) != nil || records.RecordOutputFixtureAction(w.InventoryPath, w.Scope, 0, del, "acknowledged", "") != nil {
				t.Fatal("delete receipt")
			}
			if condition == "missing-actors" {
				// Deliberately damage an otherwise valid retained inventory after
				// action recording; the records API must refuse missing actors.
				inventory, err := records.ReadOutputFixtureInventory(w.InventoryPath, w.Scope)
				if err != nil {
					t.Fatal("inventory before damage", err)
				}
				inventory.Actors = nil
				if records.WriteJSON(w.InventoryPath, inventory, 0400) != nil {
					t.Fatal("actor damage")
				}
			}
			if condition != "missing-join" {
				if records.WriteOutputFixtureJoined(w.JoinedPath, w.Scope) != nil {
					t.Fatal("joined")
				}
			}
			if condition == "wrong-count" {
				record.Scenarios[0].OutputScheduled = 2
			}
			if condition == "changed-private-source" {
				c.Profiles[0].Cloud.Region = "different-region"
			}
			if condition != "missing-input" {
				if records.WriteJSON(filepath.Join(state, "input.json"), input, 0400) != nil {
					t.Fatal("writer")
				}
			}
			if records.WriteJSON(filepath.Join(state, "cleanup-input.json"), cleanupInput, 0400) != nil {
				t.Fatal("cleaner")
			}
			err = validatePublicationRunEvidence("", filepath.Dir(private), record)
			retainedAccepted := true
			switch condition {
			case "missing-join", "wrong-birth", "wrong-count", "unknown-before-delete", "missing-input", "changed-private-source", "missing-actors", "changed-actors", "missing-cleaner-output":
				retainedAccepted = false
			}
			if (err == nil) != retainedAccepted {
				t.Fatal("scheduled evidence gate changed", err)
			}
			inv, worker, _ := telemetryImportFixture(t)
			inv.RunID, inv.Scenario, inv.Role = parent.Scope.RunID, scenario, "cleanup"
			inv.StateDir, inv.Input = state, filepath.Join(state, "cleanup-input.json")
			worker.RunID, worker.Scenario, worker.Role, worker.Actor = inv.RunID, scenario, "cleanup", "authority"
			worker.Phases = []records.PhaseResult{
				{Sequence: 1, Name: "authentication", Actor: "authority", Expected: "success", Actual: "success", Outcome: "passed", MeasurementsExpected: true},
				{Sequence: 2, Name: "resource_check", Actor: "authority", Expected: "success", Actual: "success", Outcome: "passed", MeasurementsExpected: true},
				{Sequence: 3, Name: "cleanup", Actor: "authority", Expected: "success", Actual: "success", Outcome: "passed", MeasurementsExpected: true},
			}
			worker.Cleanup = &records.Cleanup{Outcome: "passed", RemainingOwnedObjects: &remaining, UnknownEffects: &zero, BudgetReserved: &records.BudgetReservation{Requests: 5}}
			process := processResult{Status: "passed", Joined: true}
			switch condition {
			case "scheduled-empty-inventory":
				worker.Cleanup.BudgetReserved = &records.BudgetReservation{}
				worker.Phases = []records.PhaseResult{{Sequence: 1, Name: "cleanup", Actor: "authority", Expected: "success", Actual: "success", Outcome: "passed", MeasurementsExpected: false}}
			case "wrong-worker-count":
				two := int64(2)
				worker.Cleanup.RemainingOwnedObjects = &two
			case "false-zero":
				worker.Cleanup.RemainingOwnedObjects = &zero
			case "unknown-effects":
				worker.Cleanup.UnknownEffects = &remaining
			case "missing-count":
				worker.Cleanup.RemainingOwnedObjects = nil
			case "missing-phase":
				worker.Phases = worker.Phases[:2]
			case "failed-phase":
				worker.Phases[2].Outcome = "incomplete"
			case "wrong-worker-actor":
				worker.Actor = "other"
			case "unjoined-process":
				process.Joined = false
			case "wrong-cleanup-input":
				inv.Input = filepath.Join(state, "other-cleanup-input.json")
				if records.WriteJSON(inv.Input, cleanupInput, 0400) != nil {
					t.Fatal("alternate cleaner")
				}
			case "unresolved-worker":
				worker.Cleanup.Outcome = "unresolved"
			}
			if records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), worker, 0600) != nil {
				t.Fatal("cleanup worker")
			}
			s := &runState{directory: filepath.Dir(private), record: record}
			s.record.Suite = "live"
			evidence, raw, admissionErr := s.importWorker(inv, scenario, process, nil)
			accepted := condition == "scheduled" || condition == "scheduled-empty-inventory" || condition == "store-cleanup-failure" || condition == "wrong-count"
			if (admissionErr == nil) != accepted || (evidence.Outcome == "passed") != accepted {
				t.Error("exact cleanup admission changed", admissionErr)
			}
			if cleanupPassed(safeCleanup(raw, evidence)) {
				t.Fatal("scheduled residue granted generic zero-only success")
			}
			if cleanupPassed(result.Cleanup) {
				t.Fatal("aggregate-only gate accepted scheduled residue")
			}
			if condition == "scheduled" || condition == "scheduled-empty-inventory" || condition == "store-cleanup-failure" {
				inv.FailureSources = controlledFailureSources(t, private)
				inv.OutputDir = filepath.Join(state, "controlled-cleanup")
				inv, err = makeInvocation(inv, "live")
				if err != nil || records.WriteJSON(filepath.Join(state, "inventory.json"), struct{}{}, 0400) != nil {
					t.Fatal("controlled cleanup invocation")
				}
				binary, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				wantBudget := records.BudgetReservation{Requests: 5, BodyBytes: 6}
				if condition == "scheduled-empty-inventory" {
					wantBudget = records.BudgetReservation{}
				}
				s.record.Scenarios[0].OutputScheduled = 0
				joined, cleanup := s.executeCleanup(context.Background(), binary, inv, scenario, testLimits())
				if condition == "store-cleanup-failure" {
					if joined == nil || !joined.Joined || joined.Process != "process_failed" || cleanup.Outcome != "unresolved" || cleanup.HarnessFailure == nil || cleanup.HarnessFailure.Operation != "object_cleanup" || cleanup.RemainingOwnedObjects == nil || *cleanup.RemainingOwnedObjects != 2 || cleanup.UnknownEffects == nil || *cleanup.UnknownEffects != 1 || s.record.Scenarios[0].OutputScheduled != 1 {
						t.Fatal("Store failure lost independent scheduled output facts", joined, cleanup, s.record.Scenarios[0].OutputScheduled)
					}
					s.record.Scenarios[0].Cleanup = cleanup
					s.record.Scenarios[0].Outcome = "failed"
					if scenarioCleanupPassed(s.record.Scenarios[0]) || validatePublicationRunEvidence("", s.directory, s.record) != nil {
						t.Fatal("failed Store cleanup became success or lost qualified output evidence")
					}
					return
				}
				if joined == nil || joined.Outcome != "passed" || joined.Process != "passed" || !joined.Joined || joined.Failure != nil || cleanup.Outcome != "passed" || cleanup.Failure != nil || cleanup.HarnessFailure != nil || cleanup.RemainingOwnedObjects == nil || *cleanup.RemainingOwnedObjects != 1 || cleanup.UnknownEffects == nil || *cleanup.UnknownEffects != 0 || cleanup.BudgetReserved == nil || *cleanup.BudgetReserved != wantBudget || cleanupPassed(cleanup) {
					t.Fatal("exact scheduled cleanup was not promoted", joined, cleanup)
				}
				qualified := s.record.Scenarios[0]
				qualified.Cleanup, qualified.CleanupWorker = cleanup, joined
				s.record.Scenarios[0], s.record.Cleanup = qualified, cleanup
				if !scenarioCleanupPassed(qualified) || !runCleanupPassed(s.record) || !validScenarioAttemptCleanup(cleanup, qualified) || !completeWorkerPhases("cleanup", joined.Actor, joined.Phases, scenario, "live", input.Participants, &cleanup, "", nil) || validatePublicationRunEvidence("", s.directory, s.record) != nil {
					t.Fatal("later scheduled cleanup gates refused exact evidence")
				}
				if !scenarioCleanupPassed(result) || !runCleanupPassed(record) {
					t.Fatal("qualified scheduled operation refused")
				}
				zeroRun := record
				zeroRun.Cleanup = records.Cleanup{Outcome: "passed", RemainingOwnedObjects: &zero, UnknownEffects: &zero}
				if runCleanupPassed(zeroRun) {
					t.Fatal("aggregate discarded scheduled residue")
				}
			}
		})
	}
}

// full_only: false
func TestPublicationStoreOnlyResultPreservesOriginalResidue(t *testing.T) {
	for _, scenario := range []string{"publication.aws-secrets-manager.plain-secret-lifecycle/plain1_secret1_create_value_delete", "publication.gcp-secret-manager.plain-secret-lifecycle/plain1_secret1_create_value_delete", "publication.github-repository.plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete"} {
		for _, unknown := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/unknown=%t", scenario, unknown), func(t *testing.T) {
				provider := "aws"
				if strings.Contains(scenario, "gcp-secret-manager") {
					provider = "gcp"
				}
				selected, closure, private, build := publicationParentFixture(t, provider, scenario)
				name, _ := catalog.Name(scenario)
				token, err := catalog.CaseDirectoryToken(name)
				if err != nil {
					t.Fatal(err)
				}
				state := filepath.Join(private, "0000-"+token)
				if os.Mkdir(state, 0700) != nil {
					t.Fatal("Store-only publication state")
				}
				parent, err := preparePublicationInput(state, strings.Repeat("a", 32), "case-writer", scenario, selected, build, closure)
				if err != nil {
					t.Fatal(err)
				}
				w, _ := parent.WriterProjection()
				if records.WriteOutputFixtureJoined(w.JoinedPath, w.Scope) != nil {
					t.Fatal("join")
				}
				if w.Profiles[0].Cloud != nil {
					if records.SetOutputFixtureActors(w.InventoryPath, w.Scope, publicationCapturedActors(w.Profiles[0])) != nil {
						t.Fatal("actors")
					}
				}
				attempt := strings.Repeat("c", 64)
				if records.BeginOutputFixtureAction(w.InventoryPath, w.Scope, 0, attempt, contract.PublicationCreateWithValue) != nil {
					t.Fatal("create")
				}
				if !unknown {
					owned := w.Profiles[0].Targets[0].PlannedSlot
					if provider == "aws" && w.Profiles[0].Cloud != nil {
						owned += "-Ab123Z"
					}
					if records.RecordOutputFixtureAction(w.InventoryPath, w.Scope, 0, attempt, "acknowledged", owned) != nil {
						t.Fatal("receipt")
					}
				}
				if !unknown && w.Profiles[0].Scope == "aws-secrets-manager" {
					del := strings.Repeat("d", 64)
					if records.BeginOutputFixtureAction(w.InventoryPath, w.Scope, 0, del, contract.PublicationDeleteOwned) != nil || records.RecordOutputFixtureAction(w.InventoryPath, w.Scope, 0, del, "acknowledged", "") != nil {
						t.Fatal("delete")
					}
				}
				before, _ := os.ReadFile(w.InventoryPath)
				residue, err := publicationResidueState(w)
				if err != nil {
					t.Fatal(err)
				}
				zero := int64(0)
				store := records.Cleanup{Outcome: "passed", RemainingOwnedObjects: &zero, UnknownEffects: &zero}
				merged := preservePublicationResidue(store, residue)
				wantUnknown := int64(0)
				if unknown {
					wantUnknown = 1
				}
				if *merged.RemainingOwnedObjects != 1 || *merged.UnknownEffects != wantUnknown {
					t.Fatal("Store success erased output residue")
				}
				if unknown || w.Profiles[0].Scope != "aws-secrets-manager" {
					if merged.Outcome != "unresolved" || merged.HarnessFailure == nil || !merged.HarnessFailure.Validate() || merged.HarnessFailure.Operation != "output_cleanup" || merged.HarnessFailure.TargetKind != "output_inventory" {
						t.Fatal("output residue was upgraded or lost typed failure")
					}
				} else {
					if merged.Outcome != "passed" || residue.Scheduled != 1 {
						t.Fatal("known schedule became erasure or unknown")
					}
				}
				copy := workerInput{Outputs: w}.authorityOnly()
				if copy.Outputs.Validate(records.OutputFixtureScope{}, "rerun") != nil {
					t.Fatal("Store-only projection retained output authority")
				}
				inv, worker, _ := telemetryImportFixture(t)
				inv.Scenario, inv.Role = scenario, "cleanup"
				inv.StateDir, inv.Input = state, filepath.Join(state, "cleanup-retry-input-2.json")
				inv.OutputDir = filepath.Join(state, "workers", "cleanup-retry-2")
				if os.MkdirAll(inv.OutputDir, 0700) != nil {
					t.Fatal("Store-only worker owner")
				}
				worker.Scenario, worker.Role, worker.Actor = scenario, "cleanup", "operator"
				copy.RecoveryMode, copy.Participants = "disabled", map[string]string{"authority": "operator"}
				copy.CleanupRetry = &cleanupRetryInput{TargetIndex: 0, Ordinal: 2}
				if records.WriteJSON(inv.Input, copy, 0400) != nil {
					t.Fatal("Store-only worker input")
				}
				worker.Cleanup = &records.Cleanup{Outcome: "passed", RemainingOwnedObjects: &zero, UnknownEffects: &zero, BudgetReserved: &records.BudgetReservation{Requests: 5}}
				worker.Phases = []records.PhaseResult{
					{Sequence: 1, Name: "authentication", Actor: "operator", Expected: "success", Actual: "success", Outcome: "passed", MeasurementsExpected: true},
					{Sequence: 2, Name: "resource_check", Actor: "operator", Expected: "success", Actual: "success", Outcome: "passed", MeasurementsExpected: true},
					{Sequence: 3, Name: "cleanup", Actor: "operator", Expected: "success", Actual: "success", Outcome: "passed", MeasurementsExpected: true},
				}
				if records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), worker, 0600) != nil {
					t.Fatal("Store-only worker result")
				}
				index := uint32(0)
				s := &runState{directory: filepath.Dir(private), record: runRecord{Suite: "live", RunID: inv.RunID, Scenarios: []scenarioResult{{Entry: catalog.Entry{Scenario: scenario}, CleanupAttempts: []cleanupAttemptEvidence{{Ordinal: 1}, {Ordinal: 2, Decision: "gcp_exact_generation", TargetIndex: &index}}}}}}
				evidence, raw, err := s.importWorker(inv, scenario, processResult{Status: "passed", Joined: true}, nil)
				if err != nil || !cleanupPassed(safeCleanup(raw, evidence)) {
					t.Fatal("Store-only zero cleanup refused", err)
				}
				alternate := inv
				alternate.Input = filepath.Join(state, "alternate-store-input.json")
				if records.WriteJSON(alternate.Input, copy, 0400) != nil {
					t.Fatal("alternate Store input")
				}
				if _, _, err := s.importWorker(alternate, scenario, processResult{Status: "passed", Joined: true}, nil); err == nil {
					t.Fatal("arbitrary Store-only path admitted")
				}
				copy.CleanupRetry = nil
				copy.CleanupGrant = &cleanupGrantInput{GrantRunID: inv.RunID}
				granted := inv
				granted.Input, granted.OutputDir = filepath.Join(state, "granted", "input.json"), filepath.Join(state, "granted", "cleanup")
				if os.MkdirAll(granted.OutputDir, 0700) != nil || records.WriteJSON(granted.Input, copy, 0400) != nil || records.WriteJSON(filepath.Join(granted.OutputDir, "worker.json"), worker, 0600) != nil {
					t.Fatal("granted Store-only worker")
				}
				if _, _, err := s.importWorker(granted, scenario, processResult{Status: "passed", Joined: true}, nil); err == nil {
					t.Fatal("Store-only grant without recovery admitted")
				}
				s.record.RecoveryRunID = strings.Repeat("b", 32)
				if _, _, err := s.importWorker(granted, scenario, processResult{Status: "passed", Joined: true}, nil); err != nil {
					t.Fatal("granted Store-only zero cleanup refused", err)
				}
				one := int64(1)
				worker.Cleanup.RemainingOwnedObjects = &one
				if records.WriteJSON(filepath.Join(inv.OutputDir, "worker.json"), worker, 0600) != nil {
					t.Fatal("forged Store-only count")
				}
				if _, _, err := s.importWorker(inv, scenario, processResult{Status: "passed", Joined: true}, nil); err == nil {
					t.Fatal("Store-only worker admitted scheduled count without exact proof")
				}
				after, _ := os.ReadFile(w.InventoryPath)
				if string(before) != string(after) {
					t.Fatal("Store reaggregation changed output evidence")
				}
				if *store.RemainingOwnedObjects != 0 || *store.UnknownEffects != 0 {
					t.Fatal("reaggregation mutated Store receipt")
				}
			})
		}
	}
}

// full_only: false
func TestPublicationOutputFailureCannotGrantStoreRetry(t *testing.T) {
	one, index := int64(1), uint32(0)
	result := scenarioResult{CorrectnessPassed: true, Writer: &workerEvidence{Joined: true}, CleanupWorker: &workerEvidence{Joined: true}, Cleanup: records.Cleanup{Outcome: "unresolved", RemainingOwnedObjects: &one, UnknownEffects: &one, HarnessFailure: &records.HarnessFailure{Operation: "output_cleanup", Stage: "conditional_delete", Cause: "transport", Effect: "unknown", TargetKind: "output_inventory", TargetIndex: &index, Attempt: 1}}}
	if _, blocker := cleanupRetryTarget(&result, "gcp", true, 1); blocker == "" {
		t.Fatal("output failure granted a Store retry")
	}
	result.Cleanup.HarnessFailure.Operation = "object_cleanup"
	result.Cleanup.HarnessFailure.TargetKind = "inventory"
	if target, blocker := cleanupRetryTarget(&result, "gcp", true, 1); blocker != "" || target != 0 {
		t.Fatal("existing Store retry was removed", blocker)
	}
}

func publicationCapturedActors(p records.OutputFixtureProfile) records.OutputFixtureActors {
	writer := "serviceAccount:" + p.Writer.ServiceAccount
	if p.Cloud.Provider == "aws" {
		writer = "arn:aws:iam::" + p.Cloud.Account + ":user/fixture-writer"
	}
	return records.OutputFixtureActors{ProfileID: p.ProfileID, Writer: writer, ReaderA: p.ConsumerA.Principal, ReaderB: p.ConsumerB.Principal}
}
