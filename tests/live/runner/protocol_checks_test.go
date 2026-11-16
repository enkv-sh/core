package core

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/telemetry"
)

const liveProtocolRun = "0123456789abcdef0123456789abcdef"
const liveProtocolRecovery = "fedcba9876543210fedcba9876543210"

func liveProtocolInvocation(t *testing.T, role string) (records.Invocation, liveRunInput) {
	t.Helper()
	return liveProtocolInvocationLayout(t, role, "2026-09-08/03-11-01+1000-"+liveProtocolRun)
}

func liveProtocolInvocationLayout(t *testing.T, role, layout string) (records.Invocation, liveRunInput) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(root, "tests/live/runs", filepath.FromSlash(layout), "private")
	state, output := filepath.Join(private, "state"), filepath.Join(private, "writer")
	for _, path := range []string{state, output} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	input := liveRunInput{RecoveryMode: "disabled", Participants: map[string]string{"authority": "operator"}, Settings: liveSettings{Provider: liveProvider(), RecoveryMode: "disabled", AuthorityKEKID: "synthetic-authority", AuthorityKEKPublicKeyPEM: "synthetic-authority-public", ReaderKEKID: "synthetic-reader", ReaderKEKPublicKeyPEM: "synthetic-reader-public"}, Limits: liveLimits{Requests: 1000, BodyBytes: 1 << 34, Objects: 1000, ObjectBytes: 1 << 30, GeneratorCreates: 1000, GeneratorRetires: 1000, ElapsedSeconds: 10, CleanupRequests: 1000, CleanupBytes: 1 << 34, CleanupSeconds: 10}, Scenarios: []string{"state.single-value-update-preserves-other-values/members_32"}, Repetitions: 1, RunID: liveProtocolRun, Prefix: "enkv-test/" + liveProtocolRun + "/point"}
	inv := records.Invocation{SchemaVersion: records.SchemaVersion, Scenario: input.Scenarios[0], Nonce: "0123456789abcdef0123456789abcdef", RunID: liveProtocolRun, Worker: "writer-point", Role: role, Input: filepath.Join(private, "input.json"), StateDir: state, OutputDir: output}
	if records.WriteJSON(inv.Input, input, 0o400) != nil {
		t.Fatal("test input unavailable")
	}
	if role == "fresh_before" || role == "fresh_after" {
		inv.Facts = "fresh.json"
		if records.WriteJSON(filepath.Join(state, inv.Facts), freshFacts{Domain: contract.Hash([]byte(input.Prefix)), Prefix: input.Prefix}, 0o400) != nil {
			t.Fatal("test facts unavailable")
		}
	}
	inv = liveProtocolBindInvocation(t, inv, input.Scenarios[0])
	if inv.Validate() != nil {
		t.Fatal("test invocation invalid")
	}
	return inv, input
}

func liveProtocolRecoveryOutput(t *testing.T, inv records.Invocation) records.Invocation {
	t.Helper()
	_, runs, originalID, err := records.PrivateOwner(inv.StateDir)
	if err != nil || originalID != liveProtocolRun {
		t.Fatal("original recovery owner unavailable")
	}
	inv.RunID = liveProtocolRecovery
	inv.Nonce = liveProtocolNonce(t)
	inv.FreshBefore = nil
	inv.OutputDir = filepath.Join(runs, "2026-09-09", "03-11-01+1000-"+inv.RunID, "private", "cleanup")
	if os.MkdirAll(inv.OutputDir, 0o700) != nil {
		t.Fatal("recovery output unavailable")
	}
	return inv
}

// full_only: false
func TestLiveProtocolRetainedLayouts(t *testing.T) {
	for _, layout := range []string{liveProtocolRun, "undated/" + liveProtocolRun} {
		for _, role := range []string{"writer", "fresh_before", "cleanup"} {
			t.Run(layout+"/"+role, func(t *testing.T) {
				inv, input := liveProtocolInvocationLayout(t, role, layout)
				if got, err := loadLiveInput(inv, role); err != nil || got.RunID != input.RunID || got.Prefix != input.Prefix {
					t.Fatal("retained layout input or role refused")
				}
				if _, err := records.LoadInvocation(saveLiveProtocolInvocation(t, inv)); err != nil {
					t.Fatal("retained invocation could not be loaded")
				}
			})
		}
	}
}

func saveLiveProtocolInvocation(t *testing.T, inv records.Invocation) string {
	t.Helper()
	path := filepath.Join(inv.OutputDir, "invocation.json")
	if records.WriteJSON(path, inv, 0o400) != nil {
		t.Fatal("test invocation unavailable")
	}
	return path
}

// full_only: false
func TestLiveProtocolInputAndRoleBinding(t *testing.T) {
	for _, change := range []string{"none", "role", "provider", "original-run", "prefix", "traversal", "scenario", "members-default", "members", "members-zero", "members-null", "repetitions", "unbounded", "zero-generator-creates", "zero-generator-retires", "input-symlink", "state-symlink", "unknown-field"} {
		t.Run(change, func(t *testing.T) {
			inv, input := liveProtocolInvocation(t, "writer")
			switch change {
			case "role":
				inv.Role = "cleanup"
				inv = liveProtocolBindInvocation(t, inv, input.Scenarios[0])
				if inv.Validate() != nil {
					t.Fatal("role refusal fixture is not an admitted invocation")
				}
			case "provider":
				input.Settings.Provider = "other"
			case "original-run":
				input.RunID = liveProtocolRecovery
				input.Prefix = "enkv-test/" + input.RunID + "/point"
			case "prefix":
				input.Prefix = "enkv-test/foreign/point"
			case "traversal":
				input.Prefix += "/../foreign"
			case "scenario":
				input.Scenarios = []string{"unknown"}
			case "members-default", "members":
				input.Scenarios = []string{"state.identical-input-keeps-current-state/members_32"}
				inv = liveProtocolBindInvocation(t, inv, input.Scenarios[0])
				if inv.Validate() != nil {
					t.Fatal("member-count fixture is not an admitted invocation")
				}
				if change == "members" {
					input.MemberCount = 2
				}
			case "repetitions":
				input.Repetitions = 2
			case "unbounded":
				input.Limits.CleanupSeconds = 3601
			case "zero-generator-creates":
				input.Limits.GeneratorCreates = 0
			case "zero-generator-retires":
				input.Limits.GeneratorRetires = 0
			}
			if records.WriteJSON(inv.Input, input, 0o400) != nil {
				t.Fatal("changed test input unavailable")
			}
			switch change {
			case "members-zero", "members-null":
				body, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]any
				if err := json.Unmarshal(body, &fields); err != nil {
					t.Fatal(err)
				}
				fields["member_count"] = nil
				if change == "members-zero" {
					fields["member_count"] = 0
				}
				if records.WriteJSON(inv.Input, fields, 0o400) != nil {
					t.Fatal("numeric input presence fixture unavailable")
				}
			case "input-symlink":
				alias := filepath.Join(filepath.Dir(inv.Input), "input-alias.json")
				if os.Symlink(inv.Input, alias) != nil {
					t.Fatal("test symlink unavailable")
				}
				inv.Input = alias
			case "state-symlink":
				alias := inv.StateDir + "-alias"
				if os.Symlink(inv.StateDir, alias) != nil {
					t.Fatal("test symlink unavailable")
				}
				inv.StateDir = alias
			case "unknown-field":
				if records.WriteJSON(inv.Input, map[string]any{"unexpected": true}, 0o400) != nil {
					t.Fatal("malformed test input unavailable")
				}
			}
			_, err := loadLiveInput(inv, "writer")
			if (err == nil) != (change == "none" || change == "members-default") {
				t.Fatal("live input admitted the wrong run, role, or evidence")
			}
			if _, err := os.Stat(filepath.Join(inv.StateDir, "inventory.json")); !os.IsNotExist(err) {
				t.Fatal("input validation created inventory")
			}
		})
	}
	t.Run("public-artifact-race-metadata", func(t *testing.T) {
		for _, role := range []string{"writer", "fresh_before", "fresh_after", "cleanup"} {
			for _, form := range []string{"absent", "null", "false", "true", "shared-false", "shared-true", "wrong-type", "unknown-field"} {
				t.Run(role+"/"+form, func(t *testing.T) {
					inv, input := liveProtocolInvocation(t, role)
					const scenario = "public-configuration.empty-initialization/empty_initialization"
					inv = liveProtocolBindInvocation(t, inv, scenario)
					input.Scenarios = []string{scenario}
					settings := liveSettings{Provider: liveProvider(), RecoveryMode: "disabled", SDKHome: "/isolated/public", SDKMode: "aws-assume-role", SDKProfile: "selected"}
					if liveProvider() == "gcp" {
						settings.SDKMode, settings.SDKProfile, settings.SDKQuotaProject, settings.QuotaProject = "gcp-impersonated-adc", "", "fixture-project", "fixture-project"
					}
					input.Settings = settings
					input.Participants = map[string]string{}
					input.PublicConfiguration = &publicConfigurationInput{Actors: map[string]liveSettings{}}
					manifest := publicManifestRenderer{Name: "generic-json", Version: "4.0.0", Protocol: strings.Repeat("1", 64), Descriptor: strings.Repeat("2", 64), Executor: strings.Repeat("3", 64), ArtifactContract: strings.Repeat("4", 64), Dependency: strings.Repeat("5", 64), Artifact: strings.Repeat("6", 64), SHA256: strings.Repeat("7", 64), Length: 64}
					input.PublicConfiguration.Artifact.ManifestRenderer = &manifest
					for _, name := range []string{"authority", "reader", "cleanup"} {
						input.Participants[name], input.PublicConfiguration.Actors[name] = name, settings
					}
					body, err := json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					var document map[string]any
					if json.Unmarshal(body, &document) != nil {
						t.Fatal("public fixture encoding refused")
					}
					artifact := document["public_configuration"].(map[string]any)["artifact"].(map[string]any)
					if form == "shared-false" || form == "shared-true" {
						race := form == "shared-true"
						producer, err := json.Marshal(records.PublicProcessArtifact{Race: &race})
						if err != nil {
							t.Fatal(err)
						}
						artifact = nil
						if json.Unmarshal(producer, &artifact) != nil {
							t.Fatal("shared producer wire unavailable")
						}
						artifact["manifest_renderer"] = manifest
						document["public_configuration"].(map[string]any)["artifact"] = artifact
					}
					switch form {
					case "null":
						artifact["race"] = nil
					case "false":
						artifact["race"] = false
					case "true":
						artifact["race"] = true
					case "wrong-type":
						artifact["race"] = "false"
					case "unknown-field":
						artifact["future_unknown"] = true
					}
					if records.WriteJSON(inv.Input, document, 0o400) != nil {
						t.Fatal("public input fixture unavailable")
					}
					got, err := loadLiveInput(inv, role)
					want := form == "absent" || form == "null" || form == "false" || form == "true" || form == "shared-false" || form == "shared-true"
					if (err == nil) != want {
						t.Fatal("public artifact race metadata was decoded incorrectly", err)
					}
					if !want {
						return
					}
					if got.PublicConfiguration.Artifact.ManifestRenderer == nil || *got.PublicConfiguration.Artifact.ManifestRenderer != manifest {
						t.Fatal("manifest renderer extension changed")
					}
					encoded, err := json.Marshal(got.PublicConfiguration.Artifact)
					if err != nil {
						t.Fatal(err)
					}
					var result map[string]any
					if json.Unmarshal(encoded, &result) != nil {
						t.Fatal("decoded artifact unavailable")
					}
					race, present := result["race"]
					if (form == "absent" || form == "null") && present || (form == "false" || form == "shared-false") && (!present || race != false) || (form == "true" || form == "shared-true") && (!present || race != true) {
						t.Fatal("decoded race setting was lost")
					}
				})
			}
		}
	})
}

// full_only: false
func TestLiveProtocolRecoveryBindsOriginalStateAndNewOutput(t *testing.T) {
	inv, input := liveProtocolInvocation(t, "cleanup")
	originalInput := inv.Input
	inv = liveProtocolRecoveryOutput(t, inv)
	if _, err := loadLiveInput(inv, "cleanup"); err != nil {
		t.Fatal("original input and new output refused")
	}
	input.Settings.CredentialsFile, input.Settings.Profile, input.Settings.CredentialExpires = "/selected/replacement", "replacement", time.Now().Add(time.Hour)
	inv.Input = filepath.Join(filepath.Dir(inv.OutputDir), "replacement-input.json")
	if records.WriteJSON(inv.Input, input, 0o400) != nil {
		t.Fatal("replacement input unavailable")
	}
	var original liveRunInput
	if readPrivateJSON(originalInput, &original) != nil || settingsBinding(original.Settings) != settingsBinding(input.Settings) {
		t.Fatal("credential replacement changed the retained resource binding")
	}
	if _, err := loadLiveInput(inv, "cleanup"); err != nil {
		t.Fatal("replacement credentials refused for original state")
	}
	for _, change := range []func(*liveSettings){func(s *liveSettings) { s.Bucket += "other" }, func(s *liveSettings) { s.KeyID += "other" }, func(s *liveSettings) { s.Region += "other" }, func(s *liveSettings) { s.Account += "other" }, func(s *liveSettings) { s.Project += "other" }, func(s *liveSettings) { s.PublicKeyPEM += "other" }} {
		changed := input.Settings
		change(&changed)
		if settingsBinding(changed) == settingsBinding(input.Settings) {
			t.Fatal("replacement changed a retained resource without changing its binding")
		}
	}
	input.RunID, input.Prefix = inv.RunID, "enkv-test/"+inv.RunID+"/point"
	if records.WriteJSON(inv.Input, input, 0o400) != nil {
		t.Fatal("mismatched input unavailable")
	}
	if _, err := loadLiveInput(inv, "cleanup"); err == nil {
		t.Fatal("recovery adopted the output run as original state")
	}
}

// full_only: false
func TestLiveFreshDescriptorsRetainEveryBeforeReader(t *testing.T) {
	inv, input := liveProtocolInvocation(t, "writer")
	inv = liveProtocolBindInvocation(t, inv, "state.historical-bytes-get-new-identities/members_32_three_generations")
	input.Scenarios = []string{inv.Scenario}
	if records.WriteJSON(inv.Input, input, 0400) != nil {
		t.Fatal("historical child input binding unavailable")
	}
	worker, err := records.NewWorker(inv, liveProvider(), inv.Scenario, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Finish(context.Background(), true)
	first, err := prepareFreshChild(inv, worker, freshFacts{Domain: contract.Hash([]byte(input.Prefix)), Prefix: input.Prefix})
	if err != nil {
		t.Fatal(err)
	}
	second, err := prepareFreshChild(inv, worker, freshFacts{Domain: contract.Hash([]byte(input.Prefix)), Prefix: input.Prefix})
	if err != nil {
		t.Fatal(err)
	}
	var saved records.WorkerResult
	if first == second || records.ReadJSON(filepath.Join(inv.OutputDir, "worker.json"), &saved) != nil || len(saved.Children) != 2 || len(saved.FreshChecks) != 1 || saved.FreshChecks[0].Facts != "fresh-1.json" {
		t.Fatal("before-reader descriptors were lost before process launch")
	}
	owner, _, ownerID, err := records.PrivateOwner(inv.OutputDir)
	if err != nil || ownerID != inv.RunID {
		t.Fatal("fresh child owner unavailable")
	}
	for _, child := range saved.Children {
		path, err := records.SafePath(owner, child.Invocation)
		if err != nil {
			t.Fatal(err)
		}
		childInv, err := records.LoadInvocation(path)
		if err != nil || childInv.Worker != child.Worker || childInv.StateDir != inv.StateDir || childInv.OutputDir == inv.OutputDir {
			t.Fatal("fresh child does not own distinct output")
		}
	}
	t.Run("parent_save_before_child_entry", func(t *testing.T) {
		inv, input := liveProtocolInvocation(t, "writer")
		inv = liveProtocolBindInvocation(t, inv, "state.historical-bytes-get-new-identities/members_32_three_generations")
		input.Scenarios = []string{inv.Scenario}
		if records.WriteJSON(inv.Input, input, 0400) != nil {
			t.Fatal("historical child input binding unavailable")
		}
		worker, err := records.NewWorker(inv, liveProvider(), inv.Scenario, nil)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(inv.OutputDir, "worker.json")
		retained := path + ".retained"
		before, err := os.ReadFile(path)
		if err != nil || os.Rename(path, retained) != nil || os.Mkdir(path, 0700) != nil {
			t.Fatal("parent worker save obstruction unavailable", err)
		}
		childPath, err := prepareFreshChild(inv, worker, freshFacts{Domain: contract.Hash([]byte(input.Prefix)), Prefix: input.Prefix})
		if err == nil || childPath != "" {
			t.Fatal("unrecorded child acquired a launch path")
		}
		after, err := os.ReadFile(retained)
		var parent records.WorkerResult
		if err != nil || !reflect.DeepEqual(before, after) || records.ReadJSON(retained, &parent) != nil || len(parent.Children) != 0 {
			t.Fatal("failed pre-entry save changed durable child ownership")
		}
		childOutput := filepath.Join(inv.OutputDir, "fresh-before-0")
		var child records.Invocation
		if records.ReadJSON(filepath.Join(childOutput, "invocation.json"), &child) != nil || child.OutputDir != childOutput {
			t.Fatal("prepared child descriptor unavailable")
		}
		for _, name := range []string{"worker.json", "telemetry.json", "failure.json", "checkpoint.json"} {
			if _, err := os.Lstat(filepath.Join(childOutput, name)); !os.IsNotExist(err) {
				t.Fatal("child entered after parent save failure", name)
			}
		}
		if os.Remove(path) != nil || os.Rename(retained, path) != nil || worker.Finish(context.Background(), false) != nil {
			t.Fatal("failed parent completion unavailable")
		}
		if records.ReadJSON(path, &parent) != nil || parent.Outcome != "failed" {
			t.Fatal("pre-entry parent failure was not retained")
		}
	})
}

// full_only: false
func TestGeneratedFreshChildPreservesReaderInput(t *testing.T) {
	for _, scenario := range []string{"generated.mixed-apply-selects-complete-set/plain1_supplied1_generated2"} {
		for _, unknown := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/unknown=%t", scenario, unknown), func(t *testing.T) {
				inv, input := liveProtocolInvocation(t, "writer")
				input.Scenarios = []string{scenario}
				inv = liveProtocolBindInvocation(t, inv, scenario)
				input.Generator = &liveGeneratorSettings{Account: "synthetic-account", PermissionGroup: "synthetic-group", CredentialsFile: "synthetic-token", Artifact: "synthetic-artifact"}
				input.GeneratorCleanupLedger = "synthetic-ledger"
				body, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				var original map[string]any
				if json.Unmarshal(body, &original) != nil {
					t.Fatal("writer input fixture unavailable")
				}
				delete(original, "member_count")
				delete(original["settings"].(map[string]any), "credential_expires")
				if unknown {
					original["unrelated_unknown"] = map[string]any{"kept": []any{float64(1), "two"}}
				}
				if records.WriteJSON(inv.Input, original, 0o400) != nil {
					t.Fatal("writer input fixture unavailable")
				}
				worker, err := records.NewWorker(inv, liveProvider(), scenario, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer worker.Finish(context.Background(), true)
				path, err := prepareFreshChild(inv, worker, freshFacts{Domain: contract.Hash([]byte(input.Prefix)), Prefix: input.Prefix})
				if unknown {
					if err == nil {
						t.Fatal("fresh input creation admitted unknown writer input")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				child, err := records.LoadInvocation(path)
				if err != nil {
					t.Fatal(err)
				}
				var isolated map[string]any
				if records.ReadJSON(child.Input, &isolated) != nil {
					t.Fatal("fresh input unavailable")
				}
				for _, field := range []string{"generator", "generator_cleanup_ledger", "operator", "operator_cleanup"} {
					delete(original, field)
					if _, present := isolated[field]; present {
						t.Errorf("fresh input retains writer field %s", field)
					}
				}
				if !reflect.DeepEqual(original, isolated) {
					t.Error("fresh child changed remaining writer input")
				}
				if _, err := loadLiveInput(child, "fresh_before"); (err == nil) == unknown {
					t.Error("fresh role admission differs")
				}
				if !unknown {
					for _, field := range []string{"operator", "operator_cleanup"} {
						isolated[field] = map[string]any{}
						if records.WriteJSON(child.Input, isolated, 0o400) != nil {
							t.Fatal("restricted input fixture unavailable")
						}
						if _, err := loadLiveInput(child, "fresh_before"); err == nil {
							t.Errorf("fresh role admitted %s", field)
						}
						delete(isolated, field)
					}
				}
			})
		}
	}
}

// full_only: false
func TestLiveFreshChildFailureRetainsPartialTelemetry(t *testing.T) {
	for _, scenario := range []string{"state.single-value-update-preserves-other-values/members_32", "reconstruction.generated-retiring/complete_loss_generated_retiring", "reconstruction.generated-uncertain/complete_loss_generated_uncertain"} {
		changes := []string{"none"}
		if strings.HasPrefix(scenario, "reconstruction.") {
			changes = append(changes, "missing-step", "wrong-role")
		}
		for _, change := range changes {
			t.Run(scenario+"/"+change, func(t *testing.T) {
				inv, input := liveProtocolInvocation(t, "fresh_before")
				inv.Scenario = scenario
				input.Scenarios = []string{scenario}
				inv = liveProtocolBindInvocation(t, inv, scenario)
				inv.TelemetrySettings = liveMetricSettings(t)
				configured, _ := liveCustodyConstructionInput(t, false)
				input.Settings = configured.Settings
				if liveFamily == contract.GCP {
					input.Settings.ProjectNumber = "123456789"
				}
				input.Settings.CredentialsFile = filepath.Join(t.TempDir(), "missing-credentials")
				env, _ := genesisEnvironment(t, liveFamily, false)
				input.Settings.KeyID = env.SigningSelector
				input.Settings.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: env.PublicKey}))
				bindings, err := liveCustodyBindings(input.Settings, env.Domain)
				if err != nil {
					t.Fatal(err)
				}
				env.Bindings = bindings
				admission := fixtureAdmission(env)
				if admission.admission == nil {
					t.Fatal("fresh public domain fixture unavailable")
				}
				if strings.HasPrefix(scenario, "reconstruction.") {
					input.Settings.NormalSuccessorKeyID, input.Settings.NormalSuccessorPublicKeyPEM = "successor-sign", "successor-sign-public"
					input.Settings.ReaderSuccessorKEKID, input.Settings.ReaderSuccessorKEKPublicKeyPEM = "successor-reader", "successor-reader-public"
					input.Settings.AuthoritySuccessor1KEKID, input.Settings.AuthoritySuccessor1KEKPublicKeyPEM = "successor-authority-1", "successor-authority-public-1"
					input.Settings.AuthoritySuccessor2KEKID, input.Settings.AuthoritySuccessor2KEKPublicKeyPEM = "successor-authority-2", "successor-authority-public-2"
					input.ReplacementSettings = make(map[string]liveSettings)
					definition, known := catalog.DefinitionFor(scenario)
					if !known {
						t.Fatal("fresh recovery catalog unavailable")
					}
					for _, role := range definition.RolesForRecovery(input.RecoveryMode) {
						if role == "authority" {
							continue
						}
						input.Participants[role] = role
						settings := input.Settings
						settings.CredentialsFile = filepath.Join(t.TempDir(), role)
						input.ReplacementSettings[role] = settings
					}
				}
				facts := freshFacts{DomainBasis: admission.admission.descriptor, Domain: env.Domain, Prefix: input.Prefix}
				if strings.HasPrefix(scenario, "reconstruction.") {
					execution, known := catalog.ExecutionFor(scenario, "live")
					if !known || len(execution.FreshAfter) != 0 || len(execution.ExpandedFreshBefore()) != 2 {
						t.Fatal("fresh recovery child shape differs from catalog")
					}
					facts.Step = execution.ExpandedFreshBefore()[0].Step
					facts.GeneratedRecord = &generatedRecordInput{Attempt: contract.Hash([]byte("fresh-record-attempt")), Result: []byte("sealed-result")}
				}
				if change == "missing-step" {
					facts.Step = catalog.Step{}
				} else if change == "wrong-role" {
					facts.Step.Role = "observer"
				}
				inventory := inventoryImage{Version: 1, RunID: input.RunID, Binding: settingsBinding(input.Settings), Prefix: input.Prefix, Domain: env.Domain, Deleted: make(map[string]int)}
				if records.WriteJSON(inv.Input, input, 0o400) != nil || records.WriteJSON(filepath.Join(inv.StateDir, inv.Facts), facts, 0o400) != nil || records.WriteJSON(filepath.Join(inv.StateDir, "inventory.json"), inventory, 0o600) != nil {
					t.Fatal("fresh public admission fixture unavailable")
				}
				path := saveLiveProtocolInvocation(t, inv)
				if _, err := loadLiveInput(inv, "fresh_before"); err != nil {
					t.Fatalf("fresh fixture admission failed: recovery=%t actors=%t invocation=%v", liveRecoveryAdmitted(input), liveActorsAdmitted(input), inv.Validate())
				}
				binary, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				result, process, err := executeFreshChild(context.Background(), binary, path)
				wantProcess := records.FreshChildProcess{Started: true, Joined: true, Outcome: "process_failed"}
				if process == nil || *process != wantProcess {
					t.Fatalf("failed fresh child process fact = %+v, want %+v", process, wantProcess)
				}
				wantStatus, wantFailure := "complete", ""
				wantPhases := 1
				if change != "none" {
					wantPhases = 0
				}
				if err == nil || result.Outcome != "failed" || result.Failure == nil || len(result.Phases) != wantPhases || result.Telemetry.Status != wantStatus || result.Telemetry.FailureClass != wantFailure {

					t.Fatalf("failed fresh child evidence: error=%v, outcome=%s, phases=%+v, telemetry=%+v, assertions=%+v", err, result.Outcome, result.Phases, result.Telemetry, result.Assertions)
				}
				if wantPhases == 1 && (result.Phases[0].Name != "authentication" || result.Phases[0].Outcome != "failed" || result.Phases[0].Actor != "operator") {
					t.Fatal("fresh child did not bind its exact actor before authentication")
				}
				var snapshots []records.Snapshot
				if records.ReadJSON(filepath.Join(inv.OutputDir, "telemetry.json"), &snapshots) != nil || len(snapshots) != wantPhases+1 || snapshots[0].Status != wantStatus || snapshots[0].FailureClass != wantFailure || snapshots[wantPhases].Phase != "final" || snapshots[wantPhases].Status != "complete" {
					t.Fatal("failed child did not collect before exit")
				}
				var calls, failures float64
				for _, measurement := range snapshots[0].Metrics {
					if measurement.Attributes["provider"] != liveProvider() || measurement.Attributes["operation"] != "authentication" || measurement.Value == nil {
						continue
					}
					if measurement.Name == telemetry.OperationCalls {
						calls += *measurement.Value
					}
					if measurement.Name == telemetry.OperationResults && measurement.Attributes["result"] == "failure" {
						failures += *measurement.Value
					}
				}
				if calls != float64(wantPhases) || failures != float64(wantPhases) {
					t.Fatalf("local credential failure observations: calls=%v, failures=%v", calls, failures)
				}
				if result.BudgetReserved == nil || *result.BudgetReserved != (records.BudgetReservation{}) {
					t.Fatal("local authentication refusal made a remote reservation")
				}
			})
		}
	}
}

// full_only: false
func TestLiveFreshChildRejectsStaleOutputBeforeLaunch(t *testing.T) {
	for _, name := range []string{"worker.json", "telemetry.json", "failure.json", "checkpoint.json"} {
		t.Run(name, func(t *testing.T) {
			inv, _ := liveProtocolInvocation(t, "fresh_before")
			path := saveLiveProtocolInvocation(t, inv)
			output := filepath.Join(inv.OutputDir, name)
			if records.WriteJSON(output, map[string]string{"secret": "retain"}, 0o600) != nil {
				t.Fatal("stale output unavailable")
			}
			before, _ := os.ReadFile(output)
			if _, _, err := executeFreshChild(context.Background(), "/must-not-launch", path); err == nil || err.Error() != "fresh process output already exists" {
				t.Fatal("stale child output was accepted")
			}
			after, _ := os.ReadFile(output)
			if string(before) != string(after) {
				t.Fatal("stale output was overwritten")
			}
		})
	}
}

// full_only: false
func TestLiveTelemetryFailureDoesNotChangeInventoryOrBudget(t *testing.T) {
	inv, _ := liveProtocolInvocation(t, "writer")
	inv.TelemetrySettings = liveMetricSettings(t)
	worker, err := records.NewWorker(inv, liveProvider(), "state.single-value-update-preserves-other-values/members_32", nil)
	if err != nil {
		t.Fatal(err)
	}
	inventory, store := testInventory(t)
	budget := &runBudget{limits: liveLimits{Requests: 2, BodyBytes: operationBodyAllowance, Objects: 1, ObjectBytes: 5}, keys: make(map[string]bool)}
	sequence := liveBeginPhase(t, worker, "setup", true)
	ctx := worker.Context(context.Background())
	call := telemetry.Start(ctx, telemetry.Provider(liveProvider()), telemetry.OpSetupCreate)
	result := (recordedStore{Store: store, inventory: inventory, budget: budget}).Create(ctx, inventory.image.Prefix+"/new", []byte("owned"))
	call.Finish(setupWriteResult(result.Status))
	if result.Status != contract.WriteAcknowledged {
		t.Fatal("controlled fixture write failed")
	}
	before, err := os.ReadFile(inventory.path)
	if err != nil {
		t.Fatal(err)
	}
	reserved := budget.snapshot()
	if os.Mkdir(filepath.Join(inv.OutputDir, "telemetry.json"), 0o700) != nil {
		t.Fatal("controlled telemetry write refusal unavailable")
	}
	liveEndPhase(t, worker, sequence, true)
	finishLiveWorker(t, worker, budget)
	after, err := os.ReadFile(inventory.path)
	if err != nil || string(before) != string(after) || budget.snapshot() != reserved || worker.Result.Outcome != "passed" || worker.Result.Telemetry.Status != "incomplete" || worker.Result.Telemetry.FailureClass != "write_failed" {
		t.Fatal("telemetry failure changed the Product result, inventory, or budget")
	}
}

// full_only: false
func TestLiveCleanupEmptyRecoveryRetainsKnownZeros(t *testing.T) {
	for _, layout := range []string{liveProtocolRun, "undated/" + liveProtocolRun, "2026-09-08/03-11-01+1000-" + liveProtocolRun} {
		t.Run(layout, func(t *testing.T) {
			inv, input := liveProtocolInvocationLayout(t, "cleanup", layout)
			inv = liveProtocolRecoveryOutput(t, inv)
			inv.Worker = "cleanup-recovery"
			inventory := inventoryImage{Version: 1, RunID: input.RunID, Binding: settingsBinding(input.Settings), Prefix: input.Prefix, Domain: contract.Hash([]byte(input.Prefix)), Deleted: make(map[string]int)}
			inventoryPath := filepath.Join(inv.StateDir, "inventory.json")
			if writePrivateJSON(inventoryPath, inventory) != nil {
				t.Fatal("empty inventory unavailable")
			}
			before, _ := os.ReadFile(inventoryPath)
			path := saveLiveProtocolInvocation(t, inv)
			if runLiveProtocolEntry(t, "TestLiveCleanup", path) != nil {
				t.Fatal("empty recovery worker failed")
			}
			var result records.WorkerResult
			if records.ReadJSON(filepath.Join(inv.OutputDir, "worker.json"), &result) != nil || result.RunID != inv.RunID || result.Outcome != "passed" || result.Cleanup == nil || result.Cleanup.Outcome != "passed" || result.Cleanup.RemainingOwnedObjects == nil || *result.Cleanup.RemainingOwnedObjects != 0 || result.Cleanup.UnknownEffects == nil || *result.Cleanup.UnknownEffects != 0 || result.Cleanup.BudgetReserved == nil || *result.Cleanup.BudgetReserved != (records.BudgetReservation{}) {
				t.Fatal("empty recovery lost its new output identity or known zero control records")
			}
			after, _ := os.ReadFile(inventoryPath)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("empty recovery changed original inventory")
			}
		})
	}
}

func runLiveProtocolEntry(t *testing.T, name, path string) error {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-test.run=^"+name+"$", "-test.timeout=1m")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "ENKV_TEST_INVOCATION=") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, "ENKV_TEST_INVOCATION="+path)
	return command.Run()
}

// full_only: false
func TestLiveProtocolCleanupUnknownsAndWriterResumeRefusal(t *testing.T) {
	for _, mode := range []string{"pending", "unknown", "malformed", "resume"} {
		t.Run(mode, func(t *testing.T) {
			role, entry := "cleanup", "TestLiveCleanup"
			if mode == "resume" {
				role, entry = "writer", "TestLiveRun"
			}
			inv, input := liveProtocolInvocation(t, role)
			image := inventoryImage{Version: 1, RunID: input.RunID, Binding: settingsBinding(input.Settings), Prefix: input.Prefix, Domain: contract.Hash([]byte(input.Prefix)), Deleted: make(map[string]int)}
			if mode != "resume" {
				image.Intents = []objectIntent{{Key: input.Prefix + "/HEAD", Digest: bodyDigest([]byte("owned")), Bytes: 5, Kind: "create", State: mode}}
			}
			inventoryPath := filepath.Join(inv.StateDir, "inventory.json")
			if writePrivateJSON(inventoryPath, image) != nil {
				t.Fatal("controlled inventory unavailable")
			}
			before, _ := os.ReadFile(inventoryPath)
			if runLiveProtocolEntry(t, entry, saveLiveProtocolInvocation(t, inv)) == nil {
				t.Fatal("unsettled inventory or transition resume was admitted")
			}
			var result records.WorkerResult
			if records.ReadJSON(filepath.Join(inv.OutputDir, "worker.json"), &result) != nil || result.Outcome != "failed" || result.Failure == nil || result.BudgetReserved == nil || *result.BudgetReserved != (records.BudgetReservation{}) {
				t.Fatal("pre-effect refusal lost its result or zero reservations")
			}
			if role == "cleanup" {
				if result.Cleanup == nil || result.Cleanup.Outcome != "unresolved" || result.Cleanup.Failure == nil || result.Cleanup.RemainingOwnedObjects != nil || result.Cleanup.BudgetReserved == nil {
					t.Fatal("unresolved cleanup lost its independent failure")
				}
				if mode == "malformed" {
					if result.Cleanup.UnknownEffects != nil {
						t.Fatal("malformed effects were reported as known")
					}
				} else if result.Cleanup.UnknownEffects == nil || *result.Cleanup.UnknownEffects != 1 {
					t.Fatal("known unsettled effects were lost")
				}
			}
			after, _ := os.ReadFile(inventoryPath)
			if string(before) != string(after) {
				t.Fatal("refused worker changed retained inventory")
			}
		})
	}
}

func liveProtocolNonce(t testing.TB) string {
	t.Helper()
	nonce, err := records.NewInvocationNonce()
	if err != nil {
		t.Fatal("test invocation nonce unavailable")
	}
	return nonce
}

func liveProtocolBindInvocation(t testing.TB, inv records.Invocation, scenario string) records.Invocation {
	t.Helper()
	inv.Scenario, inv.Nonce, inv.FreshBefore = scenario, liveProtocolNonce(t), nil
	inv.FailureSources = &records.FailureSourceBinding{Path: os.Getenv("ENKV_TEST_FAILURE_SOURCES"), SHA256: os.Getenv("ENKV_TEST_FAILURE_SOURCES_SHA256")}
	if _, err := records.ReadFailureSources(*inv.FailureSources); err != nil {
		t.Fatal("qualified assembly source mapping unavailable")
	}
	if inv.Role == "writer" {
		execution, known := catalog.ExecutionFor(scenario, "live")
		if !known {
			t.Fatal("test invocation scenario unavailable")
		}
		for index := range execution.ExpandedFreshBefore() {
			inv.FreshBefore = append(inv.FreshBefore, records.InvocationBinding{Worker: fmt.Sprintf("fresh-before-%s-%d", bodyDigest([]byte(inv.Worker))[:12], index), Nonce: liveProtocolNonce(t)})
		}
	}
	return inv
}
