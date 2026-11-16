package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

func livePublicationInputCheck(t *testing.T) (records.Invocation, liveRunInput) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("private input directory")
	}
	domain := contract.Hash([]byte("publication caller control domain"))
	runID, scenario := strings.Repeat("2", 32), "publication.aws-secrets-manager.plain-secret-lifecycle/plain1_secret1_create_value_delete"
	scope := records.OutputFixtureScope{RunID: runID, Scenario: scenario, DomainID: hex.EncodeToString(domain[:]), WriterID: "writer-0"}
	profile := records.OutputFixtureProfile{Scope: "aws-secrets-manager", Namespace: "positive", ProfileID: "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3",
		Cloud:     &records.OutputFixtureCloud{Provider: "aws", Region: "us-east-1", Account: "123456789012", SecretNamePrefix: "test-output-positive-"},
		Writer:    &records.OutputFixtureActor{CredentialsFile: filepath.Join(directory, "writer-source"), Profile: "writer"},
		ConsumerA: &records.OutputFixtureActor{CredentialsFile: filepath.Join(directory, "consumer-a-source"), Profile: "consumer-a", Principal: "arn:aws:iam::123456789012:user/consumer-a"},
		ConsumerB: &records.OutputFixtureActor{CredentialsFile: filepath.Join(directory, "consumer-b-source"), Profile: "consumer-b", Principal: "arn:aws:iam::123456789012:user/consumer-b"},
		Native:    &records.OutputFixtureNative{ArtifactPath: filepath.Join(directory, "output-artifact"), ArtifactLength: 1, ArtifactSHA256: strings.Repeat("3", 64), CredentialPath: filepath.Join(directory, "native-route"), CredentialRouteID: strings.Repeat("4", 64), DescriptorID: strings.Repeat("5", 64), ConfigContractID: "fixture/config/v1", CredentialRouteContractID: strings.Repeat("7", 64)}}
	rows := []records.OutputFixtureRow{}
	for index, suffix := range []string{"_P", "_S"} {
		slot := "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-output-positive-" + strings.ToUpper(scope.DomainID[:32]) + suffix
		profile.Targets = append(profile.Targets, records.OutputFixtureTarget{Index: uint32(index), PlannedSlot: slot, ConsumerLocator: slot + "?stage=AWSCURRENT", ExclusiveNamespaceDigest: strings.Repeat("6", 64)})
		rows = append(rows, records.OutputFixtureRow{ProfileID: profile.ProfileID, PlannedSlot: slot, ExclusiveNamespaceDigest: strings.Repeat("6", 64)})
	}
	output := &records.OutputFixtureInput{SchemaVersion: 2, Scope: scope, InventoryPath: filepath.Join(directory, "output-inventory.json"), JoinedPath: filepath.Join(directory, "output-joined.json"), Profiles: []records.OutputFixtureProfile{profile}}
	if output.Validate(scope, "writer") != nil || records.NewOutputFixtureInventory(output.InventoryPath, scope, rows) != nil {
		t.Fatal("valid private input fixture refused")
	}
	return records.Invocation{RunID: runID, Scenario: scenario, Worker: scope.WriterID, Role: "writer", StateDir: directory}, liveRunInput{RunID: runID, Settings: liveSettings{Provider: "aws"}, Outputs: output}
}

// full_only: false
func TestLivePublicationInputBindsOriginalCaseBeforeEffects(t *testing.T) {
	inv, input := livePublicationInputCheck(t)
	if livePublicationInput(inv, input) != nil {
		t.Fatal("unchanged original writer input refused")
	}
	// References deliberately have no files: this admission reads only private
	// retained records, and must not capture credentials or execute an artifact.
	for _, condition := range []string{"writer", "run", "scenario", "provider", "state_directory", "inventory_row", "prior_action", "cleaner_in_writer", "old_schema"} {
		t.Run(condition, func(t *testing.T) {
			inv, input := livePublicationInputCheck(t)
			switch condition {
			case "old_schema":
				input.Outputs.SchemaVersion = 1
			case "writer":
				inv.Worker = "other-writer"
			case "run":
				input.RunID = strings.Repeat("7", 32)
			case "scenario":
				inv.Scenario = "publication.aws-secrets-manager.later-member-refusal/plain1_secret1_first_target_ack_later_not_sent"
			case "provider":
				input.Settings.Provider = "gcp"
			case "state_directory":
				inv.StateDir = filepath.Dir(inv.StateDir)
			case "inventory_row":
				input.Outputs.Profiles[0].Targets[0].Index, input.Outputs.Profiles[0].Targets[1].Index = 1, 0
			case "prior_action":
				if records.SetOutputFixtureActors(input.Outputs.InventoryPath, input.Outputs.Scope, records.OutputFixtureActors{ProfileID: input.Outputs.Profiles[0].ProfileID, Writer: "writer", ReaderA: "a", ReaderB: "b"}) != nil || records.BeginOutputFixtureAction(input.Outputs.InventoryPath, input.Outputs.Scope, 0, strings.Repeat("8", 64), contract.PublicationCreateEmpty) != nil {
					t.Fatal("prior action fixture")
				}
			case "cleaner_in_writer":
				input.Outputs.Profiles[0].Cleaner = &records.OutputFixtureActor{CredentialsFile: filepath.Join(inv.StateDir, "cleaner-source"), Profile: "cleaner"}
			}
			if livePublicationInput(inv, input) == nil {
				t.Fatal("changed invocation acquired output input")
			}
		})
	}
}

// full_only: false
func TestLivePublicationObserverAndStoreRetryInputsDropAllOutputReferences(t *testing.T) {
	for _, role := range []string{"fresh_before", "fresh_after", "cleanup"} {
		t.Run(role, func(t *testing.T) {
			inv, input := livePublicationInputCheck(t)
			inv.Role = role
			if role == "cleanup" {
				input.CleanupGrant = &liveCleanupGrant{}
			}
			if livePublicationInput(inv, input) == nil {
				t.Fatal("stripped role retained output authority")
			}
			input.Outputs = nil
			if livePublicationInput(inv, input) != nil {
				t.Fatal("stripped output input refused")
			}
		})
	}
	// Grant shape and exact eligibility are checked by loadLiveInput before it
	// calls this projection check; a nil output field itself grants nothing.
}

// full_only: false
func TestLivePublicationCleanupInputRequiresOriginalWriterJoin(t *testing.T) {
	inv, input := livePublicationInputCheck(t)
	profile := &input.Outputs.Profiles[0]
	profile.Cleaner = &records.OutputFixtureActor{CredentialsFile: filepath.Join(inv.StateDir, "cleaner-source"), Profile: "cleaner"}
	profile.Writer, profile.ConsumerA, profile.ConsumerB, profile.Native = nil, nil, nil, nil
	inv.Role, inv.Worker = "cleanup", "cleanup-0"
	if livePublicationInput(inv, input) == nil {
		t.Fatal("cleanup admitted before writer joined")
	}
	if records.WriteOutputFixtureJoined(input.Outputs.JoinedPath, input.Outputs.Scope) != nil || livePublicationInput(inv, input) != nil {
		t.Fatal("exact joined cleaner refused")
	}
}

// full_only: false
func TestLivePublicationNamedResourceQualification(t *testing.T) {
	attempt := contract.Hash([]byte("fixed named action attempt"))
	aws := "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3"
	gcp := "ENKV/OUTPUT/GCP-SECRET-MANAGER/v3"
	for _, test := range []struct {
		name, profile, slot, owned, resource string
		action                               uint8
		valid                                bool
	}{
		{"aws_birth", aws, "slot", "", "slot-Ab09Zx", contract.PublicationCreateEmpty, true},
		{"aws_other_slot", aws, "slot", "", "other-Ab09Zx", contract.PublicationCreateEmpty, false},
		{"aws_short_suffix", aws, "slot", "", "slot-Ab09Z", contract.PublicationCreateEmpty, false},
		{"aws_bad_suffix", aws, "slot", "", "slot-Ab_9Zx", contract.PublicationCreateEmpty, false},
		{"aws_value_attempt", aws, "slot", "slot-Ab09Zx", hex.EncodeToString(attempt[:]), contract.PublicationWriteValue, true},
		{"aws_value_not_birth", aws, "slot", "slot-Ab09Zx", "slot-Ab09Zx", contract.PublicationWriteValue, false},
		{"aws_exact_delete", aws, "slot", "slot-Ab09Zx", "slot-Ab09Zx", contract.PublicationDeleteOwned, true},
		{"aws_wrong_instance", aws, "slot", "slot-Ab09Zx", "slot-Zz09Zx", contract.PublicationDeleteOwned, false},
		{"gcp_birth", gcp, "projects/123/secrets/name", "", "projects/123/secrets/name", contract.PublicationCreateEmpty, true},
		{"gcp_numeric_version", gcp, "projects/123/secrets/name", "", "projects/123/secrets/name/versions/42", contract.PublicationWriteValue, true},
		{"gcp_maximum_version", gcp, "projects/123/secrets/name", "", "projects/123/secrets/name/versions/9223372036854775807", contract.PublicationWriteValue, true},
		{"gcp_version_overflow", gcp, "projects/123/secrets/name", "", "projects/123/secrets/name/versions/9223372036854775808", contract.PublicationWriteValue, false},
		{"gcp_zero_version", gcp, "projects/123/secrets/name", "", "projects/123/secrets/name/versions/0", contract.PublicationWriteValue, false},
		{"gcp_leading_zero", gcp, "projects/123/secrets/name", "", "projects/123/secrets/name/versions/042", contract.PublicationWriteValue, false},
		{"gcp_latest_not_version", gcp, "projects/123/secrets/name", "", "projects/123/secrets/name/versions/latest", contract.PublicationWriteValue, false},
		{"gcp_wrong_secret", gcp, "projects/123/secrets/name", "", "projects/123/secrets/other/versions/42", contract.PublicationWriteValue, false},
		{"gcp_empty_delete", gcp, "projects/123/secrets/name", "", "", contract.PublicationDeleteOwned, false},
		{"unknown_profile", "other", "slot", "slot", "slot", contract.PublicationCreateWithValue, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if livePublicationResource(test.profile, test.action, test.slot, test.owned, test.resource, attempt) != test.valid {
				t.Fatal("named action resource qualification differs")
			}
		})
	}
	for _, scope := range []string{"REPOSITORY", "ORGANIZATION", "ENVIRONMENT"} {
		profile := "ENKV/OUTPUT/GITHUB-" + scope + "/v3"
		for _, action := range []uint8{contract.PublicationCreateWithValue, contract.PublicationWriteValue, contract.PublicationDeleteOwned} {
			if !livePublicationResource(profile, action, "exact-slot", "exact-slot", "exact-slot", attempt) || livePublicationResource(profile, action, "exact-slot", "exact-slot", "other-slot", attempt) {
				t.Fatal("GitHub action accepted a different reserved slot")
			}
		}
	}
}

// full_only: false
func TestLivePublicationMixedConfigurationUsesCanonicalDestinationOrder(t *testing.T) {
	for _, cloud := range []string{livePublicationCloudScope} {
		for _, order := range []struct {
			name    string
			indices []int
		}{
			{"catalog", []int{0, 1, 2, 3}},
			{"canonical", []int{0, 3, 2, 1}},
			{"reversed", []int{3, 2, 1, 0}},
		} {
			t.Run(cloud+"/"+order.name, func(t *testing.T) {
				scopes := []string{cloud, "github-repository", "github-organization", "github-environment"}
				input := &records.OutputFixtureInput{}
				authority := contract.Hash([]byte("mixed output authority"))
				cloudBase, cloudLocator := "arn:aws:secretsmanager:us-east-1:123456789012:secret:", "?stage=AWSCURRENT"
				// These complete literals follow the public service contracts and do not
				// call the fixture destination or target constructors under test.
				cloudSource := contract.OutputDestination{ConfigContractID: "ENKV/OUTPUT/AWS-SECRETS-MANAGER/CONFIG/v1", ServiceContractID: "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", CanonicalSettings: []byte(`{"account":"123456789012","region":"us-east-1"}`), Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot}
				if cloud == "gcp-secret-manager" {
					cloudBase, cloudLocator = "projects/123456789/secrets/", "/versions/latest"
					cloudSource = contract.OutputDestination{ConfigContractID: "ENKV/OUTPUT/GCP-SECRET-MANAGER/CONFIG/v1", ServiceContractID: "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", CanonicalSettings: []byte(`{"project_number":"123456789"}`), Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot}
				}
				wantSources := map[string]contract.OutputDestination{
					cloud:                 cloudSource,
					"github-repository":   {ConfigContractID: "github-actions/repository-config/v1", ServiceContractID: "github-actions/service/v1", CanonicalSettings: []byte(`{"owner":"fixture-owner","repository":"fixture-repo"}`), Capabilities: contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot},
					"github-organization": {ConfigContractID: "github-actions/organization-config/v1", ServiceContractID: "github-actions/service/v1", CanonicalSettings: []byte(`{"owner":"fixture-owner"}`), Capabilities: contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy, Policy: contract.OutputPolicy{ContractID: "github-actions/org-visibility/v1", Data: []byte{0, 1, 3, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2}}},
					"github-environment":  {ConfigContractID: "github-actions/environment-config/v1", ServiceContractID: "github-actions/service/v1", CanonicalSettings: []byte(`{"owner":"fixture-owner","repository":"fixture-repo","environment":"test"}`), Capabilities: contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot},
				}
				for _, index := range order.indices {
					scope := scopes[index]
					profile := records.OutputFixtureProfile{Scope: scope, ProfileID: "ENKV/OUTPUT/" + strings.ToUpper(scope) + "/v3",
						ConsumerA: &records.OutputFixtureActor{Principal: "reader-a"}, ConsumerB: &records.OutputFixtureActor{Principal: "reader-b"}}
					base, suffix, prefix := cloudBase, cloudLocator, "cloud"
					if scope == cloud {
						profile.Cloud = &records.OutputFixtureCloud{Provider: "aws", Account: "123456789012", Region: "us-east-1"}
						if cloud == "gcp-secret-manager" {
							profile.Cloud = &records.OutputFixtureCloud{Provider: "gcp", ProjectNumber: "123456789"}
						}
					} else {
						prefix, suffix = "SHARED", ""
						profile.GitHub = &records.OutputFixtureGitHub{Owner: "fixture-owner"}
						base = "orgs/fixture-owner/actions/secrets/"
						if scope == "github-organization" {
							profile.GitHub.SelectedRepositoryIDs = []uint64{1, 2}
						} else {
							profile.GitHub.Repository = "fixture-repo"
							base = "repos/fixture-owner/fixture-repo/actions/secrets/"
							if scope == "github-environment" {
								profile.GitHub.Environment = "test"
								base = "repos/fixture-owner/fixture-repo/environments/test/secrets/"
							}
						}
					}
					for role, tail := range []string{"_P", "_S"} {
						slot := base + prefix + tail
						profile.Targets = append(profile.Targets, records.OutputFixtureTarget{Index: uint32(index*2 + role), PlannedSlot: slot, ConsumerLocator: slot + suffix})
					}
					input.Profiles = append(input.Profiles, profile)
				}
				entries := []ApplyEntryInput{{Name: "SHARED_P", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain}, {Name: "SHARED_S", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret}, {Name: "cloud_P", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain}, {Name: "cloud_S", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret}}
				p := &livePublicationScenario{publicationScenario: &publicationScenario{entries: entries}, runtime: &livePublicationRuntime{input: input}}
				output := p.output()
				want := []string{"publication-" + cloud, "publication-github-environment", "publication-github-organization", "publication-github-repository"}
				normalized, err := normalizeOutputApply(t.Context(), entries, []contract.ID{authority}, authority, output, nil)
				if err != nil || !checkOutputApplyInput(contract.Hash([]byte("mixed output order")), entries, normalized) {
					t.Fatal("mixed output input violates the native configuration contract", err)
				}
				wantRoutes := []outputApplyRoute{{entryName: "SHARED_P", destinations: want[1:]}, {entryName: "SHARED_S", destinations: want[1:]}, {entryName: "cloud_P", destinations: want[:1]}, {entryName: "cloud_S", destinations: want[:1]}}
				if len(normalized.bindings) != len(want) || !reflect.DeepEqual(normalized.routes, wantRoutes) {
					t.Fatal("mixed output omitted or reordered routes, or added cross-scope targets")
				}
				for i, binding := range normalized.bindings {
					scope := strings.TrimPrefix(want[i], "publication-")
					if binding.destinationID != want[i] || !reflect.DeepEqual(binding.destination, wantSources[scope]) || len(binding.targets) != 2 {
						t.Fatal("mixed output bindings or complete native settings differ")
					}
					var offered records.OutputFixtureProfile
					for _, profile := range input.Profiles {
						if profile.Scope == scope {
							offered = profile
						}
					}
					for j, target := range binding.targets {
						name := []string{"SHARED_P", "SHARED_S"}[j]
						if scope == cloud {
							name = []string{"cloud_P", "cloud_S"}[j]
						}
						wantTarget := contract.OutputTarget{ServiceContractID: wantSources[scope].ServiceContractID, CanonicalTarget: offered.Targets[j].PlannedSlot, ConsumerLocator: offered.Targets[j].ConsumerLocator, PayloadEncoding: contract.OutputEncodingRaw, Capabilities: wantSources[scope].Capabilities, Policy: wantSources[scope].Policy}
						if scope == "aws-secrets-manager" {
							wantTarget.TargetContractID = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1"
							wantTarget.ConsumerLocator = ""
							wantTarget.LocatorRequiresCreation = true
							wantTarget.WriteValueBounds.Minimum = 1
							wantTarget.WriteValueBounds.Maximum = 65536
							wantTarget.TargetData = []byte(fmt.Sprintf(`{"account":"123456789012","region":"us-east-1","name":%q}`, name))
						} else if scope == "gcp-secret-manager" {
							wantTarget.TargetContractID = "ENKV/OUTPUT/GCP-SECRET-MANAGER/TARGET/v1"
							wantTarget.WriteValueBounds.Maximum = 65536
							wantTarget.TargetData = []byte(fmt.Sprintf(`{"project_number":"123456789","name":%q}`, name))
						} else {
							wantTarget.TargetContractID = "github-actions/target/v1"
							wantTarget.CreateValueBounds.Maximum = 48000
							wantTarget.WriteValueBounds.Maximum = 48000
							scopeNumber := 1
							if scope == "github-organization" {
								scopeNumber = 2
							}
							if scope == "github-environment" {
								scopeNumber = 3
							}
							wantTarget.TargetData = []byte(fmt.Sprintf(`{"scope":%d,"coordinate":%q}`, scopeNumber, wantTarget.CanonicalTarget))
						}
						if target.entryName != name || !reflect.DeepEqual(target.target, wantTarget) || offered.Targets[j].Index != uint32(slices.Index(scopes, scope)*2+j) {
							t.Fatal("destination ordering changed the complete allocated target association")
						}
					}
				}

				for i, index := range order.indices {
					if input.Profiles[i].Scope != scopes[index] {
						t.Fatal("output construction changed the admitted profile order")
					}
				}
			})
		}
	}
}

type livePublicationConsumerCheck struct {
	liveCloudOutput
	read func(context.Context, liveOutputConsumer, string, uint32) (liveOutputRead, error)
}

func (c livePublicationConsumerCheck) ReadConsumer(ctx context.Context, consumer liveOutputConsumer, instance string, maximum uint32) (liveOutputRead, error) {
	return c.read(ctx, consumer, instance, maximum)
}

func liveConsumerScenario(t testing.TB, ctx context.Context, scope string, firstIndex uint32, changed bool) *livePublicationScenario {
	env := memoryScenarioEnvironment(t)
	fixtureCtx, cancel := context.WithTimeout(env.operationContext(), time.Minute)
	t.Cleanup(cancel)
	f := newEnvironmentFixture(t, fixtureCtx, env, nil, false)
	plain := "private data"
	if changed {
		plain = "updated plain data"
	}
	entries := []ApplyEntryInput{{Name: "plain", Recipients: []contract.ID{f.session.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte(plain)}, sharingSecretNamed(t, env, "secret", "manifest consumer source", []contract.ID{f.session.admission.recipient})}
	profile := records.OutputFixtureProfile{Scope: scope, ProfileID: "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3", Cloud: &records.OutputFixtureCloud{Provider: "aws", Account: "123456789012", Region: "us-east-1"}}
	if scope == "gcp-secret-manager" {
		profile.ProfileID = "ENKV/OUTPUT/GCP-SECRET-MANAGER/v3"
		profile.Cloud = &records.OutputFixtureCloud{Provider: "gcp", ProjectNumber: "123456789"}
	}
	out := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication-" + scope}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication-" + scope}}}}
	for index, name := range []string{"plain", "secret"} {
		slot := "arn:aws:secretsmanager:us-east-1:123456789012:secret:" + name
		locator := slot + "?stage=AWSCURRENT"
		if scope == "gcp-secret-manager" {
			slot = "projects/123456789/secrets/" + name
			locator = slot + "/versions/latest"
		}
		profile.Targets = append(profile.Targets, records.OutputFixtureTarget{Index: firstIndex + uint32(index), PlannedSlot: slot, ConsumerLocator: locator})
		out.bindings[0].targets = append(out.bindings[0].targets, outputApplyTarget{entryName: name, target: livePublicationTarget(profile, profile.Targets[index], false)})
		f.session.admission.publicationNamespaces = append(f.session.admission.publicationNamespaces, publicationNamespace{domain: env.Domain, service: livePublicationProvider(scope), physical: slot, premise: fixtureID(env.Domain, "independent consumer namespace "+name)})
	}
	f.admission.admission.publicationNamespaces = f.session.admission.publicationNamespaces
	out.bindings[0].destination = livePublicationDestination(profile, false)
	f.session = selectLivePublicationEntries(t, fixtureCtx, f.session, env, entries, out)
	f.admission = OpenContext{admission: &f.session.admission}
	adapter := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: f.admission, session: f.session}
	private := newPublicationControlledPrivate()
	private.configureOwner = func(owner *publicationControlledOwner) {
		owner.resource = owner.input.Target.CanonicalTarget
		if scope == "aws-secrets-manager" {
			owner.resource += "-AbCd12"
			owner.consumerLocator = owner.resource + "?stage=AWSCURRENT"
		}
	}
	input := publicationInput{names: []string{"plain", "secret"}, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	plan, result := adapter.session.planPublication(fixtureCtx, input, private.callbacks())
	if plan == nil {
		t.Fatal("consumer fixture creation admission", result)
	}
	created := plan.execute(fixtureCtx, private.callbacks(), func(ctx context.Context) (*StateSession, contract.Trust, Result) {
		s, r := Open(ctx, adapter.admission, adapter.store)
		return s, adapter.trust, r
	})
	if created.summary != contract.PublicationSummaryComplete {
		t.Fatal("consumer fixture selected birth", created)
	}
	f.session, result = Open(fixtureCtx, f.admission, env.Store)
	if f.session == nil {
		t.Fatal("consumer fixture cold selection", result)
	}
	return &livePublicationScenario{publicationScenario: &publicationScenario{run: &scenarioRun{t: t, ctx: ctx, env: env}, fixture: f, entries: entries, input: input}, changed: changed, runtime: &livePublicationRuntime{profiles: []livePublicationProfile{{input: profile}}}}
}

// full_only: false
func TestLivePublicationConsumersUseValueBounds(t *testing.T) {
	for _, scope := range []string{livePublicationCloudScope} {
		for _, stage := range []string{"initial", "changed", "delayed-grant", "delayed-value", "full-round"} {
			for _, firstIndex := range []uint32{0, 6} {
				t.Run(fmt.Sprintf("%s/%s/index-%d", scope, stage, firstIndex), func(t *testing.T) {
					changed := stage == "changed" || stage == "delayed-value"
					p := liveConsumerScenario(t, t.Context(), scope, firstIndex, changed)
					prior := []string{"private data", "enkv first secret test value"}
					values := prior
					if changed {
						values = []string{"updated plain data", "enkv other secret test value"}
					}
					calls, pauses := 0, 0
					var borrowed [][]byte
					var stageContext context.Context
					p.runtime.profiles[0].cloud = livePublicationConsumerCheck{read: func(ctx context.Context, consumer liveOutputConsumer, instance string, maximum uint32) (liveOutputRead, error) {
						round, row := calls/2, 1
						if calls >= 6 || consumer != liveOutputConsumer(calls%2+1) || instance != func() string {
							slot := p.runtime.profiles[0].input.Targets[row].PlannedSlot
							if scope == "aws-secrets-manager" {
								return slot + "-AbCd12?stage=AWSCURRENT"
							}
							return slot + "/versions/latest"
						}() {
							t.Fatal("consumer caller changed actor or exact instance")
						}
						if stageContext == nil {
							stageContext = ctx
						} else if ctx != stageContext {
							t.Fatal("consumer round changed its stage context")
						}
						deadline, finite := ctx.Deadline()
						if !finite || time.Until(deadline) > 10*time.Minute || ctx == p.run.ctx {
							t.Fatal("consumer stage deadline unavailable")
						}
						bound := len(values[row])
						if changed {
							bound = max(bound, len(prior[row]))
						}
						if maximum != uint32(bound) || maximum > 65536 {
							t.Fatal("consumer value bound differs")
						}
						denied := false
						if stage == "delayed-grant" && round == 0 || stage == "full-round" && (round == 0 && calls%2 == 1 || round == 1 && calls%2 == 0) {
							denied = true
						}
						calls++
						if denied {
							status := 400
							if scope == "gcp-secret-manager" {
								status = 403
							}
							return liveOutputRead{HTTPStatus: status, AccessRefused: true}, nil
						}
						value := values[row]
						if stage == "delayed-value" && round == 0 {
							value = prior[row]
						}
						body := []byte(value)
						borrowed = append(borrowed, body)
						return liveOutputRead{HTTPStatus: 200, Bytes: body}, nil
					}}
					pause := func(ctx context.Context) bool {
						if ctx != stageContext || calls%2 != 0 {
							t.Fatal("observation paused before a complete round")
						}
						pauses++
						return true
					}
					if strings.HasPrefix(stage, "delayed-") || stage == "full-round" {
						if failure := p.observeConsumers(pause); failure != nil {
							t.Fatal("qualified delayed result did not converge", failure)
						}
					} else {
						p.consumers()
					}
					wantCalls, wantPauses := 2, 0
					if strings.HasPrefix(stage, "delayed-") {
						wantCalls, wantPauses = 4, 1
					}
					if stage == "full-round" {
						wantCalls, wantPauses = 6, 2
					}
					if calls != wantCalls || pauses != wantPauses {
						t.Fatal("consumer caller omitted a round, target or actor", calls, pauses)
					}
					for _, body := range borrowed {
						if !bytes.Equal(body, make([]byte, len(body))) {
							t.Fatal("consumer caller retained returned bytes")
						}
					}
					if stageContext.Err() != context.Canceled {
						t.Fatal("stage context survived completed observation")
					}
				})
			}
		}
	}
	t.Run("finite-and-fatal", func(t *testing.T) {
		deniedStatus := 400
		if liveProvider() == "gcp" {
			deniedStatus = 403
		}
		for _, condition := range []string{"unknown-value", "denied-bytes", "transport", "auth", "budget", "malformed", "missing", "prior-after-value", "later-failure", "canceled-before", "canceled-read", "deadline-read", "canceled-wait", "deadline-wait", "round-limit", "invalid-status"} {
			t.Run(condition, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				changed := condition == "prior-after-value"
				p := liveConsumerScenario(t, ctx, livePublicationCloudScope, 6, changed)
				// Fixture admission reads t.Deadline, which is unavailable inside synctest.
				exercise := func(t *testing.T) {
					p.run.t = t
					if condition == "deadline-read" || condition == "deadline-wait" {
						ctx, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
						defer cancel()
						p.run.ctx = ctx
					}
					calls, pauses := 0, 0
					var borrowed [][]byte
					p.runtime.profiles[0].cloud = livePublicationConsumerCheck{read: func(readCtx context.Context, actor liveOutputConsumer, instance string, maximum uint32) (liveOutputRead, error) {
						calls++
						deadline, _ := readCtx.Deadline()
						if original, finite := ctx.Deadline(); finite && deadline.After(original) {
							t.Fatal("stage extended original deadline")
						}
						read := liveOutputRead{HTTPStatus: 200, Bytes: []byte("unexpected private bytes")}
						var err error
						switch condition {
						case "denied-bytes":
							read.AccessRefused = true
							read.HTTPStatus = deniedStatus
						case "transport", "auth", "budget", "malformed", "missing":
							err = errors.New("private read error")
							if condition == "missing" {
								read.HTTPStatus = 404
							}
						case "prior-after-value":
							read.Bytes = []byte("enkv first secret test value")
						case "later-failure":
							if calls < 2 {
								read = liveOutputRead{HTTPStatus: deniedStatus, AccessRefused: true}
							} else {
								err = errors.New("late private read error")
							}
						case "canceled-read":
							cancel()
						case "deadline-read":
							<-readCtx.Done()
						case "canceled-wait", "deadline-wait", "round-limit":
							read = liveOutputRead{HTTPStatus: deniedStatus, AccessRefused: true}
						case "invalid-status":
							read.HTTPStatus = 999
						}
						borrowed = append(borrowed, read.Bytes)
						return read, err
					}}
					if condition == "canceled-before" {
						cancel()
					}
					pause := func(waitCtx context.Context) bool {
						pauses++
						if condition == "canceled-wait" {
							cancel()
							return waitLiveConsumerObservation(waitCtx)
						}
						if condition == "deadline-wait" {
							return waitLiveConsumerObservation(waitCtx)
						}
						return true
					}
					failure := p.observeConsumers(pause)
					wantCalls, wantPauses, cause := 1, 0, "unexpected_result"
					switch condition {
					case "transport", "auth", "budget", "malformed", "missing":
						cause = "read_failed"
					case "later-failure":
						wantCalls = 2
						cause = "read_failed"
					case "canceled-before":
						wantCalls = 0
						cause = "canceled"
					case "canceled-read":
						cause = "canceled"
					case "deadline-read":
						cause = "deadline"
					case "canceled-wait":
						wantCalls, wantPauses, cause = 2, 1, "canceled"
					case "deadline-wait":
						wantCalls, wantPauses, cause = 2, 1, "deadline"
					case "round-limit", "prior-after-value":
						wantCalls, wantPauses, cause = 242, 120, "round_limit"
					}
					if failure == nil || failure.Cause != cause || calls != wantCalls || pauses != wantPauses || failure.ElapsedSeconds < 0 {
						t.Fatal("consumer fatal or finite boundary differs", failure, calls, pauses)
					}
					if condition == "later-failure" {
						want := liveConsumerFailure{Stage: "initial", Row: 7, Actor: liveOutputConsumerB, Attempts: 1,
							ElapsedSeconds: failure.ElapsedSeconds, HTTPStatus: 200, Length: 24, Cause: "read_failed"}
						if *failure != want {
							t.Fatal("later consumer failure lost its exact facts", failure)
						}
					}
					if (condition == "round-limit" || condition == "prior-after-value") && failure.Attempts != 121 {
						t.Fatal("observation round bound differs")
					}
					if condition == "invalid-status" && failure.HTTPStatus != 0 {
						t.Fatal("unvalidated status entered failure facts")
					}
					if condition == "prior-after-value" && (!failure.PriorMatch || failure.CurrentMatch) {
						t.Fatal("nonconverged value observation lost its prior-value facts")
					}
					if condition == "missing" && failure.HTTPStatus != 404 {
						t.Fatal("missing latest changed its fatal status")
					}
					for _, body := range borrowed {
						if !bytes.Equal(body, make([]byte, len(body))) {
							t.Fatal("failed observation retained bytes")
						}
					}
				}
				if condition == "deadline-read" || condition == "deadline-wait" {
					synctest.Test(t, exercise)
				} else {
					exercise(t)
				}
			})
		}
	})
}

// This runs the real cleanup entrypoint with settled private receipts. It must
// make no provider call: Product deletion or pending cleanup already forbids it.
// full_only: false
func TestLivePublicationCleanupWorkerPreservesIndependentResidue(t *testing.T) {
	for _, condition := range []string{"empty", "deleted", "unknown-after-delete", "pending-cleanup", "wrong-domain", "wrong-instance", "store-unsettled", "store-and-output-unknown", "missing-output-join"} {
		t.Run(condition, func(t *testing.T) {
			inv, input := liveProtocolInvocation(t, "cleanup")
			scope := "aws-secrets-manager"
			if liveProvider() == "gcp" {
				scope = "gcp-secret-manager"
			}
			output, _ := livePublicationCleanupFixture(t, scope)
			original := livePublicationCleanupRead(t, output)
			output.Scope.RunID = input.RunID
			output.InventoryPath, output.JoinedPath = filepath.Join(inv.StateDir, "output-inventory.json"), filepath.Join(inv.StateDir, "output-joined.json")
			if records.NewOutputFixtureInventory(output.InventoryPath, output.Scope, original.Rows) != nil || records.WriteOutputFixtureJoined(output.JoinedPath, output.Scope) != nil || records.SetOutputFixtureActors(output.InventoryPath, output.Scope, original.Actors[0]) != nil {
				t.Fatal("private cleanup worker evidence")
			}
			input.Outputs, input.Scenarios = output, []string{output.Scope.Scenario}
			inv = liveProtocolBindInvocation(t, inv, output.Scope.Scenario)
			body, err := hex.DecodeString(output.Scope.DomainID)
			if err != nil || len(body) != 32 {
				t.Fatal("fixed cleanup domain")
			}
			store := inventoryImage{Version: 1, RunID: input.RunID, Binding: settingsBinding(input.Settings), Prefix: input.Prefix, Domain: contract.ID(body), Deleted: make(map[string]int)}
			remaining, unknown := int64(0), int64(0)
			wantPass, unavailable := true, false
			if condition != "empty" {
				createOutcome, deleteAction := "acknowledged", uint8(contract.PublicationDeleteOwned)
				if condition == "unknown-after-delete" || condition == "store-and-output-unknown" {
					createOutcome, deleteAction = "unknown", contract.PublicationDeleteReservedSlot
				}
				livePublicationCleanupAction(t, output, 0, 1, contract.PublicationCreateEmpty, createOutcome)
				if condition == "pending-cleanup" {
					if records.BeginOutputFixtureCleanup(output.InventoryPath, output.Scope, 0, strings.Repeat("d", 64), output.JoinedPath) != nil {
						t.Fatal("pending cleanup fixture")
					}
				} else {
					livePublicationCleanupAction(t, output, 0, 2, deleteAction, "acknowledged")
				}
				if liveProvider() == "aws" {
					remaining = 1
				}
			}
			switch condition {
			case "unknown-after-delete", "pending-cleanup":
				remaining, unknown, wantPass = 1, 1, false
			case "wrong-domain":
				store.Domain, wantPass, unavailable = contract.Hash([]byte("different Store domain")), false, true
			case "wrong-instance":
				retained := livePublicationCleanupRead(t, output)
				retained.Rows[0].OwnedInstance = "other-instance"
				if records.WriteJSON(output.InventoryPath, retained, 0600) != nil {
					t.Fatal("changed private birth fixture")
				}
				wantPass, unavailable = false, true
			case "store-unsettled":
				store.Intents = []objectIntent{{Key: input.Prefix + "/HEAD", Digest: bodyDigest([]byte("owned")), Bytes: 5, Kind: "create", State: "unknown"}}
				wantPass, unknown = false, 1
			case "store-and-output-unknown":
				store.Intents = []objectIntent{{Key: input.Prefix + "/HEAD", Digest: bodyDigest([]byte("owned")), Bytes: 5, Kind: "create", State: "unknown"}}
				wantPass, unknown = false, 2
			case "missing-output-join":
				if os.Remove(output.JoinedPath) != nil {
					t.Fatal("output join obstruction unavailable")
				}
				wantPass, unavailable = false, true
			}
			if records.WriteJSON(inv.Input, input, 0400) != nil || writePrivateJSON(filepath.Join(inv.StateDir, "inventory.json"), store) != nil {
				t.Fatal("cleanup worker input")
			}
			before, err := os.ReadFile(output.InventoryPath)
			if err != nil {
				t.Fatal("cleanup inventory before child")
			}
			err = runLiveProtocolEntry(t, "TestLiveCleanup", saveLiveProtocolInvocation(t, inv))
			if (err == nil) != wantPass {
				t.Fatal("cleanup entrypoint result differs from retained evidence")
			}
			after, readErr := os.ReadFile(output.InventoryPath)
			if readErr != nil || string(before) != string(after) {
				t.Fatal("settled or unknown cleanup replayed its private receipts")
			}
			if condition == "missing-output-join" {
				// Input admission precedes worker creation. Its assertion marker
				// must survive without inventing a cleanup result or phase.
				assertions := records.InspectAssertions(inv, false)
				if assertions.Marker != "valid_failure_marker" || assertions.Checkpoint != "no_checkpoint" || assertions.Completed.Code != "none" {
					t.Fatal("missing output join lost its admission failure evidence")
				}
				for _, name := range []string{"worker.json", "telemetry.json", "checkpoint.json"} {
					if _, err := os.Lstat(filepath.Join(inv.OutputDir, name)); !os.IsNotExist(err) {
						t.Fatal("unjoined output entered cleanup", name)
					}
				}
				return
			}
			var result records.WorkerResult
			if records.ReadJSON(filepath.Join(inv.OutputDir, "worker.json"), &result) != nil || result.Cleanup == nil || result.Cleanup.BudgetReserved == nil || *result.Cleanup.BudgetReserved != (records.BudgetReservation{}) {
				t.Fatal("cleanup lost its result or made a provider reservation")
			}
			if unavailable {
				if result.Cleanup.RemainingOwnedObjects != nil || result.Cleanup.UnknownEffects != nil {
					t.Fatal("unadmitted output evidence was reported as absence")
				}
			} else {
				if result.Cleanup.UnknownEffects == nil || *result.Cleanup.UnknownEffects != unknown {
					t.Fatal("cleanup lost independent unknown effects")
				}
				if condition == "store-unsettled" || condition == "store-and-output-unknown" {
					if result.Cleanup.RemainingOwnedObjects != nil {
						t.Fatal("unsettled Store ownership acquired a count")
					}
				} else if result.Cleanup.RemainingOwnedObjects == nil || *result.Cleanup.RemainingOwnedObjects != remaining {
					t.Fatal("cleanup lost known output residue")
				}
			}
			if condition == "unknown-after-delete" || condition == "pending-cleanup" || condition == "wrong-instance" || condition == "store-and-output-unknown" {
				fact := result.Cleanup.HarnessFailure
				if fact == nil || fact.Operation != "output_cleanup" || fact.TargetKind != "output_inventory" || fact.TargetIndex == nil || *fact.TargetIndex != 0 {
					t.Fatal("output cleanup row failure was replaced with generic evidence")
				}
			}
			for _, phase := range result.Phases {
				if phase.Name == "cleanup" && phase.MeasurementsExpected {
					t.Fatal("no-effect cleanup claimed a provider measurement")
				}
			}
		})
	}
}

// full_only: false
func TestLivePublicationFreshChildRemovesOutputAuthority(t *testing.T) {
	inv, input := liveProtocolInvocation(t, "writer")
	output, _ := livePublicationCleanupFixture(t, "github-repository")
	output.Scope.RunID, output.Scope.WriterID = input.RunID, inv.Worker
	output.InventoryPath, output.JoinedPath = filepath.Join(inv.StateDir, "output-inventory.json"), filepath.Join(inv.StateDir, "output-joined.json")
	profile := &output.Profiles[0]
	profile.Cleaner = nil
	profile.Writer = &records.OutputFixtureActor{CredentialsFile: filepath.Join(inv.StateDir, "not-opened-writer")}
	profile.Native = &records.OutputFixtureNative{ArtifactPath: filepath.Join(inv.StateDir, "not-opened-artifact"), ArtifactSHA256: strings.Repeat("3", 64), ArtifactLength: 1, CredentialPath: filepath.Join(inv.StateDir, "not-opened-native-route"), CredentialRouteID: strings.Repeat("4", 64), DescriptorID: strings.Repeat("5", 64), ConfigContractID: "fixture/config/v1", CredentialRouteContractID: strings.Repeat("7", 64)}
	if output.Validate(output.Scope, "writer") != nil {
		t.Fatal("writer projection fixture")
	}
	input.Outputs, input.Scenarios = output, []string{output.Scope.Scenario}
	inv = liveProtocolBindInvocation(t, inv, output.Scope.Scenario)
	if records.WriteJSON(inv.Input, input, 0400) != nil {
		t.Fatal("original publication input")
	}
	worker, err := records.NewWorker(inv, liveProvider(), inv.Scenario, nil)
	if err != nil {
		t.Fatal("publication projection worker")
	}
	defer worker.Finish(context.Background(), true)
	work := []contract.SupportRecord{{Kind: contract.PublicationCoordinateSupportKind, RecordID: contract.Hash([]byte("opaque authenticated fixture record")), Body: []byte("exact retained support")}}
	path, err := prepareFreshChild(inv, worker, freshFacts{Domain: contract.Hash([]byte(input.Prefix)), Prefix: input.Prefix, ExpectedWork: work})
	if err != nil {
		t.Fatal("publication fresh projection")
	}
	child, err := records.LoadInvocation(path)
	if err != nil {
		t.Fatal("publication fresh invocation")
	}
	actual, err := loadLiveInput(child, "fresh_before")
	input.Outputs = nil
	if err != nil || !reflect.DeepEqual(actual, input) {
		t.Fatal("publication fresh input retained writer references or changed reader fields")
	}
	var facts freshFacts
	if records.ReadJSON(filepath.Join(child.StateDir, child.Facts), &facts) != nil || !reflect.DeepEqual(facts.ExpectedWork, work) {
		t.Fatal("publication fresh projection lost exact support bodies")
	}
}
