package records

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const outputInputDomain = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const outputInputSuffix = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func outputInputFixture(scopes ...string) *OutputFixtureInput {
	child := "plain1_secret1_create_value_delete"
	if scopes[0] == "github-organization" {
		child = "plain1_secret1_create_value_policy_delete"
	}
	if scopes[0] == "github-repository" || scopes[0] == "github-environment" {
		child = "plain1_secret1_create_value_inherited_policy_delete"
	}
	input := &OutputFixtureInput{SchemaVersion: 2, Scope: OutputFixtureScope{RunID: strings.Repeat("a", 32), Scenario: "publication." + scopes[0] + ".plain-secret-lifecycle/" + child, DomainID: outputInputDomain, WriterID: "publication-writer"}, InventoryPath: "/private-fixture/output-inventory.json", JoinedPath: "/private-fixture/output-writer-joined.json"}
	if len(scopes) > 1 {
		input.Scope.Scenario = "publication.mixed-destinations/plain1_secret1_initial_noop_delete_mixed4"
	}
	for index, scope := range scopes {
		profile := OutputFixtureProfile{Scope: scope, Namespace: "positive", ProfileID: "ENKV/OUTPUT/" + strings.ToUpper(scope) + "/v3", Native: &OutputFixtureNative{ArtifactPath: "/native-artifacts/" + scope, ArtifactSHA256: outputFixtureID(10 + index), ArtifactLength: 4096, CredentialPath: "/private-fixture/" + scope + "-native", CredentialRouteID: outputFixtureID(20 + index), DescriptorID: outputFixtureID(30 + index), ConfigContractID: "fixture-output/config/v1", CredentialRouteContractID: outputFixtureID(40 + index)}}
		actor := func(role string) *OutputFixtureActor {
			return &OutputFixtureActor{CredentialsFile: "/not-opened/" + scope + "-" + role}
		}
		profile.Writer, profile.Cleaner = actor("writer"), actor("cleaner")
		slot := ""
		switch scope {
		case "aws-secrets-manager":
			profile.Cloud = &OutputFixtureCloud{Provider: "aws", Region: "ap-southeast-2", Account: "123456789012", SecretNamePrefix: "fixture-output-positive-"}
			profile.ConsumerA, profile.ConsumerB = actor("consumer-a"), actor("consumer-b")
			for _, a := range []*OutputFixtureActor{profile.Writer, profile.Cleaner, profile.ConsumerA, profile.ConsumerB} {
				a.Profile = "fixture"
			}
			profile.ConsumerA.Principal = "arn:aws:iam::123456789012:user/consumer-a"
			profile.ConsumerB.Principal = "arn:aws:iam::123456789012:user/consumer-b"
			slot = "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:fixture-output-positive-" + outputInputSuffix
		case "gcp-secret-manager":
			profile.Cloud = &OutputFixtureCloud{Provider: "gcp", Project: "fixture-project", ProjectNumber: "123456789012", SecretNamePrefix: "projects/123456789012/secrets/fixture-output-positive-"}
			profile.ConsumerA, profile.ConsumerB = actor("consumer-a"), actor("consumer-b")
			for i, a := range []*OutputFixtureActor{profile.Writer, profile.Cleaner, profile.ConsumerA, profile.ConsumerB} {
				a.ServiceAccount = []string{"writer", "cleaner", "consumer-a", "consumer-b"}[i] + "@fixture-project.iam.gserviceaccount.com"
			}
			profile.ConsumerA.Principal = "serviceAccount:" + profile.ConsumerA.ServiceAccount
			profile.ConsumerB.Principal = "serviceAccount:" + profile.ConsumerB.ServiceAccount
			slot = "projects/123456789012/secrets/fixture-output-positive-" + outputInputSuffix
		default:
			profile.GitHub = &OutputFixtureGitHub{Owner: "fixture-owner", Repository: "fixture-repo", SecretNamePrefix: "ENKV_FIXTURE_"}
			slot = "repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_" + outputInputSuffix
			if scope == "github-organization" {
				profile.GitHub.Repository = ""
				profile.GitHub.SelectedRepositoryIDs = []uint64{101, 202}
				slot = "orgs/fixture-owner/actions/secrets/ENKV_FIXTURE_" + outputInputSuffix
			}
			if scope == "github-environment" {
				profile.GitHub.Environment = "fixture-environment"
				slot = "repos/fixture-owner/fixture-repo/environments/fixture-environment/secrets/ENKV_FIXTURE_" + outputInputSuffix
			}
		}
		for i, tail := range []string{"_P", "_S"} {
			target := OutputFixtureTarget{Index: uint32(2*index + i), PlannedSlot: slot + tail, ConsumerLocator: slot + tail, ExclusiveNamespaceDigest: outputFixtureID(40 + index)}
			if scope == "aws-secrets-manager" {
				target.ConsumerLocator += "?stage=AWSCURRENT"
			}
			if scope == "gcp-secret-manager" {
				target.ConsumerLocator += "/versions/latest"
			}
			profile.Targets = append(profile.Targets, target)
		}
		input.Profiles = append(input.Profiles, profile)
	}
	return input
}

// full_only: false
func TestOutputFixtureInputRoundTripAndRoleProjections(t *testing.T) {
	parent := outputInputFixture("aws-secrets-manager", "github-repository", "github-organization", "github-environment")
	if parent.Validate(parent.Scope, "parent") != nil {
		t.Fatal("parent shape refused")
	}
	t.Run("shared credential recipe", func(t *testing.T) {
		shared := parent.Clone()
		shared.Profiles[2].Native.CredentialRouteID = shared.Profiles[1].Native.CredentialRouteID
		shared.Profiles[2].Native.CredentialRouteContractID = shared.Profiles[1].Native.CredentialRouteContractID
		if err := shared.Validate(shared.Scope, "parent"); err != nil {
			t.Fatal("shared route refused", err)
		}
	})
	t.Run("superseded native binding schema refuses continuation", func(t *testing.T) {
		old := parent.Clone()
		old.SchemaVersion = 1
		if old.ValidateRecorded(old.Scope, "parent") == nil {
			t.Fatal("old native fields reinterpreted as current support")
		}
	})
	writer, err := parent.WriterProjection()
	if err != nil {
		t.Fatal(err)
	}
	cleaner, err := parent.CleanerProjection()
	if err != nil {
		t.Fatal(err)
	}
	for _, projection := range []struct {
		name  string
		input *OutputFixtureInput
		role  string
	}{{"writer", writer, "writer"}, {"cleanup", cleaner, "cleanup"}} {
		t.Run(projection.name, func(t *testing.T) {
			if projection.input.Validate(parent.Scope, projection.role) != nil {
				t.Fatal("role validation")
			}
			if projection.input.Validate(parent.Scope, "parent") == nil {
				t.Fatal("child restored parent refs")
			}
			body, err := json.Marshal(projection.input)
			if err != nil {
				t.Fatal(err)
			}
			var restored OutputFixtureInput
			if json.Unmarshal(body, &restored) != nil || restored.Validate(parent.Scope, projection.role) != nil || !reflect.DeepEqual(projection.input, &restored) {
				t.Fatal("private roundtrip")
			}
			for _, p := range restored.Profiles {
				if projection.role == "writer" {
					if p.Cleaner != nil {
						t.Fatal("cleaner leaked")
					}
				} else if p.Writer != nil || p.ConsumerA != nil || p.ConsumerB != nil || p.Native != nil {
					t.Fatal("writer/native leaked")
				}
			}
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if os.Chmod(directory, 0700) != nil {
				t.Fatal("private directory")
			}
			path := filepath.Join(directory, "input.json")
			if WriteJSON(path, projection.input, 0600) != nil {
				t.Fatal("record write")
			}
			var loaded OutputFixtureInput
			if ReadJSON(path, &loaded) != nil || loaded.Validate(parent.Scope, projection.role) != nil {
				t.Fatal("owning record IO")
			}
		})
	}
	for _, role := range []string{"fresh_before", "fresh_after", "rerun"} {
		t.Run(role, func(t *testing.T) {
			var stripped *OutputFixtureInput
			if stripped.Validate(parent.Scope, role) != nil || writer.Validate(parent.Scope, role) == nil || cleaner.Validate(parent.Scope, role) == nil || parent.Validate(parent.Scope, role) == nil {
				t.Fatal("fresh/retry retained outputs")
			}
		})
	}
	if parent.Validate(parent.Scope, "writer") == nil || parent.Validate(parent.Scope, "cleanup") == nil {
		t.Fatal("parent serialized as child")
	}
	if writer.Validate(parent.Scope, "cleanup") == nil || cleaner.Validate(parent.Scope, "writer") == nil {
		t.Fatal("cross-role authority")
	}
	if parent.Validate(parent.Scope, "other") == nil {
		t.Fatal("unknown mode")
	}
	var empty *OutputFixtureInput
	if empty.Clone() != nil || empty.Validate(parent.Scope, "writer") == nil || empty.Validate(parent.Scope, "cleanup") == nil {
		t.Fatal("missing output refs accepted")
	}
}

// full_only: false
func TestOutputFixtureInputAllScopesAndNamespaces(t *testing.T) {
	for _, scope := range []string{"aws-secrets-manager", "gcp-secret-manager", "github-repository", "github-organization", "github-environment"} {
		for _, namespace := range []string{"positive", "ambiguity"} {
			t.Run(scope+"/"+namespace, func(t *testing.T) {
				input := outputInputFixture(scope)
				if namespace == "ambiguity" {
					input.Scope.Scenario = "publication." + scope + ".later-member-refusal/plain1_secret1_first_target_ack_later_not_sent"
					input.Profiles[0].Namespace = namespace
					if input.Profiles[0].Cloud != nil {
						input.Profiles[0].Cloud.SecretNamePrefix = strings.ReplaceAll(input.Profiles[0].Cloud.SecretNamePrefix, "positive", "ambiguity")
						for i := range input.Profiles[0].Targets {
							input.Profiles[0].Targets[i].PlannedSlot = strings.ReplaceAll(input.Profiles[0].Targets[i].PlannedSlot, "positive", "ambiguity")
							input.Profiles[0].Targets[i].ConsumerLocator = strings.ReplaceAll(input.Profiles[0].Targets[i].ConsumerLocator, "positive", "ambiguity")
						}
					}
				}
				if input.Validate(input.Scope, "parent") != nil {
					t.Fatal("valid fixed scope/namespace")
				}
				writer, err := input.WriterProjection()
				if err != nil || writer.Validate(input.Scope, "writer") != nil {
					t.Fatal("writer")
				}
				cleaner, err := input.CleanerProjection()
				if err != nil || cleaner.Validate(input.Scope, "cleanup") != nil {
					t.Fatal("cleaner")
				}
			})
		}
	}
	t.Run("gcp-mixed", func(t *testing.T) {
		input := outputInputFixture("gcp-secret-manager", "github-repository", "github-organization", "github-environment")
		if input.Validate(input.Scope, "parent") != nil {
			t.Fatal("matching cloud mixed")
		}
	})
	t.Run("aws-prefix-entry-bound", func(t *testing.T) {
		for _, tc := range []struct {
			name         string
			prefixLength int
			entryLength  int
			admitted     bool
		}{
			{"prefix-222-entry-256", 222, 256, true},
			{"prefix-223-entry-257", 223, 257, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				input := outputInputFixture("aws-secrets-manager")
				profile := &input.Profiles[0]
				const namespaceSuffix = "-output-positive-"
				prefix := strings.Repeat("A", tc.prefixLength-len(namespaceSuffix)) + namespaceSuffix
				profile.Cloud.SecretNamePrefix = prefix
				var expected [2]string
				for index, tail := range []string{"_P", "_S"} {
					name := prefix + outputInputSuffix + tail
					if len(prefix) != tc.prefixLength || len(name) != tc.entryLength {
						t.Fatal("independent allocation width differs")
					}
					expected[index] = "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:" + name
					profile.Targets[index].PlannedSlot = expected[index]
					profile.Targets[index].ConsumerLocator = expected[index] + "?stage=AWSCURRENT"
					if profile.Targets[index].Index != uint32(index) {
						t.Fatal("allocation changed physical target index")
					}
				}
				slots, admitted := outputInputSlots(*profile, input.Scope.DomainID)
				if admitted != tc.admitted {
					t.Errorf("allocated entry length %d admitted=%t want=%t", tc.entryLength, admitted, tc.admitted)
				}
				if admitted && slots != expected {
					t.Fatal("allocation changed independently fixed physical slots")
				}
				if err := input.Validate(input.Scope, "parent"); (err == nil) != tc.admitted {
					t.Errorf("parent validation for allocated entry length %d: %v", tc.entryLength, err)
				}
			})
		}
	})
}

// full_only: false
func TestOutputFixtureInputClonesEveryMutableReference(t *testing.T) {
	parent := outputInputFixture("gcp-secret-manager", "github-repository", "github-organization", "github-environment")
	before := parent.Clone()
	copy := parent.Clone()
	writer, err := parent.WriterProjection()
	if err != nil {
		t.Fatal(err)
	}
	cleaner, err := parent.CleanerProjection()
	if err != nil {
		t.Fatal(err)
	}
	copy.Scope.DomainID = outputFixtureID(99)
	copy.Profiles[0].Cloud.Project = "changed"
	copy.Profiles[0].Writer.ServiceAccount = "changed"
	copy.Profiles[0].Cleaner.CredentialsFile = "changed"
	copy.Profiles[0].ConsumerA.Principal = "changed"
	copy.Profiles[0].ConsumerB.Principal = "changed"
	copy.Profiles[0].Native.ArtifactSHA256 = "changed"
	copy.Profiles[0].Targets[0].PlannedSlot = "changed"
	copy.Profiles[2].GitHub.Owner = "changed"
	copy.Profiles[2].GitHub.SelectedRepositoryIDs[0] = 999
	copy.Profiles[1].Scope = "changed"
	writer.Profiles[0].Writer.CredentialsFile = "writer-change"
	writer.Profiles[2].GitHub.SelectedRepositoryIDs[0] = 333
	cleaner.Profiles[0].Cleaner.CredentialsFile = "cleaner-change"
	cleaner.Profiles[0].Targets[0].PlannedSlot = "cleaner-change"
	if !reflect.DeepEqual(parent, before) {
		t.Fatal("projection or clone aliases parent")
	}
	if cleaner.Profiles[2].GitHub.SelectedRepositoryIDs[0] != 101 {
		t.Fatal("writer aliases cleaner policy")
	}
}

// full_only: false
func TestOutputFixtureInputRejectsMalformedScopeTargetsAndProjection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*OutputFixtureInput)
	}{
		{"schema", func(x *OutputFixtureInput) { x.SchemaVersion = 1 }},
		{"missing-profiles", func(x *OutputFixtureInput) { x.Profiles = nil }},
		{"too-many-profiles", func(x *OutputFixtureInput) {
			x.Profiles = append(x.Profiles, x.Profiles[0], x.Profiles[0], x.Profiles[0])
		}},
		{"duplicate-profile", func(x *OutputFixtureInput) { x.Profiles[1] = x.Profiles[0] }},
		{"profile-label", func(x *OutputFixtureInput) { x.Profiles[0].ProfileID = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1" }},
		{"scope-label", func(x *OutputFixtureInput) { x.Profiles[0].Scope = "aws" }},
		{"namespace", func(x *OutputFixtureInput) { x.Profiles[0].Namespace = "ambiguity" }},
		{"case-scope-set", func(x *OutputFixtureInput) {
			x.Scope.Scenario = "publication.github-repository.plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete"
		}},
		{"missing-mixed-scope", func(x *OutputFixtureInput) { x.Profiles = x.Profiles[:3] }},
		{"zero-domain", func(x *OutputFixtureInput) { x.Scope.DomainID = strings.Repeat("0", 64) }},
		{"upper-domain", func(x *OutputFixtureInput) { x.Scope.DomainID = strings.ToUpper(outputInputDomain) }},
		{"writer-label", func(x *OutputFixtureInput) { x.Scope.WriterID = "../writer" }},
		{"row-index-duplicate", func(x *OutputFixtureInput) { x.Profiles[1].Targets[0].Index = 0 }},
		{"row-index-outside", func(x *OutputFixtureInput) { x.Profiles[1].Targets[0].Index = 8 }},
		{"row-index-maximum", func(x *OutputFixtureInput) { x.Profiles[1].Targets[0].Index = ^uint32(0) }},
		{"one-target", func(x *OutputFixtureInput) { x.Profiles[0].Targets = x.Profiles[0].Targets[:1] }},
		{"extra-target", func(x *OutputFixtureInput) {
			x.Profiles[0].Targets = append(x.Profiles[0].Targets, x.Profiles[0].Targets[0])
		}},
		{"wrong-slot", func(x *OutputFixtureInput) { x.Profiles[0].Targets[0].PlannedSlot += "-instance" }},
		{"wrong-consumer", func(x *OutputFixtureInput) { x.Profiles[0].Targets[0].ConsumerLocator += "?other" }},
		{"swapped-plain-secret", func(x *OutputFixtureInput) {
			p := &x.Profiles[0]
			p.Targets[0], p.Targets[1] = p.Targets[1], p.Targets[0]
		}},
		{"namespace-digest-zero", func(x *OutputFixtureInput) {
			x.Profiles[0].Targets[0].ExclusiveNamespaceDigest = strings.Repeat("0", 64)
		}},
		{"namespace-digest-differs", func(x *OutputFixtureInput) { x.Profiles[0].Targets[1].ExclusiveNamespaceDigest = outputFixtureID(999) }},
		{"no-native", func(x *OutputFixtureInput) { x.Profiles[0].Native = nil }},
		{"no-writer", func(x *OutputFixtureInput) { x.Profiles[0].Writer = nil }},
		{"no-cleaner", func(x *OutputFixtureInput) { x.Profiles[0].Cleaner = nil }},
		{"no-consumer", func(x *OutputFixtureInput) { x.Profiles[0].ConsumerB = nil }},
		{"github-consumer", func(x *OutputFixtureInput) { x.Profiles[1].ConsumerA = x.Profiles[0].ConsumerA }},
		{"early-actual-writer", func(x *OutputFixtureInput) { x.Profiles[0].Writer.Principal = "observed-before-capture" }},
		{"consumer-principal-alias", func(x *OutputFixtureInput) { x.Profiles[0].ConsumerB.Principal = x.Profiles[0].ConsumerA.Principal }},
		{"cloud-scope-location", func(x *OutputFixtureInput) { x.Profiles[0].Cloud.Provider = "gcp" }},
		{"cloud-plus-github", func(x *OutputFixtureInput) { x.Profiles[0].GitHub = x.Profiles[1].GitHub }},
		{"missing-location", func(x *OutputFixtureInput) { x.Profiles[1].GitHub = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := outputInputFixture("aws-secrets-manager", "github-repository", "github-organization", "github-environment")
			tc.change(x)
			if x.Validate(x.Scope, "parent") == nil {
				t.Fatal("invalid shape accepted")
			}
			if _, err := x.WriterProjection(); err == nil {
				t.Fatal("invalid writer projection")
			}
			if _, err := x.CleanerProjection(); err == nil {
				t.Fatal("invalid cleaner projection")
			}
		})
	}
	t.Run("different-expected-scope", func(t *testing.T) {
		x := outputInputFixture("github-repository")
		for _, change := range []func(*OutputFixtureScope){func(s *OutputFixtureScope) { s.RunID = strings.Repeat("b", 32) }, func(s *OutputFixtureScope) {
			s.Scenario = "publication.github-repository.later-member-refusal/plain1_secret1_first_target_ack_later_not_sent"
		}, func(s *OutputFixtureScope) { s.DomainID = outputFixtureID(123) }, func(s *OutputFixtureScope) { s.WriterID = "other-writer" }} {
			expected := x.Scope
			change(&expected)
			if x.Validate(expected, "parent") == nil {
				t.Fatal("scope changed")
			}
		}
	})
	t.Run("three-encoded-targets-stay-visible", func(t *testing.T) {
		x := outputInputFixture("github-repository")
		x.Profiles[0].Targets = append(x.Profiles[0].Targets, x.Profiles[0].Targets[0])
		body, err := json.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		var decoded OutputFixtureInput
		if json.Unmarshal(body, &decoded) != nil || len(decoded.Profiles[0].Targets) != 3 || decoded.Validate(decoded.Scope, "parent") == nil {
			t.Fatal("array decoder dropped invalid target")
		}
	})
}

// full_only: false
func TestOutputFixtureInputRejectsPathsNativeAndLocationDamage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*OutputFixtureInput)
	}{
		{"inventory-relative", func(x *OutputFixtureInput) { x.InventoryPath = "relative.json" }},
		{"inventory-alias", func(x *OutputFixtureInput) { x.InventoryPath = "/private-fixture/../private-fixture/inventory.json" }},
		{"join-other-directory", func(x *OutputFixtureInput) { x.JoinedPath = "/other-private/joined.json" }},
		{"join-inventory-alias", func(x *OutputFixtureInput) { x.JoinedPath = x.InventoryPath }},
		{"actor-relative", func(x *OutputFixtureInput) { x.Profiles[0].Writer.CredentialsFile = "relative" }},
		{"actor-path-bound", func(x *OutputFixtureInput) { x.Profiles[0].Writer.CredentialsFile = "/" + strings.Repeat("a", 4096) }},
		{"actor-path-newline", func(x *OutputFixtureInput) { x.Profiles[0].Writer.CredentialsFile += "\n" }},
		{"actor-alias", func(x *OutputFixtureInput) {
			x.Profiles[0].Cleaner.CredentialsFile = x.Profiles[0].Writer.CredentialsFile
		}},
		{"actor-inventory-alias", func(x *OutputFixtureInput) { x.Profiles[0].Writer.CredentialsFile = x.InventoryPath }},
		{"native-actor-alias", func(x *OutputFixtureInput) {
			x.Profiles[0].Native.CredentialPath = x.Profiles[0].Writer.CredentialsFile
		}},
		{"artifact-route-alias", func(x *OutputFixtureInput) { x.Profiles[0].Native.ArtifactPath = x.Profiles[0].Native.CredentialPath }},
		{"native-route-outside", func(x *OutputFixtureInput) { x.Profiles[0].Native.CredentialPath = "/outside/credential" }},
		{"artifact-zero-hash", func(x *OutputFixtureInput) { x.Profiles[0].Native.ArtifactSHA256 = strings.Repeat("0", 64) }},
		{"artifact-hash-spelling", func(x *OutputFixtureInput) { x.Profiles[0].Native.ArtifactSHA256 = strings.Repeat("A", 64) }},
		{"artifact-zero-length", func(x *OutputFixtureInput) { x.Profiles[0].Native.ArtifactLength = 0 }},
		{"artifact-overflow", func(x *OutputFixtureInput) { x.Profiles[0].Native.ArtifactLength = 128<<20 + 1 }},
		{"route-zero-id", func(x *OutputFixtureInput) { x.Profiles[0].Native.CredentialRouteID = strings.Repeat("0", 64) }},
		{"route-contract-zero", func(x *OutputFixtureInput) {
			x.Profiles[0].Native.CredentialRouteContractID = strings.Repeat("0", 64)
		}},
		{"descriptor-id-alias", func(x *OutputFixtureInput) {
			x.Profiles[1].Native.DescriptorID = x.Profiles[0].Native.DescriptorID
		}},
		{"aws-account", func(x *OutputFixtureInput) { x.Profiles[0].Cloud.Account = "123" }},
		{"aws-other-project", func(x *OutputFixtureInput) { x.Profiles[0].Cloud.Project = "unexpected" }},
		{"aws-prefix", func(x *OutputFixtureInput) { x.Profiles[0].Cloud.SecretNamePrefix = "arbitrary-" }},
		{"github-owner-case", func(x *OutputFixtureInput) { x.Profiles[1].GitHub.Owner = "Fixture" }},
		{"github-org-set-order", func(x *OutputFixtureInput) { x.Profiles[2].GitHub.SelectedRepositoryIDs = []uint64{202, 101} }},
		{"github-org-set-duplicate", func(x *OutputFixtureInput) { x.Profiles[2].GitHub.SelectedRepositoryIDs = []uint64{101, 101} }},
		{"github-org-set-empty", func(x *OutputFixtureInput) { x.Profiles[2].GitHub.SelectedRepositoryIDs = nil }},
		{"github-repo-policy", func(x *OutputFixtureInput) { x.Profiles[1].GitHub.SelectedRepositoryIDs = []uint64{101} }},
		{"github-extra-environment", func(x *OutputFixtureInput) { x.Profiles[1].GitHub.Environment = "unexpected" }},
		{"github-env-alias", func(x *OutputFixtureInput) { x.Profiles[3].GitHub.Environment = "fixture%2Fenvironment" }},
		{"github-actor-fields", func(x *OutputFixtureInput) { x.Profiles[1].Writer.Profile = "ambient" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := outputInputFixture("aws-secrets-manager", "github-repository", "github-organization", "github-environment")
			tc.change(x)
			if x.Validate(x.Scope, "parent") == nil {
				t.Fatal("invalid private reference accepted")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*OutputFixtureInput)
	}{
		{"gcp-full-prefix", func(x *OutputFixtureInput) { x.Profiles[0].Cloud.SecretNamePrefix = "fixture-output-positive-" }},
		{"gcp-number-alias", func(x *OutputFixtureInput) { x.Profiles[0].Cloud.ProjectNumber = "0123456789012" }},
		{"gcp-number-overflow", func(x *OutputFixtureInput) { x.Profiles[0].Cloud.ProjectNumber = "9223372036854775808" }},
		{"gcp-email-alias", func(x *OutputFixtureInput) {
			x.Profiles[0].ConsumerB.ServiceAccount = x.Profiles[0].ConsumerA.ServiceAccount
			x.Profiles[0].ConsumerB.Principal = x.Profiles[0].ConsumerA.Principal
		}},
		{"gcp-principal-relation", func(x *OutputFixtureInput) {
			x.Profiles[0].ConsumerA.Principal = "serviceAccount:another@fixture-project.iam.gserviceaccount.com"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := outputInputFixture("gcp-secret-manager")
			tc.change(x)
			if x.Validate(x.Scope, "parent") == nil {
				t.Fatal("invalid GCP shape")
			}
		})
	}
	t.Run("artifact-maximum-is-shape-only", func(t *testing.T) {
		x := outputInputFixture("github-repository")
		x.Profiles[0].Native.ArtifactLength = 128 << 20
		if x.Validate(x.Scope, "parent") != nil {
			t.Fatal("existing artifact ceiling")
		}
	})
}
