package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

type livePublicationCleanupCheck func(context.Context, liveOutputCleanupTarget) (liveOutputCleanupResult, error)

func (f livePublicationCleanupCheck) DeleteFixture(ctx context.Context, target liveOutputCleanupTarget) (liveOutputCleanupResult, error) {
	return f(ctx, target)
}

func livePublicationCleanupFixture(t *testing.T, scope string) (*records.OutputFixtureInput, *runBudget) {
	child := "plain1_secret1_create_value_delete"
	if scope == "github-organization" {
		child = "plain1_secret1_create_value_policy_delete"
	}
	if scope == "github-repository" || scope == "github-environment" {
		child = "plain1_secret1_create_value_inherited_policy_delete"
	}
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("private directory")
	}
	domain := strings.Repeat("a", 64)
	suffix := strings.Repeat("A", 32)
	input := &records.OutputFixtureInput{SchemaVersion: 2, Scope: records.OutputFixtureScope{RunID: strings.Repeat("b", 32), Scenario: "publication." + scope + ".plain-secret-lifecycle/" + child, DomainID: domain, WriterID: "publication-writer"}, InventoryPath: filepath.Join(directory, "output-inventory.json"), JoinedPath: filepath.Join(directory, "output-joined.json")}
	profile := records.OutputFixtureProfile{Scope: scope, Namespace: "positive", ProfileID: "ENKV/OUTPUT/" + strings.ToUpper(scope) + "/v3", Cleaner: &records.OutputFixtureActor{CredentialsFile: filepath.Join(directory, "not-opened-cleaner")}}
	slot := ""
	switch scope {
	case "aws-secrets-manager":
		profile.Cloud = &records.OutputFixtureCloud{Provider: "aws", Region: "ap-southeast-2", Account: "123456789012", SecretNamePrefix: "fixture-output-positive-"}
		profile.Cleaner.Profile = "fixture"
		slot = "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:fixture-output-positive-" + suffix
	case "gcp-secret-manager":
		profile.Cloud = &records.OutputFixtureCloud{Provider: "gcp", Project: "fixture-project", ProjectNumber: "123456789012", SecretNamePrefix: "projects/123456789012/secrets/fixture-output-positive-"}
		profile.Cleaner.ServiceAccount = "cleaner@fixture-project.iam.gserviceaccount.com"
		slot = profile.Cloud.SecretNamePrefix + suffix
	default:
		profile.GitHub = &records.OutputFixtureGitHub{Owner: "fixture-owner", Repository: "fixture-repo", SecretNamePrefix: "ENKV_FIXTURE_"}
		slot = "repos/fixture-owner/fixture-repo/actions/secrets/ENKV_FIXTURE_" + suffix
		if scope == "github-organization" {
			profile.GitHub.Repository = ""
			profile.GitHub.SelectedRepositoryIDs = []uint64{101, 202}
			slot = "orgs/fixture-owner/actions/secrets/ENKV_FIXTURE_" + suffix
		}
		if scope == "github-environment" {
			profile.GitHub.Environment = "fixture-environment"
			slot = "repos/fixture-owner/fixture-repo/environments/fixture-environment/secrets/ENKV_FIXTURE_" + suffix
		}
	}
	rows := []records.OutputFixtureRow{}
	for index, tail := range []string{"_P", "_S"} {
		target := records.OutputFixtureTarget{Index: uint32(index), PlannedSlot: slot + tail, ConsumerLocator: slot + tail, ExclusiveNamespaceDigest: strings.Repeat("c", 64)}
		if scope == "aws-secrets-manager" {
			target.ConsumerLocator += "?stage=AWSCURRENT"
		}
		if scope == "gcp-secret-manager" {
			target.ConsumerLocator += "/versions/latest"
		}
		profile.Targets = append(profile.Targets, target)
		rows = append(rows, records.OutputFixtureRow{ProfileID: profile.ProfileID, PlannedSlot: target.PlannedSlot, ExclusiveNamespaceDigest: target.ExclusiveNamespaceDigest})
	}
	input.Profiles = []records.OutputFixtureProfile{profile}
	if input.Validate(input.Scope, "cleanup") != nil || records.NewOutputFixtureInventory(input.InventoryPath, input.Scope, rows) != nil || records.WriteOutputFixtureJoined(input.JoinedPath, input.Scope) != nil {
		t.Fatal("cleaner fixture")
	}
	if profile.Cloud != nil {
		principals := []string{"serviceAccount:writer@fixture-project.iam.gserviceaccount.com", "serviceAccount:consumer-a@fixture-project.iam.gserviceaccount.com", "serviceAccount:consumer-b@fixture-project.iam.gserviceaccount.com"}
		if scope == "aws-secrets-manager" {
			principals = []string{"arn:aws:iam::123456789012:user/writer", "arn:aws:iam::123456789012:user/consumer-a", "arn:aws:iam::123456789012:user/consumer-b"}
		}
		if records.SetOutputFixtureActors(input.InventoryPath, input.Scope, records.OutputFixtureActors{ProfileID: profile.ProfileID, Writer: principals[0], ReaderA: principals[1], ReaderB: principals[2]}) != nil {
			t.Fatal("actual actor facts")
		}
	}
	return input, &runBudget{limits: liveLimits{Requests: 32, BodyBytes: 32 * operationBodyAllowance}, keys: map[string]bool{}}
}

func livePublicationCleanupAction(t *testing.T, input *records.OutputFixtureInput, index uint32, number int, action uint8, outcome string) string {
	t.Helper()
	attempt := fmt.Sprintf("%064x", number)
	if records.BeginOutputFixtureAction(input.InventoryPath, input.Scope, index, attempt, action) != nil {
		t.Fatal("action intent")
	}
	instance := ""
	if outcome == "acknowledged" && (action == contract.PublicationCreateEmpty || action == contract.PublicationCreateWithValue) {
		for _, profile := range input.Profiles {
			for _, target := range profile.Targets {
				if target.Index == index {
					instance = target.PlannedSlot
					if profile.Scope == "aws-secrets-manager" {
						instance += "-a1B2c3"
					}
				}
			}
		}
		if instance == "" {
			t.Fatal("missing exact fixture target")
		}
	}
	if outcome != "pending" && records.RecordOutputFixtureAction(input.InventoryPath, input.Scope, index, attempt, outcome, instance) != nil {
		t.Fatal("action result")
	}
	return attempt
}

func livePublicationCleanupRead(t *testing.T, input *records.OutputFixtureInput) records.OutputFixtureInventory {
	t.Helper()
	inventory, err := records.ReadOutputFixtureInventory(input.InventoryPath, input.Scope)
	if err != nil {
		t.Fatal("inventory read")
	}
	return inventory
}

func livePublicationCleanupFact(t *testing.T, err error, operation, cause, effect string) records.HarnessFailure {
	t.Helper()
	var safe interface{ SafeHarnessFailure() records.HarnessFailure }
	if err == nil || !errors.As(err, &safe) {
		t.Fatal("safe error absent")
	}
	fact := safe.SafeHarnessFailure()
	if !fact.Validate() || fact.Operation != operation || fact.Cause != cause || fact.Effect != effect {
		t.Fatalf("safe fact %+v", fact)
	}
	if strings.Contains(err.Error(), "fixture-project") || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("raw data in failure")
	}
	return fact
}

// full_only: false
func TestLivePublicationCleanupAdmissionPrecedesHelpers(t *testing.T) {
	for _, damage := range []string{"nil", "old-schema", "writer-reference", "missing-join", "wrong-join-scope", "wrong-inventory-scope", "last-row-digest", "last-row-instance", "extra-row", "wrong-mode"} {
		t.Run(damage, func(t *testing.T) {
			input, budget := livePublicationCleanupFixture(t, "gcp-secret-manager")
			livePublicationCleanupAction(t, input, 0, 1, contract.PublicationCreateEmpty, "acknowledged")
			livePublicationCleanupAction(t, input, 1, 2, contract.PublicationCreateEmpty, "acknowledged")
			inventory := livePublicationCleanupRead(t, input)
			switch damage {
			case "old-schema":
				input.SchemaVersion = 1
			case "nil":
				input = nil
			case "writer-reference":
				input.Profiles[0].Writer = &records.OutputFixtureActor{CredentialsFile: "/not-opened/writer"}
			case "missing-join":
				if os.Remove(input.JoinedPath) != nil {
					t.Fatal("remove joined")
				}
			case "wrong-join-scope":
				joined := records.OutputFixtureJoined{SchemaVersion: 1, Scope: input.Scope, Joined: true}
				joined.Scope.DomainID = strings.Repeat("d", 64)
				if records.WriteJSON(input.JoinedPath, joined, 0600) != nil {
					t.Fatal("damage joined")
				}
			case "wrong-inventory-scope":
				inventory.Scope.DomainID = strings.Repeat("d", 64)
			case "last-row-digest":
				inventory.Rows[1].ExclusiveNamespaceDigest = strings.Repeat("d", 64)
			case "last-row-instance":
				inventory.Rows[1].OwnedInstance += "-foreign"
			case "extra-row":
				inventory.Rows = append(inventory.Rows, records.OutputFixtureRow{})
			case "wrong-mode":
				if os.Chmod(input.InventoryPath, 0644) != nil {
					t.Fatal("damage mode")
				}
			}
			if input != nil && damage != "wrong-mode" && (damage == "wrong-inventory-scope" || damage == "last-row-digest" || damage == "last-row-instance" || damage == "extra-row") {
				if records.WriteJSON(input.InventoryPath, inventory, 0600) != nil {
					t.Fatal("damage inventory")
				}
			}
			constructions := 0
			summary, err := cleanupLivePublicationWith(t.Context(), input, budget, func(records.OutputFixtureProfile, []string, *runBudget) (livePublicationCleaner, error) {
				constructions++
				return nil, errors.New("PRIVATE")
			})
			if err == nil || constructions != 0 || summary != (livePublicationCleanupSummary{}) {
				t.Fatal("incomplete group admission entered helper", constructions, summary)
			}
			var safe interface{ SafeHarnessFailure() records.HarnessFailure }
			if !errors.As(err, &safe) || !safe.SafeHarnessFailure().Validate() {
				t.Fatal("invalid admission fact")
			}
		})
	}
}

// full_only: false
func TestLivePublicationCleanupIntentOrderAndOriginalUnknown(t *testing.T) {
	input, budget := livePublicationCleanupFixture(t, "gcp-secret-manager")
	first := livePublicationCleanupAction(t, input, 0, 1, contract.PublicationCreateEmpty, "acknowledged")
	second := livePublicationCleanupAction(t, input, 1, 2, contract.PublicationCreateEmpty, "unknown")
	original := input.Clone()
	calls := 0
	constructs := 0
	summary, err := cleanupLivePublicationWith(t.Context(), input, budget, func(profile records.OutputFixtureProfile, actors []string, gotBudget *runBudget) (livePublicationCleaner, error) {
		constructs++
		want := []string{"serviceAccount:writer@fixture-project.iam.gserviceaccount.com", "serviceAccount:consumer-a@fixture-project.iam.gserviceaccount.com", "serviceAccount:consumer-b@fixture-project.iam.gserviceaccount.com"}
		if profile.Writer != nil || profile.ConsumerA != nil || profile.ConsumerB != nil || profile.Native != nil || !reflect.DeepEqual(actors, want) || gotBudget != budget {
			t.Fatal("cleaner exclusions/projection")
		}
		return livePublicationCleanupCheck(func(ctx context.Context, target liveOutputCleanupTarget) (liveOutputCleanupResult, error) {
			calls++
			inventory := livePublicationCleanupRead(t, input)
			row := inventory.Rows[target.Index]
			if row.Cleanup == nil || row.Cleanup.Outcome != "pending" || row.Cleanup.AttemptID == row.BirthAttemptID || target.CreateAttempt.IsZero() || records.ReadOutputFixtureJoined(input.JoinedPath, input.Scope) != nil {
				t.Fatal("helper lacks durable joined intent")
			}
			wantID := first
			if target.Index == 1 {
				wantID = second
				if target.OwnedInstance != "" {
					t.Fatal("uncertain create invented birth")
				}
			} else if target.OwnedInstance != target.PlannedSlot {
				t.Fatal("birth lost")
			}
			if fmt.Sprintf("%x", target.CreateAttempt[:]) != wantID {
				t.Fatal("create receipt correlation")
			}
			return liveOutputCleanupResult{Disposition: liveOutputDeleteAcknowledged, ResolvedInstance: target.PlannedSlot}, nil
		}), nil
	})
	if constructs != 1 || calls != 2 || summary != (livePublicationCleanupSummary{Attempted: 2, Resolved: 1, Remaining: 1, Unknown: 1}) {
		t.Fatal("summary/calls", summary, constructs, calls)
	}
	fact := livePublicationCleanupFact(t, err, "output_cleanup", "evidence_unavailable", "unknown")
	if fact.TargetIndex == nil || *fact.TargetIndex != 1 {
		t.Fatal("wrong unresolved row")
	}
	inventory := livePublicationCleanupRead(t, input)
	if inventory.Rows[1].Cleanup.Outcome != "acknowledged" || inventory.Rows[1].Attempts[0].Outcome != "unknown" || inventory.Rows[1].OwnedInstance != "" || !reflect.DeepEqual(input, original) {
		t.Fatal("cleanup upgraded unknown or changed input")
	}
	secondSummary, secondErr := cleanupLivePublicationWith(t.Context(), input, budget, func(records.OutputFixtureProfile, []string, *runBudget) (livePublicationCleaner, error) {
		t.Fatal("cleanup replay")
		return nil, nil
	})
	if secondErr == nil || secondSummary != (livePublicationCleanupSummary{Resolved: 1, Remaining: 1, Unknown: 1}) {
		t.Fatal("reentry changed retained state", secondSummary, secondErr)
	}
}

// full_only: false
func TestLivePublicationCleanupEligibilityAndScheduledResidue(t *testing.T) {
	for _, scope := range []string{"aws-secrets-manager", "gcp-secret-manager", "github-repository", "github-organization", "github-environment"} {
		for _, state := range []string{"no-create", "not-sent", "no-effect", "terminal-delete", "pending-cleanup", "unknown-cleanup", "scheduled-cleanup"} {
			if state == "scheduled-cleanup" && scope != "aws-secrets-manager" {
				continue
			}
			t.Run(scope+"/"+state, func(t *testing.T) {
				input, budget := livePublicationCleanupFixture(t, scope)
				want := livePublicationCleanupSummary{}
				if state != "no-create" {
					outcome := "acknowledged"
					if state == "not-sent" {
						outcome = "not_sent"
					}
					if state == "no-effect" {
						outcome = "no_effect"
					}
					livePublicationCleanupAction(t, input, 0, 1, contract.PublicationCreateWithValue, outcome)
					if state == "terminal-delete" {
						livePublicationCleanupAction(t, input, 0, 2, contract.PublicationDeleteOwned, "acknowledged")
						want.Resolved = 1
						if scope == "aws-secrets-manager" {
							want = livePublicationCleanupSummary{Remaining: 1, Scheduled: 1}
						}
					}
					if strings.HasSuffix(state, "cleanup") {
						if records.BeginOutputFixtureCleanup(input.InventoryPath, input.Scope, 0, fmt.Sprintf("%064x", 3), input.JoinedPath) != nil {
							t.Fatal("cleanup intent")
						}
						outcome = "pending"
						if state == "unknown-cleanup" {
							outcome = "unknown"
						}
						if state == "scheduled-cleanup" {
							outcome = "scheduled"
						}
						if outcome != "pending" && records.RecordOutputFixtureCleanup(input.InventoryPath, input.Scope, 0, fmt.Sprintf("%064x", 3), outcome) != nil {
							t.Fatal("cleanup outcome")
						}
						want = livePublicationCleanupSummary{Remaining: 1, Unknown: 1}
						if outcome == "scheduled" {
							want = livePublicationCleanupSummary{Remaining: 1, Scheduled: 1}
						}
					}
				}
				got, err := cleanupLivePublicationWith(t.Context(), input, budget, func(records.OutputFixtureProfile, []string, *runBudget) (livePublicationCleaner, error) {
					t.Fatal("ineligible cleanup entered constructor")
					return nil, nil
				})
				if got != want || (err != nil) != (want.Unknown != 0) {
					t.Fatal("retained state", got, want, err)
				}
			})
		}
	}
}

// full_only: false
func TestLivePublicationCleanupResultsAndOneAttempt(t *testing.T) {
	for _, tc := range []struct {
		name, scope            string
		disposition            liveOutputCleanupDisposition
		invalid, helperFailure bool
		want                   livePublicationCleanupSummary
		outcome                string
	}{
		{"gcp-absent", "gcp-secret-manager", liveOutputAbsent, false, false, livePublicationCleanupSummary{Attempted: 1, Resolved: 1}, "absent"},
		{"aws-absent", "aws-secrets-manager", liveOutputAbsent, false, false, livePublicationCleanupSummary{Attempted: 1, Resolved: 1}, "absent"},
		{"gcp-ack", "gcp-secret-manager", liveOutputDeleteAcknowledged, false, false, livePublicationCleanupSummary{Attempted: 1, Resolved: 1}, "acknowledged"},
		{"github-ack", "github-repository", liveOutputDeleteAcknowledged, false, false, livePublicationCleanupSummary{Attempted: 1, Resolved: 1}, "acknowledged"},
		{"aws-scheduled", "aws-secrets-manager", liveOutputDeletionScheduled, false, false, livePublicationCleanupSummary{Attempted: 1, Remaining: 1, Scheduled: 1}, "scheduled"},
		{"github-false-absence", "github-repository", liveOutputAbsent, false, false, livePublicationCleanupSummary{Attempted: 1, Remaining: 1, Unknown: 1}, "unknown"},
		{"aws-false-erasure", "aws-secrets-manager", liveOutputDeleteAcknowledged, false, false, livePublicationCleanupSummary{Attempted: 1, Remaining: 1, Unknown: 1}, "unknown"},
		{"foreign-instance", "gcp-secret-manager", liveOutputDeleteAcknowledged, true, false, livePublicationCleanupSummary{Attempted: 1, Remaining: 1, Unknown: 1}, "unknown"},
		{"helper-error", "github-repository", 0, false, true, livePublicationCleanupSummary{Attempted: 1, Remaining: 1, Unknown: 1}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, budget := livePublicationCleanupFixture(t, tc.scope)
			livePublicationCleanupAction(t, input, 0, 1, contract.PublicationCreateWithValue, "acknowledged")
			calls := 0
			summary, err := cleanupLivePublicationWith(t.Context(), input, budget, func(records.OutputFixtureProfile, []string, *runBudget) (livePublicationCleaner, error) {
				return livePublicationCleanupCheck(func(context.Context, liveOutputCleanupTarget) (liveOutputCleanupResult, error) {
					calls++
					if tc.helperFailure {
						return liveOutputCleanupResult{}, errors.New("PRIVATE provider secret")
					}
					instance := livePublicationCleanupRead(t, input).Rows[0].OwnedInstance
					if tc.invalid {
						instance += "-foreign"
					}
					return liveOutputCleanupResult{Disposition: tc.disposition, ResolvedInstance: instance}, nil
				}), nil
			})
			if calls != 1 || summary != tc.want || (err != nil) != (tc.want.Unknown != 0) || livePublicationCleanupRead(t, input).Rows[0].Cleanup.Outcome != tc.outcome {
				t.Fatal("result interpretation", calls, summary, err)
			}
			again, againErr := cleanupLivePublicationWith(t.Context(), input, budget, func(records.OutputFixtureProfile, []string, *runBudget) (livePublicationCleaner, error) {
				t.Fatal("second helper attempt")
				return nil, nil
			})
			wantAgain := tc.want
			wantAgain.Attempted = 0
			if again != wantAgain || (againErr != nil) != (tc.want.Unknown != 0) {
				t.Fatal("second result", again, againErr)
			}
		})
	}
}

// full_only: false
func TestLivePublicationCleanupCancellationAndPersistence(t *testing.T) {
	for _, mode := range []string{"cancel-before-intent", "record-fails", "first-error-other-row-cleaned"} {
		t.Run(mode, func(t *testing.T) {
			input, budget := livePublicationCleanupFixture(t, "gcp-secret-manager")
			livePublicationCleanupAction(t, input, 0, 1, contract.PublicationCreateEmpty, "acknowledged")
			if mode == "first-error-other-row-cleaned" {
				livePublicationCleanupAction(t, input, 1, 2, contract.PublicationCreateEmpty, "acknowledged")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancel-before-intent" {
				cancel()
			}
			calls := 0
			summary, err := cleanupLivePublicationWith(ctx, input, budget, func(records.OutputFixtureProfile, []string, *runBudget) (livePublicationCleaner, error) {
				return livePublicationCleanupCheck(func(_ context.Context, target liveOutputCleanupTarget) (liveOutputCleanupResult, error) {
					calls++
					if mode == "record-fails" {
						if os.Chmod(input.InventoryPath, 0400) != nil {
							t.Fatal("record failure setup")
						}
					}
					if mode == "first-error-other-row-cleaned" && target.Index == 0 {
						return liveOutputCleanupResult{}, livePublicationCleanupError(&target.Index, "conditional_delete", "transport", "unknown")
					}
					return liveOutputCleanupResult{Disposition: liveOutputDeleteAcknowledged, ResolvedInstance: target.PlannedSlot}, nil
				}), nil
			})
			if err == nil {
				t.Fatal("failure silenced")
			}
			switch mode {
			case "cancel-before-intent":
				if calls != 0 || summary != (livePublicationCleanupSummary{Remaining: 1}) || livePublicationCleanupRead(t, input).Rows[0].Cleanup != nil {
					t.Fatal("cancel entered effect", summary, calls)
				}
				livePublicationCleanupFact(t, err, "output_cleanup", "cancelled", "no_send")
			case "record-fails":
				if calls != 1 || summary != (livePublicationCleanupSummary{Attempted: 1, Remaining: 1, Unknown: 1}) {
					t.Fatal("lost pending intent", summary, calls)
				}
				livePublicationCleanupFact(t, err, "output_cleanup", "persistence_failed", "unknown")
				if os.Chmod(input.InventoryPath, 0600) != nil || livePublicationCleanupRead(t, input).Rows[0].Cleanup.Outcome != "pending" {
					t.Fatal("pending state lost")
				}
				again, againErr := cleanupLivePublicationWith(t.Context(), input, budget, func(records.OutputFixtureProfile, []string, *runBudget) (livePublicationCleaner, error) {
					t.Fatal("persistence failure replay")
					return nil, nil
				})
				if againErr == nil || again.Attempted != 0 {
					t.Fatal("persistence replay")
				}
			case "first-error-other-row-cleaned":
				if calls != 2 || summary != (livePublicationCleanupSummary{Attempted: 2, Resolved: 1, Remaining: 1, Unknown: 1}) {
					t.Fatal("other exact row not cleaned", summary, calls)
				}
				fact := livePublicationCleanupFact(t, err, "output_cleanup", "transport", "unknown")
				if *fact.TargetIndex != 0 {
					t.Fatal("first error replaced")
				}
			}
		})
	}
}

// full_only: false
func TestLivePublicationCleanupRealGitHub404RetainsResidue(t *testing.T) {
	input, budget := livePublicationCleanupFixture(t, "github-repository")
	if os.WriteFile(input.Profiles[0].Cleaner.CredentialsFile, []byte("github_pat_CONTROLLED"), 0600) != nil {
		t.Fatal("controlled bearer")
	}
	livePublicationCleanupAction(t, input, 0, 1, contract.PublicationCreateWithValue, "acknowledged")
	requests := 0
	body := &liveGitHubCheckBody{Reader: strings.NewReader(`{"message":"Not Found"}`)}
	summary, err := cleanupLivePublicationWith(t.Context(), input, budget, func(profile records.OutputFixtureProfile, actors []string, budget *runBudget) (livePublicationCleaner, error) {
		helper, err := newLivePublicationCleaner(profile, actors, budget)
		if err != nil {
			return nil, err
		}
		github := helper.(*liveGitHubOutput)
		github.transport = liveGitHubCheckTransport(func(request *http.Request) (*http.Response, error) {
			requests++
			if request.Method != "GET" || request.URL.Path != "/"+profile.Targets[0].PlannedSlot {
				t.Fatal("unexpected exact request")
			}
			return &http.Response{StatusCode: 404, Body: body}, nil
		})
		return github, nil
	})
	if requests != 1 || !body.closed || summary != (livePublicationCleanupSummary{Attempted: 1, Remaining: 1, Unknown: 1}) || budget.snapshot().Requests != 1 || livePublicationCleanupRead(t, input).Rows[0].Cleanup.Outcome != "unknown" {
		t.Fatal("404 became absence", requests, summary, budget.snapshot())
	}
	livePublicationCleanupFact(t, err, "output_cleanup", "evidence_unavailable", "no_effect")
	_, againErr := cleanupLivePublication(t.Context(), input, budget)
	if againErr == nil || requests != 1 {
		t.Fatal("real helper replay")
	}
}

// full_only: false
func TestLivePublicationCleanupRealConstructorsStayLazy(t *testing.T) {
	cloudScope := "aws-secrets-manager"
	if liveFamily == contract.GCP {
		cloudScope = "gcp-secret-manager"
	}
	for _, scope := range []string{cloudScope, "github-repository", "github-organization", "github-environment"} {
		t.Run(scope, func(t *testing.T) {
			input, budget := livePublicationCleanupFixture(t, scope)
			var otherActors []string
			if input.Profiles[0].Cloud != nil {
				actors := livePublicationCleanupRead(t, input).Actors[0]
				otherActors = []string{actors.Writer, actors.ReaderA, actors.ReaderB}
			}
			helper, err := newLivePublicationCleaner(input.Profiles[0], otherActors, budget)
			if err != nil || helper == nil || budget.snapshot().Requests != 0 {
				t.Fatal("lazy helper constructor", err)
			}
			if _, err = os.Stat(input.Profiles[0].Cleaner.CredentialsFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("constructor opened/created source")
			}
		})
	}
}

// full_only: false
func TestLivePublicationCleanupRejectsUnqualifiedAbsence(t *testing.T) {
	input, budget := livePublicationCleanupFixture(t, "gcp-secret-manager")
	livePublicationCleanupAction(t, input, 0, 1, contract.PublicationCreateEmpty, "unknown")
	summary, err := cleanupLivePublicationWith(t.Context(), input, budget, func(records.OutputFixtureProfile, []string, *runBudget) (livePublicationCleaner, error) {
		return livePublicationCleanupCheck(func(context.Context, liveOutputCleanupTarget) (liveOutputCleanupResult, error) {
			return liveOutputCleanupResult{Disposition: liveOutputAbsent}, nil
		}), nil
	})
	if summary != (livePublicationCleanupSummary{Attempted: 1, Remaining: 1, Unknown: 1}) || livePublicationCleanupRead(t, input).Rows[0].Cleanup.Outcome != "unknown" {
		t.Fatal("unqualified empty response recorded absence", summary)
	}
	livePublicationCleanupFact(t, err, "output_cleanup", "invalid_acknowledgement", "unknown")
}

// full_only: false
func TestLivePublicationCleanupMixedAdmissionAndVector(t *testing.T) {
	for _, damage := range []bool{false, true} {
		t.Run(fmt.Sprintf("last-row-damaged-%t", damage), func(t *testing.T) {
			cloudScope := "aws-secrets-manager"
			if liveFamily == contract.GCP {
				cloudScope = "gcp-secret-manager"
			}
			input, budget := livePublicationCleanupFixture(t, cloudScope)
			inventory := livePublicationCleanupRead(t, input)
			input.Scope.Scenario = "publication.mixed-destinations/plain1_secret1_initial_noop_delete_mixed4"
			inventory.Scope = input.Scope
			for profileIndex, scope := range []string{"github-repository", "github-organization", "github-environment"} {
				fixture, _ := livePublicationCleanupFixture(t, scope)
				profile := fixture.Profiles[0]
				for index := range profile.Targets {
					profile.Targets[index].Index = uint32(2*(profileIndex+1) + index)
					target := profile.Targets[index]
					inventory.Rows = append(inventory.Rows, records.OutputFixtureRow{ProfileID: profile.ProfileID, PlannedSlot: target.PlannedSlot, ExclusiveNamespaceDigest: target.ExclusiveNamespaceDigest, Attempts: []records.OutputFixtureAttempt{}})
				}
				input.Profiles = append(input.Profiles, profile)
			}
			if input.Validate(input.Scope, "cleanup") != nil || records.WriteJSON(input.InventoryPath, inventory, 0600) != nil || records.WriteJSON(input.JoinedPath, records.OutputFixtureJoined{SchemaVersion: 1, Scope: input.Scope, Joined: true}, 0600) != nil {
				t.Fatal("mixed fixture admission")
			}
			for index := range input.Profiles {
				livePublicationCleanupAction(t, input, uint32(index*2), index+1, contract.PublicationCreateWithValue, "acknowledged")
			}
			if damage {
				inventory = livePublicationCleanupRead(t, input)
				inventory.Rows[7].ExclusiveNamespaceDigest = strings.Repeat("d", 64)
				if records.WriteJSON(input.InventoryPath, inventory, 0600) != nil {
					t.Fatal("last row damage")
				}
			}
			constructed, calls := 0, []uint32{}
			summary, err := cleanupLivePublicationWith(t.Context(), input, budget, func(profile records.OutputFixtureProfile, actors []string, gotBudget *runBudget) (livePublicationCleaner, error) {
				constructed++
				if profile.Cloud != nil && len(actors) != 3 || profile.GitHub != nil && len(actors) != 0 || gotBudget != budget {
					t.Fatal("mixed credential scope")
				}
				return livePublicationCleanupCheck(func(_ context.Context, target liveOutputCleanupTarget) (liveOutputCleanupResult, error) {
					if constructed != 4 {
						t.Fatal("effects entered before all lazy constructors admitted")
					}
					calls = append(calls, target.Index)
					disposition := liveOutputDeleteAcknowledged
					instance := target.PlannedSlot
					if profile.Cloud != nil && profile.Cloud.Provider == "aws" {
						disposition = liveOutputDeletionScheduled
						instance += "-a1B2c3"
					}
					return liveOutputCleanupResult{Disposition: disposition, ResolvedInstance: instance}, nil
				}), nil
			})
			if damage {
				if constructed != 0 || len(calls) != 0 || err == nil || summary != (livePublicationCleanupSummary{}) {
					t.Fatal("last row damage allowed earlier effect", constructed, calls, summary, err)
				}
				return
			}
			want := livePublicationCleanupSummary{Attempted: 4, Resolved: 4}
			if liveFamily == contract.AWS {
				want = livePublicationCleanupSummary{Attempted: 4, Resolved: 3, Remaining: 1, Scheduled: 1}
			}
			if err != nil || summary != want || !reflect.DeepEqual(calls, []uint32{0, 2, 4, 6}) {
				t.Fatal("mixed fixed result vector", summary, calls, err)
			}
		})
	}
}
