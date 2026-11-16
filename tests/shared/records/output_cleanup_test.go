package records

import (
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func outputCleanupStateFixture(profile string, actions []OutputFixtureAttempt, cleanup string) OutputFixtureInventory {
	row := OutputFixtureRow{ProfileID: profile, PlannedSlot: "exact-slot", ExclusiveNamespaceDigest: outputFixtureID(1), Attempts: []OutputFixtureAttempt{}}
	for index, action := range actions {
		action.AttemptID = outputFixtureID(index + 10)
		row.Attempts = append(row.Attempts, action)
		if (action.Action == contract.PublicationCreateEmpty || action.Action == contract.PublicationCreateWithValue) && action.Outcome == "acknowledged" {
			row.BirthAttemptID, row.OwnedInstance = action.AttemptID, "exact-instance"
		}
	}
	if cleanup != "" {
		row.Cleanup = &OutputFixtureCleanup{AttemptID: outputFixtureID(30), Outcome: cleanup}
	}
	inventory := OutputFixtureInventory{SchemaVersion: 1, Scope: OutputFixtureScope{RunID: strings.Repeat("a", 32), Scenario: "publication.value-policy-delete/plain1_secret1_value_policy_delete", DomainID: outputFixtureID(2), WriterID: "publication-writer"}, Rows: []OutputFixtureRow{row}, Actors: []OutputFixtureActors{}}
	if outputCloudProfile(profile) {
		inventory.Actors = append(inventory.Actors, OutputFixtureActors{ProfileID: profile, Writer: "writer", ReaderA: "consumer-a", ReaderB: "consumer-b"})
	}
	return inventory
}

// full_only: false
func TestOutputFixtureCleanupStatePreservesUnknown(t *testing.T) {
	// These literal expectations follow the retained original receipts. A later
	// acknowledgement or point-in-time absence cannot settle their late effects.
	for _, profile := range []string{outputAWSProfile, outputGCPProfile, outputGitHubProfile, "ENKV/OUTPUT/GITHUB-ORGANIZATION/v3", "ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3"} {
		for _, original := range []struct {
			name    string
			actions []OutputFixtureAttempt
		}{
			{"create-pending", []OutputFixtureAttempt{{Action: contract.PublicationCreateEmpty, Outcome: "pending"}}},
			{"create-unknown", []OutputFixtureAttempt{{Action: contract.PublicationCreateWithValue, Outcome: "unknown"}}},
			{"write-unknown", []OutputFixtureAttempt{{Action: contract.PublicationCreateEmpty, Outcome: "acknowledged"}, {Action: contract.PublicationWriteValue, Outcome: "unknown"}}},
			{"policy-unknown", []OutputFixtureAttempt{{Action: contract.PublicationCreateEmpty, Outcome: "acknowledged"}, {Action: contract.PublicationUpdatePolicy, Outcome: "unknown"}}},
			{"delete-unknown", []OutputFixtureAttempt{{Action: contract.PublicationCreateEmpty, Outcome: "acknowledged"}, {Action: contract.PublicationDeleteOwned, Outcome: "unknown"}}},
			{"reserved-delete-unknown", []OutputFixtureAttempt{{Action: contract.PublicationCreateEmpty, Outcome: "unknown"}, {Action: contract.PublicationDeleteReservedSlot, Outcome: "unknown"}}},
			{"delete-ack-after-unknown", []OutputFixtureAttempt{{Action: contract.PublicationCreateEmpty, Outcome: "unknown"}, {Action: contract.PublicationDeleteReservedSlot, Outcome: "acknowledged"}}},
		} {
			for _, cleanup := range []string{"", "pending", "unknown", "absent", "acknowledged", "scheduled"} {
				if cleanup == "scheduled" && profile != outputAWSProfile {
					continue
				}
				t.Run(profile+"/"+original.name+"/"+cleanup, func(t *testing.T) {
					inventory := outputCleanupStateFixture(profile, original.actions, cleanup)
					before := inventory.clone()
					want := OutputFixtureCleanupState{Remaining: true, Unknown: true}
					terminal := original.name == "delete-ack-after-unknown"
					want.Eligible = cleanup == "" && !terminal
					want.Scheduled = profile == outputAWSProfile && (cleanup == "scheduled" || cleanup == "acknowledged" || cleanup != "absent" && terminal)
					got, err := inventory.CleanupState(0)
					if original.name == "policy-unknown" && profile != "ENKV/OUTPUT/GITHUB-ORGANIZATION/v3" {
						if err == nil || !reflect.DeepEqual(inventory, before) {
							t.Fatal("unsupported policy record accepted or changed")
						}
						return
					}
					if err != nil || got != want {
						t.Fatalf("state %+v want %+v, error %v", got, want, err)
					}
					if !reflect.DeepEqual(inventory, before) {
						t.Fatal("classification changed retained evidence")
					}
				})
			}
		}
	}
}

// full_only: false
func TestOutputFixtureCleanupStateKnownOutcomes(t *testing.T) {
	create := OutputFixtureAttempt{Action: contract.PublicationCreateEmpty, Outcome: "acknowledged"}
	deleteACK := OutputFixtureAttempt{Action: contract.PublicationDeleteOwned, Outcome: "acknowledged"}
	for _, profile := range []string{outputAWSProfile, outputGCPProfile, outputGitHubProfile} {
		for _, tc := range []struct {
			name    string
			actions []OutputFixtureAttempt
			cleanup string
			want    OutputFixtureCleanupState
		}{
			{"empty", nil, "", OutputFixtureCleanupState{}},
			{"not-sent", []OutputFixtureAttempt{{Action: contract.PublicationCreateEmpty, Outcome: "not_sent"}}, "", OutputFixtureCleanupState{}},
			{"no-effect", []OutputFixtureAttempt{{Action: contract.PublicationCreateEmpty, Outcome: "no_effect"}}, "", OutputFixtureCleanupState{}},
			{"eligible", []OutputFixtureAttempt{create}, "", OutputFixtureCleanupState{Eligible: true, Remaining: true}},
			{"pending", []OutputFixtureAttempt{create}, "pending", OutputFixtureCleanupState{Remaining: true, Unknown: true}},
			{"unknown", []OutputFixtureAttempt{create}, "unknown", OutputFixtureCleanupState{Remaining: true, Unknown: true}},
			{"absent", []OutputFixtureAttempt{create}, "absent", OutputFixtureCleanupState{}},
			{"acknowledged", []OutputFixtureAttempt{create}, "acknowledged", OutputFixtureCleanupState{Remaining: profile == outputAWSProfile, Scheduled: profile == outputAWSProfile}},
			{"terminal-delete", []OutputFixtureAttempt{create, deleteACK}, "", OutputFixtureCleanupState{Remaining: profile == outputAWSProfile, Scheduled: profile == outputAWSProfile}},
			{"later-write-not-terminal", []OutputFixtureAttempt{create, deleteACK, {Action: contract.PublicationWriteValue, Outcome: "acknowledged"}}, "", OutputFixtureCleanupState{Eligible: true, Remaining: true}},
		} {
			t.Run(profile+"/"+tc.name, func(t *testing.T) {
				got, err := outputCleanupStateFixture(profile, tc.actions, tc.cleanup).CleanupState(0)
				if err != nil || got != tc.want {
					t.Fatalf("state %+v want %+v, error %v", got, tc.want, err)
				}
			})
		}
	}
	got, err := outputCleanupStateFixture(outputAWSProfile, []OutputFixtureAttempt{create}, "scheduled").CleanupState(0)
	if err != nil || got != (OutputFixtureCleanupState{Remaining: true, Scheduled: true}) {
		t.Fatal("known AWS schedule became erasure or uncertainty", got, err)
	}
}

// full_only: false
func TestOutputFixtureCleanupStateValidatesWholeInventory(t *testing.T) {
	for _, damage := range []string{"index", "scope", "other-row", "actors", "foreign-schedule"} {
		t.Run(damage, func(t *testing.T) {
			inventory := outputCleanupStateFixture(outputGCPProfile, []OutputFixtureAttempt{{Action: contract.PublicationCreateEmpty, Outcome: "acknowledged"}}, "")
			index := uint32(0)
			switch damage {
			case "index":
				index = ^uint32(0)
			case "scope":
				inventory.Scope.DomainID = ""
			case "other-row":
				inventory.Rows = append(inventory.Rows, OutputFixtureRow{})
			case "actors":
				inventory.Actors = nil
			case "foreign-schedule":
				inventory.Rows[0].Cleanup = &OutputFixtureCleanup{AttemptID: outputFixtureID(30), Outcome: "scheduled"}
			}
			got, err := inventory.CleanupState(index)
			if err == nil || got != (OutputFixtureCleanupState{}) {
				t.Fatal("invalid inventory granted state", got, err)
			}
		})
	}
}
