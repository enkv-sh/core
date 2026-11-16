package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

type livePublicationCleanupSummary struct {
	Attempted, Resolved, Remaining, Unknown, Scheduled uint32
}

type livePublicationCleaner interface {
	DeleteFixture(context.Context, liveOutputCleanupTarget) (liveOutputCleanupResult, error)
}

// The local seam controls fixture cleanup, never Product execution. Its normal
// implementation only constructs the existing lazy provider helpers.
type livePublicationCleanerFactory func(records.OutputFixtureProfile, []string, *runBudget) (livePublicationCleaner, error)

type livePublicationCleanupFailure struct{ fact records.HarnessFailure }

func (e livePublicationCleanupFailure) Error() string                              { return "output fixture cleanup refused" }
func (e livePublicationCleanupFailure) SafeHarnessFailure() records.HarnessFailure { return e.fact }

func livePublicationCleanupError(index *uint32, stage, cause, effect string) error {
	fact := records.HarnessFailure{Operation: "setup_check", Stage: stage, Cause: cause, Effect: effect}
	if index != nil {
		value := *index
		fact.Operation, fact.TargetKind, fact.TargetIndex = "output_cleanup", "output_inventory", &value
	}
	if effect != "no_send" {
		fact.Attempt = 1
	}
	return livePublicationCleanupFailure{fact}
}

func livePublicationCleanupHelperError(err error, index uint32) error {
	var safe interface{ SafeHarnessFailure() records.HarnessFailure }
	if errors.As(err, &safe) {
		fact := safe.SafeHarnessFailure()
		if fact.Validate() {
			fact.Operation, fact.TargetKind, fact.TargetIndex = "output_cleanup", "output_inventory", &index
			return livePublicationCleanupFailure{fact}
		}
	}
	return livePublicationCleanupError(&index, "conditional_delete", "unknown_effect", "unknown")
}

func newLivePublicationCleaner(profile records.OutputFixtureProfile, otherActors []string, budget *runBudget) (livePublicationCleaner, error) {
	cleaner := liveOutputActor(*profile.Cleaner)
	if cloud := profile.Cloud; cloud != nil {
		return newLiveCloudOutput(liveCloudOutputSpec{Location: liveOutputLocation{Provider: cloud.Provider, Region: cloud.Region,
			Account: cloud.Account, ProjectNumber: cloud.ProjectNumber, SecretNamePrefix: cloud.SecretNamePrefix}, Cleaner: &cleaner,
			OtherActorPrincipals: append([]string(nil), otherActors...), Budget: budget})
	}
	github := profile.GitHub
	return newLiveGitHubOutput(liveGitHubOutputSpec{Scope: profile.Scope, Owner: github.Owner, Repository: github.Repository,
		Environment: github.Environment, SecretNamePrefix: github.SecretNamePrefix, Cleaner: &cleaner, Budget: budget})
}

func livePublicationCleanupInstance(profile records.OutputFixtureProfile, slot, instance string) bool {
	if instance == "" {
		return true
	}
	if profile.Cloud == nil || profile.Cloud.Provider == "gcp" {
		return instance == slot
	}
	if len(instance) != len(slot)+7 || !strings.HasPrefix(instance, slot+"-") {
		return false
	}
	for _, character := range instance[len(slot)+1:] {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", character) {
			return false
		}
	}
	return true
}

type livePublicationCleanupRow struct {
	profile  int
	target   liveOutputCleanupTarget
	state    records.OutputFixtureCleanupState
	possible bool
}

// cleanupLivePublication consumes only the original cleaner projection and
// positively joined writer evidence. It never retries a pending cleanup.
func cleanupLivePublication(ctx context.Context, input *records.OutputFixtureInput, budget *runBudget) (livePublicationCleanupSummary, error) {
	return cleanupLivePublicationWith(ctx, input, budget, newLivePublicationCleaner)
}

func cleanupLivePublicationWith(ctx context.Context, input *records.OutputFixtureInput, budget *runBudget, construct livePublicationCleanerFactory) (summary livePublicationCleanupSummary, resultErr error) {
	if ctx == nil || input == nil || budget == nil || construct == nil {
		return summary, livePublicationCleanupError(nil, "admission", "invalid_request", "no_send")
	}
	input = input.Clone()
	if input.Validate(input.Scope, "cleanup") != nil {
		return summary, livePublicationCleanupError(nil, "admission", "invalid_request", "no_send")
	}
	inventory, err := records.ReadOutputFixtureInventory(input.InventoryPath, input.Scope)
	if err != nil || len(inventory.Rows) != 2*len(input.Profiles) {
		return summary, livePublicationCleanupError(nil, "ownership_check", "evidence_unavailable", "no_send")
	}
	if records.ReadOutputFixtureJoined(input.JoinedPath, input.Scope) != nil {
		return summary, livePublicationCleanupError(nil, "writer_join", "evidence_unavailable", "no_send")
	}
	rows := make([]livePublicationCleanupRow, len(inventory.Rows))
	actors := make([][]string, len(input.Profiles))
	actorCount := 0
	// Admit the whole immutable group, including rows which need no operation,
	// before any helper can capture a credential or send a request.
	for profileIndex, profile := range input.Profiles {
		for _, actor := range inventory.Actors {
			if actor.ProfileID == profile.ProfileID && profile.Cloud != nil {
				actors[profileIndex] = []string{actor.Writer, actor.ReaderA, actor.ReaderB}
				actorCount++
			}
		}
		for _, target := range profile.Targets {
			row, rowErr := inventory.Row(target.Index, profile.ProfileID, target.PlannedSlot)
			if rowErr != nil || row.ExclusiveNamespaceDigest != target.ExclusiveNamespaceDigest || !livePublicationCleanupInstance(profile, target.PlannedSlot, row.OwnedInstance) {
				return summary, livePublicationCleanupError(&target.Index, "ownership_check", "ownership_mismatch", "no_send")
			}
			if profile.Cloud != nil && len(row.Attempts) != 0 && len(actors[profileIndex]) != 3 {
				return summary, livePublicationCleanupError(&target.Index, "ownership_check", "evidence_unavailable", "no_send")
			}
			state, stateErr := inventory.CleanupState(target.Index)
			if stateErr != nil {
				return summary, livePublicationCleanupError(&target.Index, "ownership_check", "evidence_unavailable", "no_send")
			}
			entry := livePublicationCleanupRow{profile: profileIndex, state: state, target: liveOutputCleanupTarget{Index: target.Index, PlannedSlot: target.PlannedSlot, OwnedInstance: row.OwnedInstance}}
			for _, attempt := range row.Attempts {
				if (attempt.Action == contract.PublicationCreateEmpty || attempt.Action == contract.PublicationCreateWithValue) &&
					(attempt.Outcome == "pending" || attempt.Outcome == "unknown" || attempt.Outcome == "acknowledged") {
					decoded, decodeErr := hex.DecodeString(attempt.AttemptID)
					if decodeErr != nil || len(decoded) != len(entry.target.CreateAttempt) {
						return summary, livePublicationCleanupError(&target.Index, "ownership_check", "ownership_mismatch", "no_send")
					}
					copy(entry.target.CreateAttempt[:], decoded)
					entry.possible = true
				}
			}
			rows[target.Index] = entry
		}
	}
	if actorCount != len(inventory.Actors) {
		return summary, livePublicationCleanupError(nil, "ownership_check", "ownership_mismatch", "no_send")
	}
	refreshSummary := func() {
		summary.Resolved, summary.Remaining, summary.Unknown, summary.Scheduled = 0, 0, 0, 0
		for _, row := range rows {
			if row.state.Remaining {
				summary.Remaining++
			} else if row.possible {
				summary.Resolved++
			}
			if row.state.Unknown {
				summary.Unknown++
			}
			if row.state.Scheduled {
				summary.Scheduled++
			}
		}
	}
	refreshSummary()
	helpers := make([]livePublicationCleaner, len(input.Profiles))
	for _, row := range rows {
		if !row.state.Eligible || helpers[row.profile] != nil {
			continue
		}
		helper, constructErr := construct(input.Profiles[row.profile], actors[row.profile], budget)
		if constructErr != nil || helper == nil {
			return summary, livePublicationCleanupError(&row.target.Index, "admission", "invalid_request", "no_send")
		}
		helpers[row.profile] = helper
	}
	remember := func(err error) {
		if resultErr == nil {
			resultErr = err
		}
	}
	for rowIndex := range rows {
		row := &rows[rowIndex]
		index := row.target.Index
		if !row.state.Eligible {
			continue
		}
		if ctx.Err() != nil {
			cause := "cancelled"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				cause = "deadline"
			}
			remember(livePublicationCleanupError(&index, "admission", cause, "no_send"))
			break
		}
		var attempt contract.ID
		if _, err := rand.Read(attempt[:]); err != nil || attempt.IsZero() {
			remember(livePublicationCleanupError(&index, "persistence", "persistence_failed", "no_send"))
			break
		}
		attemptID := hex.EncodeToString(attempt[:])
		if records.BeginOutputFixtureCleanup(input.InventoryPath, input.Scope, index, attemptID, input.JoinedPath) != nil {
			// A failed durable write can still leave a pending intent. Read that
			// state before returning; it can never authorize another helper call.
			updated, readErr := records.ReadOutputFixtureInventory(input.InventoryPath, input.Scope)
			state, stateErr := updated.CleanupState(index)
			if readErr == nil && stateErr == nil {
				row.state = state
			} else {
				row.state = records.OutputFixtureCleanupState{Remaining: true, Unknown: true, Scheduled: row.state.Scheduled}
			}
			remember(livePublicationCleanupError(&index, "persistence", "persistence_failed", "no_send"))
			break
		}
		summary.Attempted++
		result, helperErr := helpers[row.profile].DeleteFixture(ctx, row.target)
		outcome := "unknown"
		profile := input.Profiles[row.profile]
		if helperErr != nil {
			remember(livePublicationCleanupHelperError(helperErr, index))
		} else {
			valid := livePublicationCleanupInstance(profile, row.target.PlannedSlot, result.ResolvedInstance)
			if profile.Cloud == nil || profile.Cloud.Provider == "gcp" {
				valid = result.ResolvedInstance == row.target.PlannedSlot
			}
			if row.target.OwnedInstance != "" && result.ResolvedInstance != row.target.OwnedInstance {
				valid = false
			}
			switch result.Disposition {
			case liveOutputAbsent:
				if profile.GitHub != nil {
					valid = false
				}
				outcome = "absent"
			case liveOutputDeleteAcknowledged:
				if profile.Cloud != nil && profile.Cloud.Provider == "aws" || result.ResolvedInstance == "" {
					valid = false
				}
				outcome = "acknowledged"
			case liveOutputDeletionScheduled:
				if profile.Cloud == nil || profile.Cloud.Provider != "aws" || result.ResolvedInstance == "" {
					valid = false
				}
				outcome = "scheduled"
			default:
				valid = false
			}
			if !valid {
				outcome = "unknown"
				remember(livePublicationCleanupError(&index, "acknowledgement", "invalid_acknowledgement", "unknown"))
			}
		}
		if records.RecordOutputFixtureCleanup(input.InventoryPath, input.Scope, index, attemptID, outcome) != nil {
			row.state = records.OutputFixtureCleanupState{Remaining: true, Unknown: true, Scheduled: row.state.Scheduled}
			remember(livePublicationCleanupError(&index, "persistence", "persistence_failed", "unknown"))
			break
		}
		updated, readErr := records.ReadOutputFixtureInventory(input.InventoryPath, input.Scope)
		state, stateErr := updated.CleanupState(index)
		if readErr != nil || stateErr != nil {
			row.state = records.OutputFixtureCleanupState{Remaining: true, Unknown: true, Scheduled: row.state.Scheduled}
			remember(livePublicationCleanupError(&index, "persistence", "evidence_unavailable", "unknown"))
			break
		}
		row.state = state
	}
	refreshSummary()
	if resultErr == nil {
		for _, row := range rows {
			if row.state.Unknown || row.state.Remaining && !row.state.Scheduled {
				resultErr = livePublicationCleanupError(&row.target.Index, "ownership_check", "evidence_unavailable", "unknown")
				break
			}
		}
	}
	return summary, resultErr
}
