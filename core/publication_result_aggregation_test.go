package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationEqualFailurePriorityKeepsOneDeterministicEpisode(t *testing.T) {
	want := Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonAccess, RequestedRevision: contract.ID{10}, ObservedRevision: contract.ID{30}, ObservedSnapshotID: contract.ID{31}, Evidence: AuthenticatedClosure}
	other := want
	other.RequestedRevision, other.ObservedRevision, other.ObservedSnapshotID = contract.ID{20}, contract.ID{21}, contract.ID{22}
	for _, reverse := range []bool{false, true} {
		failures := []Result{want, other}
		if reverse {
			failures[0], failures[1] = other, want
		}
		plan := publicationPlan{session: &StateSession{}, vector: contract.PublicationOutcomeVector{Schema: 2, DomainID: contract.ID{1}, OperationID: contract.ID{2}, SnapshotID: contract.ID{3}, SelectionDigest: contract.ID{4}}}
		for i := range failures {
			plan.targets = append(plan.targets, publicationTargetPlan{actions: []uint8{contract.PublicationWriteValue}})
			plan.vector.Entries = append(plan.vector.Entries, contract.PublicationTargetOutcome{CoordinateID: contract.ID{byte(i + 1)}, Actions: []contract.PublicationOutcome{{Action: contract.PublicationWriteValue, ProjectionCommitment: contract.ID{8}, Disposition: contract.PublicationNotSent, CoreReason: uint16(AdmissionInvalid)}}})
		}
		calls := 0
		got := plan.executePublication(t.Context(), publicationPrivate{}, func(context.Context) (*StateSession, contract.Trust, Result) {
			failure := failures[calls]
			calls++
			return nil, nil, failure
		})
		if calls != 2 || got.state != want {
			t.Error("same-priority order changed or mixed selection episodes", reverse, calls, got.state)
		}
	}
}

// full_only: false
func TestPublicationOperationFailureIsIndependentOfTargetOrder(t *testing.T) {
	failures := []Result{
		{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonAccess},
		{Outcome: Contention, Reason: StalePrecondition},
		{Outcome: AdmissionRefused, Reason: InvalidIntent},
	}
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		plan := publicationPlan{session: &StateSession{}, vector: contract.PublicationOutcomeVector{Schema: 2, DomainID: contract.ID{1}, OperationID: contract.ID{2}, SnapshotID: contract.ID{3}, SelectionDigest: contract.ID{4}}}
		for i := range order {
			plan.targets = append(plan.targets, publicationTargetPlan{actions: []uint8{contract.PublicationWriteValue}})
			plan.vector.Entries = append(plan.vector.Entries, contract.PublicationTargetOutcome{CoordinateID: contract.ID{byte(i + 1)}, Actions: []contract.PublicationOutcome{{Action: contract.PublicationWriteValue, ProjectionCommitment: contract.ID{8}, Disposition: contract.PublicationNotSent, CoreReason: uint16(AdmissionInvalid)}}})
		}
		calls := 0
		got := plan.executePublication(t.Context(), publicationPrivate{}, func(context.Context) (*StateSession, contract.Trust, Result) {
			failure := failures[order[calls]]
			calls++
			return nil, nil, failure
		})
		if calls != 3 || got.state != failures[0] || got.summary != contract.PublicationSummaryFailed {
			t.Errorf("order %v changed invocation failure: calls=%d state=%+v summary=%d", order, calls, got.state, got.summary)
		}
		for i, target := range got.output.Entries {
			if len(target.Actions) != 1 || target.Actions[0].Disposition != contract.PublicationNotSent || target.Actions[0].CoreReason != uint16(failures[order[i]].Reason) {
				t.Errorf("order %v lost exact not-sent failure for target %d: %+v", order, i, target)
			}
		}
	}
}
