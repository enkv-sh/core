package core

import (
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedRetirementAcknowledgementClosesAtAcknowledgedCeiling(t *testing.T) {
	s, original, duty, _ := generatedEnteredRetirementState(t, true)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	revision := generatedVectorID(96)
	closure, err := g.generatedRetirementAcknowledgement(t.Context(), original.record.AttemptID, revision)
	if err != nil {
		t.Fatal(err)
	}
	if closure.duty.DutyID != duty.DutyID || closure.duty.CompletionClass != contract.GeneratedCompletionAcknowledged ||
		closure.release.InboxID != original.record.InboxID || closure.release.OriginalResultID != original.record.ResultID ||
		closure.release.SelectedHandoffDigest != contract.Hash(original.result) || closure.release.ObjectLength != uint32(len(original.result)) ||
		closure.release.HandoffRevisionID != revision || closure.release.State != contract.GeneratedReleasePending {
		t.Fatal("acknowledged retirement changed its ceiling or selected handoff")
	}

	generatedRepackSupportAtLocations(t, s, closure.rows, g.bundles, closure.locations)
	s.root.Generated.Slices = closure.slices
	for _, page := range s.access {
		if page != nil {
			page.Records = slices.DeleteFunc(page.Records, func(row contract.AccessRecord) bool {
				return row.MaterialKind == 3 && row.MaterialID == closure.material
			})
		}
	}
	s.root.AccessRecordCount = 0
	s.root.Generated.ActiveOwner, s.root.Generated.ActivePhase, s.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	s.root.Generated.Duties, s.root.Generated.Retiring, s.root.Generated.Results, s.root.Generated.Materials = 0, 0, 0, 0
	s.root.Generated.PendingReleases = 1
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{closure.release.InboxID})
	if err != nil {
		t.Fatal(err)
	}
	s.recountChildren()
	generatedCommitFixtureAccess(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("acknowledgement release material index")
	}
	after, err := s.selectedGeneratedWork(context.Background())
	if err != nil || !after.hasRecord(generatedRecordKey{12, closure.release.InboxID}) ||
		after.hasRecord(generatedRecordKey{10, duty.DutyID}) || len(after.attempts) != 0 {
		t.Fatal("acknowledged closure did not release the retirement and retain only pending inbox release", err)
	}
}

// full_only: false
func TestGeneratedRetirementAcknowledgementRefusesUnknownOrContradictoryResult(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		s, a, duty := generatedParkedRetirementState(t)
		g, err := s.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.generatedRetirementAcknowledgement(t.Context(), a.record.AttemptID, generatedVectorID(96)); err == nil {
			t.Fatal("unknown retirement closed as acknowledged")
		}
		if !g.hasRecord(generatedRecordKey{10, duty.DutyID}) {
			t.Fatal("unknown retirement lost its duty")
		}
	})
	t.Run("different target", func(t *testing.T) {
		s, a, _, _ := generatedEnteredRetirementState(t, true)
		g, err := s.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		a = g.attempts[a.record.AttemptID]
		a.expected.TargetResourceDigest = generatedVectorID(96)
		g.attempts[a.record.AttemptID] = a
		if _, err := g.generatedRetirementAcknowledgement(t.Context(), a.record.AttemptID, generatedVectorID(97)); err == nil {
			t.Fatal("acknowledgement for a different target closed retirement")
		}
	})
}
