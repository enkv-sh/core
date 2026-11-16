package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedIdentityAllocationPreservesFutureAttemptsAndSourceKeys(t *testing.T) {
	for _, sources := range [][]contract.GeneratorDeclarationEntry{nil, {generatedSealedSource(t, "alpha")}} {
		s := generatedReservationState(t, sources...)
		selected, err := s.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		used := map[contract.ID]bool{generatedVectorID(99): true}
		if s.retainGeneratedIdentities(t.Context(), used) != nil {
			t.Fatal("generated identities refused")
		}
		want := []contract.ID{generatedVectorID(99), selected.parent.OperationID, selected.parent.MaterialID, selected.parent.PlanGraphID, selected.phase.PhaseID}
		for _, lineage := range selected.bundles[0].Lineages {
			want = append(want, lineage.LineageID, lineage.EntryIncarnationID)
			for _, x := range lineage.Templates[:lineage.TemplateCount] {
				data, commitment, err := contract.GeneratorResultKeyIDs(x.ResultID)
				if err != nil {
					t.Fatal(err)
				}
				want = append(want, x.AttemptID, x.ResourceIncarnationID, x.PlannedValueSlotID, x.DutyID, x.HazardID,
					x.TransmissionID, x.ResultID, x.InboxID, data, commitment)
			}
		}
		if len(sources) != 0 {
			source, err := contract.InspectSealedInputEnvelope(sources[0].Payload)
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, source.Core.FileIdentity, source.Core.SourceID, source.Core.DataKeyID)
			material, err := contract.InspectOperationMaterialRecord(selected.records[generatedRecordKey{contract.OperationMaterialSupportKind, selected.parent.MaterialID}].Body)
			if err != nil {
				t.Fatal(err)
			}
			protected, err := contract.InspectGeneratedSourceProtections(material, selected.protected[material.Core.OperationMaterialID])
			if err != nil {
				t.Fatal(err)
			}
			row, err := protected.Row(0)
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, row.Transfer.Core.EnvelopeID)
		}
		for _, id := range want {
			if id.IsZero() || !used[id] {
				t.Fatal("live or planned identity became reusable", id)
			}
		}
		if used[contract.ID{}] {
			t.Fatal("absent identity became allocated")
		}
	}
}

// full_only: false
func TestGeneratedIdentityAllocationPreservesRetainedValueKeys(t *testing.T) {
	s, retained, _ := generatedCanonicalState(t, true)
	used := make(map[contract.ID]bool)
	if s.retainGeneratedIdentities(t.Context(), used) != nil {
		t.Fatal("canonical identities refused")
	}
	payload, err := contract.InspectCanonicalPayload(retained.Entry.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []contract.ID{retained.Entry.Incarnation, retained.Entry.ValueState, retained.Entry.OriginSnapshot,
		retained.Entry.OriginTransition, payload.DataKeyID, payload.CommitmentKeyID} {
		if !used[id] {
			t.Fatal("retained value identity became reusable", id)
		}
	}
	if s.retainGeneratedIdentities(t.Context(), nil) == nil {
		t.Fatal("missing identity accumulator accepted")
	}
	s.root.Domain = generatedVectorID(99)
	if s.retainGeneratedIdentities(t.Context(), make(map[contract.ID]bool)) == nil {
		t.Fatal("different selected domain supplied retained identities")
	}
}
