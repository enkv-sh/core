package core

import (
	"bytes"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestInstalledGeneratedCanonicalCaptureBorrowsSelectedOwnerVector(t *testing.T) {
	s, retained, _ := generatedCanonicalState(t, false)
	g := mustSelectedGeneratedWork(t, s)
	first := captureInstalledCanonicalOwner(t, s, g, retained.Entry.ValueState)
	second := captureInstalledCanonicalOwner(t, s, g, retained.Entry.ValueState)
	selected := selectedCanonicalOwnerVector(t, g, first.Owner)
	if !reflect.DeepEqual(first.Consumers, selected) || !reflect.DeepEqual(second.Consumers, selected) {
		t.Fatal("installed capture changed the exact authenticated consumer vector")
	}
	if &first.Consumers[0] != &selected[0] || &second.Consumers[0] != &selected[0] {
		t.Error("repeated same-owner installed capture copied the complete consumer header vector")
	}
	for i := range selected {
		if &first.Consumers[i][0] != &selected[i][0] || &second.Consumers[i][0] != &selected[i][0] {
			t.Error("repeated same-owner installed capture copied a selected consumer row", i)
		}
	}
}

// full_only: false
func TestInstalledGeneratedCanonicalCaptureKeepsDistinctOwnersSeparate(t *testing.T) {
	left, leftRetained, _ := generatedCanonicalState(t, false, "generated-left")
	right, rightRetained, _ := generatedCanonicalState(t, false, "generated-right")
	a := captureInstalledCanonicalOwner(t, left, mustSelectedGeneratedWork(t, left), leftRetained.Entry.ValueState)
	b := captureInstalledCanonicalOwner(t, right, mustSelectedGeneratedWork(t, right), rightRetained.Entry.ValueState)
	if a.Owner.RecordID == b.Owner.RecordID || &a.Consumers[0] == &b.Consumers[0] || &a.Consumers[0][0] == &b.Consumers[0][0] {
		t.Fatal("distinct authenticated owners shared captured consumer backing")
	}
	for _, input := range []contract.GeneratedCanonicalSelection{a, b} {
		for _, body := range input.Consumers {
			row, err := contract.InspectGeneratorConsumer(body)
			if err != nil || row.OwnerID != input.Owner.RecordID {
				t.Fatal("captured vector substituted a different owner", err)
			}
		}
	}
}

// full_only: false
func TestGeneratedCanonicalConsumerReturnKeepsIndependentOwnership(t *testing.T) {
	s, retained, _ := generatedCanonicalState(t, false)
	g := mustSelectedGeneratedWork(t, s)
	capture := captureInstalledCanonicalOwner(t, s, g, retained.Entry.ValueState)
	key := generatedRecordKey{kind: capture.Owner.Kind, id: capture.Owner.RecordID}
	returned, err := g.canonicalConsumer(key, retained.Entry.ValueState, s.admission.recipient)
	if err != nil {
		t.Fatal("public canonical consumer", err)
	}
	selected := selectedCanonicalOwnerVector(t, g, capture.Owner)
	if !reflect.DeepEqual(returned.Consumers, selected) || &returned.Consumers[0] == &selected[0] {
		t.Fatal("public canonical consumer borrowed the selected consumer headers")
	}
	for i := range selected {
		if &returned.Consumers[i][0] == &selected[i][0] {
			t.Fatal("public canonical consumer borrowed selected row bytes", i)
		}
	}
	owner := g.records[key]
	if &returned.Owner.Body[0] == &owner.Body[0] {
		t.Fatal("public canonical consumer borrowed the selected owner")
	}
	before := bytes.Clone(selected[0])
	returned.Consumers[0][0] ^= 1
	returned.Owner.Body[0] ^= 1
	if !bytes.Equal(selected[0], before) || !bytes.Equal(owner.Body, capture.Owner.Body) {
		t.Fatal("public return mutation changed selected or installed capture bytes")
	}
}

func captureInstalledCanonicalOwner(t *testing.T, s *StateSession, g *generatedSelection, value contract.ID) contract.GeneratedCanonicalSelection {
	t.Helper()
	_, plan, _, err := s.installedGeneratedCommon(t.Context(), g)
	if err != nil {
		t.Fatal("capture from authenticated installed selected state", err)
	}
	for _, row := range plan.Canonical {
		if row.Record.Entry.ValueState == value {
			if row.Owner.Kind == 0 || len(row.Consumers) == 0 {
				t.Fatal("installed input lost the retained consumer owner")
			}
			return row
		}
	}
	t.Fatal("installed input omitted the declared retained canonical")
	return contract.GeneratedCanonicalSelection{}
}

func selectedCanonicalOwnerVector(t *testing.T, g *generatedSelection, owner contract.SupportRecord) [][]byte {
	t.Helper()
	row, err := contract.InspectGeneratedDutyRecord(owner.Body)
	if err != nil || owner.Kind != contract.GeneratedDutySupportKind {
		t.Fatal("fixture did not select its real Duty", err)
	}
	key := generatedVectorKey{ownerKind: owner.Kind, owner: owner.RecordID, kind: contract.GeneratorVectorConsumers, vector: row.Consumers}
	vector, ok := g.vectors.entries[key]
	if !ok || len(vector.rows) == 0 {
		t.Fatal("authenticated selected vector absent")
	}
	return vector.rows
}
