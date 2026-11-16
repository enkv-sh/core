package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedInspectionRefusesInvalidClosure(t *testing.T) {
	if _, err := (&StateSession{}).inspectGeneratedWork(context.Background()); err == nil {
		t.Fatal("inspection accepted an unauthenticated empty closure")
	}
}

// full_only: false
func TestGeneratedInspectionRetainsLiveUnknownRetirementEvidence(t *testing.T) {
	s, original, duty := generatedParkedRetirementState(t)
	before, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	duty, err = contract.InspectGeneratedDutyRecord(before.records[generatedRecordKey{10, duty.DutyID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	wantFacts, err := before.vectors.resolve(9, original.record.AttemptID, contract.GeneratorVectorFacts, original.record.Facts)
	if err != nil {
		t.Fatal(err)
	}
	wantProgress, err := before.vectors.resolve(10, duty.DutyID, contract.GeneratorVectorProgress, duty.Progress)
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.inspectGeneratedWork(context.Background())
	if err != nil || !view.activeOwner.IsZero() || len(view.effects) != 1 || len(view.duties) != 1 ||
		len(view.hazards) != 0 || len(view.releases) != 0 || view.possibleGarbage ||
		view.effects[0].attempt.AttemptID != original.record.AttemptID || view.duties[0] != duty ||
		view.effects[0].evidenceCeiling != contract.ReceiptEvidenceProviderFacts ||
		!slices.EqualFunc(view.effects[0].facts, wantFacts, bytes.Equal) || !slices.EqualFunc(view.dutyProgress[duty.DutyID], wantProgress, bytes.Equal) {
		t.Fatal("inspection lost live unknown retirement or invented completion", err)
	}
	// Projection buffers do not grant write access to the retained evidence.
	if len(view.effects[0].facts) != 0 {
		view.effects[0].facts[0][0] ^= 1
	}
	after, err := s.inspectGeneratedWork(context.Background())
	if err != nil || !reflect.DeepEqual(after.effects[0].facts, wantFacts) {
		t.Fatal("inspection exposed mutable selected evidence", err)
	}
}

// full_only: false
func TestGeneratedInspectionReportsUnknownInboxReleaseAsPossibleGarbage(t *testing.T) {
	for _, state := range []uint8{contract.GeneratedReleasePending, contract.GeneratedReleaseUnknown} {
		s, attempt, release := generatedInboxReleaseTemplateState(t, 2, 0, state)
		view, err := s.inspectGeneratedWork(context.Background())
		if err != nil || len(view.releases) != 1 || view.releases[0] != release || len(view.effects) != 1 ||
			view.effects[0].attempt.AttemptID != attempt.record.AttemptID ||
			view.effects[0].evidenceCeiling != contract.ReceiptEvidenceAcknowledged ||
			view.warnings&contract.ReceiptWarningInvalidationNotConfirmed == 0 ||
			view.possibleGarbage != (state == contract.GeneratedReleaseUnknown) ||
			len(view.duties) != 0 || len(view.hazards) != 0 {
			t.Fatal("release-only inspection changed its ceiling or reported unknown garbage as clean", err)
		}
	}
}
