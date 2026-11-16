package core

import (
	"context"
	"reflect"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedCurrentProjectionKeeps320ByteLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 || unsafe.Sizeof(GeneratedCurrentGeneration{}) != 320 {
		t.Fatal("trusted profile kind changed the bounded current-generation layout")
	}
}

// full_only: false
func TestGeneratedListIncludesReleasedCreateAndDeleteAttempts(t *testing.T) {
	for _, action := range []uint8{contract.GeneratorActionCreate, contract.GeneratorActionDelete} {
		for _, state := range []uint8{contract.GeneratedReleasePending, contract.GeneratedReleaseUnknown} {
			s, original, release := generatedInboxReleaseTemplateState(t, action, 0, state)
			g, err := s.selectedGeneratedWork(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			view, err := projectGeneratedList(t.Context(), g)
			if err != nil || len(view.Effects) != 1 || view.Effects[0].Record != original.record ||
				view.Effects[0].Action != action || len(view.PendingReleases) != 1 || view.PendingReleases[0].PendingInboxReleaseRecord != release ||
				len(view.NextActions) != 0 || view.PossibleGarbage != (state == contract.GeneratedReleaseUnknown) {
				t.Fatal("list lost release-only actual work or supplied a send selector", action, state, view, err)
			}
			row := view.PendingReleases[0]
			if row.OriginalOperationID != original.record.OperationID || row.OriginalAttemptID != original.record.AttemptID || row.Action != action || row.EffectState != original.record.State || row.CompletionClass != original.record.CompletionClass || row.EffectIndex != 0 || len(view.PendingReleases) != cap(view.PendingReleases) {
				t.Fatal("remote cleanup projection lost typed origin, status or exact capacity", row)
			}
		}
	}
}

// full_only: false
func TestGeneratedPendingResultCleanupKeepsBoundedTypedLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 || unsafe.Sizeof(GeneratedPendingResultCleanup{})-unsafe.Sizeof(contract.PendingInboxReleaseRecord{}) != 72 {
		t.Fatal("pending cleanup DTO changed its typed layout", unsafe.Sizeof(GeneratedPendingResultCleanup{}), unsafe.Sizeof(contract.PendingInboxReleaseRecord{}))
	}
}

// full_only: false
func TestGeneratedListKeepsDetachedRetirementTargetAndExactSelectors(t *testing.T) {
	s, original, duty := generatedParkedRetirementState(t)
	g, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	target, err := g.retirementTarget(t.Context(), duty)
	if err != nil {
		t.Fatal(err)
	}
	view, err := projectGeneratedList(t.Context(), g)
	if err != nil || len(view.CurrentGenerations) != 0 || len(view.Duties) != 1 || view.Duties[0].Target == nil ||
		*view.Duties[0].Target != target || !view.Duties[0].GenerationID.IsZero() || view.Duties[0].RetirementMode != 0 {
		t.Fatal("list substituted current metadata for detached old work", view, err)
	}
	want := []GeneratedNextAction{
		{Command: "generated retire", DutyID: duty.DutyID},
		{Command: "generated accept-retirement-risk", DutyID: duty.DutyID, AttemptID: original.record.AttemptID},
	}
	if !reflect.DeepEqual(view.NextActions, want) {
		t.Fatal("list lost exact non-authoritative selectors", view.NextActions, want)
	}
	view.Duties[0].Target.Name = "changed returned name"
	again, err := projectGeneratedList(context.Background(), g)
	if err != nil || again.Duties[0].Target.Name != target.Name {
		t.Fatal("list returned mutable selected target backing", err)
	}
}

// full_only: false
func TestLocalGeneratedActiveFactsKeepRemoteFieldsAbsent(t *testing.T) {
	before := generatedEmptyPredecessor(t)
	input := generatedReservationInputFixture(t, before)
	x := input.graph.Lineages[0].Templates[0]
	x.Schema, x.LifecycleMode, x.ResultReaderID = contract.GeneratorAttemptTemplateSchema, contract.GeneratorLifecycleNone, contract.GeneratorResultReaderID()
	x.ResourceContractID, x.HazardID, x.TargetSourceID = contract.ID{}, contract.ID{}, contract.ID{}
	x.CompletionClass, x.NoEffectBudget, x.ResidueBudget, x.TargetKind = 0, 0, 0, 0
	var err error
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(x)
	if err != nil {
		t.Fatal(err)
	}
	a, d, err := generatedCreateRecords(contract.GeneratedParentRecord(input.parent), x, generatedVectorID(90), contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers))
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeGeneratedDutyRecord(d)
	if err != nil {
		t.Fatal(err)
	}
	lineage := input.graph.Lineages[0]
	lineage.Schema, lineage.TemplateCount, lineage.Templates = contract.GeneratorLineageTemplateSchema, 1, [5]contract.GeneratorAttemptTemplate{x}
	g := &generatedSelection{image: before.selectedImage(), attempts: map[contract.ID]generatedAttempt{a.AttemptID: {record: a, expected: contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Template: x}}}, records: map[generatedRecordKey]contract.SupportRecord{{contract.GeneratedDutySupportKind, d.DutyID}: {Kind: contract.GeneratedDutySupportKind, RecordID: d.DutyID, Body: body}}}
	t.Run("effect", func(t *testing.T) {
		fact, err := generatedEffectFactForLineage(t.Context(), g, a.AttemptID, lineage)
		if err != nil {
			t.Fatal("local active effect required a remote vector", err)
		}
		if fact.Target != nil || len(fact.Progress) != 0 || !fact.ResourceDigest.IsZero() || fact.Warnings != (GeneratedResultWarnings{}) {
			t.Fatal("local effect invented remote facts")
		}
		changed := g.attempts[a.AttemptID]
		changed.record.Progress = contract.GeneratorDescriptor{Digest: generatedVectorID(99), Length: 117, Count: 1}
		g.attempts[a.AttemptID] = changed
		if _, err := generatedEffectFactForLineage(t.Context(), g, a.AttemptID, lineage); err == nil {
			t.Fatal("local effect accepted a remote progress descriptor")
		}
		g.attempts[a.AttemptID] = generatedAttempt{record: a, expected: contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Template: x}}
	})
	t.Run("create duty", func(t *testing.T) {
		fact, err := generatedDutyFact(t.Context(), g, d.DutyID)
		if err != nil {
			t.Fatal("local create duty required a remote vector", err)
		}
		if fact.Target != nil || len(fact.Progress) != 0 || fact.RetirementMode != 0 || fact.Warnings != (GeneratedResultWarnings{}) {
			t.Fatal("local create Duty invented remote facts")
		}
	})
}
