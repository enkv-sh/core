package core

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// Direct selected-state tests supply their own context. Runtime cleanup paths
// pass the caller context to selectGeneratedCleanup.

// full_only: false
func TestGeneratedRepeatedDeleteReflectionOrdersEveryActualOriginalCoordinate(t *testing.T) {
	s, g, h := generatedRepeatedRetirementHazardState(t, 8)
	var ordered []generatedAttempt
	packets := make(map[contract.ID][]byte)
	for _, a := range g.attempts {
		ordered = append(ordered, a)
		packets[a.record.ResultID] = generatedRetirementResultFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged)
	}
	// Operation IDs are distinct here. This expectation does not call the
	// production coordinate flattening or owner-order comparator.
	slices.SortFunc(ordered, func(a, b generatedAttempt) int {
		return bytes.Compare(a.record.OperationID[:], b.record.OperationID[:])
	})
	if ordered[0].record.AttemptID == h.OriginalAttemptID {
		t.Fatal("fixture does not distinguish actual-coordinate order from the final anchor")
	}
	first := ordered[0].record.ResultID
	later := ordered[1].record.ResultID
	preserved := packets[later]
	packets[later] = []byte("malformed later original")
	if selected, ok, err := g.selectGeneratedCleanup(context.Background(), packets); err != nil || !ok || selected.attempt.record.ResultID != first {
		t.Fatal("later malformed original blocked the first available result", err)
	}
	packets[later] = preserved
	for _, want := range ordered {
		selection, ok, err := g.selectGeneratedCleanup(context.Background(), packets)
		if err != nil || !ok || selection.kind != generatedCleanupReflection || selection.attempt.record.AttemptID != want.record.AttemptID || selection.hazard.HazardID != h.HazardID {
			t.Fatal("original-result selection followed anchor or history order", err)
		}
		packet := packets[want.record.ResultID]
		packets[want.record.ResultID] = []byte("malformed earlier original")
		if _, _, err := g.selectGeneratedCleanup(context.Background(), packets); err == nil {
			t.Fatal("malformed first original was skipped for a later result or provider cleanup")
		}
		packets[want.record.ResultID] = packet
		delete(packets, want.record.ResultID)
	}
	selection, ok, err := g.selectGeneratedCleanup(context.Background(), packets)
	if err != nil || !ok || selection.kind != generatedCleanupHazard || selection.hazard.HazardID != h.HazardID {
		t.Fatal("missing originals invented an effect fact or blocked exact eligible cleanup", err)
	}
}

// full_only: false
func TestGeneratedRepeatedDeleteReflectionStopsReadingAfterFirstAvailableOriginal(t *testing.T) {
	s, _, _ := generatedRepeatedRetirementHazardState(t, 2)
	generatedLifecycleFixture(t, s)
	s.admission.store.Prefix, s.admission.store.HeadKey = "fixture", "fixture/HEAD"
	s.admission.composition, s.admission.expires = generatedVectorID(244), time.Now().Add(time.Minute)
	store := &generatedInboxDeleteStore{descriptor: s.admission.store}
	s.store = store
	if !s.admission.valid(s.store) {
		t.Fatal("fixture has no valid Core admission")
	}
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ordered []generatedAttempt
	for _, a := range g.attempts {
		ordered = append(ordered, a)
	}
	slices.SortFunc(ordered, func(a, b generatedAttempt) int {
		return bytes.Compare(a.record.OperationID[:], b.record.OperationID[:])
	})
	first := ordered[0]
	store.read = contract.ReadResult{Status: contract.ReadOK, Body: generatedRetirementResultFixture(t, s, first, contract.GeneratorDispositionRetirementAcknowledged)}
	selection, ok, err := s.readGeneratedCleanup(context.Background())
	if err != nil || !ok || selection.attempt.record.AttemptID != first.record.AttemptID || store.readCalls != 1 {
		t.Fatal("first qualified original read a later inbox", err, store.readCalls)
	}
}

// full_only: false
func TestGeneratedRepeatedDeleteReflectionCannotSkipUnavailableOriginal(t *testing.T) {
	s, _, _ := generatedRepeatedRetirementHazardState(t, 2)
	generatedLifecycleFixture(t, s)
	s.admission.store.Prefix, s.admission.store.HeadKey = "fixture", "fixture/HEAD"
	s.admission.composition, s.admission.expires = generatedVectorID(244), time.Now().Add(time.Minute)
	unavailable := &generatedInboxDeleteStore{descriptor: s.admission.store, read: contract.ReadResult{Status: contract.ReadUnavailable}}
	s.store = unavailable
	if !s.admission.valid(s.store) {
		t.Fatal("unavailable-read fixture has no valid Core admission")
	}
	if _, ok, err := s.readGeneratedCleanup(context.Background()); err == nil || ok || unavailable.readCalls != 1 || unavailable.deleteCalls != 0 {
		t.Fatal("unavailable earlier original was skipped or granted cleanup")
	}
}

// full_only: false
func TestGeneratedCleanupReflectsQualifiedOriginalBeforeOrdinaryCleanup(t *testing.T) {
	s, original, h := generatedCreateHazardState(t, 0, 0)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[original.record.AttemptID]
	late := generatedPublicResultFixture(t, a, 1)
	selected, ok, err := g.selectGeneratedCleanup(context.Background(), map[contract.ID][]byte{a.record.ResultID: late})
	if err != nil || !ok || selected.kind != generatedCleanupReflection || selected.hazard.HazardID != h.HazardID ||
		selected.attempt.record.AttemptID != a.record.AttemptID || selected.closeOwner {
		t.Fatal("qualified original create did not select exact late-effect reflection", err)
	}

	if selected, ok, err = g.selectGeneratedCleanup(context.Background(), nil); err != nil || ok || selected.kind != 0 {
		t.Fatal("missing original result did not fall through without inventing cleanup authority", err)
	}
	if _, _, err := g.selectGeneratedCleanup(context.Background(), map[contract.ID][]byte{a.record.ResultID: []byte("malformed")}); err == nil {
		t.Fatal("malformed original result did not refuse reflection")
	}
}

// full_only: false
func TestGeneratedCleanupConfirmedNoEffectCreateClosesExactOriginal(t *testing.T) {
	s, original, hazard := generatedCreateHazardState(t, 0, 0)
	work := mustSelectedGeneratedWork(t, s)
	packet := generatedPublicResultFixture(t, original, contract.GeneratorDispositionConfirmedNoEffect)
	selection, present, err := work.selectGeneratedCleanup(t.Context(), map[contract.ID][]byte{original.record.ResultID: packet})
	if err != nil || !present || selection.kind != generatedCleanupReflection || !selection.closeOwner || selection.hazard != hazard ||
		selection.attempt.record != original.record || !bytes.Equal(selection.result, packet) || selection.target != (contract.GeneratorTarget{}) {
		t.Fatal("qualified no-effect create did not select exact target-free closure", err)
	}
	plan, err := s.generatedReflectionPlan(t.Context(), original.record.ResultID, packet, generatedLifecycleFixture(t, s))
	if err != nil || plan.kind != generatedLifecycleCleanupClose || !plan.target.IsZero() {
		t.Fatal("no-effect create reflection did not derive its own target-free closure", err)
	}
	for name, damage := range map[string]func(*generatedLifecyclePlan){
		"wrong kind":  func(p *generatedLifecyclePlan) { p.kind = generatedLifecycleReflection },
		"wrong owner": func(p *generatedLifecyclePlan) { p.owner = generatedVectorID(251) },
		"late effect result": func(p *generatedLifecyclePlan) {
			p.result = generatedPublicResultFixture(t, original, contract.GeneratorDispositionCompleteCreate)
			p.evidence = contract.Hash(p.result)
		},
		"unequal result evidence": func(p *generatedLifecyclePlan) { p.evidence = generatedVectorID(252) },
		"invented target":         func(p *generatedLifecyclePlan) { p.target = generatedVectorID(253) },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := *plan
			damage(&invalid)
			if _, err := s.deriveGeneratedLifecycle(t.Context(), &invalid, nil); err == nil {
				t.Fatal("target-free closure accepted changed authority or evidence")
			}
		})
	}
	proposal, err := s.deriveGeneratedLifecycle(t.Context(), plan, nil)
	if err != nil {
		t.Fatal("qualified no-effect create closure did not derive", err)
	}
	after := mustSelectedGeneratedWork(t, proposal.state)
	if after.hasRecord(generatedRecordKey{contract.GeneratedHazardSupportKind, hazard.HazardID}) ||
		!proposal.state.root.Generated.ActiveOwner.IsZero() || len(after.attempts) != 0 ||
		!after.hasRecord(generatedRecordKey{contract.PendingInboxReleaseSupportKind, original.record.InboxID}) {
		t.Fatal("no-effect reflection retained work or lost the exact release-only mapping")
	}
}

// full_only: false
func TestGeneratedCleanupUsesOnlyExactOwnedSourceClasses(t *testing.T) {
	t.Run("unselected duty", func(t *testing.T) {
		s, original := generatedUnselectedCleanupState(t, 0)
		g, err := s.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		selected, ok, err := g.selectGeneratedCleanup(context.Background(), nil)
		if err != nil || !ok || selected.kind != generatedCleanupDuty || selected.duty.Kind != contract.GeneratedDutyUnselectedCleanup ||
			selected.attempt.record.AttemptID != original.record.AttemptID || selected.target.ResourceDigest.IsZero() {
			t.Fatal("exact unselected cleanup duty was not selected", err)
		}
	})

	t.Run("retirement duty", func(t *testing.T) {
		s, _, _ := generatedDetachedRetirementState(t, "absent", 0)
		g, err := s.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, ok, err := g.selectGeneratedCleanup(context.Background(), nil); err != nil || ok {
			t.Fatal("ordinary retirement duty granted cleanup authority", err)
		}
	})

	t.Run("eligible fenced hazard", func(t *testing.T) {
		s, a, h, target := generatedDeleteHazardState(t, 0)
		g, err := s.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		selected, ok, err := g.selectGeneratedCleanup(context.Background(), nil)
		if err != nil || !ok || selected.kind != generatedCleanupHazard || selected.hazard.HazardID != h.HazardID ||
			selected.attempt.record.AttemptID != a.record.AttemptID || selected.target != target {
			t.Fatal("exact eligible fenced Hazard was not selected", err)
		}
	})
}

// full_only: false
func TestGeneratedCleanupDeleteReflectionUsesAcknowledgementCeiling(t *testing.T) {
	s, a, h, _ := generatedDeleteHazardState(t, 2)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	selected, ok, err := g.selectGeneratedCleanup(context.Background(), nil)
	if err != nil || !ok || selected.kind != generatedCleanupReflection || !selected.closeOwner ||
		selected.hazard.HazardID != h.HazardID || selected.attempt.record.AttemptID != a.record.AttemptID ||
		selected.attempt.record.CompletionClass != h.CompletionClass {
		t.Fatal("exact delete acknowledgement did not select closure at its retained class", err)
	}
}
