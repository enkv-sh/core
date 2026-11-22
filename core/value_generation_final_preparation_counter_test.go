package core

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedFinalPreparationReservesLastTwoPhaseSteps(t *testing.T) {
	// This request-owner test supplies terminal phase facts at the finite
	// counter boundary. It does not claim an authenticated billion-step
	// history or private replay authority from these synthetic counters.
	for _, before := range []uint32{^uint32(0) - 2, ^uint32(0) - 1, ^uint32(0)} {
		t.Run(map[uint32]string{^uint32(0) - 2: "two_steps", ^uint32(0) - 1: "one_step", ^uint32(0): "exhausted"}[before], func(t *testing.T) {
			base := generatedEmptyPredecessor(t)
			reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputFixture(t, base))
			if err != nil {
				t.Fatal("reservation", err)
			}
			s := reservation.state
			g := mustSelectedGeneratedWork(t, s)
			a := g.attempts[g.phase.FrontierAttemptID]
			record, err := s.generatedRecordRequest(t.Context(), a.record.AttemptID, generatedPublicResultFixture(t, a, 1), generatedContinuationContext(t, s, 220, 221))
			if err != nil {
				t.Fatal("successful terminal record", err)
			}
			recorded, err := s.deriveGeneratedRecord(t.Context(), record)
			if err != nil {
				t.Fatal("terminal record", err)
			}
			s = recorded.state
			g = mustSelectedGeneratedWork(t, s)
			phase := *g.phase
			phase.Phase = before
			body, err := contract.EncodeGeneratedPhaseRecord(phase)
			if err != nil {
				t.Fatal("finite terminal phase", err)
			}
			generatedReplaceRecord(t, s, contract.GeneratedPhaseSupportKind, phase.OperationID, body)
			generatedRefreshSupport(t, s)
			plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 222, 223))
			if before == ^uint32(0)-2 {
				if err != nil || plan == nil || !plan.selecting || plan.materialization != nil || plan.phase.AfterPhase != ^uint32(0)-1 {
					t.Fatal("last complete preparation/Final pair refused", err)
				}
				g = mustSelectedGeneratedWork(t, s)
				rows := []contract.CryptoGeneratedValueEntryResult{generatedPreparedValueEntryFixture(t, s, plan.entryPlans[0])}
				checkpoint, err := s.deriveGeneratedFinalPreparation(t.Context(), g, plan, rows, nil, nil)
				if err != nil {
					t.Fatal("public checkpoint construction at last pair", err)
				}
				final, err := checkpoint.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, checkpoint.state, 224, 225))
				if err != nil || final == nil || final.materialization == nil || final.phase.BeforePhase != ^uint32(0)-1 || final.phase.AfterPhase != ^uint32(0) {
					t.Fatal("selected image lost its remaining one Final step", err)
				}
			} else if err == nil || plan != nil {
				t.Fatal("insufficient preparation/Final phase budget accepted", before)
			}
			if s.prepared {
				t.Fatal("counter request entered private preparation")
			}
			s.admission.endWorkInvocation = generatedVectorID(235)
			ids := endWorkIDs{operation: generatedVectorID(236), transition: generatedVectorID(237), snapshot: generatedVectorID(238),
				revision: generatedVectorID(239), receipts: generatedVectorID(240), receiptIndex: generatedVectorID(241)}
			owner := mustSelectedGeneratedWork(t, s).parent.OperationID
			candidate, ended, err := s.deriveEndWorkCandidate(t.Context(), owner, ids)
			if err != nil || candidate == nil || ended == nil || !ended.root.Generated.ActiveOwner.IsZero() || !ended.validEndWorkSelection() {
				t.Fatal("finite generated phase prevented independent administrative ending", err)
			}

		})
	}
}
