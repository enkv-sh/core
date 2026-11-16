package core

import (
	"bytes"
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedPreparationClaimKeepsSelectedReadResult(t *testing.T) {
	for _, fault := range []struct {
		name string
		want Result
	}{
		{"missing", failure(EvidenceUnavailable, MissingSelectedObject)},
		{"unavailable-access", Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonAccess}},
		{"unavailable-transport", Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}},
		{"invalid", failure(IntegrityFailure, InvalidFormat)},
		{"changed", failure(IntegrityFailure, InvalidReference)},
		{"canceled", failure(EvidenceUnavailable, ReadUnavailable)},
	} {
		t.Run(fault.name, func(t *testing.T) {
			before := generatedEmptyPredecessor(t)
			before.admission.store.HeadKey = before.admission.store.Prefix + "/HEAD"
			before.admission.composition = generatedVectorID(244)
			before.admission.expires = time.Now().Add(time.Minute)
			reservation, err := before.deriveGeneratedReservation(context.Background(), generatedReservationInputFixture(t, before))
			if err != nil {
				t.Fatal("derive reservation before selected read damage", err)
			}
			selected := reservation.state
			generatedInstallFixtureSupportReader(t, selected)
			backing := selected.store.(*generatedFixtureSupportStore)
			selected.cache, selected.generatedWork, selected.generatedGraphs = nil, nil, nil
			generatedVerifySelectedFixtureSlices(t, selected)
			facts, err := selected.selectedGeneratedWork(t.Context())
			if err != nil || facts == nil || facts.parent == nil {
				t.Fatal("complete selected reservation before damage", err)
			}
			graph, present := facts.content.locations[generatedContentKey{contract.GeneratorContentGraph, facts.parent.PlanGraphID}]
			if !present {
				t.Fatal("reservation has no selected graph")
			}
			var faultKey string
			var faultLimit uint32
			var released int
			for location, fact := range selected.fragmentFacts {
				if location.BlobID != graph.BlobID {
					continue
				}
				faultKey, err = format.Key(selected.admission.store.Prefix, fact.ref)
				if err != nil {
					t.Fatal("selected graph key", err)
				}
				faultLimit = fact.ref.Length
				for i := range selected.support {
					if selected.support[i].Index == location.SupportPageIndex {
						selected.support[i].Records[location.RowSlot].Body = nil
						released++
					}
				}
			}
			if released != 1 || faultKey == "" || faultLimit == 0 {
				t.Fatalf("selected graph fragments=%d key present=%t bound=%d", released, faultKey != "", faultLimit)
			}
			// Complete selected images retain authenticated fragment facts and
			// read every fragment body from its exact Store reference.
			for i := range selected.support {
				for j := range selected.support[i].Records {
					if selected.support[i].Records[j].Kind == contract.GeneratedFragmentSupportKind {
						selected.support[i].Records[j].Body = nil
					}
				}
			}
			store := &generatedInboxReleaseReadStore{readFailureStore: &readFailureStore{}, descriptor: selected.admission.store}
			armed, damagedReads := false, 0
			ctx, cancelRead := context.WithCancel(t.Context())
			defer cancelRead()
			store.onReadCtx = func(ctx context.Context) (contract.ReadResult, bool) {
				last := len(store.keys) - 1
				key, limit := store.keys[last], store.limits[last]
				if !armed || key != faultKey {
					return backing.Read(ctx, key, limit), true
				}
				if limit != faultLimit {
					t.Fatalf("selected graph read bound=%d want=%d", limit, faultLimit)
				}
				damagedReads++
				switch fault.name {
				case "missing":
					return contract.ReadResult{Status: contract.ReadMissing}, true
				case "unavailable-access":
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}, true
				case "unavailable-transport":
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}, true
				case "invalid":
					return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}, true
				case "changed":
					body := bytes.Clone(backing.objects[key])
					body[len(body)-1] ^= 1
					return contract.ReadResult{Status: contract.ReadOK, Body: body}, true
				case "canceled":
					cancelRead()
					return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(backing.objects[key])}, true
				default:
					t.Fatal("unknown selected read fault")
					return contract.ReadResult{}, true
				}
			}
			selected.store = store
			before.store = store
			if !before.admission.valid(store) {
				t.Fatal("claim fixture admission is invalid")
			}
			healthyReads := len(store.keys)
			if err := selected.validateGeneratedSelection(ctx, nil); err != nil {
				t.Fatal("healthy reservation proof refused", err)
			}
			if len(store.keys) == healthyReads {
				t.Fatal("healthy reservation proof did not read the selected Store")
			}
			selected.generatedWork, selected.generatedGraphs = nil, nil
			candidate := reservation.candidate
			candidate.generated = &generatedCandidateFacts{reservation: reservation}
			candidate.producer = &generatedPreparation{reservation: reservation,
				operation: &cryptoOperation{adapter: refusalBoundary{t: t}}}
			trust := &generatedInboxReleaseReadTrust{identity: before.admission.trust, family: before.admission.store.Family}
			armed = true
			claimed, result := before.ClaimGeneratedPreparation(ctx, candidate, trust)
			if claimed != nil || result != fault.want || damagedReads == 0 || store.writes != 0 || trust.signs != 0 ||
				candidate.generated.claimed || !candidate.generated.authority.IsZero() || selected.generatedWork != nil || selected.generatedGraphs != nil {
				t.Fatal("selected claim read lost its exact result, published facts or reached private work", result, damagedReads)
			}
		})
	}
}
