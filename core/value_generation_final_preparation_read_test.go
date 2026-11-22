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
func TestGeneratedFinalPreparationClaimKeepsSelectedReadResult(t *testing.T) {
	for _, fault := range []struct {
		name  string
		want  Result
		reads int
	}{
		{"missing", failure(EvidenceUnavailable, MissingSelectedObject), 1},
		{"denied", Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonAccess}, 1},
		{"unavailable", Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}, 3},
		{"limited", Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonLimit}, 1},
		{"malformed", failure(IntegrityFailure, InvalidFormat), 1},
		{"digest mismatch", failure(IntegrityFailure, InvalidReference), 1},
	} {
		t.Run(fault.name, func(t *testing.T) {
			before, plan := observationFinalFixture(t, "generated")
			before.admission.store.HeadKey = before.admission.store.Prefix + "/HEAD"
			before.admission.composition = generatedVectorID(244)
			before.admission.expires = time.Now().Add(time.Minute)
			prepared := generatedPreparedValueEntryFixture(t, before, plan.entryPlans[0])
			reservation, err := before.deriveGeneratedFinalPreparation(t.Context(), mustSelectedGeneratedWork(t, before), plan,
				[]contract.CryptoGeneratedValueEntryResult{prepared}, nil, nil)
			if err != nil || reservation == nil {
				t.Fatal("derive selected FinalPreparation", err)
			}
			selected := reservation.state
			generatedInstallFixtureSupportReader(t, selected)
			backing := selected.store.(*generatedFixtureSupportStore)
			selected.cache, selected.generatedWork, selected.generatedGraphs = nil, nil, nil
			generatedVerifySelectedFixtureSlices(t, selected)
			facts, err := selected.selectedGeneratedWork(t.Context())
			if err != nil || facts == nil || facts.preparation == nil || selected.head.Generator.Purpose != contract.GeneratorAuthorityFinalPreparation {
				t.Fatal("complete selected FinalPreparation before damage", err)
			}
			declaration, present := facts.content.locations[generatedContentKey{contract.GeneratorContentDeclaration, facts.parent.OperationID}]
			if !present {
				t.Fatal("selected FinalPreparation has no declaration")
			}
			var faultKey string
			var faultLimit uint32
			fragments := 0
			for location, fact := range selected.fragmentFacts {
				if location.BlobID != declaration.BlobID {
					continue
				}
				faultKey, err = format.Key(selected.admission.store.Prefix, fact.ref)
				if err != nil {
					t.Fatal("selected declaration key", err)
				}
				faultLimit = fact.ref.Length
				fragments++
			}
			if fragments != 1 || faultKey == "" || faultLimit == 0 {
				t.Fatal("selected declaration needs one bounded fragment", fragments)
			}
			for i := range selected.support {
				for j := range selected.support[i].Records {
					if selected.support[i].Records[j].Kind == contract.GeneratedFragmentSupportKind {
						selected.support[i].Records[j].Body = nil
					}
				}
			}
			store := &generatedInboxReleaseReadStore{readFailureStore: &readFailureStore{}, descriptor: selected.admission.store}
			armed, damagedReads := false, 0
			store.onReadCtx = func(ctx context.Context) (contract.ReadResult, bool) {
				last := len(store.keys) - 1
				key, limit := store.keys[last], store.limits[last]
				if !armed || key != faultKey {
					return backing.Read(ctx, key, limit), true
				}
				if limit != faultLimit {
					t.Fatal("selected declaration read changed its bound", limit, faultLimit)
				}
				damagedReads++
				switch fault.name {
				case "missing":
					return contract.ReadResult{Status: contract.ReadMissing}, true
				case "denied":
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}, true
				case "unavailable":
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}, true
				case "limited":
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}, true
				case "malformed":
					return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}, true
				case "digest mismatch":
					body := bytes.Clone(backing.objects[key])
					body[len(body)-1] ^= 1
					return contract.ReadResult{Status: contract.ReadOK, Body: body}, true
				default:
					t.Fatal("unknown declaration fault")
					return contract.ReadResult{}, true
				}
			}
			selected.store, before.store = store, store
			if !before.admission.valid(store) {
				t.Fatal("FinalPreparation claim admission is invalid")
			}
			if err := selected.validateGeneratedSelection(t.Context(), nil); err != nil {
				t.Fatal("healthy FinalPreparation proof refused", err)
			}
			retained := selected.generatedWork
			if retained == nil || retained.selection.preparation == nil {
				t.Fatal("healthy FinalPreparation did not publish its validated facts")
			}
			candidate := reservation.candidate
			candidate.generated = &generatedCandidateFacts{reservation: reservation}
			candidate.producer = &generatedPreparation{reservation: reservation, operation: &cryptoOperation{adapter: refusalBoundary{t: t}}}
			trust := &generatedInboxReleaseReadTrust{identity: before.admission.trust, family: before.admission.store.Family}
			armed = true
			claimed, result := before.ClaimGeneratedPreparation(t.Context(), candidate, trust)
			if claimed != nil || result != fault.want || damagedReads != fault.reads || store.writes != 0 || trust.signs != 0 ||
				candidate.generated.claimed || !candidate.generated.authority.IsZero() || selected.generatedWork != retained {
				t.Fatal("late FinalPreparation declaration failure lost its exact result or reached private work", result, damagedReads)
			}
		})
	}
}
