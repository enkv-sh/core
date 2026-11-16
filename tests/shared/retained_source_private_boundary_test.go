package core

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedPrivateFinalChecksSurvivingSourceBeforeClaim(t *testing.T) {
	f := newRetainedReaderFixture(t, true, 3)
	env, selected := f.env, f.selected
	sources, canonical := generatedCurrentDeclaration(t, selected)
	input := generatedPlanInputForGenerations(t, selected, testID(t.Name()+" success"), []string{"new-success"}, defaultGeneratedFixtureProfile(), sources...)
	prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, canonical)
	recorded, _, _, _ := selectActualGeneratedPacketRecord(t, env, selected, prior, custody.StandardValue, true, nil)
	admitted := generatedPlanInputFixture(t, recorded).context
	admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" initial final admission"), testID(t.Name()+" initial final session")
	plan, err := recorded.generatedFinalRequest(t.Context(), admitted)
	if err != nil || plan == nil || !plan.selecting {
		t.Fatal("initial Final", err)
	}
	checkpoint, _ := preparePrivateGeneratedFinal(t, env, recorded, plan)
	env.Custody.RetireGenerated()
	reader := fixtureID(env.Domain, "reader")
	owner := retainedReaderOwnerIDs(f)[0]
	for _, damage := range []string{"exact", "missing retained wrap", "changed retained wrap", "changed Recovery wrap", "unsupported extra wrap", "wrong consumer context"} {
		t.Run(damage, func(t *testing.T) {
			base := retainedReaderColdOpen(t, checkpoint, env.Store)
			admitted := generatedPlanInputFixture(t, base).context
			admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" admission"), testID(t.Name()+" session")
			plan, err := base.generatedFinalRequest(t.Context(), admitted)
			if err != nil || plan == nil || !plan.selecting || plan.materialization == nil {
				t.Fatal("actual saved Final dispatch", err)
			}
			preparation, result := base.PrepareGeneratedFinal(t.Context(), admitPrivateGeneratedFinal(t, env, base, plan))
			if preparation == nil || result.Outcome != ObservedCurrent {
				t.Fatal("actual Final preparation", result)
			}
			candidate := generatedPrivateCandidate(t, preparation)
			if candidate.Subject.Purpose != contract.GeneratorAuthorityFinal || !candidate.ActiveOwner.IsZero() {
				t.Fatal("fixture did not reach actual selecting Final")
			}
			entry := slices.IndexFunc(candidate.Entries, func(e custody.GeneratedCandidateEntry) bool { return e.Entry.ValueState == f.current.ValueState })
			if entry < 0 || slices.Contains(candidate.Entries[entry].Entry.Recipients, reader) {
				t.Fatal("reader must be retained-only")
			}
			material := slices.IndexFunc(candidate.AccessRecords, func(row contract.AccessRecord) bool {
				return row.MaterialKind == contract.ValueMaterialKind && row.MaterialID == f.value.ValueState
			})
			if material < 0 {
				t.Fatal("retained material absent")
			}
			candidate.AccessRecords = slices.Clone(candidate.AccessRecords)
			body, err := contract.EncodeAccessRecord(candidate.AccessRecords[material])
			if err != nil {
				t.Fatal(err)
			}
			candidate.AccessRecords[material], err = contract.DecodeAccessRecord(body)
			if err != nil {
				t.Fatal(err)
			}
			wraps := &candidate.AccessRecords[material].Wraps
			retained := slices.IndexFunc(*wraps, func(w contract.WrapRow) bool {
				return w.SubjectKind == contract.OrdinaryWrapSubject && w.SubjectID == reader
			})
			if retained < 0 {
				t.Fatal("retained-only wrap absent")
			}
			switch damage {
			case "missing retained wrap":
				*wraps = slices.Delete(*wraps, retained, retained+1)
			case "changed retained wrap":
				(*wraps)[retained].RSACiphertext[0] ^= 1
			case "changed Recovery wrap":
				i := slices.IndexFunc(*wraps, func(w contract.WrapRow) bool { return w.SubjectKind == contract.RecoveryWrapSubject })
				if i < 0 {
					t.Fatal("Recovery absent")
				}
				(*wraps)[i].RSACiphertext[0] ^= 1
			case "wrong consumer context":
				corruptRetainedCandidateConsumer(t, &candidate, owner)
			case "unsupported extra wrap":
				retainedReaderAddUnsupportedWrap(t, f, &candidate.AccessRecords[material])
			}
			if len(candidate.CurrentAccess.AccessPageRefs) != 1 {
				t.Fatal("fixture requires one actual access page")
			}
			ref := candidate.CurrentAccess.AccessPageRefs[0]
			pageBody, err := format.EncodeAccessPage(format.AccessPage{Domain: ref.Domain, Object: ref.Object, Index: ref.Index, Records: candidate.AccessRecords})
			if err != nil {
				t.Fatal(err)
			}
			ref, err = format.Reference(contract.AccessKind, ref.Domain, ref.Object, ref.Index, pageBody)
			if err != nil {
				t.Fatal(err)
			}
			candidate.CurrentAccess.AccessPageRefs = []contract.Ref{ref}
			candidate.CurrentAccess.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(env.Domain, candidate.AccessRecords)
			if err != nil {
				t.Fatal(err)
			}
			candidate.PublicState.AccessRoot, err = contract.AccessRoot(candidate.CurrentAccess)
			if err != nil {
				t.Fatal(err)
			}
			candidate.Subject.AfterAccessDigest = candidate.PublicState.AccessRoot
			candidate.PublicState.RequiredSupport, err = contract.RequiredSupportDescriptor(env.Domain, candidate.SupportRecords)
			if err != nil {
				t.Fatal(err)
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			public, private := env.Custody.Calls()
			code := env.Custody.BindGeneratedCandidate(t.Context(), preparation.operation.context.AdmissionID, candidate)
			want := contract.CryptoInvalidAdmission
			if damage == "exact" {
				want = contract.CryptoSuccess
			}
			if code != want {
				t.Fatal("actual Final binding", code, want)
			}
			if damage != "exact" {
				if claimed, _ := base.ClaimGeneratedPreparation(t.Context(), preparation.reservation.candidate, env.Trust); claimed != nil {
					t.Fatal("invalid private Final reached Claim")
				}
			}
			if p, k := env.Custody.Calls(); p != public || k != private || store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatal("binding/failed Claim changed custody, signing or storage")
			}
			env.Custody.RetireGenerated()
		})
	}
}

func corruptRetainedCandidateConsumer(t *testing.T, candidate *custody.GeneratedCandidate, owner contract.ID) {
	t.Helper()
	var carriers []contract.GeneratorVectorCarrier
	kept := make([]contract.SupportRecord, 0, len(candidate.SupportRecords))
	for _, row := range candidate.SupportRecords {
		if row.Kind == contract.GeneratorVectorSupportKind {
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if carrier.OwnerID == owner && carrier.VectorKind == contract.GeneratorVectorConsumers {
				carriers = append(carriers, carrier)
				continue
			}
		}
		kept = append(kept, row)
	}
	slices.SortFunc(carriers, func(a, b contract.GeneratorVectorCarrier) int { return int(a.Ordinal) - int(b.Ordinal) })
	var bodies [][]byte
	changed := false
	for _, carrier := range carriers {
		consumer, err := contract.InspectGeneratorConsumer(carrier.Row)
		if err != nil {
			t.Fatal(err)
		}
		body := carrier.Row
		if consumer.SubjectKind == contract.GeneratorConsumerRetainedCanonicalValue {
			consumer.ContextDigest = testID(t.Name() + " wrong material context")
			body, err = contract.EncodeGeneratorConsumer(consumer)
			if err != nil {
				t.Fatal(err)
			}
			changed = true
		}
		bodies = append(bodies, body)
	}
	if !changed {
		t.Fatal("surviving canonical consumer absent")
	}
	descriptor, rows, err := generatedCarrierRows(candidate.PublicState.Domain, contract.GeneratedHazardSupportKind, owner, contract.GeneratorVectorConsumers, bodies)
	if err != nil {
		t.Fatal(err)
	}
	position := slices.IndexFunc(kept, func(row contract.SupportRecord) bool {
		return row.Kind == contract.GeneratedHazardSupportKind && row.RecordID == owner
	})
	if position < 0 {
		t.Fatal("surviving Hazard absent")
	}
	hazard, err := contract.InspectGeneratedHazardRecord(kept[position].Body)
	if err != nil {
		t.Fatal(err)
	}
	hazard.Consumers = descriptor
	kept[position].Body, err = contract.EncodeGeneratedHazardRecord(hazard)
	if err != nil {
		t.Fatal(err)
	}
	candidate.SupportRecords = append(kept, rows...)
	slices.SortFunc(candidate.SupportRecords, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
}

// full_only: false
func TestGeneratedPrivateReservationRequiresCompleteRetainedPredecessor(t *testing.T) {
	f := newRetainedReaderFixture(t, true, 2)
	env, selected := f.env, f.selected
	sources, canonical := generatedCurrentDeclaration(t, selected)
	input := generatedPlanInputForGenerations(t, selected, testID(t.Name()+" next"), []string{"next"}, defaultGeneratedFixtureProfile(), sources...)
	plan, err := selected.generatedPlanRequest(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := contract.EncodeGeneratorPlanBundle(input.graph)
	if err != nil {
		t.Fatal(err)
	}
	public, err := selected.publicProjection()
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := generatedDeclarationOutputEntries(declaration)
	if err != nil {
		t.Fatal(err)
	}
	output, err := selected.generatedOutputTransition(t.Context(), desired)
	if err != nil {
		t.Fatal(err)
	}
	original := custody.GeneratedPlanInput{Declaration: input.declaration, Canonical: canonical, CurrentIntents: generatedCurrentIntentInputs(t.Context(), t, selected, graph, input.declaration), CurrentValues: generatedCurrentValueInputs(t, selected, input.graph, input.declaration)}
	deadline := time.Unix(0, int64(input.context.Expiry))
	reader := fixtureID(env.Domain, "reader")
	for _, damage := range []string{"exact", "missing source and wrap", "missing source fact and wrap", "changed source body"} {
		t.Run(damage, func(t *testing.T) {
			request := plan.request
			request.Context.AdmissionID, request.Context.SessionID = testID(t.Name()+" admission"), testID(t.Name()+" session")
			witness, err := output.Own(public)
			if err != nil {
				t.Fatal(err)
			}
			privateInput := original
			privateInput.Canonical = slices.Clone(original.Canonical)
			if len(witness.Retained) != 1 {
				t.Fatal("expected one predecessor source")
			}
			sourceID := witness.Retained[0].RecordID
			if damage == "changed source body" {
				witness.Retained[0].Body[len(witness.Retained[0].Body)-1] ^= 1
			}
			if damage == "missing source and wrap" || damage == "missing source fact and wrap" {
				witness.Retained = nil
				if damage == "missing source fact and wrap" {
					witness.Rows.Facts = slices.DeleteFunc(witness.Rows.Facts, func(fact contract.SupportRecordDigest) bool {
						return fact.Kind() == contract.RetainedCanonicalSupportKind && fact.RecordID() == sourceID
					})
				}
				for i := range privateInput.Canonical {
					access := &privateInput.Canonical[i].Selection.Access
					access.Wraps = slices.DeleteFunc(slices.Clone(access.Wraps), func(w contract.WrapRow) bool {
						return w.SubjectKind == contract.OrdinaryWrapSubject && w.SubjectID == reader
					})
				}
			}
			pub, priv := env.Custody.Calls()
			err = env.Custody.AdmitGeneratedPlan(request, currentControlOf(selected), custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: witness}, privateInput, deadline)
			if (err == nil) != (damage == "exact") {
				t.Fatal("private predecessor census", err)
			}
			if p, k := env.Custody.Calls(); p != pub || k != priv {
				t.Fatal("census admission reached private work")
			}
			if damage != "exact" {
				// A rejected census must not occupy the private session slot.
				if err := env.Custody.AdmitGeneratedPlan(request, currentControlOf(selected), custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: output}, original, deadline); err != nil {
					t.Fatal("rejected census retained private ownership", err)
				}
			}
			env.Custody.RetireGenerated()
		})
	}
}
