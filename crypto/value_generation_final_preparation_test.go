package crypto

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

func generatedFinalReplayFixture(t *testing.T, change func(*contract.GeneratedFinalPreparationImage)) (generatedRuntimeFixture, contract.ID) {
	t.Helper()
	f, _, plan, _ := generatedEntriesFixture(t, false)
	first := f.finalRuntime(t)
	op, _ := generatedAdoptionCompare(t, first, f)
	reply := applyCall(first, t.Context(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, []contract.CryptoGeneratedValueEntryPlan{plan}, 0, 1))
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("original randomized preparation", reply.ResultCode)
	}
	view, err := contract.InspectCryptoGeneratedValueEntriesResult(reply.Body)
	if err != nil {
		t.Fatal("original prepared row", err)
	}
	prepared, err := view.Own()
	if err != nil || len(prepared.Rows) != 1 {
		t.Fatal("original prepared row ownership", err)
	}
	first.retireGenerated()
	expectedEntry := firstPreparedEntryDigest(t, f.compare.Context.DomainID, prepared.Rows[0])
	originalPhase, err := contract.GeneratorPhaseID(f.final.Phase)
	if err != nil {
		t.Fatal("original materialization phase", err)
	}
	binding, err := contract.GeneratedFinalPreparationBindingDigest(f.final.Session.Control, f.final.Session.Bindings)
	if err != nil {
		t.Fatal("fixed control and binding commitment", err)
	}
	image := contract.GeneratedFinalPreparationImage{Schema: 1, DomainID: f.compare.Context.DomainID, OperationID: f.compare.Parent.OperationID,
		MaterializationPhaseID: originalPhase, ControlBindingDigest: binding, Generated: prepared.Rows}
	if change != nil {
		change(&image)
		for i := range image.Generated {
			context, err := contract.ValueMaterialContextDigest(image.Generated[i].ValueCore)
			if err != nil {
				t.Fatal("modified prepared context framing", err)
			}
			image.Generated[i].Access.MaterialContextDigest = context
		}
	}
	t.Cleanup(image.Clear)
	body, err := contract.EncodeGeneratedFinalPreparationImage(image)
	if err != nil {
		t.Fatal("exact prepared image", err)
	}
	record := contract.GeneratedFinalPreparationRecord{Schema: 1, DomainID: image.DomainID, OperationID: image.OperationID,
		MaterializationPhase: f.final.Phase, ControlBindingDigest: binding, Image: contract.GeneratorLogicalSlice{Schema: 1,
			ContentKind: contract.GeneratorContentFinalPreparation, ContentID: contract.Hash(body), Digest: contract.Hash(body), Length: uint32(len(body))}}
	recordBody, err := contract.EncodeGeneratedFinalPreparationRecord(record)
	if err != nil {
		t.Fatal("authenticated preparation association", err)
	}
	checkpoint := record.MaterializationPhase
	checkpoint.TransitionKind = contract.GeneratorAuthorityFinalPreparation
	checkpoint.Evidence, err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{record.Image})
	if err != nil {
		t.Fatal("checkpoint image descriptor", err)
	}
	checkpointID, err := contract.GeneratorPhaseID(checkpoint)
	if err != nil {
		t.Fatal("checkpoint phase identity", err)
	}
	empty := contract.EmptyGeneratorRecordSet
	phase := contract.GeneratedPhaseRecord{Schema: contract.GeneratedPhaseSchema, DomainID: record.DomainID, OperationID: record.OperationID,
		OwnerID: record.OperationID, PlanGraphID: f.compare.Parent.PlanGraphID, UsePlanDigest: f.compare.UsePlanDigest,
		PhaseID: checkpointID, Phase: checkpoint.AfterPhase, LineageIndex: contract.GeneratorMaxLineageTemplates, Stage: contract.GeneratedStageTerminal,
		FinalPreparationID: record.Image.ContentID, AcceptedResults: empty(contract.GeneratorPhaseResults), Attempts: empty(contract.GeneratorPhaseAttempts),
		Duties: empty(contract.GeneratorPhaseDuties), Hazards: empty(contract.GeneratorPhaseHazards), PendingReleases: empty(contract.GeneratorPhaseReleases),
		Proofs: contract.EmptyGeneratorVector(contract.GeneratorVectorProofs)}
	phaseBody, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal("selected preparation phase", err)
	}
	facts := slices.DeleteFunc(slices.Clone(f.final.Session.Output.Rows.Facts), func(fact contract.SupportRecordDigest) bool {
		return fact.Kind() == contract.GeneratedPhaseSupportKind && fact.RecordID() == record.OperationID
	})
	for _, row := range []contract.SupportRecord{
		{Kind: contract.GeneratedPhaseSupportKind, RecordID: phase.OperationID, Body: phaseBody},
		{Kind: contract.GeneratedFinalPreparationSupportKind, RecordID: record.OperationID, Body: recordBody},
	} {
		fact, err := contract.InspectSupportRecordDigest(record.DomainID, row)
		if err != nil {
			t.Fatal("selected preparation fact", err)
		}
		facts = append(facts, fact)
	}
	slices.SortFunc(facts, func(a, b contract.SupportRecordDigest) int {
		if a.Kind() != b.Kind() {
			return int(a.Kind()) - int(b.Kind())
		}
		x, y := a.RecordID(), b.RecordID()
		return bytes.Compare(x[:], y[:])
	})
	f.final.Session.Output.Rows.Facts = facts
	f.final.Session.BeforePublic.RequiredSupport, err = contract.RequiredSupportDescriptorFromDigests(record.DomainID, facts)
	if err != nil || f.final.Session.Output.Inspect(f.final.Session.BeforePublic) != nil {
		t.Fatal("selected preparation support witness", err)
	}
	f.compare.Context.PredecessorHEADDigest = consumerID("independently selected preparation HEAD")
	f.compare.Context.OriginalConditionDigest = consumerID("selected preparation HEAD condition")
	f.final.Phase.ObservedHEADDigest = f.compare.Context.PredecessorHEADDigest
	f.final.Phase.ConditionDigest = f.compare.Context.OriginalConditionDigest
	f.final.Phase.BeforePhase, f.final.Phase.AfterPhase = checkpoint.AfterPhase, checkpoint.AfterPhase+1
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal("fresh Final admission commitment", err)
	}
	f.final.Preparation, f.final.PreparationPhase, f.final.PreparedImage = &record, &phase, body
	return f, expectedEntry
}

// full_only: false
func TestGeneratedFinalReplayQualifiesPreparedImageBeforeFreeze(t *testing.T) {
	f, expectedEntry := generatedFinalReplayFixture(t, nil)
	replayed := f.finalRuntime(t)
	before := f.base.route.privateCalls
	generatedAdoptionCompare(t, replayed, f)
	state := replayed.generated.purpose.final
	if replayed.generated.stage != contract.CryptoFreeze || state.entryNext != 1 || !state.entryPreparations[0].prepared ||
		state.entryPreparations[0].entryDigest != expectedEntry ||
		f.base.route.privateCalls != before+2 {
		t.Fatalf("prepared replay stage=%d entries=%d ready=%t private_calls=%d", replayed.generated.stage, state.entryNext,
			state.entryPreparations[0].prepared, f.base.route.privateCalls-before)
	}
}

// full_only: false
func TestGeneratedFinalReplacementRequiresCompletePrivateQualification(t *testing.T) {
	for _, mode := range []string{"omitted carrier", "mode without carrier", "same-binding record only", "safe image has no legacy authority"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := generatedFinalReplayFixture(t, nil)
			if mode == "safe image has no legacy authority" {
				f.final.QualifyLegacy = true
			} else {
				if mode == "same-binding record only" {
					body, err := contract.EncodeGeneratedFinalPreparationRecord(*f.final.Preparation)
					if err != nil {
						t.Fatal(err)
					}
					f.final.CheckpointSupport = []contract.SupportRecord{{Kind: contract.GeneratedFinalPreparationSupportKind, RecordID: f.final.Preparation.OperationID, Body: body}}
				}
				f.final.Preparation, f.final.PreparationPhase, f.final.PreparedImage = nil, nil, nil
				f.final.QualifyLegacy = mode == "mode without carrier"
			}
			runtime := newConsumerRuntime(t, f.base.route)
			defer runtime.retireGenerated()
			before := f.base.route.privateCalls
			err := runtime.admitGeneratedFinal(f.compare, f.final, f.base.deadline)
			if mode != "safe image has no legacy authority" {
				if err == nil || runtime.generated != nil || f.base.route.privateCalls != before {
					t.Fatal("selected same-binding preparation lost its required private qualification", err)
				}
				return
			}
			if err != nil {
				t.Fatal("healthy exact image qualification admission", err)
			}
			active := runtime.generated.purpose.final
			body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(runtime, t.Context(), contract.CryptoCompare, body)
			runtime.mu.Lock()
			changed := active.qualificationImage != nil || active.preparedImage != nil || active.entryNext != 0 || len(active.supplied) != 0 ||
				len(active.entryPreparations) != 0 && active.entryPreparations[0].prepared
			runtime.mu.Unlock()
			if reply.ResultCode != contract.CryptoInvalidAdmission || len(reply.Body) != 0 || f.base.route.privateCalls-before != 2 ||
				changed {
				t.Fatal("qualification mode alone granted replacement or altered fresh preparation", reply.ResultCode)
			}
			if retry := applyCall(runtime, t.Context(), contract.CryptoCompare, body); retry.ResultCode != contract.CryptoAlreadyUsed || f.base.route.privateCalls-before != 2 {
				t.Fatal("failed qualification permitted another private attempt", retry.ResultCode)
			}
		})
	}
}

func firstPreparedEntryDigest(t testing.TB, domain contract.ID, row contract.CryptoGeneratedValueEntryResult) contract.ID {
	t.Helper()
	digest, err := contract.PublicValueEntryDigest(domain, row.Slot, row.Entry)
	if err != nil {
		t.Fatal("prepared entry digest", err)
	}
	return digest
}

// full_only: false
func TestGeneratedFinalReplayRejectsModifiedPreparedMeaning(t *testing.T) {
	// Each image and its selected support association are canonically recommitted.
	// Successful framing cannot replace the private expected result/source proof.
	for _, test := range []struct {
		name      string
		change    func(*contract.GeneratedFinalPreparationImage)
		admission bool
		code      contract.CryptoResultCode
		calls     int
	}{
		{"output_encoding", func(image *contract.GeneratedFinalPreparationImage) {
			image.Generated[0].Entry.OutputEncoding = contract.OutputEncodingBase64
		}, true, contract.CryptoInvalidAdmission, 1},
		{"entry_incarnation", func(image *contract.GeneratedFinalPreparationImage) {
			image.Generated[0].Entry.Incarnation = consumerID("different prepared entry incarnation")
			image.Generated[0].ValueCore.EntryIncarnationID = image.Generated[0].Entry.Incarnation
		}, true, contract.CryptoInvalidAdmission, 1},
		{"recipient", func(image *contract.GeneratedFinalPreparationImage) {
			row := &image.Generated[0]
			for i := range row.Entry.Recipients {
				id := contract.ID{}
				id[0], id[31] = 0xee, byte(i+1)
				row.Entry.Recipients[i] = id
				row.Access.Wraps[i].SubjectID = id
			}
		}, true, contract.CryptoInvalidAdmission, 1},
		{"commitment", func(image *contract.GeneratedFinalPreparationImage) {
			row := &image.Generated[0]
			payload, err := contract.DecodeCanonicalPayload(row.Entry.ValueBytes)
			if err != nil {
				t.Fatal("prepared commitment fixture", err)
			}
			defer clear(payload.Ciphertext[:cap(payload.Ciphertext)])
			payload.SemanticCommitment[0] ^= 1
			changed, err := contract.EncodeCanonicalPayload(payload)
			if err != nil {
				t.Fatal("modified canonical commitment", err)
			}
			clear(row.Entry.ValueBytes[:cap(row.Entry.ValueBytes)])
			row.Entry.ValueBytes = changed
		}, true, contract.CryptoStoredAuthenticationFailed, 1},
		{"value_context", func(image *contract.GeneratedFinalPreparationImage) {
			image.Generated[0].ValueCore.DomainID = consumerID("different prepared value domain")
		}, true, contract.CryptoStoredAuthenticationFailed, 1},
		{"materialization_context", func(image *contract.GeneratedFinalPreparationImage) {
			image.MaterializationPhaseID = consumerID("unselected prepared materialization phase")
		}, false, contract.CryptoInvalidAdmission, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, _ := generatedFinalReplayFixture(t, test.change)
			runtime := newConsumerRuntime(t, f.base.route)
			before := f.base.route.privateCalls
			err := runtime.admitGeneratedFinal(f.compare, f.final, f.base.deadline)
			if !test.admission {
				if err == nil || runtime.generated != nil || f.base.route.privateCalls != before {
					t.Fatal("unqualified context admitted or opened private material")
				}
				return
			}
			if err != nil {
				t.Fatal("canonical selected-image setup", err)
			}
			body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
			if err != nil {
				t.Fatal("fresh private replay request", err)
			}
			reply := applyCall(runtime, t.Context(), contract.CryptoCompare, body)
			runtime.mu.Lock()
			freeze, candidate := runtime.generated.stage == contract.CryptoFreeze, runtime.generated.candidate != nil
			runtime.mu.Unlock()
			runtime.retireGenerated()
			if reply.ResultCode != test.code || len(reply.Body) != 0 || freeze ||
				f.base.route.privateCalls-before != test.calls || candidate || runtime.generated != nil {
				t.Fatalf("modified prepared meaning code=%d body_length=%d private_calls=%d freeze=%t candidate=%t", reply.ResultCode,
					len(reply.Body), f.base.route.privateCalls-before, freeze, candidate)
			}
		})
	}
}

// full_only: false
func TestGeneratedFinalReplayQualifiesPlainSuppliedRepresentation(t *testing.T) {
	for _, input := range []uint8{contract.InputEncodingRaw, contract.InputEncodingBase64} {
		t.Run(fmt.Sprint(input), func(t *testing.T) {
			domain, operation, phase := consumerID("plain replay domain"), consumerID("plain replay operation"), consumerID("plain replay phase")
			recipient := consumerID("plain replay recipient")
			value := []byte("ABC")
			if input == contract.InputEncodingBase64 {
				value = []byte("QUJD")
			}
			declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: domain, OperationID: operation, Entries: []contract.GeneratorDeclarationEntry{{
				Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain, Name: "plain", InputEncoding: input,
				OutputEncoding: contract.OutputEncodingBase64, Recipients: []contract.ID{recipient}, Payload: value}}}
			body, err := contract.EncodeGeneratorDeclaration(declaration)
			if err != nil {
				t.Fatal(err)
			}
			plan := contract.GeneratorValueEntryPlan{Schema: contract.GeneratorValueEntryPlanSchema, Name: "plain", Slot: 0,
				EntryIncarnationID: consumerID("plain replay incarnation"), ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
				InputEncoding: input, OutputEncoding: contract.OutputEncodingBase64, ChangeMask: contract.GeneratorValueChangeContent}
			final := &generatedFinalPreparationState{materializationPhaseID: phase, preparedImage: &contract.GeneratedFinalPreparationImage{}, suppliedCount: 1,
				plan: generatedPlanState{declaration: body, recipients: [][]contract.ID{{recipient}}}}
			admission := generatedAdmission{request: contract.CryptoGeneratedCompareRequest{Context: contract.ApplyContext{DomainID: domain}},
				graph: contract.GeneratorPlanBundle{ValueEntryPlans: []contract.GeneratorValueEntryPlan{plan}}, purpose: generatedPurposeState{final: final}}
			identity, ok := admission.finalFreshIdentity(0)
			if !ok {
				t.Fatal("valid phase identity refused")
			}
			expected := contract.ValueEntry{Name: "plain", Incarnation: identity.Incarnation, ValueState: identity.ValueState, OriginSnapshot: identity.OriginSnapshot,
				OriginTransition: identity.OriginTransition, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
				InputEncoding: input, OutputEncoding: contract.OutputEncodingBase64, ContentLength: 3, RetainedLength: uint32(len(value)),
				Recipients: []contract.ID{recipient}, ValueBytes: value}
			want, err := contract.PublicValueEntryDigest(domain, 0, expected)
			if err != nil {
				t.Fatal(err)
			}
			out := contract.CryptoResponse{}
			if code := admission.openPreparedSupplied(t.Context(), nil, &out); code != contract.CryptoSuccess || len(final.supplied) != 1 || final.supplied[0].entryDigest != want || len(out.KeyUseRows) != 0 {
				t.Fatal("prepared plain replay lost selected representation", code, len(final.supplied))
			}
		})
	}
}
