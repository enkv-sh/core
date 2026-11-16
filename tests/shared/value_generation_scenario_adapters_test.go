package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedScenarioObservationsOwnRetainedBytes(t *testing.T) {
	for _, mode := range []uint8{1, 2} {
		t.Run(fmt.Sprintf("source%d", mode), func(t *testing.T) {
			ctx := t.Context()
			env, _ := genesisEnvironment(t, contract.GCP, true)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, nil, false)
			input, canonical := generatedSourcePlanInput(t, run, f, mode)
			inputs := captureGeneratedScenarioInputs(t, input, contract.ID{})
			wantExpected := inputs.expected
			wantDeclaration := bytes.Clone(input.declaration)
			wantSources, wantPlans := slices.Clone(input.graph.SourceUses), slices.Clone(input.graph.ValueEntryPlans)
			producer := mustPrepareGeneratedScenarioProducer(t, run.env, f.session, input, canonical, inputs)
			selected, outcome := producer.selectCandidate(ctx, f.session)
			body, sends := producer.observation()
			if selected == nil || outcome.Outcome != ObservedCurrent || sends != 1 || len(body) == 0 {
				t.Fatal("generated observation fixture entry", outcome)
			}
			resultBody := bytes.Clone(body)
			body[0] ^= 1
			if again, sends := producer.observation(); !bytes.Equal(again, resultBody) || sends != 1 {
				t.Fatal("producer observation borrowed the retained result")
			}
			env.Custody.RetireGenerated()
			plan := generatedRecordPlanForResult(t, selected, inputs.expected.Template.AttemptID, resultBody, "scenario observation")
			record := preparePrivateGeneratedRecord(t, run.env, selected, plan)
			selected, outcome = selected.selectCandidate(ctx, record.reservation.candidate)
			if selected == nil || outcome.Outcome != ObservedCurrent {
				t.Fatal("generated observation fixture record", outcome)
			}
			cached := mustSelectedGeneratedWork(t, selected)
			before := observeSelectedState(t, selected)
			var expectedStoreReads uint64
			workPages := make(map[format.Ref]bool)
			if selected.fragmentFacts != nil {
				intent, present := cached.content.locations[generatedContentKey{contract.GeneratorContentIntent, wantExpected.Template.IntentDigest}]
				if !present {
					t.Fatal("observation fixture Intent location")
				}
				receiptIndex, err := selected.receiptIndexID()
				if err != nil {
					t.Fatal("observation fixture receipt index", err)
				}
				// Each Intent observation reads its released selected fragments.
				// Each support observation reads every exact page that contains a
				// released work fragment. These counts come from the fixture Refs,
				// before any observation or measured Store call.
				for _, fact := range selected.fragmentFacts {
					position, present := selected.selectedSupportPosition(fact.ref)
					if !present || int(fact.logical) >= len(selected.support[position].Records) {
						t.Fatal("observation fixture selected fragment Ref")
					}
					if selected.support[position].Records[fact.logical].Body != nil {
						continue
					}
					if fact.blob == intent.BlobID {
						expectedStoreReads += 2
					}
					if fact.blob != receiptIndex {
						workPages[fact.ref] = true
					}
				}
			}
			for _, page := range selected.supportFacts {
				position, present := selected.selectedSupportPosition(page.ref)
				if !present || len(page.rows) != len(selected.support[position].Records) {
					t.Fatal("observation fixture selected support facts")
				}
				for i, fact := range page.rows {
					if fact.Kind() == contract.OutputConfigurationSliceSupportKind && selected.support[position].Records[i].Body == nil {
						workPages[page.ref] = true
					}
				}
			}
			// Each of the two support observations reads each physical page
			// once, including shared fragment/configuration pages only once.
			expectedStoreReads += 2 * uint64(len(workPages))
			beforeEffects := observeScenarioEffects(run.spy)
			beforePublic, beforePrivate := env.Custody.Calls()

			input.declaration[0] ^= 1
			input.graph.Lineages[0].Templates[0].AttemptID[0] ^= 1
			input.graph.ResultUses[0].ResultID[0] ^= 1
			input.requestBindings[0].Digest[0] ^= 1
			input.graph.ValueEntryPlans[0].IntendedMembership.Digest[0] ^= 1
			if len(input.graph.SourceUses) != 0 {
				input.graph.SourceUses[0].SourceID[0] ^= 1
			}
			if inputs.expected != wantExpected || !bytes.Equal(inputs.declaration, wantDeclaration) ||
				!slices.Equal(inputs.sources, wantSources) || !slices.Equal(inputs.entryPlans, wantPlans) {
				t.Fatal("captured generated inputs changed with the original fixture")
			}

			attempt, err := observeGeneratedAttempt(t.Context(), selected, wantExpected.Template.AttemptID)
			if err != nil || !attempt.present || attempt.expected != wantExpected || !bytes.Equal(attempt.result, resultBody) {
				t.Fatal("selected attempt changed with the original fixture", err)
			}
			wantRecord, wantIntent := attempt.record, bytes.Clone(attempt.intent)
			attempt.result[0] ^= 1
			attempt.intent[0] ^= 1
			attempt.record.State = 0
			attempt.expected.Template.AttemptID[0] ^= 1
			again, err := observeGeneratedAttempt(t.Context(), selected, wantExpected.Template.AttemptID)
			if err != nil || !again.present || again.record != wantRecord || again.expected != wantExpected ||
				!bytes.Equal(again.result, resultBody) || !bytes.Equal(again.intent, wantIntent) {
				t.Fatal("attempt observation borrowed selected evidence", err)
			}

			retained, err := observeGeneratedRetention(selected)
			if err != nil || !slices.Equal(retained.sources, wantSources) || !slices.Equal(retained.entryPlans, wantPlans) {
				t.Fatal("retention observation differs from the original declaration", err)
			}
			wantConsumers, wantProtected := slices.Clone(retained.consumers), slices.Clone(retained.protectedSources)
			if mode == 1 {
				if len(retained.sources) != 1 || len(retained.consumers) == 0 || len(retained.protectedSources) != 1 {
					t.Fatal("sealed source fixture omitted mutable retention rows")
				}
				retained.sources[0].SourceID[0] ^= 1
				retained.consumers[0].SubjectID[0] ^= 1
				retained.protectedSources[0][0] ^= 1
			}
			retained.entryPlans[0].Name = "changed observation"
			retained, err = observeGeneratedRetention(selected)
			if err != nil || !slices.Equal(retained.sources, wantSources) || !slices.Equal(retained.entryPlans, wantPlans) ||
				!slices.Equal(retained.consumers, wantConsumers) || !slices.Equal(retained.protectedSources, wantProtected) {
				t.Fatal("retention observation borrowed selected rows", err)
			}

			support, err := observePreservedGeneratedSupport(ctx, selected)
			if err != nil || len(support) == 0 {
				t.Fatal("generated support observation", err)
			}
			wantSupport := slices.Clone(support)
			for index := range support {
				wantSupport[index].Body = bytes.Clone(support[index].Body)
				support[index].Body[0] ^= 1
				support[index].RecordID[0] ^= 1
			}
			if rows, err := observePreservedGeneratedSupport(ctx, selected); err != nil || !reflect.DeepEqual(rows, wantSupport) {
				t.Fatal("support observation borrowed selected record bodies", err)
			}
			access, present := observeMaterialAccess(selected, contract.OperationSeedMaterialKind, wantExpected.Plan.MaterialID)
			wantAccess, err := contract.EncodeAccessRecord(access)
			if !present || err != nil || len(access.Wraps) == 0 {
				t.Fatal("seed access observation", err)
			}
			access.Wraps[0].RSACiphertext[0] ^= 1
			access.Wraps[0].BindingID[0] ^= 1
			access, present = observeMaterialAccess(selected, contract.OperationSeedMaterialKind, wantExpected.Plan.MaterialID)
			accessBody, err := contract.EncodeAccessRecord(access)
			if !present || err != nil || !bytes.Equal(accessBody, wantAccess) {
				t.Fatal("access observation borrowed a selected wrap", err)
			}

			if mode == 2 {
				_, entry := observeCurrentValueEntry(t, selected, "secret")
				wantEntry, err := contract.EncodeValueEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				entry.Recipients[0][0] ^= 1
				entry.ValueBytes[0] ^= 1
				_, entry = observeCurrentValueEntry(t, selected, "secret")
				entryBody, err := contract.EncodeValueEntry(entry)
				if err != nil || !bytes.Equal(entryBody, wantEntry) {
					t.Fatal("entry observation borrowed current recipients or value bytes", err)
				}
				declaration, canonical := generatedCurrentDeclaration(t, selected)
				declaration[0].Recipients[0][0] ^= 1
				declaration[0].Payload[0] ^= 1
				canonical[0].Record.Entry.Recipients[0][0] ^= 1
				canonical[0].Record.Entry.ValueBytes[0] ^= 1
				canonical[0].Selection.Entry.Recipients[0][0] ^= 1
				canonical[0].Selection.Entry.ValueBytes[0] ^= 1
				canonical[0].Selection.Payload.Ciphertext[0] ^= 1
				canonical[0].Selection.Access.Wraps[0].RSACiphertext[0] ^= 1
				canonical[0].Selection.Binding.Binding.SPKI[0] ^= 1
				retained, result := selectGeneratedScenarioConsumer(ctx, selected, contract.GeneratedDutySupportKind,
					wantExpected.Template.DutyID, entry.ValueState, selected.admission.recipient)
				wantRetained, err := json.Marshal(retained)
				if result.Outcome != ObservedCurrent || err != nil || len(retained.Owner.Body) == 0 || len(retained.Consumers) == 0 {
					t.Fatal("retained consumer observation", result, err)
				}
				retained.Record.Entry.ValueBytes[0] ^= 1
				retained.Record.Entry.Recipients[0][0] ^= 1
				retained.Selection.Entry.ValueBytes[0] ^= 1
				retained.Selection.Entry.Recipients[0][0] ^= 1
				retained.Selection.Payload.Ciphertext[0] ^= 1
				retained.Selection.Access.Wraps[0].RSACiphertext[0] ^= 1
				retained.Selection.Binding.Binding.SPKI[0] ^= 1
				retained.Owner.Body[0] ^= 1
				retained.Consumers[0][0] ^= 1
				retained.Consumers[0] = nil
				retained, result = selectGeneratedScenarioConsumer(ctx, selected, contract.GeneratedDutySupportKind,
					wantExpected.Template.DutyID, entry.ValueState, selected.admission.recipient)
				retainedBody, err := json.Marshal(retained)
				if result.Outcome != ObservedCurrent || err != nil || !bytes.Equal(retainedBody, wantRetained) {
					t.Fatal("retained consumer observation borrowed nested evidence", result, err)
				}
			}
			assertStateImage(t, selected, before)
			if work, err := selected.selectedGeneratedWork(context.Background()); err != nil || work != cached {
				t.Fatal("scenario observation replaced the shared selected cache", err)
			}
			public, private := env.Custody.Calls()
			_, sends = producer.observation()
			wantEffects := beforeEffects
			wantEffects.StoreRead += expectedStoreReads
			if effects := observeScenarioEffects(run.spy); effects != wantEffects || public != beforePublic || private != beforePrivate || sends != 1 {
				t.Fatal("scenario observation caused external or private effects")
			}
		})
	}
}

// full_only: false
func TestGeneratedScenarioActionsPreserveRefusalAndEffects(t *testing.T) {
	for _, name := range []string{"expired claim", "lost private claim reply"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, contract.GCP, true)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, nil, false)
			input := generatedPlanInputFixture(t, f.session)
			prepared, _ := prepareUnclaimedGeneratedReservation(t, run.env, f.session, input, nil)
			if code := keys.BindGeneratedCandidate(ctx, prepared.operation.context.AdmissionID, generatedPrivateCandidate(t, prepared)); code != contract.CryptoSuccess {
				t.Fatal("claim failure fixture binding", code)
			}
			changed := &changedCryptoReply{inner: prepared.operation.adapter, kind: contract.CryptoClaim,
				change: func(reply contract.CryptoResponse) contract.CryptoResponse {
					reply.ResultCode, reply.Body = contract.CryptoResponseUnknown, nil
					return reply
				}}
			prepared.operation.adapter = changed
			want, wantCalls := failure(EvidenceUnavailable, CustodyUnavailable), 1
			if name == "expired claim" {
				prepared.operation.deadline = time.Now().Add(-time.Second)
				want, wantCalls = refused(AdmissionInvalid), 0
			}
			before := observeSelectedState(t, f.session)
			beforeHead := observeSelectedHead(f.session)
			beforeEffects := observeScenarioEffects(run.spy)
			beforePublic, beforePrivate := keys.Calls()
			candidate, result := claimGeneratedScenarioPreparation(ctx, f.session, prepared, run.env.Trust)
			if candidate != nil || result != want || prepared.claimed || changed.calls != wantCalls || observeScenarioEffects(run.spy) != beforeEffects {
				t.Fatal("raw claim action changed the refusal or crossed the write boundary", result, changed.calls)
			}
			sends := 0
			if prepared.reservation.candidate.bindFirstSend(prepared, func(context.Context, contract.ID) contract.CryptoResultCode {
				sends++
				return contract.CryptoSuccess
			}) || sends != 0 {
				t.Fatal("failed private claim gained a first-send handoff")
			}
			if body, receipt := f.session.MutationReceipt(ctx, input.graph.Request.OperationID); body != nil || receipt != refused(AdmissionInvalid) {
				t.Fatal("failed private claim created a receipt", receipt)
			}
			if name == "expired claim" {
				if public, private := keys.Calls(); public != beforePublic || private != beforePrivate {
					t.Fatal("expired private claim acquired custody")
				}
			}
			assertStateImage(t, f.session, before)
			read := readSelectedHead(ctx, f.session)
			if read.Status != contract.ReadOK || !bytes.Equal(read.Body, beforeHead) || sends != 0 {
				t.Fatal("failed private claim changed selected HEAD or sent an effect")
			}
		})
	}
}

// full_only: false
func TestGeneratedScenarioObservationKeepsAbsenceAndInvalidEvidenceDistinct(t *testing.T) {
	a := newGeneratedResultFixture(t, 0, false)
	session := a.f.session
	tracked, ok := session.store.(scenarioStore)
	if !ok {
		t.Fatal("observation fixture is not tracked")
	}
	ownSelectedSupportForMutationFixture(t, t.Context(), session)
	beforeEffects := observeScenarioEffects(tracked.spy)
	beforePublic, beforePrivate := a.env.Custody.Calls()
	absentID := testID("absent exact generated attempt")
	if observation, err := observeGeneratedAttempt(t.Context(), session, absentID); err != nil || observation.present {
		t.Fatal("an absent exact attempt became the current frontier", err)
	}
	if observation, err := observeGeneratedAttempt(t.Context(), nil, absentID); err == nil || observation.present {
		t.Fatal("missing selected session became valid absence")
	}
	if observation, err := observeGeneratedRetention(nil); err == nil || observation.active {
		t.Fatal("missing selected session became closed generated work")
	}
	original, err := observeGeneratedAttempt(t.Context(), session, a.expected.Template.AttemptID)
	if err != nil || !original.present {
		t.Fatal("original exact attempt is absent", err)
	}
	changed := original.record
	changed.OwnerID = testID("unrelated generated owner")
	body, err := contract.EncodeGeneratedAttemptRecord(changed)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, session, contract.GeneratedAttemptSupportKind, changed.AttemptID, body)
	generatedRefreshPhaseSets(t, session)
	session.generatedWork = nil
	for _, id := range []contract.ID{absentID, a.expected.Template.AttemptID} {
		if observation, err := observeGeneratedAttempt(t.Context(), session, id); err == nil || observation.present {
			t.Fatal("invalid selected evidence became valid absence or an attempt")
		}
	}
	if observation, err := observeGeneratedRetention(session); err == nil || observation.active {
		t.Fatal("invalid selected evidence became valid retained work")
	}
	public, private := a.env.Custody.Calls()
	if observeScenarioEffects(tracked.spy) != beforeEffects || public != beforePublic || private != beforePrivate || a.calls != 1 {
		t.Fatal("invalid or absent observation acquired custody or caused external effects")
	}
}
