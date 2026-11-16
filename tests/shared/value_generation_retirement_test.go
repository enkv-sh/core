package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

type cloudflareRetirementResponse struct {
	status         int
	body           string
	earlyEOF       bool
	reason         uint8
	park           bool
	previous       int
	late           bool
	mode           uint8
	timeout        bool
	cleanupResidue bool
}

func runCloudflareTaggedRetirementScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, response cloudflareRetirementResponse) {
	t.Helper()
	memory, ok := underlyingAdmittedMemoryStore(env.Store)
	if !ok {
		t.Fatal("native retirement requires the admitted memory store")
	}
	const targetToken = hermeticCloudflareToken
	intent, requestBody := hermeticCloudflareIntent()
	var requests atomic.Int32
	var creates atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			creates.Add(1)
			body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
			if err != nil || !bytes.Equal(body, requestBody) || request.URL.Path != "/client/v4/accounts/"+hermeticCloudflareAccount+"/tokens" {
				t.Error("initial create differs from the admitted intent")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%s","value":"%s","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`,
				targetToken, hermeticCloudflareSecret, hermeticCloudflarePermission, hermeticCloudflareAccount)
			return
		}
		ordinal := requests.Add(1)
		body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		if err != nil || request.Method != http.MethodDelete ||
			request.URL.Path != "/client/v4/accounts/"+hermeticCloudflareAccount+"/tokens/"+targetToken ||
			request.ProtoMajor != 1 || !request.Close || request.Header.Get("Authorization") != "Bearer "+hermeticCloudflareBearer ||
			request.Header.Get("Accept-Encoding") != "identity" || len(body) != 0 {
			t.Errorf("unexpected tagged Cloudflare retirement request: method=%s path=%s proto=%s close=%t body=%q err=%v",
				request.Method, request.URL.Path, request.Proto, request.Close, body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		if response.timeout {
			<-request.Context().Done()
			return
		}
		if response.late && ordinal == 1 {
			_, _ = fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, targetToken)
			return
		}
		if response.earlyEOF && (!response.cleanupResidue || ordinal <= int32(response.previous+1)) {
			connection, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_, writeErr := buffer.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}")
			if err := buffer.Flush(); err != nil || writeErr != nil {
				t.Error("early EOF response", err, writeErr)
			}
			if err := connection.Close(); err != nil {
				t.Error(err)
			}
			return
		}
		if response.body != "" {
			status := response.status
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			if _, err := io.WriteString(w, response.body); err != nil {
				t.Error(err)
			}
			return
		}
		_, _ = fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, targetToken)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	origin := server.URL + "/client/v4"
	artifact, implementation := buildHermeticCloudflareGenerator(t, origin)
	profile := nativeGeneratedFixtureProfile(t, implementation)
	profile.RetirementMode = response.mode
	if profile.RetirementMode == 0 {
		profile.RetirementMode = contract.GeneratedRetirementManual
	}

	keys := env.Custody
	run := newScenarioRun(t, ctx, env)
	env = run.env
	if env.FreshGeneratedRecord == nil || env.FreshCurrent == nil || env.Put == nil {
		t.Fatal("retirement scenario requires fresh record, fresh current and object-write hooks")
	}
	var fixture *environmentFixture
	var selected *StateSession
	var duty contract.GeneratedDutyRecord
	var target contract.GeneratorTarget
	var latePacket []byte
	var lateAttempt contract.ID
	var verifyAutomatic func(*StateSession)
	configure := func(t testing.TB, path string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
		return hermeticCloudflareConfig(t, path, origin, implementation, expected)
	}
	run.phase("setup", func() {
		fixture = newEnvironmentFixture(t, ctx, run.env, nil, false)
		initial := generatedPlanInputForGenerationsIntent(t, fixture.session, generatedVectorID(230), []string{"generated"}, intent, profile)
		initial.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
		selected = selectHermeticGeneratedProcessOperation(t, ctx, env, fixture.session, initial, artifact, configure)
		old := *selected.valueEntry(0)
		if old.Generated.ResourceDigest != hermeticCloudflareResourceDigest(targetToken) || old.Generated.RetirementMode != profile.RetirementMode || creates.Load() != 1 || requests.Load() != 0 {
			t.Fatal("selected target did not come from one admitted create before retirement")
		}
		selectRotation := selectPrivateGeneratedOperation
		if profile.RetirementMode == contract.GeneratedRetirementAuto {
			selectRotation = selectPrivateGeneratedValueSet
		}
		selected = selectRotation(t, env, selected,
			generatedStatePlanInput(t, selected, generatedVectorID(231), []string{old.Name}, profile, old.Generated.Epoch+1,
				map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), "retirement rotation")
		before, err := selected.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if profile.RetirementMode == contract.GeneratedRetirementAuto && (!generatedSelectionAnchored(before) ||
			before.parent.OperationID != generatedVectorID(231) || before.phase.SelectionPhaseID != before.phase.PhaseID || requests.Load() != 0) {
			t.Fatal("automatic rotation lost its original selection before retirement")
		}
		current := selected.valueEntry(0)
		if current == nil || current.Generated.RetirementMode != profile.RetirementMode || current.Generated.RetiringDutyPresent != 1 || selected.root.Generated.Retiring != 1 {
			t.Fatal("rotation did not retain one exact retiring generation")
		}
		dutyRow, ok := before.records[generatedRecordKey{kind: 10, id: current.Generated.RetiringDutyID}]
		if !ok {
			t.Fatal("rotation omitted its retirement Duty")
		}
		duty, err = contract.InspectGeneratedDutyRecord(dutyRow.Body)
		if err != nil {
			t.Fatal(err)
		}
		target, err = before.retirementTarget(t.Context(), duty)
		if err != nil || target.ResourceDigest != hermeticCloudflareResourceDigest(targetToken) {
			t.Fatal("rotation changed the exact Cloudflare retirement target", err)
		}

	})
	retainedEntry := *selected.valueEntry(0)
	wantDeletes := int32(response.previous + 1)
	run.phase("transition", func() {
		if profile.RetirementMode == contract.GeneratedRetirementAuto {
			process := &generatedProcessFixture{Artifact: artifact, Implementation: implementation, Configure: configure}
			selected, verifyAutomatic = selectGeneratedAutomaticRetirementAcknowledgement(t, ctx, env, selected, process, target)
			return
		}
		for i := 0; i < response.previous; i++ {
			operation := generatedVectorID(byte(235 + i))
			input, inputCanonical := generatedDeletePlanInput(t, selected, operation, duty, target, 2)
			input.requestBindings[0].Digest = generatedRetirementRequestDigest(target)
			prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, inputCanonical)
			producer, expected := preparePrivateGeneratedProcessProducerWithConfig(t, env, selected, prior, artifact, configure)
			var packet []byte
			var facts contract.GeneratorSafeFacts
			var code contract.CryptoResultCode
			if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
				packet, facts, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("prior retirement producer handoff")
			}
			entered, result := selected.selectCandidate(ctx, producer.reservation.candidate)
			if response.late && i == 0 {
				if len(packet) == 0 || facts.Disposition != contract.GeneratorDispositionRetirementAcknowledged || generatedFactsResourceDigest(facts) != target.ResourceDigest {
					t.Fatal("first native delete did not seal an exact original acknowledgement")
				}
				latePacket, lateAttempt = bytes.Clone(packet), expected.Template.AttemptID
				// Keep only the delayed encrypted packet outside Core. Its inbox
				// has not received it, so no original terminal evidence is available.
				packet = nil
				facts = generatedUnknownFixtureFacts(expected, generatedTargetEvidence(t, entered, target))
			}
			if entered == nil || result.Outcome != ObservedCurrent || code != contract.CryptoSuccess || len(packet) != 0 || facts.Disposition != contract.GeneratorDispositionUnknown || facts.Reason != response.reason || requests.Load() != int32(i+1) {
				t.Fatal("prior exact retirement did not enter once and retain its ambiguity", code, result, facts)
			}
			keys.RetireGenerated()
			entered = generatedLifecycleReopen(t, ctx, entered, env.Store)
			ambiguity, err := contract.EncodeGeneratorSafeFacts(facts)
			if err != nil {
				t.Fatal(err)
			}
			permit, err := entered.admitGeneratedRetirementUnknown(context.Background(), duty.DutyID, ambiguity, generatedPlanInputFixture(t, entered).context)
			if err != nil {
				t.Fatal("prior retirement parking admission", err)
			}
			candidate, prepared := entered.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("prior retirement parking prepare", prepared)
			}
			selected, result = entered.selectCandidate(ctx, candidate)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("prior retirement parking selection", result)
			}
			selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
			work, err := selected.selectedGeneratedWork(context.Background())
			if err != nil || work.attempts[expected.Template.AttemptID].record.State != contract.GeneratedEffectUnknown || selected.root.Generated.Retiring != 1 || selected.root.Generated.Hazards != 0 {
				t.Fatal("prior retirement lost the named obligation or uncertainty", err)
			}
			duty, err = contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{10, duty.DutyID}].Body)
			if err != nil || duty.History.Count != uint32(i+1) || duty.Consumers.Count != uint32(i+1) {
				t.Fatal("prior retirement history or original readers were reset", err)
			}
		}
		operation := generatedVectorID(232)
		input, inputCanonical := generatedDeletePlanInput(t, selected, operation, duty, target, 2)
		input.requestBindings[0].Digest = generatedRetirementRequestDigest(target)
		prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, inputCanonical)
		producer, expected := preparePrivateGeneratedProcessProducerWithConfig(t, env, selected, prior, artifact, configure)
		var result []byte
		var facts contract.GeneratorSafeFacts
		var code contract.CryptoResultCode
		if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
			result, facts, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
			return code
		}) {
			t.Fatal("retirement producer handoff")
		}
		entered, outcome := selected.selectCandidate(ctx, producer.reservation.candidate)
		if entered == nil || outcome.Outcome != ObservedCurrent || code != contract.CryptoSuccess || requests.Load() != wantDeletes {
			t.Fatal("tagged Cloudflare retirement did not cross one selected first send", code, requests.Load(), outcome)
		}
		if response.reason != 0 {
			if len(result) != 0 || facts.Disposition != contract.GeneratorDispositionUnknown || facts.Reason != response.reason {
				t.Fatal("ambiguous child result differs", len(result), facts.Disposition, facts.Reason)
			}
			ambiguity, err := contract.EncodeGeneratorSafeFacts(facts)
			if err != nil {
				t.Fatal(err)
			}
			keys.RetireGenerated()
			fresh := generatedLifecycleReopen(t, ctx, entered, env.Store)
			enteredWork, err := fresh.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			enteredDuty, err := contract.InspectGeneratedDutyRecord(enteredWork.records[generatedRecordKey{10, duty.DutyID}].Body)
			if err != nil {
				t.Fatal(err)
			}
			admitted := generatedPlanInputFixture(t, fresh).context
			if _, err := fresh.admitGeneratedRetirementClose(context.Background(), expected.Template.AttemptID, admitted); err == nil {
				t.Fatal("unknown delete closed as acknowledged")
			}
			var permit *admittedGeneratedLifecycle
			if response.park {
				permit, err = fresh.admitGeneratedRetirementUnknown(context.Background(), duty.DutyID, ambiguity, admitted)
			} else {
				permit, err = fresh.admitGeneratedActiveRetirementResidue(context.Background(), duty.DutyID, ambiguity, admitted)
			}
			if response.reason == 10 && !response.park {
				if err == nil || permit != nil || fresh.root.Generated.Retiring != 1 || fresh.root.Generated.Duties != 1 || fresh.root.Generated.Hazards != 0 {
					t.Fatal("contradictory active identity granted residue closure or changed the obligation", err)
				}
				selected = fresh
				return
			}
			if err != nil {
				t.Fatal("active residue admission", err)
			}
			priorReceipts, err := fresh.receiptWindows(ctx)
			if err != nil {
				t.Fatal("retirement uncertainty predecessor receipt order", err)
			}
			candidate, prepared := fresh.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("active residue prepare", prepared)
			}
			closed, outcome := fresh.selectCandidate(ctx, candidate)
			if closed == nil || outcome.Outcome != ObservedCurrent || requests.Load() != wantDeletes {
				t.Fatal("active residue select", outcome)
			}
			closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
			work, err := closed.selectedGeneratedWork(context.Background())
			if response.park {
				if err != nil || work.parent != nil || work.phase != nil || closed.root.Generated.Retiring != 1 || closed.root.Generated.Duties != 1 || closed.root.Generated.Hazards != 0 {
					t.Fatal("parked uncertainty lost the exact unfinished obligation", err)
				}
				current, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{10, duty.DutyID}].Body)
				if err != nil || current.Status != contract.GeneratedEffectUnknown || current.Target != enteredDuty.Target || current.Progress != enteredDuty.Progress || current.CompletionClass != enteredDuty.CompletionClass || current.Consumers != enteredDuty.Consumers {
					t.Fatal("parking changed the exact obligation", err)
				}
				rows, err := work.vectors.resolve(9, expected.Template.AttemptID, contract.GeneratorVectorFacts, work.attempts[expected.Template.AttemptID].record.Facts)
				if err != nil || len(rows) != 1 {
					t.Fatal("parking lost ambiguity evidence", err)
				}
				fact, err := contract.InspectGeneratorFactsRow(rows[0])
				if err != nil || !bytes.Equal(fact.Facts, ambiguity) {
					t.Fatal("parking changed child ambiguity", err)
				}
				body, status := closed.MutationReceipt(ctx, operation)
				receipt, err := contract.InspectCompactMutationReceipt(body)
				if status.Outcome != ObservedCurrent || err != nil || receipt.OperationKind != 38 || receipt.SummaryCounts[contract.ReceiptSummaryUnknownCount] != 1 || receipt.SummaryCounts[contract.ReceiptDutyCount] != 1 || receipt.AcknowledgedCount != 0 || receipt.ConfirmedCount != 0 {
					t.Fatal("unknown retirement receipt", err, status)
				}
				selectedReceipts, err := closed.receiptWindows(ctx)
				wantOrder := append(slices.Clone(priorReceipts.Order), operation)
				if err != nil || !slices.Equal(selectedReceipts.Order, wantOrder) ||
					!slices.Equal(selectedReceipts.Successes, priorReceipts.Successes) || len(selectedReceipts.Failures) != len(priorReceipts.Failures)+1 ||
					!slices.Equal(selectedReceipts.Failures[:len(priorReceipts.Failures)], priorReceipts.Failures) || selectedReceipts.Failures[len(priorReceipts.Failures)].OperationID != operation {
					t.Fatal("unknown retirement did not append exactly its terminal failure in common order", err)
				}
				admitted := generatedPlanInputFixture(t, closed).context
				parked, err := closed.admitGeneratedRetirementResidueFixture(duty.DutyID, admitted)
				if response.reason == 10 {
					if err == nil || parked != nil {
						t.Fatal("contradictory identity granted residue closure")
					}
					selected = closed
					return
				}
				if err != nil {
					t.Fatal("parked residue admission", err)
				}
				candidate, result := closed.PrepareGeneratedLifecycle(ctx, parked, env.Trust)
				if candidate == nil || result.Outcome != ObservedCurrent {
					t.Fatal("parked residue prepare", result)
				}
				closed, result = closed.selectCandidate(ctx, candidate)
				if closed == nil || result.Outcome != ObservedCurrent || requests.Load() != wantDeletes || closed.root.Generated.Retiring != 0 || closed.root.Generated.Hazards != 1 {
					t.Fatal("parked residue select", result)
				}
				selected = closed
				return
			}
			if err != nil || work.parent != nil || work.phase != nil || closed.root.Generated.Retiring != 0 || closed.root.Generated.Duties != 0 || closed.root.Generated.Hazards != 1 {
				t.Fatal("active residue closure", err)
			}
			hazard, err := contract.InspectGeneratedHazardRecord(work.records[generatedRecordKey{11, expected.Template.HazardID}].Body)
			if err != nil || hazard.OwnerID != duty.DutyID || hazard.Exposure != contract.GeneratedExposurePossibleLive || hazard.CompletionClass != duty.CompletionClass || hazard.Fenced != 1 {
				t.Fatal("active residue changed exact Hazard", err)
			}
			targetAfter, err := work.generatedCleanupTarget(11, hazard.HazardID, hazard.Target)
			if err != nil || targetAfter != target {
				t.Fatal("active residue retargeted original", err)
			}
			body, status := closed.MutationReceipt(ctx, permit.plan.identity.operation)
			receipt, err := contract.InspectCompactMutationReceipt(body)
			if status.Outcome != ObservedCurrent || err != nil || receipt.OperationKind != 39 || receipt.StateResult != 6 || receipt.SummaryCounts[contract.ReceiptEffectCount] != 0 || receipt.SummaryCounts[contract.ReceiptHazardCount] != 1 || receipt.WarningBits != contract.ReceiptWarningPossibleLive {
				t.Fatal("active residue receipt", err, status)
			}
			if requests.Load() != wantDeletes {
				t.Fatal("residue restart repeated provider effect")
			}
			if response.cleanupResidue {
				cleanup, ok, err := work.selectGeneratedCleanup(context.Background(), nil)
				if err != nil || !ok || cleanup.kind != generatedCleanupHazard || cleanup.hazard.HazardID != hazard.HazardID || cleanup.attempt.record.AttemptID != expected.Template.AttemptID {
					t.Fatal("native deleting Hazard was not the exact cleanup source", err)
				}
				row := work.records[generatedRecordKey{kind: 11, id: cleanup.hazard.HazardID}]
				operation := testID("native deleting-Hazard cleanup operation")
				input, inputCanonical := generatedDeletePlanInputForSource(t, closed, operation, row, cleanup.target)
				input.requestBindings[0].Digest = generatedRetirementRequestDigest(cleanup.target)
				prior, _ := preparePrivateGeneratedReservation(t, env, closed, input, inputCanonical)
				producer, cleanupExpected := preparePrivateGeneratedProcessProducerWithConfig(t, env, closed, prior, artifact, configure)
				var packet []byte
				var facts contract.GeneratorSafeFacts
				var code contract.CryptoResultCode
				if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
					packet, facts, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
					return code
				}) {
					t.Fatal("native deleting-Hazard cleanup handoff")
				}
				entered, outcome := closed.selectCandidate(ctx, producer.reservation.candidate)
				wantDeletes++
				if entered == nil || outcome.Outcome != ObservedCurrent || code != contract.CryptoSuccess || len(packet) == 0 || facts.Disposition != contract.GeneratorDispositionRetirementAcknowledged || generatedFactsResourceDigest(facts) != cleanup.target.ResourceDigest || requests.Load() != wantDeletes {
					t.Fatal("native deleting-Hazard cleanup acknowledgement", outcome, code, facts, requests.Load())
				}
				keys.RetireGenerated()
				recorded := env.FreshGeneratedRecord(t, entered, cleanupExpected.Template.AttemptID, packet)
				closed = selectOrdinaryGeneratedCleanupClose(t, ctx, env, recorded, cleanupExpected.Template.AttemptID)
				deleteStore := &generatedCleanupDeleteStore{Store: env.Store, memoryStore: memory}
				closed = selectActualGeneratedInboxRelease(t, ctx, env, closed, deleteStore, cleanupExpected.Template.AttemptID, false)
				closed = generatedLifecycleReopen(t, ctx, closed, deleteStore)
				after := mustSelectedGeneratedWork(t, closed)
				mapping, present := after.releases[expected.Template.AttemptID]
				if !present || mapping.release.State != contract.GeneratedReleaseUnobserved || len(after.releases) != 1 || len(after.attempts) != 0 || closed.root.Generated.Hazards != 0 || closed.root.Generated.Duties != 0 {
					t.Fatal("native deleting-Hazard cleanup lost the earlier unknown inbox or retained provider work")
				}
				view, err := closed.inspectGeneratedWork(context.Background())
				if err != nil || !view.possibleGarbage {
					t.Fatal("native deleting-Hazard cleanup reported an unobserved original inbox as clean", err)
				}
			}
			selected = closed
			return
		}
		if len(result) == 0 {
			t.Fatal("acknowledged child omitted its sealed result")
		}
		decoded, err := contract.DecodeGeneratedResultRecord(result)
		if err != nil || decoded.SafeFacts.Disposition != contract.GeneratorDispositionRetirementAcknowledged || generatedFactsResourceDigest(decoded.SafeFacts) != target.ResourceDigest || len(decoded.Payload.Ciphertext) != 16 {
			t.Fatal("tagged Cloudflare retirement returned different sealed acknowledgement", err)
		}
		keys.RetireGenerated()
		recorded := env.FreshGeneratedRecord(t, entered, expected.Template.AttemptID, result)
		admitted := generatedPlanInputFixture(t, recorded).context
		admitted.AdmissionID, admitted.SessionID = testID("retirement close admission"), testID("retirement close session")
		closePlan, err := recorded.generatedRetirementClosePlan(ctx, expected.Template.AttemptID, admitted)
		if err != nil {
			t.Fatal("retirement close plan", err)
		}
		permit, err := recorded.admitGeneratedLifecyclePlan(t.Context(), closePlan)
		if err != nil {
			t.Fatal("retirement close admission", err, recorded.admission.valid(recorded.store), recorded.prepared)
		}
		candidate, prepared := recorded.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
		if candidate == nil || prepared.Outcome != ObservedCurrent || requests.Load() != wantDeletes {
			t.Fatal("retirement close preparation", prepared, requests.Load())
		}
		closed, outcome := recorded.selectCandidate(ctx, candidate)
		if closed == nil || outcome.Outcome != ObservedCurrent || requests.Load() != wantDeletes {
			t.Fatal("retirement close selection", outcome, requests.Load())
		}
		reopened, outcome := Open(ctx, OpenContext{admission: &closed.admission}, env.Store)
		if reopened == nil || outcome.Outcome != ObservedCurrent {
			t.Fatal("retirement close authenticated reopen", outcome)
		}
		after, err := reopened.selectedGeneratedWork(context.Background())
		if err != nil || reopened.root.Generated.Retiring != 0 || reopened.root.Generated.Duties != 0 ||
			reopened.root.Generated.PendingReleases != 1 || len(after.releases) != 1 {
			t.Fatal("retirement close did not release only the retiring slot", err)
		}
		if entry := reopened.valueEntry(0); entry == nil || entry.Generated.RetiringDutyPresent != 0 || !entry.Generated.RetiringDutyID.IsZero() {
			t.Fatal("retirement close retained the released slot pointer")
		}
		body, receiptResult := reopened.MutationReceipt(ctx, operation)
		receipt, receiptErr := contract.InspectCompactMutationReceipt(body)
		if receiptResult.Outcome != ObservedCurrent || receiptErr != nil || receipt.EvidenceCeiling != contract.ReceiptEvidenceAcknowledged ||
			receipt.WarningBits != contract.ReceiptWarningInvalidationNotConfirmed || receipt.AcknowledgedCount != 1 || receipt.ConfirmedCount != 0 ||
			receipt.SummaryCounts[contract.ReceiptSummarySuccessCount] != 1 {
			t.Fatal("retirement receipt lost its acknowledgement ceiling", receiptResult, receiptErr, receipt)
		}
		if requests.Load() != wantDeletes || !bytes.Equal(result, decodedBytes(t, decoded)) {
			t.Fatal("retirement changed the original result")
		}
		selected = reopened
	})
	want := sessionStateImage(t, selected)
	run.phase("verification", func() {
		cold := generatedLifecycleReopen(t, ctx, selected, env.Store)
		assertStateImage(t, cold, want)
		if verifyAutomatic != nil {
			verifyAutomatic(cold)
		}
		expected := retainedEntry
		if response.reason != 10 {
			expected.Generated.RetiringDutyPresent, expected.Generated.RetiringDutyID = 0, contract.ID{}
		}
		actual := cold.valueEntry(0)
		if actual == nil {
			t.Fatal("retirement removed the selected generation")
		}
		got, err := contract.PublicValueEntryDigest(cold.root.Domain, 0, *actual)
		wanted, wantErr := contract.PublicValueEntryDigest(cold.root.Domain, 0, expected)
		if err != nil || wantErr != nil || got != wanted {
			t.Fatal("retirement changed selected value, identity or membership", err, wantErr)
		}
		inspection, err := cold.inspectGeneratedWork(context.Background())
		wantEffects := int(wantDeletes)
		if response.cleanupResidue {
			wantEffects = 1
		}
		var wantActiveOwner contract.ID
		if response.reason == 10 && !response.park {
			wantActiveOwner = generatedVectorID(232)
		}
		if err != nil || inspection.activeOwner != wantActiveOwner || len(inspection.effects) != wantEffects || requests.Load() != wantDeletes {
			t.Fatal("authenticated inspection lost exact retirement work", err)
		}
		if response.previous > 0 {
			if len(inspection.hazards) != 1 || len(inspection.duties) != 0 || inspection.hazards[0].History.Count != uint32(wantDeletes) || inspection.hazards[0].Consumers.Count != uint32(wantDeletes) {
				t.Fatal("repeated residue lost its full original-coordinate history")
			}
			work, err := cold.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range work.attempts {
				if len(a.result) != 0 || a.record.Stage != contract.GeneratedStageTerminal || a.record.OwnerID != duty.DutyID ||
					!work.materials[materialIdentity{3, a.material.Core.OperationMaterialID}] || len(work.consumers[materialIdentity{3, a.material.Core.OperationMaterialID}]) != 1 {
					t.Fatal("repeated residue lost an exact original material or reader")
				}
			}
		}
		if response.reason == 0 && (inspection.effects[0].evidenceCeiling != contract.ReceiptEvidenceAcknowledged ||
			inspection.warnings != contract.ReceiptWarningInvalidationNotConfirmed || len(inspection.releases) != 1) {
			t.Fatal("inspection promoted or lost the acknowledgement ceiling")
		}
	})
	run.phase("reopen", func() {
		env.FreshCurrent(t, fixture.admission, selected)
		if requests.Load() != wantDeletes {
			t.Fatal("restart repeated the retirement effect")
		}
	})
	if response.late {
		run.phase("late original reflection", func() {
			fresh := generatedLifecycleReopen(t, ctx, selected, env.Store)
			g, err := fresh.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			original := g.attempts[lateAttempt]
			key, err := format.GeneratedResultKey(env.Store.Descriptor().Prefix, original.record.DomainID, original.record.InboxID)
			if err != nil {
				t.Fatal(err)
			}
			if err := env.Put(ctx, key, bytes.Clone(latePacket)); err != nil {
				t.Fatal("write delayed original", err)
			}
			permit := admitPrivateGeneratedOriginalReflection(t, keys, fresh, original.record.ResultID, latePacket, generatedPlanInputFixture(t, fresh).context)
			run.spy.mu.Lock()
			run.spy.scenarioEffects = scenarioEffects{}
			run.spy.mu.Unlock()
			candidate, result := fresh.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
			if candidate == nil || result.Outcome != ObservedCurrent || run.spy.StoreCAS != 0 || run.spy.TrustSign != 1 || requests.Load() != wantDeletes {
				t.Fatal("native original verification did not precede one K2 preparation", result)
			}
			closed, result := fresh.selectCandidate(ctx, candidate)
			if closed == nil || result.Outcome != ObservedCurrent || run.spy.StoreCAS != 1 || run.spy.TrustSign != 1 || requests.Load() != wantDeletes {
				t.Fatal("native original reflection dispatched or did not close once", result)
			}
			cold := generatedLifecycleReopen(t, ctx, closed, env.Store)
			work, err := cold.selectedGeneratedWork(context.Background())
			if err != nil || len(work.attempts) != 0 || len(work.releases) != len(g.releases)+int(wantDeletes) || cold.root.Generated.Hazards != 0 || !cold.root.Generated.ActiveOwner.IsZero() {
				t.Fatalf("native original closure: error=%v attempts=%d materials=%d releases=%d previous releases=%d hazards=%d", err, len(work.attempts), len(work.materials), len(work.releases), len(g.releases), cold.root.Generated.Hazards)
			}
			for _, a := range g.attempts {
				if work.materials[materialIdentity{3, a.material.Core.OperationMaterialID}] {
					t.Fatal("native original closure retained an original seed")
				}
			}
			view, err := cold.inspectGeneratedWork(context.Background())
			if err != nil || !view.possibleGarbage || len(view.effects) != int(wantDeletes) {
				t.Fatal("native original closure reported unobserved inboxes as clean", err)
			}
			env.FreshCurrent(t, fixture.admission, cold)
			if requests.Load() != wantDeletes {
				t.Fatal("fresh-process reflection repeated a provider effect")
			}
		})
	}
}

func decodedBytes(t testing.TB, result contract.GeneratedResultRecord) []byte {
	t.Helper()
	body, err := contract.EncodeGeneratedResultRecord(result)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func selectHermeticGeneratedProcessOperation(t testing.TB, operationCtx context.Context, env fixtureEnvironment, s *StateSession, input generatedPlanInput,
	artifact string, configure func(testing.TB, string, contract.GeneratorResultExpectation) custody.GeneratedProcessConfig, cold ...bool) *StateSession {
	t.Helper()
	ctx := env.operationContext()
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, nil)
	producer, expected := preparePrivateGeneratedProcessProducerWithConfig(t, env, s, prior, artifact, configure)
	var result []byte
	var facts contract.GeneratorSafeFacts
	var code contract.CryptoResultCode
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		result, facts, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("initial real-process handoff")
	}
	entered, outcome := s.selectCandidate(ctx, producer.reservation.candidate)
	if entered == nil || outcome.Outcome != ObservedCurrent || len(result) == 0 {
		t.Fatal("initial real-process entry", outcome, code, facts.Disposition, facts.Reason, facts.ProviderFacts)
	}
	env.Custody.RetireGenerated()
	if len(cold) != 0 && cold[0] {
		entered = generatedLifecycleReopen(t, operationCtx, entered, env.Store)
	}
	recorded := env.FreshGeneratedRecord(t, entered, expected.Template.AttemptID, result)
	if len(cold) != 0 && cold[0] {
		recorded = generatedLifecycleReopen(t, operationCtx, recorded, env.Store)
	}
	admitted := generatedPlanInputFixture(t, recorded).context
	admitted.AdmissionID, admitted.SessionID = testID("initial process final admission"), testID("initial process final session")
	plan, err := recorded.generatedFinalRequest(t.Context(), admitted)
	if err != nil || !plan.selecting {
		t.Fatal("initial real-process final request", err)
	}
	recorded, final := preparePrivateGeneratedFinal(t, env, recorded, plan)
	selected, outcome := recorded.selectCandidate(ctx, final.reservation.candidate)
	if selected == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("initial real-process final selection", outcome)
	}
	env.Custody.RetireGenerated()
	return selected
}

func selectGeneratedAutomaticRetirementAcknowledgement(t testing.TB, ctx context.Context, env fixtureEnvironment, selected *StateSession,
	process *generatedProcessFixture, target contract.GeneratorTarget) (*StateSession, func(*StateSession)) {
	t.Helper()
	before := mustSelectedGeneratedWork(t, selected)
	if !generatedSelectionAnchored(before) || before.phase.SelectionPhaseID != before.phase.PhaseID ||
		len(contract.GeneratedAutomaticRetirementIndices(before.bundles[0])) != 1 {
		t.Fatal("automatic retirement requires its exact first selection")
	}
	parent, anchor, successor := *before.parent, *before.phase, *selected.valueEntry(0)
	graph := before.bundles[0]
	x, _, ok := generatedAutomaticTemplate(before, anchor.LineageIndex)
	if !ok || x.AttemptID != anchor.FrontierAttemptID || x.ResourceIncarnationID != target.ResourceID ||
		x.DutyID != successor.Generated.RetiringDutyID || selected.root.Generated.ActiveOwner != parent.OperationID {
		t.Fatal("automatic retirement changed its original parent or exact target")
	}
	windows, err := selected.receiptWindows(ctx)
	if err != nil {
		t.Fatal("automatic predecessor receipts", err)
	}
	if _, _, found, err := selected.retainedMutationReceipt(parent.OperationID); err != nil || found {
		t.Fatal("automatic first selection already has a terminal receipt", err)
	}
	checkAccess := func(prior, next *StateSession) {
		pins := make(map[materialIdentity]contract.ID)
		for _, row := range prior.accessRecords() {
			digest, err := contract.AccessRecordDigest(row)
			if err != nil {
				t.Fatal("automatic predecessor access", err)
			}
			pins[materialIdentity{row.MaterialKind, row.MaterialID}] = digest
		}
		for _, row := range next.accessRecords() {
			digest, err := contract.AccessRecordDigest(row)
			if err != nil || pins[materialIdentity{row.MaterialKind, row.MaterialID}] != digest {
				t.Fatal("automatic step added or rewrote surviving access", err)
			}
		}
	}
	checkAnchor := func(next *StateSession) {
		work := mustSelectedGeneratedWork(t, next)
		if !generatedSelectionAnchored(work) || work.parent.OperationID != parent.OperationID ||
			work.phase.SelectionPhaseID != anchor.SelectionPhaseID || work.phase.ChangedSubjects != anchor.ChangedSubjects || work.phase.ChangedAccess != anchor.ChangedAccess {
			t.Fatal("automatic step changed its original selection anchor")
		}
		got, err := contract.PublicValueEntryDigest(next.root.Domain, 0, *next.valueEntry(0))
		want, wantErr := contract.PublicValueEntryDigest(next.root.Domain, 0, successor)
		if err != nil || wantErr != nil || got != want {
			t.Fatal("automatic step changed its selected successor", err, wantErr)
		}
	}
	admitted := generatedPlanInputFixture(t, selected).context
	digest := generatedRetirementRequestDigest(target)
	plan, err := selected.generatedAutomaticReservationRequest(ctx, admitted, digest)
	if err != nil {
		t.Fatal("automatic same-parent reservation", err)
	}
	prior, result := selected.PrepareGeneratedSuccessorReservation(ctx, &admittedGeneratedSuccessorReservation{session: selected, plan: plan})
	if prior == nil || result.Outcome != ObservedCurrent {
		t.Fatal("automatic reservation preparation", result)
	}
	producer, expected := preparePrivateGeneratedProcessProducerForAttempt(t, env, selected, prior, env.Custody, x.AttemptID, process.Artifact, process.Configure)
	if expected.Plan.OperationID != parent.OperationID || expected.Template != x || expected.TargetResourceDigest != target.ResourceDigest {
		t.Fatal("automatic producer replaced the admitted original template")
	}
	if process.BeforeDelete != nil {
		if err := process.BeforeDelete(x.AttemptID, generatedTargetProviderTokenID(t, selected, target)); err != nil {
			if process.SelectFailure != nil {
				process.SelectFailure("generated_retire", contract.ID{}, contract.ID{}, contract.ID{}, 0, false)
			}
			t.Fatal("record automatic delete intent", err)
		}
	}
	var packet []byte
	var facts contract.GeneratorSafeFacts
	var code contract.CryptoResultCode
	var authority contract.ID
	invoked := false
	failed := func() {
		if process.SelectFailure != nil {
			process.SelectFailure("generated_retire", producer.operation.context.AdmissionID, producer.producerLocator, authority, code, invoked)
		}
	}
	if !producer.reservation.candidate.bindFirstSend(producer, func(callctx context.Context, sendAuthority contract.ID) contract.CryptoResultCode {
		invoked, authority = true, sendAuthority
		var outcome custody.GeneratedProducerOutcome
		packet, facts, outcome = env.Custody.InvokeGeneratedProducerOutcome(callctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		code = outcome.Code
		if process.ObserveOutcome != nil {
			process.ObserveOutcome(outcome)
		}
		return code
	}) {
		failed()
		t.Fatal("automatic retirement producer handoff")
	}
	entered, result := selected.selectCandidate(ctx, producer.reservation.candidate)
	if facts.Disposition == contract.GeneratorDispositionRetirementAcknowledged && (len(facts.ResourceData) > 0) && generatedFactsResourceDigest(facts) == target.ResourceDigest && process.AfterDelete != nil {
		if err := process.AfterDelete(x.AttemptID, generatedTargetProviderTokenID(t, selected, target), facts); err != nil {
			failed()
			t.Fatal("record automatic acknowledgement", err)
		}
	}
	if entered == nil || result.Outcome != ObservedCurrent || code != contract.CryptoSuccess || len(packet) == 0 ||
		facts.Disposition != contract.GeneratorDispositionRetirementAcknowledged || len(facts.ResourceData) == 0 || generatedFactsResourceDigest(facts) != target.ResourceDigest {
		failed()
		t.Fatal("automatic retirement lacks exact native acknowledgement", result, code, facts.Disposition, facts.Reason, facts.ProviderFacts)
	}
	sealed, err := contract.DecodeGeneratedResultRecord(packet)
	if err != nil || sealed.SafeFacts.Disposition != contract.GeneratorDispositionRetirementAcknowledged || generatedFactsResourceDigest(sealed.SafeFacts) != target.ResourceDigest || len(sealed.Payload.Ciphertext) != 16 {
		t.Fatal("automatic retirement sealed acknowledgement differs", err)
	}
	checkAccess(selected, entered)
	checkAnchor(entered)
	env.Custody.RetireGenerated()
	recorded := env.FreshGeneratedRecord(t, entered, x.AttemptID, packet)
	checkAccess(entered, recorded)
	checkAnchor(recorded)
	work := mustSelectedGeneratedWork(t, recorded)
	if !bytes.Equal(work.attempts[x.AttemptID].result, packet) {
		t.Fatal("automatic fresh recording changed the sealed original result")
	}
	var effects []contract.SupportRecord
	for _, lineage := range graph.Lineages {
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			if template.AttemptID != x.AttemptID && (lineage.Purpose != contract.GeneratorLineageCreate || before.attempts[template.AttemptID].record.AttemptID.IsZero()) {
				continue
			}
			row, present := work.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, template.AttemptID}]
			attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if !present || err != nil || row.Kind != contract.GeneratedAttemptSupportKind || row.RecordID != template.AttemptID || attempt.AttemptID != template.AttemptID ||
				attempt.OperationID != parent.OperationID || attempt.ResourceID != template.ResourceIncarnationID || attempt.ResultID != template.ResultID || attempt.InboxID != template.InboxID ||
				attempt.State != contract.GeneratedEffectSucceeded || attempt.Stage != contract.GeneratedStageTerminal {
				t.Fatal("automatic original effect set differs", err)
			}
			effects = append(effects, row)
		}
	}
	if len(effects) != 2 {
		t.Fatal("automatic rotation must retain its exact CREATE and DELETE")
	}
	// Raw frames follow the independent receipt example in
	// recipient_replacement_receipt_test.go; no production hash/encoder is used.
	generator := func(label string, value []byte, count uint32) contract.GeneratorDescriptor {
		framed := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v1/"+label+"\x00"), uint32(len(value)))
		return contract.GeneratorDescriptor{Digest: sha256.Sum256(append(framed, value...)), Length: uint64(len(value)), Count: count}
	}
	appendDescriptor := func(out []byte, descriptor contract.GeneratorDescriptor) []byte {
		out = append(out, descriptor.Digest[:]...)
		out = binary.BigEndian.AppendUint64(out, descriptor.Length)
		return binary.BigEndian.AppendUint32(out, descriptor.Count)
	}
	effectBytes := binary.BigEndian.AppendUint32(nil, 2)
	for _, row := range effects {
		effectBytes = binary.BigEndian.AppendUint32(effectBytes, uint32(37+len(row.Body)))
		effectBytes = append(effectBytes, 9)
		effectBytes = append(effectBytes, row.RecordID[:]...)
		effectBytes = binary.BigEndian.AppendUint32(effectBytes, uint32(len(row.Body)))
		effectBytes = append(effectBytes, row.Body...)
	}
	effectDescriptor := generator("effect-results", effectBytes, 2)
	closePlan, err := recorded.generatedAutomaticClosePlan(ctx, generatedPlanInputFixture(t, recorded).context)
	if err != nil {
		t.Fatal("automatic original-parent close plan", err)
	}
	counts := [12]uint32{0: 2, 4: anchor.ChangedAccess.Count, 5: 2}
	projection := binary.BigEndian.AppendUint16(nil, 3)
	projection = binary.BigEndian.AppendUint16(projection, graph.Request.OperationKind)
	for _, id := range []contract.ID{selected.root.Domain, parent.OperationID, parent.RequestCoreDigest, graph.Request.PredecessorRevisionID, closePlan.identity.revision, closePlan.identity.revision} {
		projection = append(projection, id[:]...)
	}
	for _, scalar := range []uint16{1, 2, 0, 3} {
		projection = binary.BigEndian.AppendUint16(projection, scalar)
	}
	projection = append(projection, 1)
	projection = appendDescriptor(projection, anchor.ChangedSubjects)
	projection = binary.BigEndian.AppendUint64(projection, 2)
	for _, count := range counts {
		projection = binary.BigEndian.AppendUint32(projection, count)
	}
	for _, count := range []uint32{1, 0, 0} {
		projection = binary.BigEndian.AppendUint32(projection, count)
	}
	projection = append(projection, make([]byte, 78)...)
	for _, descriptor := range []contract.GeneratorDescriptor{anchor.ChangedAccess, effectDescriptor,
		generator("output-results", make([]byte, 4), 0), generator("result-duties", make([]byte, 4), 0), generator("result-hazards", make([]byte, 4), 0)} {
		projection = appendDescriptor(projection, descriptor)
	}
	projection = append(projection, make([]byte, 32)...)
	if len(projection) != 647 {
		t.Fatal("independent automatic result projection length", len(projection))
	}
	framed := binary.BigEndian.AppendUint32(nil, 1)
	framed = binary.BigEndian.AppendUint32(framed, 647)
	complete := generator("complete-result", append(framed, projection...), 1)
	wantReceipt := contract.CompactMutationReceipt{Schema: 3, OperationKind: graph.Request.OperationKind, DomainID: selected.root.Domain,
		OperationID: parent.OperationID, RequestIdentityDigest: parent.RequestIdentityDigest, PredecessorRevisionID: graph.Request.PredecessorRevisionID,
		RequestedRevisionID: closePlan.identity.revision, ObservedRevisionID: closePlan.identity.revision, StateResult: 1, EffectSummary: 2,
		EvidenceCeiling: 3, CanonicalOutcome: 1, ChangedSubjects: anchor.ChangedSubjects, CompleteResult: complete,
		WarningBits: 2, SummaryCounts: counts, AcknowledgedCount: 1}
	permit, err := recorded.admitGeneratedLifecyclePlan(ctx, closePlan)
	if err != nil {
		t.Fatal("automatic close admission", err)
	}
	candidate, result := recorded.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("automatic close preparation", result)
	}
	closed, result := recorded.selectCandidate(ctx, candidate)
	if closed == nil || result.Outcome != ObservedCurrent {
		t.Fatal("automatic original-parent close selection", result)
	}
	checkAccess(recorded, closed)
	expectedReleases := make(map[contract.ID]contract.PendingInboxReleaseRecord, len(before.releases)+1)
	for id, released := range before.releases {
		expectedReleases[id] = released.release
	}
	expectedReleases[x.AttemptID] = contract.PendingInboxReleaseRecord{Schema: contract.GeneratorRecordSchema, DomainID: selected.root.Domain,
		InboxID: x.InboxID, OriginalResultID: x.ResultID, SelectedHandoffDigest: contract.Hash(packet), HandoffRevisionID: closePlan.identity.revision,
		CapacityReservation: parent.Capacity, ObjectLength: uint32(len(packet)), State: contract.GeneratedReleasePending}
	verify := func(cold *StateSession) {
		t.Helper()
		current := mustSelectedGeneratedWork(t, cold)
		if current.parent != nil || current.phase != nil || !cold.root.Generated.ActiveOwner.IsZero() || cold.root.Generated.Retiring != 0 ||
			cold.root.Generated.Duties != 0 || len(current.releases) != len(expectedReleases) {
			t.Fatal("automatic close retained its parent or changed its release set")
		}
		for id, want := range expectedReleases {
			if got, found := current.releases[id]; !found || got.release != want {
				t.Fatal("automatic close changed an exact original inbox release")
			}
		}
		retained := successor
		retained.Generated.RetiringDutyPresent, retained.Generated.RetiringDutyID = 0, contract.ID{}
		got, err := contract.PublicValueEntryDigest(cold.root.Domain, 0, *cold.valueEntry(0))
		want, wantErr := contract.PublicValueEntryDigest(cold.root.Domain, 0, retained)
		if err != nil || wantErr != nil || got != want {
			t.Fatal("automatic close changed its current successor", err, wantErr)
		}
		body, observed := cold.MutationReceipt(ctx, parent.OperationID)
		receipt, err := contract.InspectCompactMutationReceipt(body)
		if observed.Outcome != ObservedCurrent || err != nil || receipt != wantReceipt {
			t.Fatal("automatic original receipt differs from its independent exact result", err, observed)
		}
		after, err := cold.receiptWindows(ctx)
		if err != nil || len(after.Successes) != len(windows.Successes)+1 || len(after.Failures) != len(windows.Failures) {
			t.Fatal("automatic close added a separate retirement receipt", err)
		}
		for at, previous := range windows.Successes {
			if after.Successes[at] != previous {
				t.Fatal("automatic close changed a prior success receipt")
			}
		}
		for at, previous := range windows.Failures {
			if after.Failures[at] != previous {
				t.Fatal("automatic close changed a prior failure receipt")
			}
		}
		assertSuccessReceiptOrder(t, windows, after, parent.OperationID)
		inspection, err := cold.inspectGeneratedWork(ctx)
		if err != nil || len(inspection.effects) != 1 || inspection.effects[0].attempt.AttemptID != x.AttemptID ||
			inspection.effects[0].attempt.OperationID != parent.OperationID || inspection.effects[0].evidenceCeiling != contract.ReceiptEvidenceAcknowledged {
			t.Fatal("cold automatic inspection changed its exact DELETE", err)
		}
	}
	verify(closed)
	return closed, verify
}
