package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedProcessFacts(t *testing.T, s *StateSession, record *generatedRecordInput) processStoreFacts {
	t.Helper()
	var f processFixture
	if record == nil {
		f = selectedProcessFacts(t, OpenContext{admission: &s.admission}, s)
	} else {
		f = selectedGeneratedProcessFacts(t, s)
	}
	var err error
	f.ExpectedWork, err = s.workSupportRecords(t.Context())
	if err != nil {
		t.Fatal("generated process public facts", err)
	}
	f.GeneratedRecord = record
	return processStoreFacts{Domain: f.Domain, Trust: f.Trust, Descriptor: f.Descriptor, PublicKey: f.PublicKey,
		DomainBasis: f.DomainBasis, ExpectedImage: f.ExpectedImage, Generated: &f}
}

// full_only: false
func TestGeneratedResultProcessLossPreservesOriginalWork(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for mode := uint8(0); mode < 3; mode++ {
			for _, barrier := range []string{"before-first-create", "after-result-readback", "after-root-readback", "after-cas-acceptance"} {
				t.Run(fmt.Sprintf("recovery%t/source%d/%s", recovery, mode, barrier), func(t *testing.T) {
					ctx := context.Background()
					env, keys := genesisEnvironment(t, contract.GCP, recovery)
					env = syntheticAuthorityScenarioEnvironment(t, env)
					run := newScenarioRun(t, ctx, env)
					f := newEnvironmentFixture(t, ctx, run.env, nil, false)
					input, canonical := generatedSourcePlanInput(t, run, f, mode)
					prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
					producer, expected := preparePrivateGeneratedProducer(t, env, f.session, prior, nil)
					var originalResult []byte
					sends := 0
					if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
						sends++
						var code contract.CryptoResultCode
						originalResult, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
						return code
					}) {
						t.Fatal("original producer handoff")
					}
					selected, res := f.session.selectCandidate(ctx, producer.reservation.candidate)
					if selected == nil || res.Outcome != ObservedCurrent || sends != 1 || len(originalResult) == 0 {
						t.Fatal("original producer entry", res)
					}
					keys.RetireGenerated()
					resultKey := expectedGeneratedResultKey(env.Store.Descriptor().Prefix, expected)
					if key, _, err := selected.generatedResultCoordinate(t.Context(), expected.Template.AttemptID); err != nil || key != resultKey {
						t.Fatal("selected work lost its absent original result coordinate")
					}
					original, err := selected.selectedGeneratedWork(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					for _, target := range []uint8{1, 2} {
						if target == 2 && !recovery {
							continue
						}
						operation, mask, approval := uint8(1), uint8(3), uint8(1)
						if recovery {
							approval = 2
						}
						if target == 2 {
							operation, mask, approval = 3, 12, 1
						}
						actors := env.ReplacementActors(t, ctx, selected, operation, mask, approval)
						permit := admitAuthorityReplacement(t, selected, actors.Keys, actors.After, operation, approval, mask, actors.Source)
						candidate, res := selected.PrepareSuccession(ctx, permit, actors.Signers)
						if candidate == nil || res.Outcome != ObservedCurrent {
							t.Fatal("occupied replacement preparation", res)
						}
						admission := deliverSuccessionBasis(t, candidate)
						if res := selected.Select(ctx, candidate); res.Outcome != ObservedCurrent {
							t.Fatal("occupied replacement selection", res)
						}
						keys.RetireAccess()
						selected, res = Open(ctx, admission, env.Store)
						if selected == nil || res.Outcome != ObservedCurrent {
							t.Fatal("current-key reopen", res)
						}
						actors.Activate(t, selected)
					}
					before := selected
					work, err := before.selectedGeneratedWork(context.Background())
					if err != nil || *work.parent != *original.parent || *work.phase != *original.phase ||
						work.attempts[expected.Template.AttemptID].record != original.attempts[expected.Template.AttemptID].record {
						t.Fatal("replacement changed original reservation", err)
					}
					if key, _, err := before.generatedResultCoordinate(t.Context(), expected.Template.AttemptID); err != nil || key != resultKey {
						t.Fatal("replacement changed original inbox")
					}
					store := env.Store.(*memoryStore)
					directory := processStoreDiagnostics(t)
					facts := generatedProcessFacts(t, before, &generatedRecordInput{Attempt: expected.Template.AttemptID, Result: originalResult})
					writer := startProcessStoreChild(t, directory, "generated-killed", facts)
					creates, cas := store.creates, store.cas
					planned, err := serveGeneratedProcess(t, writer, store, before, *facts.Generated.GeneratedRecord, barrier)
					if err != nil {
						t.Fatal(err)
					}
					writer.trace = append(writer.trace, "validated generated barrier: "+barrier)
					if err := writer.stop(); err != nil || !writer.joined {
						t.Fatal("generated process termination did not join", err)
					}
					wantCreates, wantCAS := len(planned.candidate.objects)+1, 0
					switch barrier {
					case "before-first-create":
						wantCreates = 0
					case "after-result-readback":
						wantCreates = 1
					case "after-cas-acceptance":
						wantCAS = 1
					}
					if store.creates-creates != wantCreates || store.cas-cas != wantCAS {
						t.Fatal("generated barrier write counts differ", store.creates-creates, store.cas-cas)
					}
					selected, res = Open(ctx, OpenContext{admission: &before.admission}, store)
					if selected == nil || res.Outcome != ObservedCurrent {
						t.Fatal("post-kill selected closure", res)
					}
					if wantCAS == 0 {
						if selected.head.Core != before.head.Core || selected.token != before.token || !reflect.DeepEqual(selected.supportRecords(), before.supportRecords()) {
							t.Fatal("pre-CAS process loss changed selected work")
						}
					} else {
						assertGeneratedProcessSuccessor(t, before, selected, expected.Template.AttemptID, originalResult)
					}
					if barrier == "before-first-create" {
						if body, present, res := selected.ReadGeneratedResult(ctx, expected.Template.AttemptID); present || body != nil || res.Outcome != 0 {
							t.Fatal("process loss invented an absent result", res)
						}
					}
					reader := startProcessStoreChild(t, directory, "generated-reader", generatedProcessFacts(t, selected, nil))
					if err := serveProcessReader(t, reader, store, sessionStateImage(t, selected)); err != nil {
						t.Fatal(err)
					}
					if err := reader.join(); err != nil {
						t.Fatal("independent generated reader failed", err)
					}
					if wantCAS == 0 {
						var supplied []byte
						if barrier == "before-first-create" {
							supplied = originalResult
						}
						record := generatedRecordInput{Attempt: expected.Template.AttemptID, Result: supplied}
						child := startProcessStoreChild(t, directory, "generated-record", generatedProcessFacts(t, selected, &record))
						if _, err := serveGeneratedProcess(t, child, store, selected, record, ""); err != nil {
							t.Fatal(err)
						}
						if err := child.join(); err != nil {
							t.Fatal("fresh generated record did not join", err)
						}
						selected, res = Open(ctx, OpenContext{admission: &before.admission}, store)
						if selected == nil || res.Outcome != ObservedCurrent {
							t.Fatal("fresh generated record reopen", res)
						}
						assertGeneratedProcessSuccessor(t, before, selected, expected.Template.AttemptID, originalResult)
					}
					if !bytes.Equal(store.objects[resultKey].Body, originalResult) || sends != 1 {
						t.Fatal("process loss changed original return or repeated its effect")
					}
					if again, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, producer.reservation.candidate.generated.authority); code == contract.CryptoSuccess || len(again) != 0 {
						t.Fatal("restart regenerated a producer return")
					}
				})
			}
		}
	}
}

func assertGeneratedProcessSuccessor(t *testing.T, before, after *StateSession, attempt contract.ID, result []byte) {
	t.Helper()
	if !reflect.DeepEqual(before.pages, after.pages) || !reflect.DeepEqual(before.recipients, after.recipients) ||
		!reflect.DeepEqual(before.access, after.access) || !reflect.DeepEqual(freshReceiptExpectations(t, before), freshReceiptExpectations(t, after)) {
		t.Fatal("record changed values, recipients, access or receipts")
	}
	old, oldErr := before.selectedGeneratedWork(context.Background())
	next, err := after.selectedGeneratedWork(context.Background())
	if oldErr != nil || err != nil || old.parent == nil || next.parent == nil || *next.parent != *old.parent ||
		next.phase.Phase != old.phase.Phase+1 || next.phase.FrontierAttemptID != attempt ||
		next.phase.Branch != old.phase.Branch || next.phase.LineageIndex != old.phase.LineageIndex ||
		next.phase.NoEffectUsed != old.phase.NoEffectUsed || next.phase.ResidueUsed != old.phase.ResidueUsed ||
		next.phase.AcceptedResultID != old.attempts[attempt].record.ResultID || next.phase.ResultDigest != contract.Hash(result) ||
		len(next.attempts) != len(old.attempts) || !bytes.Equal(next.attempts[attempt].result, result) {
		t.Fatal("record changed the original operation or accepted result", oldErr, err)
	}
	a, want := next.attempts[attempt].record, old.attempts[attempt].record
	want.State, want.Stage, want.Facts = contract.GeneratedEffectSucceeded, contract.GeneratedStageTerminal, a.Facts
	if a != want || !reflect.DeepEqual(next.bundles, old.bundles) || !reflect.DeepEqual(next.sources, old.sources) || !reflect.DeepEqual(next.protected, old.protected) {
		t.Fatal("record changed original identities, source obligations or branch rights")
	}
}

func processGeneratedRecordChild(t *testing.T, ctx context.Context, store *processStore, before *StateSession, facts processStoreFacts) {
	t.Helper()
	if facts.Generated == nil || facts.Generated.GeneratedRecord == nil || facts.Writer != nil {
		t.Fatal("generated phase child lacks exact public facts")
	}
	installFreshGeneratedOutputSources(t, before, facts.Generated.GeneratedOutputBindings)
	input := *facts.Generated.GeneratedRecord
	if input.Result == nil {
		body, present, res := before.ReadGeneratedResult(ctx, input.Attempt)
		if !present || res.Outcome != 0 {
			t.Fatal("durable original result unavailable", res)
		}
		input.Result = body
	}
	keys := memoryCurrentAuthorityKeys(t, before)
	env := fixtureEnvironment{Store: store, Trust: memoryCurrentAuthoritySigner(t, before), Custody: keys}
	admitted := generatedPlanInputFixture(t, before).context
	admitted.AdmissionID, admitted.SessionID = testID("process record admission"), testID("process record session")
	plan, err := before.generatedRecordRequest(context.Background(), input.Attempt, input.Result, admitted)
	if err != nil {
		t.Fatal("generated phase request", err)
	}
	p := preparePrivateGeneratedRecord(t, env, before, plan)
	selected, res := before.selectCandidate(ctx, p.reservation.candidate)
	if selected == nil || res.Outcome != ObservedCurrent || p.reservation.candidate.firstSend != nil {
		t.Fatal("generated phase selection", res)
	}
	if reply, _, code := keys.InvokeGeneratedProducer(ctx, plan.request.Context.AdmissionID, contract.ID{}, contract.ID{}); code == contract.CryptoSuccess || len(reply) != 0 {
		t.Fatal("record admission restored producer permission")
	}
	keys.RetireGenerated()
	assertGeneratedProcessSuccessor(t, before, selected, input.Attempt, input.Result)
	store.call(processStoreRequest{Method: "authenticated-generated-record"})
}

func processGeneratedRecordConfigurationReadRequests(t testing.TB, descriptor contract.Descriptor, image stateImage) []processStoreRequest {
	t.Helper()
	requests := processConfigurationReadRequests(t, descriptor, image, true)
	// Record preserves body-opaque configuration pages. Private candidate custody
	// acquires their complete rows with one read per retained physical page.
	for _, page := range image.AdministrativeIndex.Pages {
		for _, row := range page.Rows {
			if row.Kind == contract.OutputConfigurationSliceSupportKind {
				requests = append(requests, processStoreRequest{Method: "read", Key: mustKey(t, descriptor.Prefix, page.Ref), Maximum: page.Ref.Length})
				break
			}
		}
	}
	return requests
}

func serveGeneratedProcess(t *testing.T, child *processStoreChild, store *memoryStore, before *StateSession, input generatedRecordInput, barrier string) (*generatedReservation, error) {
	t.Helper()
	for _, expected := range processReadRequests(t, store.desc, sessionStateImage(t, before)) {
		if err := serveProcessRead(child, store, expected); err != nil {
			return nil, err
		}
	}
	configuration := processGeneratedRecordConfigurationReadRequests(t, store.desc, sessionStateImage(t, before))
	if input.Result == nil {
		configuration = nil // Durable-result lookup precedes both plan checks.
	}
	pending, err := serveProcessFragmentReads(t, child, store, sessionStateImage(t, before), configuration)
	if err != nil {
		return nil, err
	}
	key, _, err := before.generatedResultCoordinate(t.Context(), input.Attempt)
	if err != nil {
		return nil, errors.New("generated barrier has no original result coordinate")
	}
	if input.Result == nil {
		input.Result = store.objects[key].Body
		if err := serveProcessReadRequest(child, store, pending, processStoreRequest{Method: "read", Key: key, Maximum: uint32(contract.GeneratedResultRecordMaxLength)}); err != nil {
			return nil, err
		}
		configuration = processGeneratedRecordConfigurationReadRequests(t, store.desc, sessionStateImage(t, before))
		pending, err = serveProcessFragmentReads(t, child, store, sessionStateImage(t, before), configuration)
		if err != nil {
			return nil, err
		}
	}
	plan, err := before.generatedRecordRequest(t.Context(), input.Attempt, input.Result, generatedPlanInputFixture(t, before).context)
	if err != nil {
		return nil, err
	}
	// Reuse the public construction for the bounded Store call plan. This is
	// transaction evidence, not an independent encoding/hash oracle. The
	// successor's preserved application and work meaning is checked separately.
	planned, err := before.deriveGeneratedRecord(context.Background(), plan)
	if err != nil {
		return nil, err
	}
	requests := []processStoreRequest{{Method: "create", Key: key, Body: input.Result}, {Method: "read", Key: key, Maximum: uint32(contract.GeneratedResultRecordMaxLength)}}
	for _, object := range planned.candidate.objects {
		key := mustKey(t, store.desc.Prefix, object.ref)
		requests = append(requests, processStoreRequest{Method: "create", Key: key, Body: object.body}, processStoreRequest{Method: "read", Key: key, Maximum: object.ref.Length})
	}
	requests = append(requests, processStoreRequest{Method: "cas", Key: store.desc.HeadKey, Token: before.token},
		processStoreRequest{Method: "read", Key: store.desc.HeadKey, Maximum: contract.MaxHeadLength})
	for index, expected := range requests {
		request := pending
		var err error
		if index != 0 || pending.Method == "" {
			request, err = child.next()
		}
		if err != nil {
			return nil, err
		}
		if expected.Method == "cas" {
			head, err := format.DecodeHead(request.Body)
			if err != nil || head.AuthKind != format.GeneratorAuth || head.Generator == nil || head.Core != planned.candidate.head.Core ||
				*head.Generator != *planned.candidate.head.Generator {
				return nil, errors.New("generated record CAS changed its original conditional authority")
			}
			assertGeneratedProcessSuccessor(t, before, planned.state, input.Attempt, input.Result)
			expected.Body = request.Body
		}
		if !processRequestMatches(request, expected) {
			return nil, fmt.Errorf("generated process operation differs: got %s %s, want %s %s", request.Method, request.Key, expected.Method, expected.Key)
		}
		if barrier == "before-first-create" && index == 0 || barrier == "after-result-readback" && index == 2 || barrier == "after-root-readback" && expected.Method == "cas" {
			return planned, nil
		}
		reply, err := processStoreOperation(store, request, false)
		if err != nil || request.Method == "read" && reply.Read.Status != contract.ReadOK ||
			request.Method != "read" && reply.Write.Status != contract.WriteAcknowledged && (request.Method != "create" || reply.Write.Status != contract.WritePrecondition) {
			return nil, errors.New("generated process Store operation did not complete")
		}
		if barrier == "after-cas-acceptance" && request.Method == "cas" {
			return planned, nil
		}
		if err := child.reply(reply); err != nil {
			return nil, err
		}
	}
	marker, err := serveProcessFragmentReads(t, child, store, sessionStateImage(t, before), processConfigurationReadRequests(t, store.desc, sessionStateImage(t, planned.state), true), sessionStateImage(t, planned.state))
	if err != nil || !processStoreMarker(marker, "authenticated-generated-record") {
		return nil, errors.New("generated process authentication marker differs")
	}
	return planned, child.reply(processStoreReply{})
}
