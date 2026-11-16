package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedControlledRetirementRecordsNonfinalAcknowledgement(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			ctx := context.Background()
			env, _ := genesisEnvironment(t, contract.GCP, recovery)
			env = syntheticAuthorityScenarioEnvironment(t, env)
			f := newEnvironmentFixture(t, ctx, env, nil, false)
			p := defaultGeneratedFixtureProfile()
			p.CompletionClass = contract.GeneratedCompletionConfirmed
			s := selectPrivateGeneratedOperation(t, env, f.session, generatedPlanInputForGenerations(t, f.session, generatedVectorID(230), []string{"generated"}, p), "controlled original")
			old := *s.valueEntry(0)
			s = selectPrivateGeneratedOperation(t, env, s, generatedStatePlanInput(t, s, generatedVectorID(231), []string{old.Name}, p, old.Generated.Epoch+1, map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), "controlled rotation")
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			d, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, s.valueEntry(0).Generated.RetiringDutyID}].Body)
			if err != nil {
				t.Fatal(err)
			}
			target, err := g.retirementTarget(ctx, d)
			if err != nil {
				t.Fatal(err)
			}
			reservationInput, reservationCanonical := generatedDeletePlanInput(t, s, generatedVectorID(232), d, target, 2)
			prior, _ := preparePrivateGeneratedReservation(t, env, s, reservationInput, reservationCanonical)
			producer, expected := preparePrivateGeneratedProducer(t, env, s, prior, nil)
			var packet []byte
			if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
				var code contract.CryptoResultCode
				packet, _, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("controlled producer handoff")
			}
			entered, result := s.selectCandidate(ctx, producer.reservation.candidate)
			if entered == nil || result.Outcome != ObservedCurrent || len(packet) == 0 {
				t.Fatal("controlled exact ACK", result)
			}
			env.Custody.RetireGenerated()
			plan, err := entered.generatedRecordRequest(context.Background(), expected.Template.AttemptID, packet, generatedPlanInputFixture(t, entered).context)
			if err != nil {
				t.Fatal(err)
			}
			record := preparePrivateGeneratedRecord(t, env, entered, plan)
			recorded, result := entered.selectCandidate(ctx, record.reservation.candidate)
			if recorded == nil || result.Outcome != ObservedCurrent {
				t.Fatal("record", result)
			}
			env.Custody.RetireGenerated()
			recorded = generatedLifecycleReopen(t, ctx, recorded, env.Store)
			work, err := recorded.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			d, err = contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{10, d.DutyID}].Body)
			if err != nil || d.Progress.Count != 1 || d.Step != 2 || recorded.root.Generated.Retiring != 1 {
				t.Fatal("nonfinal ACK did not retain proved progress and retiring slot", d.Step, d.Progress.Count, err)
			}
			parked := selectControlledRetirementClose(t, ctx, env, recorded, expected.Template.AttemptID)
			if parked.root.Generated.SuccessWindow != recorded.root.Generated.SuccessWindow || parked.root.Generated.FailureWindow != recorded.root.Generated.FailureWindow || parked.root.Generated.ReceiptOrder != recorded.root.Generated.ReceiptOrder {
				t.Fatal("nonfinal parking changed terminal receipt windows")
			}
			if !parked.root.Generated.ActiveOwner.IsZero() || parked.root.Generated.Retiring != 1 || parked.valueEntry(0).Generated.RetiringDutyID != d.DutyID {
				t.Fatal("ACK closed stronger obligation")
			}
			for _, row := range parked.supportRecords() {
				if row.Kind == 12 {
					t.Fatal("nonfinal ACK released original")
				}
			}
			checkFreshGeneratedProcess(t, env.Store.(*memoryStore), parked)
			f.session = parked
			a := &generatedActualOperation{env: env, fixture: f}
			env = selectActualGeneratedLoss(t, a, generatedActualLoss{name: "controlled-authority-kek", operation: 1, approval: contract.NormalSigningRole, mask: 2})
			parked = a.fixture.session
			work, err = parked.selectedGeneratedWork(ctx)
			if err != nil {
				t.Fatal(err)
			}
			d, err = contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{10, d.DutyID}].Body)
			if err != nil {
				t.Fatal(err)
			}
			progress, err := work.controlledRetirementProgress(d, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			input, inputCanonical := generatedDeletePlanInput(t, parked, generatedVectorID(233), d, target, 2)
			scope := contract.GeneratorControlledRetirementScope(d.DescriptorID, d.ConfigContractID, d.ResultContractID)
			input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(d.DomainID, d.ResourceID, target.ResourceDigest, scope, progress.ack.record.ResultID, contract.Hash(progress.ack.result))
			checkControlledReservationRefusals(t, env, parked, input, d, target)
			responder := custody.NewControlledRetirementResponder(d.ResourceID, target.ResourceDigest, scope)
			defer responder.Close()
			responder.DeleteExact(target.ResourceDigest)
			prior, _ = preparePrivateGeneratedReservation(t, env, parked, input, inputCanonical)
			checkControlledProducerRefusals(t, env, parked, prior)
			probes := 0
			producer, second := preparePrivateGeneratedProducerProbe(t, env, parked, prior, custody.StandardValue, nil, func(ctx context.Context, c contract.GeneratedProducerCommand) []byte {
				probes++
				return responder.Probe(ctx, c)
			})
			packet = nil
			if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
				var code contract.CryptoResultCode
				packet, _, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("probe handoff")
			}
			entered, result = parked.selectCandidate(ctx, producer.reservation.candidate)
			if entered == nil || result.Outcome != ObservedCurrent || len(packet) == 0 || probes != 1 {
				t.Fatal("exact controlled probe", result, probes)
			}
			env.Custody.RetireGenerated()
			plan, err = entered.generatedRecordRequest(context.Background(), second.Template.AttemptID, packet, generatedPlanInputFixture(t, entered).context)
			if err != nil {
				t.Fatal("confirmation record request", err)
			}
			if _, err := entered.deriveGeneratedRecord(ctx, plan); err != nil {
				t.Fatal("second exact derive", err)
			}
			record = preparePrivateGeneratedRecord(t, env, entered, plan)
			recorded, result = entered.selectCandidate(ctx, record.reservation.candidate)
			if recorded == nil || result.Outcome != ObservedCurrent {
				t.Fatal("confirmation record", result)
			}
			env.Custody.RetireGenerated()
			live, err := recorded.inspectGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if rows := live.dutyProgress[d.DutyID]; len(rows) != 2 || rows[0][111] != 1 || rows[1][111] != 3 {
				t.Fatal("live ordered inspection lost semantic step order", rows)
			}
			beforeFinal, err := recorded.receiptWindows(ctx)
			if err != nil {
				t.Fatal("controlled final-close predecessor receipt order", err)
			}
			closed := selectControlledRetirementClose(t, ctx, env, recorded, second.Template.AttemptID)
			afterFinal, err := closed.receiptWindows(ctx)
			if err != nil {
				t.Fatal("controlled final-close selected receipt order", err)
			}
			assertSuccessReceiptOrder(t, beforeFinal, afterFinal, second.Plan.OperationID)
			if closed.root.Generated.Retiring != 0 || !closed.valueEntry(0).Generated.RetiringDutyID.IsZero() {
				t.Fatal("qualified confirmation retained slot")
			}
			work, err = closed.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("final history reopen", err)
			}
			if _, present := work.records[generatedRecordKey{10, d.DutyID}]; present || len(work.releases) != 2 {
				t.Fatal("not every exact original released", present, len(work.releases))
			}
			for _, material := range []contract.ID{progress.ack.material.Core.OperationMaterialID, second.Plan.MaterialID} {
				if _, present := work.records[generatedRecordKey{1, material}]; present {
					t.Fatal("dead original seed retained for display", material)
				}
				if _, present := closed.materialAccess(3, material); present {
					t.Fatal("dead original seed access retained", material)
				}
			}
			for _, id := range []contract.ID{expected.Template.AttemptID, second.Template.AttemptID} {
				if _, present := work.attempts[id]; present {
					t.Fatal("final original still adoptable", id)
				}
				if _, present := work.releases[id]; !present {
					t.Fatal("original mapping missing", id)
				}
			}
			inspection, err := closed.inspectGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			masks := map[contract.ID]uint8{}
			ceilings := map[contract.ID]uint16{}
			for _, e := range inspection.effects {
				if e.attempt.OwnerID != d.DutyID {
					continue
				}
				ceilings[e.attempt.AttemptID] = e.evidenceCeiling
				if len(e.progress) == 0 {
					t.Fatal("historical ordered progress lost", e.attempt.AttemptID)
				}
				if e.progress[0][111] != 1 || e.attempt.AttemptID == second.Template.AttemptID && (len(e.progress) != 2 || e.progress[1][111] != 3) {
					t.Fatal("released inspection is not in semantic step order", e.progress)
				}
				for _, row := range e.progress {
					p, err := contract.InspectGeneratorProgress(row)
					if err != nil {
						t.Fatal(err)
					}
					if p.CompletedSteps > masks[e.attempt.AttemptID] {
						masks[e.attempt.AttemptID] = p.CompletedSteps
					}
				}
			}
			if masks[expected.Template.AttemptID] != 1 || masks[second.Template.AttemptID] != 3 || ceilings[expected.Template.AttemptID] != contract.ReceiptEvidenceAcknowledged || ceilings[second.Template.AttemptID] != contract.ReceiptEvidenceConfirmed {
				t.Fatal("historical evidence upgraded or lost", masks, ceilings)
			}
			checkFreshGeneratedProcess(t, env.Store.(*memoryStore), closed)
		})
	}
}

// full_only: false
func TestGeneratedControlledDeleteSourceRequiresCompleteSelectedSupport(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, s, d, target := controlledParkedAcknowledgement(t, recovery)
			g := mustSelectedGeneratedWork(t, s)
			progress, err := g.controlledRetirementProgress(d, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			input, inputCanonical := generatedDeletePlanInput(t, s, generatedVectorID(233), d, target, 2)
			input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(d.DomainID, d.ResourceID, target.ResourceDigest,
				contract.GeneratorControlledRetirementScope(d.DescriptorID, d.ConfigContractID, d.ResultContractID), progress.ack.record.ResultID, contract.Hash(progress.ack.result))
			plan, err := s.generatedPlanRequest(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			graph, err := contract.EncodeGeneratorPlanBundle(input.graph)
			if err != nil {
				t.Fatal(err)
			}
			public, err := s.publicProjection()
			if err != nil {
				t.Fatal(err)
			}
			predecessor := generatedControlledPredecessorInput(t, s, g, d)
			predecessor.Source = g.records[generatedRecordKey{10, d.DutyID}]
			predecessor.BeforeRecords = nil
			pub, priv := env.Custody.Calls()
			store := env.Store.(*memoryStore)
			creates, cas := store.creates, store.cas
			currentIntents := generatedCurrentIntentInputs(t.Context(), t, s, graph, input.declaration)
			if err := env.Custody.AdmitGeneratedControlledDeletePlan(plan.request, currentControlOf(s),
				custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: generatedControlledOutputWitness(t, s, public, nil)},
				custody.GeneratedPlanInput{Declaration: input.declaration, Canonical: inputCanonical, CurrentIntents: currentIntents}, *plan.phase, target, predecessor, time.Unix(0, int64(plan.request.Context.Expiry))); err == nil {
				t.Fatal("caller source without complete selected support admitted")
			}
			if p, k := env.Custody.Calls(); p != pub || k != priv || store.creates != creates || store.cas != cas {
				t.Fatal("missing selected source view reached key route or writes")
			}
		})
	}
}

// full_only: false
func TestGeneratedControlledSelectedAckStoreDamageRefusesColdReopen(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, s, d, _ := controlledParkedAcknowledgement(t, recovery)
			work := mustSelectedGeneratedWork(t, s)
			progress, err := work.controlledRetirementProgress(d, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			ack := progress.ack
			r, err := contract.InspectGeneratedResultRecord(ack.result)
			if err != nil || len(r.Payload.Ciphertext) == 0 {
				t.Fatal("actual selected ACK ciphertext", err)
			}
			store := env.Store.(*memoryStore)
			damaged := false
			for _, ref := range s.root.RequiredSupport {
				key, err := format.Key(store.desc.Prefix, ref)
				if err != nil {
					t.Fatal(err)
				}
				object := store.objects[key]
				if !bytes.Contains(object.Body, ack.result) {
					continue
				}
				if damaged || bytes.Count(object.Body, r.Payload.Ciphertext) != 1 {
					t.Fatal("selected ACK is not unique immutable backing")
				}
				object.Body = bytes.Clone(object.Body)
				at := bytes.Index(object.Body, r.Payload.Ciphertext)
				object.Body[at] ^= 1
				store.objects[key] = object
				damaged = true
			}
			if !damaged {
				t.Fatal("actual selected ACK backing not found")
			}
			pub, priv := env.Custody.Calls()
			creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).signs
			cold, result := Open(context.Background(), OpenContext{admission: &s.admission}, store)
			if cold != nil || result != failure(IntegrityFailure, InvalidReference) {
				t.Fatal("damaged immutable selected ACK reopened", result)
			}
			if p, k := env.Custody.Calls(); p != pub || k != priv || store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).signs != signs {
				t.Fatal("stored-byte damage reached key route, K2 or writes")
			}
		})
	}
}

func checkControlledProducerRefusals(t *testing.T, env fixtureEnvironment, s *StateSession, prior *generatedPreparation) {
	t.Helper()
	keys := env.Custody
	keys.RetireGenerated()
	admitted := prior.operation.context
	admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = testID("controlled probe refusal admission"), testID("controlled probe refusal session"), contract.DescriptorVector{}
	q, preparation, err := s.generatedProducerRequest(context.Background(), prior, admitted)
	if err != nil {
		t.Fatal(err)
	}
	g, err := prior.reservation.state.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[g.phase.FrontierAttemptID]
	input := generatedProducerInput(env.operationContext(), t, s, g, a.record.AttemptID)
	input.Phase = prior.producerPhase
	input.Preparation = preparation
	input.Attempt = a.record
	input.Duty, err = contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, a.record.OwnerID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	input.Intent, err = g.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, a.expected.Template.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	input.Progress, err = g.vectors.resolve(10, input.Duty.DutyID, contract.GeneratorVectorProgress, input.Duty.Progress)
	if err != nil {
		t.Fatal(err)
	}
	input.Consumers, err = g.vectors.resolve(10, input.Duty.DutyID, contract.GeneratorVectorConsumers, input.Duty.Consumers)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv := keys.Calls()
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	probes := 0
	for _, kind := range []string{"ordinary ACK Return", "tampered probe transcript", "missing predecessor"} {
		bad := input
		if kind != "ordinary ACK Return" {
			bad.Probe = func(context.Context, contract.GeneratedProducerCommand) []byte { probes++; return nil }
		}
		if kind == "tampered probe transcript" {
			bad.Preparation.RequestDigest = generatedVectorID(242)
		}
		if kind == "missing predecessor" {
			bad.ControlledPredecessor = nil
		}
		if err := keys.AdmitGeneratedProducer(q, currentControlOf(s), bad, custody.StandardValue, time.Unix(0, int64(q.Context.Expiry))); err == nil {
			t.Fatal("Step2 admitted unqualified remaining-step path", kind)
		}
		if p, k := keys.Calls(); p != pub || k != priv || store.creates != creates || store.cas != cas || probes != 0 {
			t.Fatal("Step2 invalid admission reached key use/probe/write", kind)
		}
	}
}

func checkControlledReservationRefusals(t *testing.T, env fixtureEnvironment, s *StateSession, input generatedPlanInput, d contract.GeneratedDutyRecord, target contract.GeneratorTarget) {
	t.Helper()
	keys := env.Custody
	g, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.generatedPlanRequest(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := contract.EncodeGeneratorPlanBundle(input.graph)
	if err != nil {
		t.Fatal(err)
	}
	public, err := s.publicProjection()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Unix(0, int64(plan.request.Context.Expiry))
	pub, priv := keys.Calls()
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	currentIntents := generatedCurrentIntentInputs(t.Context(), t, s, graph, input.declaration)
	if err := keys.AdmitGeneratedDeletePlan(plan.request, currentControlOf(s),
		custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: generatedControlledOutputWitness(t, s, public, nil)},
		custody.GeneratedPlanInput{Declaration: input.declaration, CurrentIntents: currentIntents}, *plan.phase, target, deadline); err == nil {
		t.Fatal("generic reservation omitted private immutable Duty/predecessor witness")
	}
	currentIntents = generatedCurrentIntentInputs(t.Context(), t, s, graph, input.declaration)
	if err := keys.AdmitGeneratedPlan(plan.request, currentControlOf(s),
		custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: generatedControlledOutputWitness(t, s, public, nil)},
		custody.GeneratedPlanInput{Declaration: input.declaration, CurrentIntents: currentIntents}, deadline); err == nil {
		t.Fatal("generic initial plan omitted stronger standalone witness/target")
	}
	if p, k := keys.Calls(); p != pub || k != priv || store.creates != creates || store.cas != cas {
		t.Fatal("omitted witness reached key route or write")
	}
	predecessor := generatedControlledPredecessorInput(t, s, g, d)
	for _, name := range []string{"unmatched packet digest", "changed scope", "changed class", "changed ordered step"} {
		bad := predecessor
		bad.Result = bytes.Clone(predecessor.Result)
		duty, err := contract.InspectGeneratedDutyRecord(bad.Source.Body)
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case "unmatched packet digest":
			bad.Result[len(bad.Result)-1] ^= 1
		case "changed scope":
			duty.ResourceContractID = generatedVectorID(240)
		case "changed class":
			duty.CompletionClass = contract.GeneratedCompletionAcknowledged
		case "changed ordered step":
			duty.Step = 1
		}
		bad.Source.Body, err = contract.EncodeGeneratedDutyRecord(duty)
		if err != nil {
			t.Fatal(err)
		}
		currentIntents := generatedCurrentIntentInputs(t.Context(), t, s, graph, input.declaration)
		if err := keys.AdmitGeneratedControlledDeletePlan(plan.request, currentControlOf(s),
			custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: generatedControlledOutputWitness(t, s, public, nil)},
			custody.GeneratedPlanInput{Declaration: input.declaration, CurrentIntents: currentIntents}, *plan.phase, target, bad, deadline); err == nil {
			t.Fatal("invalid private witness admitted", name)
		}
		if p, k := keys.Calls(); p != pub || k != priv || store.creates != creates || store.cas != cas {
			t.Fatal("invalid witness reached K2 or writes", name)
		}
	}
	bad := input
	bad.requestBindings = slices.Clone(input.requestBindings)
	bad.requestBindings[0].Digest = generatedVectorID(241)
	if _, err := s.generatedPlanRequest(t.Context(), bad); err == nil {
		t.Fatal("arbitrary probe request digest admitted")
	}
	if p, k := keys.Calls(); p != pub || k != priv || store.creates != creates || store.cas != cas {
		t.Fatal("probe digest damage reached key route or write")
	}
	checkControlledPredecessorDamagedAEAD(t, t.Context(), env, s, plan, graph, public, target, predecessor)
}

func checkControlledPredecessorDamagedAEAD(t *testing.T, operationCtx context.Context, env fixtureEnvironment, s *StateSession, plan *generatedPlan, graph []byte, public contract.PublicState, target contract.GeneratorTarget, predecessor custody.GeneratedControlledPredecessor) {
	t.Helper()
	s = generatedLifecycleReopen(t, operationCtx, s, env.Store)
	input := plan.input
	input.context.AdmissionID, input.context.SessionID, input.context.IntentDescriptor = testID("damaged controlled predecessor admission"), testID("damaged controlled predecessor session"), contract.DescriptorVector{}
	var err error
	plan, err = s.generatedPlanRequest(t.Context(), input)
	if err != nil {
		t.Fatal("fresh damaged predecessor context", err)
	}
	bad := predecessor
	r, err := contract.DecodeGeneratedResultRecord(predecessor.Result)
	if err != nil || len(r.Payload.Ciphertext) == 0 {
		t.Fatal("original ACK ciphertext", err)
	}
	r.Payload.Ciphertext = bytes.Clone(r.Payload.Ciphertext)
	r.Payload.Ciphertext[len(r.Payload.Ciphertext)-1] ^= 1
	bad.Result, err = contract.EncodeGeneratedResultRecord(r)
	if err != nil || contract.ValidateGeneratedResult(bad.Expected, bad.Material, r) != nil {
		t.Fatal("damaged AEAD must retain exact public framing", err)
	}
	progress, err := contract.EncodeGeneratorProgress(contract.GeneratorProgress{Schema: 1, AttemptID: r.Core.AttemptID, ResultID: r.Core.ResultID,
		Evidence: contract.GeneratorDescriptor{Digest: contract.Hash(bad.Result), Length: uint64(len(bad.Result)), Count: 1}, RequiredSteps: 2, CompletedSteps: 1, CompletionClass: contract.GeneratedCompletionConfirmed})
	if err != nil {
		t.Fatal(err)
	}
	d, err := contract.InspectGeneratedDutyRecord(bad.Source.Body)
	if err != nil {
		t.Fatal(err)
	}
	d.Progress, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorProgress, [][]byte{progress})
	if err != nil {
		t.Fatal(err)
	}
	duty, err := contract.EncodeGeneratedDutyRecord(d)
	if err != nil {
		t.Fatal(err)
	}
	phase := *plan.phase
	bad.Source.Body = duty
	phase.Evidence, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseDuties, d.DomainID, []contract.SupportRecord{{Kind: 10, RecordID: d.DutyID, Body: duty}})
	if err != nil {
		t.Fatal(err)
	}
	keys := env.Custody
	deadline := time.Unix(0, int64(plan.request.Context.Expiry))
	pub, priv := keys.Calls()
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	currentIntents := generatedCurrentIntentInputs(t.Context(), t, s, graph, plan.input.declaration)
	if err := keys.AdmitGeneratedControlledDeletePlan(plan.request, currentControlOf(s),
		custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: generatedControlledOutputWitness(t, s, public, nil)},
		custody.GeneratedPlanInput{Declaration: plan.input.declaration, CurrentIntents: currentIntents}, phase, target, bad, deadline); err == nil {
		t.Fatal("caller-only damaged ACK subset admitted without selected history")
	}
	if p, k := keys.Calls(); p != pub || k != priv || store.creates != creates || store.cas != cas {
		t.Fatal("caller-only damaged ACK reached seed open, K2 or writes")
	}
	// This second negative is descriptor-complete trusted private-parent
	// malformed-input evidence, not selected-store proof: the stored root/HEAD
	// still pins the original support. Keep source identities, graph, material,
	// facts and readers, and rebind every affected full vector/public descriptor
	// to test Crypto's separate ACK AEAD authentication before K2 or writes.
	bad.BeforeRecords = slices.Clone(predecessor.BeforeRecords)
	type vectorKey struct {
		kind   uint8
		id     contract.ID
		vector contract.GeneratorVectorKind
	}
	vectors := make(map[vectorKey][]contract.GeneratorVectorCarrier)
	for i, row := range bad.BeforeRecords {
		if row.Kind == 4 && row.RecordID == r.Core.ResultID {
			bad.BeforeRecords[i].Body = bytes.Clone(bad.Result)
		}
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		c, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		switch c.VectorKind {
		case contract.GeneratorVectorHistory:
			h, err := contract.InspectGeneratorHistory(c.Row)
			if err != nil {
				t.Fatal(err)
			}
			if h.ResultID == r.Core.ResultID {
				h.ResultDigest = contract.Hash(bad.Result)
				c.Row, err = contract.EncodeGeneratorHistory(h)
				if err != nil {
					t.Fatal(err)
				}
			}
		case contract.GeneratorVectorProgress:
			p, err := contract.InspectGeneratorProgress(c.Row)
			if err != nil {
				t.Fatal(err)
			}
			if p.ResultID == r.Core.ResultID {
				p.Evidence.Digest, p.Evidence.Length = contract.Hash(bad.Result), uint64(len(bad.Result))
				c.Row, err = contract.EncodeGeneratorProgress(p)
				if err != nil {
					t.Fatal(err)
				}
			}
		default:
			continue
		}
		key := vectorKey{c.OwnerKind, c.OwnerID, c.VectorKind}
		vectors[key] = append(vectors[key], c)
	}
	descriptors := make(map[vectorKey]contract.GeneratorDescriptor)
	for key, carriers := range vectors {
		slices.SortFunc(carriers, func(a, b contract.GeneratorVectorCarrier) int { return int(a.Ordinal) - int(b.Ordinal) })
		rows := make([][]byte, len(carriers))
		for i, c := range carriers {
			rows[i] = c.Row
		}
		descriptor, err := contract.GeneratorVectorDescriptor(key.vector, rows)
		if err != nil {
			t.Fatal(err)
		}
		descriptors[key] = descriptor
		for _, c := range carriers {
			old := c
			// Find the old carrier by its exact owner/vector ordinal. The
			// revised row may no longer have its old content-derived ID.
			for i, row := range bad.BeforeRecords {
				if row.Kind != contract.GeneratorVectorSupportKind {
					continue
				}
				prior, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if prior.OwnerKind == old.OwnerKind && prior.OwnerID == old.OwnerID && prior.VectorKind == old.VectorKind && prior.Ordinal == old.Ordinal {
					c.Vector = descriptor
					body, err := contract.EncodeGeneratorVectorCarrier(c)
					id, idErr := contract.GeneratorVectorCarrierID(c)
					if err != nil || idErr != nil {
						t.Fatal(err, idErr)
					}
					bad.BeforeRecords[i] = contract.SupportRecord{Kind: row.Kind, RecordID: id, Body: body}
					break
				}
			}
		}
	}
	for i, row := range bad.BeforeRecords {
		if row.Kind == 9 {
			attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if descriptor, ok := descriptors[vectorKey{9, attempt.AttemptID, contract.GeneratorVectorHistory}]; ok {
				attempt.History = descriptor
			}
			if descriptor, ok := descriptors[vectorKey{9, attempt.AttemptID, contract.GeneratorVectorProgress}]; ok {
				attempt.Progress = descriptor
			}
			bad.BeforeRecords[i].Body, err = contract.EncodeGeneratedAttemptRecord(attempt)
			if err != nil {
				t.Fatal(err)
			}
		} else if row.Kind == 10 && row.RecordID == d.DutyID {
			d.History = descriptors[vectorKey{10, d.DutyID, contract.GeneratorVectorHistory}]
			d.Progress = descriptors[vectorKey{10, d.DutyID, contract.GeneratorVectorProgress}]
			bad.Source.Body, err = contract.EncodeGeneratedDutyRecord(d)
			if err != nil {
				t.Fatal(err)
			}
			bad.BeforeRecords[i].Body = bad.Source.Body
		}
	}
	slices.SortFunc(bad.BeforeRecords, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	public.RequiredSupport, err = contract.RequiredSupportDescriptor(d.DomainID, bad.BeforeRecords)
	if err != nil {
		t.Fatal(err)
	}
	phase.Evidence, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseDuties, d.DomainID, []contract.SupportRecord{bad.Source})
	if err != nil {
		t.Fatal(err)
	}
	currentIntents = generatedCurrentIntentInputs(t.Context(), t, s, graph, plan.input.declaration)
	if err := keys.AdmitGeneratedControlledDeletePlan(plan.request, currentControlOf(s),
		custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: generatedControlledOutputWitness(t, s, public, bad.BeforeRecords)},
		custody.GeneratedPlanInput{Declaration: plan.input.declaration, CurrentIntents: currentIntents}, phase, target, bad, deadline); err != nil {
		t.Fatal("complete private-parent malformed ACK input refused before authentication", err)
	}
	defer keys.RetireGenerated()
	control := currentControlOf(s)
	compared := &changedCryptoReply{inner: keys.Crypto(), kind: contract.CryptoCompare, change: func(reply contract.CryptoResponse) contract.CryptoResponse {
		if reply.ResultCode != contract.CryptoStoredAuthenticationFailed || len(reply.Body) != 0 || len(reply.KeyUseRows) != 1 ||
			reply.KeyUseRows[0].BindingID != control.AuthorityKMSBinding.BindingID || reply.KeyUseRows[0].SubjectID != control.AuthorityRecipientID ||
			reply.KeyUseRows[0].Purpose != contract.KeyUseMaterialOpen || reply.KeyUseRows[0].Outcome != contract.KeyUseCompleted || reply.KeyUseRows[0].Count != 1 {
			t.Fatal("damaged predecessor must fail actual authentication after exactly one seed open", reply.ResultCode, reply.KeyUseRows)
		}
		return reply
	}}
	permit := &admittedGeneratedPlan{session: s, plan: plan, crypto: compared, instance: compared.InstanceID(), deadline: deadline}
	spy := &scenarioSpy{}
	creates, cas = store.creates, store.cas
	pub, priv = keys.Calls()
	prepared, result := s.PrepareGeneratedPlan(context.Background(), permit)
	if prepared != nil || result != failure(IntegrityFailure, InvalidProof) || compared.calls != 1 || store.creates != creates || store.cas != cas {
		t.Fatal("damaged predecessor reached new reserve/probe authority, K2 or writes", result)
	}
	if candidate, result := s.ClaimGeneratedPreparation(context.Background(), nil, scenarioTrust{Trust: env.Trust, spy: spy}); candidate != nil || result != refused(AdmissionInvalid) || spy.TrustSign != 0 || store.creates != creates || store.cas != cas {
		t.Fatal("failed authentication allowed a subsequent K2 claim or writes", result, spy.TrustSign)
	}
	if p, k := keys.Calls(); p != pub || k != priv+1 {
		t.Fatal("damaged predecessor did not use exactly its current-authority seed open")
	}
}

func selectControlledRetirementClose(t *testing.T, operationCtx context.Context, env fixtureEnvironment, s *StateSession, attempt contract.ID) *StateSession {
	t.Helper()
	ctx := context.Background()
	permit, err := s.admitGeneratedRetirementClose(ctx, attempt, generatedPlanInputFixture(t, s).context)
	if err != nil {
		t.Fatal("controlled close admission", err)
	}
	candidate, result := s.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("controlled close preparation", result)
	}
	next, result := s.selectCandidate(ctx, candidate)
	if next == nil || result.Outcome != ObservedCurrent {
		t.Fatal("controlled close selection", result)
	}
	return generatedLifecycleReopen(t, operationCtx, next, env.Store)
}

func controlledParkedAcknowledgement(t *testing.T, recovery bool) (fixtureEnvironment, *StateSession, contract.GeneratedDutyRecord, contract.GeneratorTarget) {
	t.Helper()
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, recovery)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	p := defaultGeneratedFixtureProfile()
	p.CompletionClass = contract.GeneratedCompletionConfirmed
	s := selectPrivateGeneratedOperation(t, env, f.session, generatedPlanInputForGenerations(t, f.session, generatedVectorID(230), []string{"generated"}, p), "controlled original")
	old := *s.valueEntry(0)
	s = selectPrivateGeneratedOperation(t, env, s, generatedStatePlanInput(t, s, generatedVectorID(231), []string{old.Name}, p, old.Generated.Epoch+1, map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), "controlled rotation")
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, s.valueEntry(0).Generated.RetiringDutyID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	target, err := g.retirementTarget(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	input, inputCanonical := generatedDeletePlanInput(t, s, generatedVectorID(232), d, target, 2)
	// Even Step1 must not omit the private immutable Duty witness.
	plan, err := s.generatedPlanRequest(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := contract.EncodeGeneratorPlanBundle(input.graph)
	if err != nil {
		t.Fatal(err)
	}
	public, err := s.publicProjection()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv := env.Custody.Calls()
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	currentIntents := generatedCurrentIntentInputs(t.Context(), t, s, graph, input.declaration)
	if err := env.Custody.AdmitGeneratedDeletePlan(plan.request, currentControlOf(s),
		custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: generatedControlledOutputWitness(t, s, public, nil)},
		custody.GeneratedPlanInput{Declaration: input.declaration, Canonical: inputCanonical, CurrentIntents: currentIntents}, *plan.phase, target, time.Unix(0, int64(plan.request.Context.Expiry))); err == nil {
		t.Fatal("Step1 omitted Duty witness admitted")
	}
	if p, k := env.Custody.Calls(); p != pub || k != priv || store.creates != creates || store.cas != cas {
		t.Fatal("Step1 omission reached key route/writes")
	}
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, inputCanonical)
	producer, expected := preparePrivateGeneratedProducer(t, env, s, prior, nil)
	var packet []byte
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		var code contract.CryptoResultCode
		packet, _, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("ACK handoff")
	}
	entered, result := s.selectCandidate(ctx, producer.reservation.candidate)
	if entered == nil || result.Outcome != ObservedCurrent || len(packet) == 0 {
		t.Fatal("ACK selection", result)
	}
	env.Custody.RetireGenerated()
	recordPlan, err := entered.generatedRecordRequest(context.Background(), expected.Template.AttemptID, packet, generatedPlanInputFixture(t, entered).context)
	if err != nil {
		t.Fatal(err)
	}
	record := preparePrivateGeneratedRecord(t, env, entered, recordPlan)
	recorded, result := entered.selectCandidate(ctx, record.reservation.candidate)
	if recorded == nil || result.Outcome != ObservedCurrent {
		t.Fatal("ACK record", result)
	}
	env.Custody.RetireGenerated()
	s = selectControlledRetirementClose(t, ctx, env, recorded, expected.Template.AttemptID)
	g, err = s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d, err = contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, d.DutyID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	return env, s, d, target
}

// full_only: false
func TestGeneratedControlledAckThenUnknownProbeTransfersResidue(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, s, duty, target := controlledParkedAcknowledgement(t, recovery)
			g := mustSelectedGeneratedWork(t, s)
			progress, err := g.controlledRetirementProgress(duty, nil, true)
			if err != nil || len(progress.rows) != 1 {
				t.Fatal("selected ACK prefix", err)
			}
			scope := contract.GeneratorControlledRetirementScope(duty.DescriptorID, duty.ConfigContractID, duty.ResultContractID)
			input, inputCanonical := generatedDeletePlanInput(t, s, generatedVectorID(235), duty, target, 2)
			input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(duty.DomainID, duty.ResourceID, target.ResourceDigest,
				scope, progress.ack.record.ResultID, contract.Hash(progress.ack.result))
			prior, _ := preparePrivateGeneratedReservation(t, env, s, input, inputCanonical)
			responder := custody.NewControlledRetirementResponder(duty.ResourceID, target.ResourceDigest, scope)
			defer responder.Close()
			producer, unknown := preparePrivateGeneratedProducerProbe(t, env, s, prior, custody.StandardValue, nil,
				func(ctx context.Context, command contract.GeneratedProducerCommand) []byte {
					return responder.ProbeWithWrongCredential(ctx, command)
				})
			var packet []byte
			var facts contract.GeneratorSafeFacts
			if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
				var code contract.CryptoResultCode
				packet, facts, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("unknown probe handoff")
			}
			entered, result := s.selectCandidate(context.Background(), producer.reservation.candidate)
			if entered == nil || result.Outcome != ObservedCurrent || len(packet) != 0 || facts.Disposition != contract.GeneratorDispositionUnknown {
				t.Fatal("unknown probe selection", result, facts.Disposition)
			}
			env.Custody.RetireGenerated()
			body, err := contract.EncodeGeneratorSafeFacts(facts)
			if err != nil {
				t.Fatal(err)
			}
			permit, err := entered.admitGeneratedActiveRetirementResidue(context.Background(), duty.DutyID, body, generatedPlanInputFixture(t, entered).context)
			if err != nil {
				t.Fatal("controlled residue plan", err)
			}
			candidate, prepared := entered.PrepareGeneratedLifecycle(context.Background(), permit, env.Trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("controlled residue preparation", prepared)
			}
			residue, selected := entered.selectCandidate(context.Background(), candidate)
			if residue == nil || selected.Outcome != ObservedCurrent {
				t.Fatal("controlled residue selection", selected)
			}
			residue = generatedLifecycleReopen(t, t.Context(), residue, env.Store)
			work := mustSelectedGeneratedWork(t, residue)
			source, err := work.generatedDeleteSource(duty.DutyID)
			if err != nil || source.Record.Kind != 11 || source.Hazard.OriginalResults.Count != 1 {
				t.Fatal("residue lost selected earlier ACK", err)
			}
			got, err := work.controlledDeleteSourceProgress(source, nil, true)
			if err != nil || len(got.rows) != 1 || got.ack.record.ResultID != progress.ack.record.ResultID {
				t.Fatal("residue changed historical ACK progress", err)
			}
			fresh, freshCanonical := generatedDeletePlanInputForSource(t, residue, generatedVectorID(236), source.Record, target)
			freshTemplate := fresh.graph.Lineages[0].Templates[0]
			freshScope := contract.GeneratorControlledRetirementScope(source.DescriptorID, source.ConfigContractID, freshTemplate.ResultContractID)
			fresh.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(source.DomainID, source.ResourceID, target.ResourceDigest,
				freshScope, got.ack.record.ResultID, contract.Hash(got.ack.result))
			env.Custody.RetireGenerated()
			freshPrior, _ := preparePrivateGeneratedReservation(t, env, residue, fresh, freshCanonical)
			responder.DeleteExact(target.ResourceDigest)
			confirmed, _, final, finalPacket := selectActualGeneratedPacketRecord(t, env, residue, freshPrior, custody.StandardValue, true,
				func(ctx context.Context, command contract.GeneratedProducerCommand) []byte {
					return responder.Probe(ctx, command)
				})
			if len(finalPacket) == 0 {
				t.Fatal("remaining confirmation missing")
			}
			env.Custody.RetireGenerated()
			closed := selectOrdinaryGeneratedCleanupClose(t, t.Context(), env, confirmed, final.Template.AttemptID)
			closed = generatedLifecycleReopen(t, t.Context(), closed, env.Store)
			released := mustSelectedGeneratedWork(t, closed).releases[unknown.Template.AttemptID]
			if released.release.State != contract.GeneratedReleaseUnobserved ||
				released.attempt.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) ||
				released.attempt.History.Count != 1 || released.attempt.Facts.Count != 1 {
				t.Fatal("unobserved probe retained live progress or lost unknown history")
			}
		})
	}
}

// full_only: false
func TestGeneratedControlledReleaseClearsTwoUnobservedProbePrefixes(t *testing.T) {
	env, s, duty, target := controlledParkedAcknowledgement(t, false)
	scope := contract.GeneratorControlledRetirementScope(duty.DescriptorID, duty.ConfigContractID, duty.ResultContractID)
	responder := custody.NewControlledRetirementResponder(duty.ResourceID, target.ResourceDigest, scope)
	defer responder.Close()
	var unknown []contract.ID
	for i := 0; i < 2; i++ {
		g := mustSelectedGeneratedWork(t, s)
		progress, err := g.controlledRetirementProgress(duty, nil, true)
		if err != nil || len(progress.rows) != 1 {
			t.Fatal("ACK progress before unknown probe", err)
		}
		input, inputCanonical := generatedDeletePlanInput(t, s, generatedVectorID(uint8(237+i)), duty, target, 2)
		input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(duty.DomainID, duty.ResourceID, target.ResourceDigest,
			scope, progress.ack.record.ResultID, contract.Hash(progress.ack.result))
		prior, _ := preparePrivateGeneratedReservation(t, env, s, input, inputCanonical)
		producer, expected := preparePrivateGeneratedProducerProbe(t, env, s, prior, custody.StandardValue, nil,
			func(ctx context.Context, command contract.GeneratedProducerCommand) []byte {
				return responder.ProbeWithWrongCredential(ctx, command)
			})
		var packet []byte
		var facts contract.GeneratorSafeFacts
		if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
			var code contract.CryptoResultCode
			packet, facts, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
			return code
		}) {
			t.Fatal("unknown confirmation handoff")
		}
		entered, selected := s.selectCandidate(context.Background(), producer.reservation.candidate)
		if entered == nil || selected.Outcome != ObservedCurrent || len(packet) != 0 || facts.Disposition != contract.GeneratorDispositionUnknown {
			t.Fatal("unknown confirmation selection", selected)
		}
		env.Custody.RetireGenerated()
		body, err := contract.EncodeGeneratorSafeFacts(facts)
		if err != nil {
			t.Fatal(err)
		}
		permit, err := entered.admitGeneratedRetirementUnknown(context.Background(), duty.DutyID, body, generatedPlanInputFixture(t, entered).context)
		if err != nil {
			t.Fatal(err)
		}
		candidate, prepared := entered.PrepareGeneratedLifecycle(context.Background(), permit, env.Trust)
		if candidate == nil || prepared.Outcome != ObservedCurrent {
			t.Fatal("unknown confirmation park", prepared)
		}
		s, selected = entered.selectCandidate(context.Background(), candidate)
		if s == nil || selected.Outcome != ObservedCurrent {
			t.Fatal("unknown confirmation selection", selected)
		}
		s = generatedLifecycleReopen(t, t.Context(), s, env.Store)
		g = mustSelectedGeneratedWork(t, s)
		duty, err = contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, duty.DutyID}].Body)
		if err != nil || duty.Progress.Count != 1 {
			t.Fatal("park lost selected ACK", err)
		}
		unknown = append(unknown, expected.Template.AttemptID)
	}
	g := mustSelectedGeneratedWork(t, s)
	progress, err := g.controlledRetirementProgress(duty, nil, true)
	if err != nil || len(progress.rows) != 1 {
		t.Fatal("ACK progress before final probe", err)
	}
	input, inputCanonical := generatedDeletePlanInput(t, s, generatedVectorID(239), duty, target, 2)
	input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(duty.DomainID, duty.ResourceID, target.ResourceDigest,
		scope, progress.ack.record.ResultID, contract.Hash(progress.ack.result))
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, inputCanonical)
	responder.DeleteExact(target.ResourceDigest)
	confirmed, _, final, packet := selectActualGeneratedPacketRecord(t, env, s, prior, custody.StandardValue, true,
		func(ctx context.Context, command contract.GeneratedProducerCommand) []byte {
			return responder.Probe(ctx, command)
		})
	if len(packet) == 0 {
		t.Fatal("final confirmation missing")
	}
	env.Custody.RetireGenerated()
	closed := selectControlledRetirementClose(t, t.Context(), env, confirmed, final.Template.AttemptID)
	closed = generatedLifecycleReopen(t, t.Context(), closed, env.Store)
	releases := mustSelectedGeneratedWork(t, closed).releases
	for _, id := range unknown {
		mapping, ok := releases[id]
		if !ok || mapping.release.State != contract.GeneratedReleaseUnobserved ||
			mapping.attempt.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) ||
			mapping.attempt.Facts.Count != 1 || mapping.attempt.History.Count != 1 {
			t.Fatal("unknown probe release lost history or retained progress", id)
		}
	}
}

// full_only: false
func TestGeneratedControlledRetirementRetainsUnqualifiedObservation(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, kind := range []string{"continued use", "conflicting incarnation", "generic authentication"} {
			t.Run(fmt.Sprintf("%t/%s", recovery, kind), func(t *testing.T) {
				env, s, d, target := controlledParkedAcknowledgement(t, recovery)
				ctx := context.Background()
				g, err := s.selectedGeneratedWork(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				progress, err := g.controlledRetirementProgress(d, nil, true)
				if err != nil {
					t.Fatal(err)
				}
				scope := contract.GeneratorControlledRetirementScope(d.DescriptorID, d.ConfigContractID, d.ResultContractID)
				resource := d.ResourceID
				if kind == "conflicting incarnation" {
					resource = generatedVectorID(240)
				}
				responder := custody.NewControlledRetirementResponder(resource, target.ResourceDigest, scope)
				defer responder.Close()
				if kind != "continued use" {
					responder.DeleteExact(target.ResourceDigest)
				}
				input, inputCanonical := generatedDeletePlanInput(t, s, generatedVectorID(233), d, target, 2)
				input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(d.DomainID, d.ResourceID, target.ResourceDigest, scope, progress.ack.record.ResultID, contract.Hash(progress.ack.result))
				prior, _ := preparePrivateGeneratedReservation(t, env, s, input, inputCanonical)
				calls := 0
				probe := func(ctx context.Context, c contract.GeneratedProducerCommand) []byte {
					calls++
					if kind == "generic authentication" {
						return responder.ProbeWithWrongCredential(ctx, c)
					}
					return responder.Probe(ctx, c)
				}
				producer, expected := preparePrivateGeneratedProducerProbe(t, env, s, prior, custody.StandardValue, nil, probe)
				var packet []byte
				var facts contract.GeneratorSafeFacts
				if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
					var code contract.CryptoResultCode
					packet, facts, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
					return code
				}) {
					t.Fatal("probe handoff")
				}
				entered, result := s.selectCandidate(ctx, producer.reservation.candidate)
				if entered == nil || result.Outcome != ObservedCurrent || calls != 1 {
					t.Fatal("probe selection", result, calls)
				}
				env.Custody.RetireGenerated()
				var retained *StateSession
				if kind == "generic authentication" {
					if len(packet) != 0 || facts.Disposition != contract.GeneratorDispositionUnknown {
						t.Fatal("generic authentication became confirmation")
					}
					body, err := contract.EncodeGeneratorSafeFacts(facts)
					if err != nil {
						t.Fatal(err)
					}
					permit, err := entered.admitGeneratedRetirementUnknown(context.Background(), d.DutyID, body, generatedPlanInputFixture(t, entered).context)
					if err != nil {
						t.Fatal(err)
					}
					candidate, result := entered.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
					if candidate == nil || result.Outcome != ObservedCurrent {
						t.Fatal("retain ambiguity", result)
					}
					retained, result = entered.selectCandidate(ctx, candidate)
					if retained == nil || result.Outcome != ObservedCurrent {
						t.Fatal(result)
					}
				} else {
					want := uint8(7)
					if kind == "conflicting incarnation" {
						want = 8
					}
					if len(packet) == 0 || facts.Disposition != want {
						t.Fatal("functional contradictory observation not sealed", facts.Disposition)
					}
					plan, err := entered.generatedRecordRequest(context.Background(), expected.Template.AttemptID, packet, generatedPlanInputFixture(t, entered).context)
					if err != nil {
						t.Fatal(err)
					}
					record := preparePrivateGeneratedRecord(t, env, entered, plan)
					recorded, result := entered.selectCandidate(ctx, record.reservation.candidate)
					if recorded == nil || result.Outcome != ObservedCurrent {
						t.Fatal(result)
					}
					env.Custody.RetireGenerated()
					retained = selectControlledRetirementClose(t, ctx, env, recorded, expected.Template.AttemptID)
				}
				retained = generatedLifecycleReopen(t, ctx, retained, env.Store)
				g, err = retained.selectedGeneratedWork(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				d, err = contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, d.DutyID}].Body)
				if err != nil || d.Step != 2 || d.Progress.Count != 1 || retained.root.Generated.Retiring != 1 || len(g.releases) != 0 {
					t.Fatal("unqualified fact closed or lost progress", err, d.Step, d.Progress.Count)
				}
				p, err := g.controlledRetirementProgress(d, nil, true)
				if err != nil || (kind != "generic authentication" && !p.contradiction) {
					t.Fatal("cold history lost contradiction", err)
				}
				if kind != "generic authentication" {
					fresh, _ := generatedDeletePlanInput(t, retained, generatedVectorID(234), d, target, 2)
					fresh.requestBindings[0].Digest = input.requestBindings[0].Digest
					if _, err := retained.generatedPlanRequest(t.Context(), fresh); err == nil {
						t.Fatal("known contradiction granted fresh completion authority")
					}
				}
			})
		}
	}
}

func generatedControlledOutputWitness(t testing.TB, s *StateSession, public contract.PublicState, records []contract.SupportRecord) *contract.GeneratedOutputTransition {
	t.Helper()
	w, err := s.generatedOutputTransition(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if records != nil {
		w.Rows.Facts = nil
		w.Rows.Records = nil
		w.Retained = nil
		for _, row := range records {
			fact, err := contract.InspectSupportRecordDigest(public.Domain, row)
			if err != nil {
				t.Fatal(err)
			}
			w.Rows.Facts = append(w.Rows.Facts, fact)
			if row.Kind == contract.RetainedCanonicalSupportKind {
				w.Retained = append(w.Retained, row)
			}
			if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind || row.Kind == contract.OutputConfigurationSliceSupportKind {
				w.Rows.Records = append(w.Rows.Records, row)
			}
		}
	}
	owned, err := w.Own(public)
	if err != nil {
		t.Fatal("controlled selected output facts", err)
	}
	return owned
}
