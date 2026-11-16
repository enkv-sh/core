package core

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedCleanupPreparationKeepsLateInboxReadResult(t *testing.T) {
	for _, name := range []string{"transport_unavailable", "synchronous_cancellation", "invalid_inbox", "healthy", "earlier_original_reflection"} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			env, s, original, packet := resultlessCreateObligation(t, ctx, custody.GeneratedTerminalFailure)
			work := mustSelectedGeneratedWork(t, s)
			var successor generatedAttempt
			for id, attempt := range work.attempts {
				if id != original.record.AttemptID {
					successor = attempt
				}
			}
			warning := s.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
			s = endGeneratedObligation(t, ctx, env, s, successor.expected.Template.HazardID,
				[]contract.ID{successor.expected.Template.HazardID}, s.currentEntryInputs(), warning)
			s, later := selectPrivateOwnedUnusableAggregate(t, env, s, []string{"unrelated"}, testID("unrelated cleanup preparation source"))
			s = generatedLifecycleReopen(t, ctx, s, env.Store)
			work = mustSelectedGeneratedWork(t, s)
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			inbox := expectedGeneratedResultKey(store.desc.Prefix, original.expected)
			delete(store.objects, inbox)
			hazard, err := contract.InspectGeneratedHazardRecord(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, original.expected.Template.HazardID}].Body)
			t.Logf("cleanup fixture: attempts=%d hazards=%d earlier_fenced=%d earlier_exposure=%d earlier_inbox_missing=%t",
				len(work.attempts), s.root.Generated.Hazards, hazard.Fenced, hazard.Exposure, len(store.objects[inbox].Body) == 0)
			if err != nil || len(work.attempts) != 2 || s.root.Generated.Hazards != 2 || hazard.Fenced != 1 ||
				hazard.Exposure != contract.GeneratedExposurePossibleLive || len(work.attempts[original.record.AttemptID].result) != 0 ||
				later.record.State != contract.GeneratedEffectFailedTerminal || len(later.result) == 0 ||
				later.record.OperationID == original.record.OperationID || later.record.ResourceID == original.record.ResourceID {
				t.Fatal("fixture lacks the missing fenced original and independent later cleanup source")
			}
			selection, present, err := s.readGeneratedCleanup(ctx)
			t.Logf("healthy cleanup selection: present=%t kind=%d later_source=%t", present, selection.kind, selection.hazard.HazardID == later.expected.Template.HazardID)
			if err != nil || !present || selection.kind != generatedCleanupHazard || selection.hazard.HazardID != later.expected.Template.HazardID || selection.target.ResourceID != later.record.ResourceID {
				t.Fatal("healthy selection did not choose the actual later cleanup source")
			}
			row := work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, selection.hazard.HazardID}]
			input, inputCanonical := generatedDeletePlanInputForSource(t, s, testID("late read cleanup preparation"), row, selection.target)
			permit := admitCleanupPreparationPlan(t, env, s, input, inputCanonical, selection.target)
			captured := &generatedOrdinaryComparisonCrypto{inner: permit.crypto}
			permit.crypto = captured
			initialInboxReads := 0
			store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if key == inbox {
					initialInboxReads++
				}
				return read
			}
			defer func() { store.readHook = nil }()
			recomputed, err := s.generatedPlanRequest(ctx, permit.plan.input)
			matches := err == nil && recomputed != nil && recomputed.request == permit.plan.request && recomputed.capacity == permit.plan.capacity &&
				recomputed.intents.equal(permit.plan.intents) && slices.Equal(recomputed.bindings, permit.plan.bindings)
			t.Logf("cleanup admission: permit_admitted=%t initial_plan_matches=%t initial_inbox_reads=%d", !permit.used, matches, initialInboxReads)
			if !matches || initialInboxReads != 0 {
				t.Fatal("initial healthy plan recomputation failed or entered the late inbox")
			}
			prepareContext, cancel := context.WithCancel(ctx)
			defer cancel()
			lateInboxReads := 0
			store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if key != inbox {
					return read
				}
				lateInboxReads++
				switch name {
				case "transport_unavailable":
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
				case "invalid_inbox":
					return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonNone}
				case "synchronous_cancellation":
					cancel()
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonNone}
				case "earlier_original_reflection":
					return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(packet)}
				default:
					return read
				}
			}
			if name == "earlier_original_reflection" {
				reflected, present, err := s.readGeneratedCleanup(ctx)
				t.Logf("late selection control: present=%t kind=%d earlier_owner=%t inbox_reads=%d", present, reflected.kind, reflected.hazard.HazardID == original.expected.Template.HazardID, lateInboxReads)
				if err != nil || !present || reflected.kind != generatedCleanupReflection || reflected.hazard.HazardID != original.expected.Template.HazardID || !bytes.Equal(reflected.result, packet) || lateInboxReads != 1 {
					t.Fatal("real late original did not produce a valid higher-priority reflection")
				}
				lateInboxReads = 0
			}
			creates, cas, signs := store.creates, store.cas, trust.signs
			public, private := env.Custody.Calls()
			prepared, result := s.PrepareGeneratedPlan(prepareContext, permit)
			p, k := env.Custody.Calls()
			t.Logf("late cleanup recheck: inbox_reads=%d preparation_present=%t outcome=%d reason=%d store_reason=%d permit_used=%t crypto_exchanges=%d creates=%d cas=%d signs=%d public_key_calls=%d private_key_calls=%d",
				lateInboxReads, prepared != nil, result.Outcome, result.Reason, result.StoreReason, permit.used, len(captured.kinds), store.creates-creates, store.cas-cas, trust.signs-signs, p-public, k-private)
			if store.creates != creates || store.cas != cas || trust.signs != signs || !permit.used {
				t.Error("cleanup preparation wrote, signed or did not consume its permit")
			}
			if name == "healthy" {
				if prepared == nil || result != s.observed(ObservedCurrent) || lateInboxReads != 1 || len(captured.kinds) == 0 {
					t.Error("healthy cleanup preparation did not reach Crypto successfully", result)
				}
			} else {
				want := Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable}
				wantReads := 1
				switch name {
				case "transport_unavailable":
					want.StoreReason, wantReads = contract.ReasonTransport, 3
				case "synchronous_cancellation":
					want.StoreReason = contract.ReasonMalformed
				case "invalid_inbox":
					want = failure(IntegrityFailure, InvalidFormat)
				case "earlier_original_reflection":
					want = refused(InvalidRelation)
				}
				if prepared != nil || result != want || lateInboxReads != wantReads || len(captured.kinds) != 0 || p != public || k != private || s.prepared {
					t.Error("late cleanup failure lost its exact result or crossed the sensitive-call boundary", result)
				}
			}
			store.readHook = nil
			reads, exchanges := store.reads, len(captured.kinds)
			reused, result := s.PrepareGeneratedPlan(ctx, permit)
			t.Logf("cleanup permit reuse: preparation_present=%t outcome=%d reason=%d reads=%d crypto_exchanges=%d", reused != nil, result.Outcome, result.Reason, store.reads-reads, len(captured.kinds)-exchanges)
			if reused != nil || result != refused(AdmissionInvalid) || store.reads != reads || len(captured.kinds) != exchanges || store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Error("consumed cleanup permit regained preparation or effect permission", result)
			}
		})
	}
}

// full_only: false
func TestGeneratedCleanupPreparationKeepsSelectedOriginalAfterInboxLoss(t *testing.T) {
	ctx := t.Context()
	env, s, duty, target := controlledParkedAcknowledgement(t, false)
	env.Context = ctx
	work := mustSelectedGeneratedWork(t, s)
	progress, err := work.controlledRetirementProgress(duty, nil, true)
	if err != nil || len(progress.rows) != 1 || len(progress.ack.result) == 0 {
		t.Fatal("fixture lacks a selected original acknowledgement", err)
	}
	scope := contract.GeneratorControlledRetirementScope(duty.DescriptorID, duty.ConfigContractID, duty.ResultContractID)
	input, inputCanonical := generatedDeletePlanInput(t, s, generatedVectorID(235), duty, target, 2)
	input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(duty.DomainID, duty.ResourceID, target.ResourceDigest,
		scope, progress.ack.record.ResultID, contract.Hash(progress.ack.result))
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, inputCanonical)
	responder := custody.NewControlledRetirementResponder(duty.ResourceID, target.ResourceDigest, scope)
	defer responder.Close()
	producer, unknown := preparePrivateGeneratedProducerProbe(t, env, s, prior, custody.StandardValue, nil,
		responder.ProbeWithWrongCredential)
	var packet []byte
	var facts contract.GeneratorSafeFacts
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		var code contract.CryptoResultCode
		packet, facts, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("unknown probe handoff refused")
	}
	entered, result := s.selectCandidate(ctx, producer.reservation.candidate)
	if entered == nil || result.Outcome != ObservedCurrent || len(packet) != 0 || facts.Disposition != contract.GeneratorDispositionUnknown {
		t.Fatal("fixture probe did not retain unknown evidence", result)
	}
	env.Custody.RetireGenerated()
	body, err := contract.EncodeGeneratorSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	residuePermit, err := entered.admitGeneratedActiveRetirementResidue(context.Background(), duty.DutyID, body, generatedPlanInputFixture(t, entered).context)
	if err != nil {
		t.Fatal("unknown probe residue admission", err)
	}
	candidate, result := entered.PrepareGeneratedLifecycle(ctx, residuePermit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("unknown probe residue preparation", result)
	}
	s, result = entered.selectCandidate(ctx, candidate)
	if s == nil || result.Outcome != ObservedCurrent {
		t.Fatal("unknown probe residue selection", result)
	}
	s = generatedLifecycleReopen(t, ctx, s, env.Store)
	work = mustSelectedGeneratedWork(t, s)
	source, err := work.generatedDeleteSource(duty.DutyID)
	if err != nil || source.Record.Kind != contract.GeneratedHazardSupportKind || source.Hazard.OriginalResults.Count != 1 {
		t.Fatal("residue lost its exact selected original", err)
	}
	selectedOriginal := work.attempts[progress.ack.record.AttemptID]
	if !bytes.Equal(selectedOriginal.result, progress.ack.result) {
		t.Fatal("residue changed the selected acknowledgement")
	}
	selection, present, err := s.readGeneratedCleanup(ctx)
	if err != nil || !present || selection.kind != generatedCleanupHazard || selection.hazard.HazardID != source.Hazard.HazardID || selection.target != target {
		t.Fatal("healthy cleanup selected another owner or target", err)
	}
	input, inputCanonical = generatedDeletePlanInputForSource(t, s, generatedVectorID(236), source.Record, target)
	template := input.graph.Lineages[0].Templates[0]
	cleanupScope := contract.GeneratorControlledRetirementScope(source.DescriptorID, source.ConfigContractID, template.ResultContractID)
	input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(source.DomainID, source.ResourceID, target.ResourceDigest,
		cleanupScope, selectedOriginal.record.ResultID, contract.Hash(selectedOriginal.result))
	env.Custody.RetireGenerated()
	permit := admitCleanupPreparationPlan(t, env, s, input, inputCanonical, target)
	captured := &generatedOrdinaryComparisonCrypto{inner: permit.crypto}
	permit.crypto = captured
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	inbox := expectedGeneratedResultKey(store.desc.Prefix, selectedOriginal.expected)
	unknownInbox := expectedGeneratedResultKey(store.desc.Prefix, unknown)
	delete(store.objects, inbox)
	delete(store.objects, unknownInbox)
	inboxReads := 0
	store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
		if key == inbox {
			inboxReads++
			if read.Status != contract.ReadMissing {
				t.Error("selected original inbox was not absent")
			}
		}
		return read
	}
	defer func() { store.readHook = nil }()
	selection, present, err = s.readGeneratedCleanup(ctx)
	if err != nil || !present || selection.kind != generatedCleanupHazard || selection.hazard.HazardID != source.Hazard.HazardID || selection.target != target || inboxReads != 1 {
		t.Fatal("absent inbox changed the retained cleanup owner or target", err)
	}
	inboxReads = 0
	creates, cas, signs := store.creates, store.cas, trust.signs
	prepared, result := s.PrepareGeneratedPlan(ctx, permit)
	t.Logf("retained_original_bytes=%d original_inbox_reads=%d preparation_present=%t outcome=%d permit_used=%t crypto_exchanges=%d creates=%d cas=%d signs=%d",
		len(selectedOriginal.result), inboxReads, prepared != nil, result.Outcome, permit.used, len(captured.kinds), store.creates-creates, store.cas-cas, trust.signs-signs)
	if prepared == nil || result != s.observed(ObservedCurrent) || !permit.used || inboxReads == 0 || len(captured.kinds) == 0 || store.creates != creates || store.cas != cas || trust.signs != signs {
		t.Error("retained original did not support exact effect-free cleanup preparation", result)
	}
	reads, exchanges := store.reads, len(captured.kinds)
	reused, result := s.PrepareGeneratedPlan(ctx, permit)
	if reused != nil || result != refused(AdmissionInvalid) || store.reads != reads || len(captured.kinds) != exchanges || store.creates != creates || store.cas != cas || trust.signs != signs {
		t.Error("consumed retained-result permit regained preparation permission", result)
	}
}

func admitCleanupPreparationPlan(t *testing.T, env fixtureEnvironment, s *StateSession, input generatedPlanInput, canonical []custody.GeneratedCanonicalSelection, target contract.GeneratorTarget) *admittedGeneratedPlan {
	t.Helper()
	ctx := t.Context()
	plan, err := s.generatedPlanRequest(ctx, input)
	if err != nil || plan.phase == nil || plan.phase.TransitionKind != contract.GeneratorAuthorityCleanupReserve {
		t.Fatal("actual cleanup source did not produce a cleanup reservation plan", err)
	}
	graph, err := contract.EncodeGeneratorPlanBundle(input.graph)
	if err != nil {
		t.Fatal("cleanup private graph encoding", err)
	}
	public, err := s.publicProjection()
	if err != nil {
		t.Fatal("cleanup private public projection", err)
	}
	output, err := s.generatedOutputTransition(ctx)
	if err != nil {
		t.Fatal("cleanup private output predecessor", err)
	}
	deadline := time.Unix(0, int64(input.context.Expiry))
	currentIntents := generatedCurrentIntentInputs(ctx, t, s, graph, input.declaration)
	selected, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal("cleanup private selected predecessor", err)
	}
	deletion, present, err := s.generatedDeleteReservationSelection(ctx, input.graph, selected)
	if err != nil || !present || deletion.phase != *plan.phase || deletion.target != target {
		t.Fatal("cleanup private target differs from its admitted source", err)
	}
	if deletion.source.CompletionClass == contract.GeneratedCompletionConfirmed {
		predecessor := generatedControlledSourcePredecessorInput(t, s, selected, deletion.source)
		err = env.Custody.AdmitGeneratedControlledDeletePlan(plan.request, currentControlOf(s),
			custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: output},
			custody.GeneratedPlanInput{Declaration: input.declaration, Canonical: canonical, CurrentIntents: currentIntents}, *plan.phase, target, predecessor, deadline)
	} else {
		err = env.Custody.AdmitGeneratedDeletePlan(plan.request, currentControlOf(s),
			custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: output},
			custody.GeneratedPlanInput{Declaration: input.declaration, Canonical: canonical, CurrentIntents: currentIntents}, *plan.phase, target, deadline)
	}
	if err != nil {
		t.Fatal("cleanup private admission", err)
	}
	t.Cleanup(env.Custody.RetireGenerated)
	return &admittedGeneratedPlan{session: s, plan: plan, crypto: env.Custody.Crypto(), instance: env.Custody.Crypto().InstanceID(), deadline: deadline}
}
