package core

import (
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func liveGeneratedProfile(t testing.TB, implementation contract.GeneratorImplementation, mode uint8) generatedFixtureProfile {
	t.Helper()
	profile := nativeGeneratedFixtureProfile(t, implementation)
	profile.RetirementMode = mode
	return profile
}

func selectLiveGeneratedProcessOperation(t testing.TB, ctx context.Context, env fixtureEnvironment, s *StateSession, input generatedPlanInput) *StateSession {
	t.Helper()
	live := env.GeneratedProcess
	if live == nil || env.FreshGeneratedRecord == nil {
		t.Fatal("live generated operation requires process and fresh record")
	}
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, nil)
	producer, expected := preparePrivateGeneratedProcessProducerWithConfig(t, env, s, prior, live.Artifact, live.Configure)
	if live.BeforeCreate != nil {
		if err := live.BeforeCreate(expected.Template.AttemptID); err != nil {
			if live.SelectFailure != nil {
				live.SelectFailure("generated_create", contract.ID{}, contract.ID{}, contract.ID{}, 0, false)
			}
			t.Fatal("record create intent", err)
		}
	}
	var packet []byte
	var facts contract.GeneratorSafeFacts
	var code contract.CryptoResultCode
	var sendAuthority contract.ID
	invoked := false
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		invoked, sendAuthority = true, authority
		var outcome custody.GeneratedProducerOutcome
		packet, facts, outcome = env.Custody.InvokeGeneratedProducerOutcome(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		code = outcome.Code
		if live.ObserveOutcome != nil {
			live.ObserveOutcome(outcome)
		}
		return code
	}) {
		if live.SelectFailure != nil {
			live.SelectFailure("generated_create", contract.ID{}, contract.ID{}, contract.ID{}, 0, false)
		}
		t.Fatal("live create handoff")
	}
	entered, result := s.selectCandidate(ctx, producer.reservation.candidate)
	if (len(facts.ResourceData) > 0) && !generatedFactsResourceDigest(facts).IsZero() && live.AfterCreate != nil {
		if err := live.AfterCreate(expected.Template.AttemptID, facts); err != nil {
			if live.SelectFailure != nil {
				live.SelectFailure("generated_create", producer.operation.context.AdmissionID, producer.producerLocator, sendAuthority, code, invoked)
			}
			t.Fatal("record create identity", err)
		}
	}
	if entered == nil || result.Outcome != ObservedCurrent || code != contract.CryptoSuccess || len(packet) == 0 ||
		facts.Disposition != 1 || len(facts.ResourceData) == 0 || generatedFactsResourceDigest(facts).IsZero() {
		if live.SelectFailure != nil {
			live.SelectFailure("generated_create", producer.operation.context.AdmissionID, producer.producerLocator, sendAuthority, code, invoked)
		}
		t.Fatal("live create did not return a qualified selected result", result, code, facts.Disposition, facts.Reason, facts.ProviderFacts)
	}
	env.Custody.RetireGenerated()
	recorded := env.FreshGeneratedRecord(t, entered, expected.Template.AttemptID, packet)
	admitted := generatedPlanInputFixture(t, recorded).context
	admitted.AdmissionID, admitted.SessionID = testID("live create final admission"), testID("live create final session")
	finalPlan, err := recorded.generatedFinalRequest(t.Context(), admitted)
	if err != nil || !finalPlan.selecting {
		t.Fatal("live create final request", err)
	}
	recorded, final := preparePrivateGeneratedFinal(t, env, recorded, finalPlan)
	selected, result := recorded.selectCandidate(ctx, final.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("live create final selection", result)
	}
	env.Custody.RetireGenerated()
	return selected
}

func runLiveGeneratedRetirementScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, automatic bool) {
	t.Helper()
	live := env.GeneratedProcess
	if live == nil || env.FreshCurrent == nil || env.FreshGeneratedRecord == nil {
		t.Fatal("live retirement requires a process and fresh-process verification")
	}
	mode := uint8(contract.GeneratedRetirementManual)
	if automatic {
		mode = contract.GeneratedRetirementAuto
	}
	profile := liveGeneratedProfile(t, live.Implementation, mode)
	run := newScenarioRun(t, ctx, env)
	env = run.env
	var fixture *environmentFixture
	var selected *StateSession
	var target contract.GeneratorTarget
	var duty contract.GeneratedDutyRecord
	var successor contract.ValueEntry
	var verifyAutomatic func(*StateSession)
	run.phase("setup", func() {
		fixture = newEnvironmentFixture(t, ctx, env, nil, false)
		initial := generatedPlanInputForGenerationsIntent(t, fixture.session, generatedVectorID(230), []string{"generated"}, live.Intent, profile)
		initial.requestBindings[0].Digest = live.RequestDigest
		selected = selectLiveGeneratedProcessOperation(t, ctx, env, fixture.session, initial)
		old := selected.valueEntry(0)
		if old == nil || old.Generated.ResourceDigest.IsZero() || old.Generated.RetirementMode != mode {
			t.Fatal("live initial generation lacks exact provider identity")
		}
		rotationOperation := generatedVectorID(231)
		input := generatedStatePlanInput(t, selected, rotationOperation, []string{old.Name}, profile, old.Generated.Epoch+1,
			map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: *old})
		reservation := generatedReservationInputForStateIntent(t, selected, rotationOperation, []string{old.Name}, live.Intent, profile,
			old.Generated.Epoch+1, map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: *old})
		input.graph, input.declaration, input.registry, input.recoveryPolicy = reservation.graph, reservation.declaration,
			reservation.graph.Request.Registry, reservation.graph.Request.RecoveryPolicyID
		input.requestBindings = slices.Clone(reservation.requestBindings)
		input.requestBindings[0].Digest = live.RequestDigest
		selected = selectLiveGeneratedProcessOperation(t, ctx, env, selected, input)
		successor = *selected.valueEntry(0)
		work, err := selected.selectedGeneratedWork(context.Background())
		if err != nil || successor.Generated.ResourceDigest == old.Generated.ResourceDigest || successor.Generated.RetiringDutyPresent != 1 ||
			selected.root.Generated.Retiring != 1 {
			t.Fatal("live rotation did not retain the exact predecessor", err)
		}
		row, ok := work.records[generatedRecordKey{kind: 10, id: successor.Generated.RetiringDutyID}]
		if !ok {
			t.Fatal("live rotation omitted its retirement duty")
		}
		duty, err = contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			t.Fatal("live retirement duty", err)
		}
		target, err = work.retirementTarget(t.Context(), duty)
		if err != nil || target.ResourceDigest != old.Generated.ResourceDigest {
			t.Fatal("live rotation changed retirement target", err)
		}
	})
	run.phase("transition", func() {
		if automatic {
			selected, verifyAutomatic = selectGeneratedAutomaticRetirementAcknowledgement(t, ctx, env, selected, live, target)
			return
		}
		operation := generatedVectorID(232)
		input, inputCanonical := generatedDeletePlanInput(t, selected, operation, duty, target, 2)
		input.requestBindings[0].Digest = generatedRetirementRequestDigest(target)
		prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, inputCanonical)
		producer, expected := preparePrivateGeneratedProcessProducerWithConfig(t, env, selected, prior, live.Artifact, live.Configure)
		if live.BeforeDelete != nil {
			if err := live.BeforeDelete(expected.Template.AttemptID, generatedTargetProviderTokenID(t, selected, target)); err != nil {
				if live.SelectFailure != nil {
					live.SelectFailure("generated_retire", contract.ID{}, contract.ID{}, contract.ID{}, 0, false)
				}
				t.Fatal("record delete intent", err)
			}
		}
		var packet []byte
		var facts contract.GeneratorSafeFacts
		var code contract.CryptoResultCode
		var sendAuthority contract.ID
		invoked := false
		if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
			invoked, sendAuthority = true, authority
			var outcome custody.GeneratedProducerOutcome
			packet, facts, outcome = env.Custody.InvokeGeneratedProducerOutcome(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
			code = outcome.Code
			if live.ObserveOutcome != nil {
				live.ObserveOutcome(outcome)
			}
			return code
		}) {
			if live.SelectFailure != nil {
				live.SelectFailure("generated_retire", contract.ID{}, contract.ID{}, contract.ID{}, 0, false)
			}
			t.Fatal("live retirement handoff")
		}
		entered, result := selected.selectCandidate(ctx, producer.reservation.candidate)
		if facts.Disposition == contract.GeneratorDispositionRetirementAcknowledged && (len(facts.ResourceData) > 0) && generatedFactsResourceDigest(facts) == target.ResourceDigest && live.AfterDelete != nil {
			if err := live.AfterDelete(expected.Template.AttemptID, generatedTargetProviderTokenID(t, selected, target), facts); err != nil {
				if live.SelectFailure != nil {
					live.SelectFailure("generated_retire", producer.operation.context.AdmissionID, producer.producerLocator, sendAuthority, code, invoked)
				}
				t.Fatal("record delete acknowledgement", err)
			}
		}
		if entered == nil || result.Outcome != ObservedCurrent || code != contract.CryptoSuccess || len(packet) == 0 ||
			facts.Disposition != contract.GeneratorDispositionRetirementAcknowledged || len(facts.ResourceData) == 0 || generatedFactsResourceDigest(facts) != target.ResourceDigest {
			if live.SelectFailure != nil {
				live.SelectFailure("generated_retire", producer.operation.context.AdmissionID, producer.producerLocator, sendAuthority, code, invoked)
			}
			t.Fatal("live retirement lacks exact acknowledgement", result, code, facts.Disposition, facts.Reason, facts.ProviderFacts)
		}
		env.Custody.RetireGenerated()
		recorded := env.FreshGeneratedRecord(t, entered, expected.Template.AttemptID, packet)
		admitted := generatedPlanInputFixture(t, recorded).context
		admitted.AdmissionID, admitted.SessionID = testID("live retirement close admission"), testID("live retirement close session")
		closePlan, err := recorded.generatedRetirementClosePlan(ctx, expected.Template.AttemptID, admitted)
		if err != nil {
			t.Fatal("live retirement close plan", err)
		}
		permit, err := recorded.admitGeneratedLifecyclePlan(t.Context(), closePlan)
		if err != nil {
			t.Fatal("live retirement close admission", err)
		}
		candidate, prepared := recorded.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
		if candidate == nil || prepared.Outcome != ObservedCurrent {
			t.Fatal("live retirement close preparation", prepared)
		}
		selected, result = recorded.selectCandidate(ctx, candidate)
		if selected == nil || result.Outcome != ObservedCurrent || selected.root.Generated.Retiring != 0 || selected.root.Generated.Duties != 0 ||
			selected.root.Generated.PendingReleases != 1 {
			t.Fatal("live retirement close selection", result)
		}
		body, receiptResult := selected.MutationReceipt(ctx, operation)
		receipt, err := contract.InspectCompactMutationReceipt(body)
		if receiptResult.Outcome != ObservedCurrent || err != nil || receipt.EvidenceCeiling != contract.ReceiptEvidenceAcknowledged ||
			receipt.WarningBits != contract.ReceiptWarningInvalidationNotConfirmed || receipt.AcknowledgedCount != 1 || receipt.ConfirmedCount != 0 {
			t.Fatal("live retirement receipt exceeded its acknowledgement ceiling", receiptResult, err)
		}
	})
	run.phase("verification", func() {
		cold := generatedLifecycleReopen(t, ctx, selected, env.Store)
		if verifyAutomatic != nil {
			verifyAutomatic(cold)
		}
		entry := cold.valueEntry(0)
		if entry == nil || entry.Generated.ResourceDigest != successor.Generated.ResourceDigest || entry.Generated.RetiringDutyPresent != 0 ||
			cold.root.Generated.Retiring != 0 {
			t.Fatal("cold retirement changed the selected successor")
		}
		inspection, err := cold.inspectGeneratedWork(context.Background())
		if err != nil || len(inspection.releases) != 1 || len(inspection.effects) != 1 ||
			inspection.effects[0].evidenceCeiling != contract.ReceiptEvidenceAcknowledged {
			t.Fatal("cold retirement lost its exact acknowledgement", err)
		}
	})
	run.phase("reopen", func() { env.FreshCurrent(t, fixture.admission, selected) })
}
