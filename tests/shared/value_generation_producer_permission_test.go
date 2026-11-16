package core

import (
	"context"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedClaimedFinalRejectsProducerRequests(t *testing.T) {
	for _, original := range []bool{false, true} {
		for _, zero := range []bool{false, true} {
			t.Run(fmt.Sprintf("original%t/zero-attempt%t", original, zero), func(t *testing.T) {
				env, _ := genesisEnvironment(t, contract.GCP, true)
				before := newEnvironmentFixture(t, t.Context(), env, nil, false).session
				reservation, _ := preparePrivateGeneratedReservation(t, env, before, generatedPlanInputFixture(t, before), nil)
				recorded, _, _, _ := selectActualGeneratedPacketRecord(t, env, before, reservation, custody.StandardValue, true, nil)
				finalContext := generatedPlanInputFixture(t, recorded).context
				finalContext.AdmissionID, finalContext.SessionID = testID("claimed Final admission"), testID("claimed Final session")
				plan, err := recorded.generatedFinalRequest(t.Context(), finalContext)
				if err != nil {
					t.Fatal("Final request", err)
				}
				recorded, final := preparePrivateGeneratedFinal(t, env, recorded, plan)
				admitted := final.operation.context
				admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = testID("final producer admission"), testID("final producer session"), contract.DescriptorVector{}
				attempt := testID("nonmember Final attempt")
				if zero {
					attempt = contract.ID{}
				}
				request := recorded.generatedProducerRequestForAttempt
				if original {
					request = recorded.generatedOriginalProducerRequest
				}
				defer func() {
					if failure := recover(); failure != nil {
						t.Errorf("claimed Final producer request panicked: %v", failure)
					}
				}()
				if _, _, err := request(t.Context(), final, attempt, admitted); err == nil {
					t.Fatal("claimed Final granted producer admission")
				}
				if !final.reservation.candidate.generatedReady() || final.reservation.candidate.generated.producerMode.Load() == uint32(generatedOriginalSetMode) {
					t.Fatal("producer refusal changed Final readiness")
				}
			})
		}
	}
}

func prepareTwoOriginalPermissions(t *testing.T, env fixtureEnvironment, before *StateSession) ([2]*generatedPreparation, [2]*custody.Fixture) {
	t.Helper()
	input := generatedPlanInputForGenerations(t, before, generatedVectorID(10), []string{"alpha", "omega"}, defaultGeneratedFixtureProfile())
	reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
	facts := acquireGeneratedProducerFixtureFacts(t, env, before, reservation)
	keys := [2]*custody.Fixture{env.Custody, env.Custody.ForkGenerated(t)}
	var producers [2]*generatedPreparation
	for i := range producers {
		producers[i], _ = preparePrivateGeneratedOriginalProducerForAttempt(t, env, before, reservation,
			keys[i], input.requestBindings[i].AttemptID, facts, custody.StandardValue, nil, nil)
		t.Cleanup(keys[i].RetireGenerated)
	}
	if candidate, result := before.ClaimGeneratedOriginalSet(t.Context(), producers[:], env.Trust); candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("complete original producer set", result)
	}
	return producers, keys
}

func assertFreshGeneratedInitialPermissionRefused(t *testing.T, s *StateSession) {
	t.Helper()
	work := mustSelectedGeneratedWork(t, s)
	if work.parent == nil || work.phase == nil || work.phase.Phase != 1 {
		t.Fatal("cold refusal requires the accepted original reservation")
	}
	input := generatedPlanInputFixture(t, s)
	if _, err := s.generatedPlanRequest(t.Context(), input); err == nil {
		t.Fatal("cold original reservation readmitted an initial plan")
	}
	if _, err := s.generatedSuccessorReservationRequest(t.Context(), input.context); err == nil {
		t.Fatal("cold original reservation made an entered original dispatchable again")
	}
	for _, lineage := range work.bundles[0].Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate {
			continue
		}
		attempt := work.attempts[lineage.Templates[0].AttemptID]
		if attempt.record.State != contract.GeneratedEffectTransmitted || len(attempt.result) != 0 {
			t.Fatal("zero-call cold original changed conservative evidence")
		}
		if _, _, err := s.generatedProducerRequestForAttempt(t.Context(), nil, attempt.record.AttemptID, input.context); err == nil {
			t.Fatal("cold original acquired initial permission without retained custody")
		}
		if _, _, err := s.generatedOriginalProducerRequest(t.Context(), nil, attempt.record.AttemptID, input.context); err == nil {
			t.Fatal("cold original acquired complete-set permission without retained custody")
		}
	}
	if p, result := s.PrepareGeneratedProducer(t.Context(), nil); p != nil || result.Outcome != AdmissionRefused {
		t.Fatal("cold preparation accepted no opaque producer admission", result)
	}
	if p, result := s.PrepareGeneratedOriginalProducer(t.Context(), nil); p != nil || result.Outcome != AdmissionRefused {
		t.Fatal("cold complete-original preparation accepted no opaque producer admission", result)
	}
}

// full_only: false
func TestGeneratedRecordCannotRecreateOriginalFirstSend(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, true)
	before := newEnvironmentFixture(t, t.Context(), env, nil, false).session
	producers, keys := prepareTwoOriginalPermissions(t, env, before)
	var authority contract.ID
	if !producers[0].reservation.candidate.bindFirstSend(producers[0], func(_ context.Context, accepted contract.ID) contract.CryptoResultCode {
		authority = accepted
		return contract.CryptoSuccess
	}) {
		t.Fatal("original selection handoff")
	}
	selected, result := before.selectCandidate(t.Context(), producers[0].reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent || authority.IsZero() {
		t.Fatal("initial reservation selection", result)
	}
	var first []byte
	for i, producer := range producers {
		packet, _, code := keys[i].InvokeGeneratedProducer(t.Context(), producer.operation.context.AdmissionID, producer.producerLocator, authority)
		if code != contract.CryptoSuccess || len(packet) == 0 {
			t.Fatal("original entry", i, code)
		}
		if i == 0 {
			first = packet
		}
		keys[i].RetireGenerated()
	}
	// The second exact original was sent, but its result was lost. Current
	// recording progress cannot restore that original reservation's permission.
	selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
	plan, err := selected.generatedRecordRequest(t.Context(), producers[0].attempt, first, generatedPlanInputFixture(t, selected).context)
	if err != nil {
		t.Fatal("first original Record", err)
	}
	record := preparePrivateGeneratedRecord(t, env, selected, plan)
	admitted := record.operation.context
	admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = testID("later producer admission"), testID("later producer session"), contract.DescriptorVector{}
	public, private := env.Custody.Calls()
	for name, request := range map[string]generatedProducerRequestFunction{
		"single original":    selected.generatedProducerRequestForAttempt,
		"complete originals": selected.generatedOriginalProducerRequest,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := request(t.Context(), record, producers[1].attempt, admitted); err == nil {
				t.Error("later Record granted an original first send")
				if name == "complete originals" {
					permit, _ := admitPrivateGeneratedProducerWithAdmission(t, env, selected, record, env.Custody, producers[1].attempt, custody.StandardValue, nil, nil,
						generatedProducerFixtureSteps{request: selected.generatedOriginalProducerRequest})
					p, result := selected.PrepareGeneratedOriginalProducer(t.Context(), permit)
					if p != nil || result.Outcome != AdmissionRefused {
						t.Error("wrong-mode complete-original preparation was accepted", result)
					}
				}
			}
			if !record.reservation.candidate.generatedReady() || record.reservation.candidate.generated.producerMode.Load() == uint32(generatedOriginalSetMode) {
				t.Error("refused producer request changed Record readiness")
			}
		})
	}
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("refused later producer request entered private custody")
	}
	// Readiness is necessary but the contract requires this exact valid
	// Record to remain selectable after either refused producer request.
	selected, result = selected.selectCandidate(t.Context(), record.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("refused wrong-mode request poisoned valid Record selection", result)
	}
	env.Custody.RetireGenerated()
	cold := generatedLifecycleReopen(t, t.Context(), selected, env.Store)
	work := mustSelectedGeneratedWork(t, cold)
	if work.phase.FrontierAttemptID != producers[1].attempt || work.attempts[producers[1].attempt].record.State != contract.GeneratedEffectTransmitted {
		t.Fatal("selected Record changed the unsatisfied original or recreated its send right")
	}
}

// full_only: false
func TestGeneratedRetainedOriginalPermissionSurvivesRecord(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, true)
	before := newEnvironmentFixture(t, t.Context(), env, nil, false).session
	producers, keys := prepareTwoOriginalPermissions(t, env, before)
	var authority contract.ID
	if !producers[0].reservation.candidate.bindFirstSend(producers[0], func(_ context.Context, accepted contract.ID) contract.CryptoResultCode {
		authority = accepted
		return contract.CryptoSuccess
	}) {
		t.Fatal("original selection handoff")
	}
	selected, result := before.selectCandidate(t.Context(), producers[0].reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent || authority.IsZero() {
		t.Fatal("initial reservation selection", result)
	}
	first, _, code := keys[0].InvokeGeneratedProducer(t.Context(), producers[0].operation.context.AdmissionID, producers[0].producerLocator, authority)
	if code != contract.CryptoSuccess || len(first) == 0 {
		t.Fatal("first original entry", code)
	}
	keys[0].RetireGenerated()
	// Recording is done by a fresh process. The uninterrupted caller still
	// owns the second original's claimed custody and initial authority.
	recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), selected, producers[0].attempt, first)
	work := mustSelectedGeneratedWork(t, recorded)
	if work.phase.FrontierAttemptID != producers[1].attempt {
		t.Fatal("Record did not advance to the second original")
	}
	second, _, code := keys[1].InvokeGeneratedProducer(t.Context(), producers[1].operation.context.AdmissionID, producers[1].producerLocator, authority)
	if code != contract.CryptoSuccess || len(second) == 0 {
		t.Fatal("retained initial permission was lost after Record", code)
	}
	if again, _, code := keys[1].InvokeGeneratedProducer(t.Context(), producers[1].operation.context.AdmissionID, producers[1].producerLocator, authority); code == contract.CryptoSuccess || len(again) != 0 {
		t.Fatal("retained initial permission was reusable")
	}
}

// full_only: false
func TestGeneratedLostAcceptanceCannotGrantOriginalFirstSend(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "capability lost before entry", true: "acceptance lost before entry"}[lost], func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, true)
			fixture := newEnvironmentFixture(t, t.Context(), env, nil, false)
			before := fixture.session
			producers, keys := prepareTwoOriginalPermissions(t, env, before)
			grants := 0
			if lost && !producers[0].reservation.candidate.bindFirstSend(producers[0], func(context.Context, contract.ID) contract.CryptoResultCode {
				grants++
				return contract.CryptoSuccess
			}) {
				t.Fatal("original selection handoff")
			}
			store := env.Store.(*memoryStore)
			if lost {
				store.casMode = "lost-after"
			}
			selected, result := before.selectCandidate(t.Context(), producers[0].reservation.candidate)
			store.casMode = ""
			if selected == nil || result.Outcome != ObservedCurrent || grants != 0 {
				t.Fatal("lost capability unexpectedly granted first send", result, grants)
			}
			for _, key := range keys {
				key.RetireGenerated()
			}
			fresh := selectedProcessFacts(t, fixture.admission, selected)
			fresh.GeneratedInitialPermissionRefusal = true
			work, err := selected.workSupportRecords(t.Context())
			if err != nil {
				t.Fatal("fresh original refusal work", err)
			}
			fresh.ExpectedWork = work
			fresh.Objects = store.objects
			checkFreshProcessInput(t, fresh)
			cold, result := Open(t.Context(), fixture.admission, env.Store)
			if cold == nil || result.Outcome != ObservedCurrent {
				t.Fatal("cold reservation", result)
			}
			for _, producer := range producers {
				work := mustSelectedGeneratedWork(t, cold)
				attempt := work.attempts[producer.attempt]
				if attempt.record.State != contract.GeneratedEffectTransmitted || len(attempt.result) != 0 {
					t.Fatal("zero-call interruption changed transmitted evidence")
				}
				admitted := producer.operation.context
				admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = testID("cold producer admission"), testID("cold producer session"), contract.DescriptorVector{}
				if _, _, err := cold.generatedProducerRequestForAttempt(t.Context(), producer, producer.attempt, admitted); err == nil {
					t.Fatal("cold selection recreated an initial permission with zero previous grants")
				}
			}
		})
	}
}
