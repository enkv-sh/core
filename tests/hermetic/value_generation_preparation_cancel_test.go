package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedPreparationCancellationConsumesAcceptedPermit(t *testing.T) {
	for _, stage := range []string{"Plan", "Record", "Producer", "OriginalProducer", "Final", "CreateResidue", "SuccessorReservation"} {
		for _, cut := range []string{"pre_canceled", "selected_read", "foreign_session", "prepared_session", "nil_context", "expired_deadline"} {
			if cut == "expired_deadline" && stage != "CreateResidue" {
				continue
			}
			if (cut == "foreign_session" || cut == "prepared_session") && stage != "Record" || cut == "nil_context" && stage != "SuccessorReservation" {
				continue
			}
			if (stage == "Producer" || stage == "OriginalProducer") && cut == "selected_read" {
				continue // Both producer variants read an owned, unpublished candidate.
			}
			if stage == "Plan" && cut == "selected_read" {
				continue // Admission has already loaded this selected graph.
			}
			t.Run(stage+"/"+cut, func(t *testing.T) {
				ctx := t.Context()
				env, _ := genesisEnvironment(t, contract.GCP, false)
				env.Context = ctx
				s := newEnvironmentFixture(t, ctx, env, nil, false).session
				var prepare func(context.Context, *StateSession) (bool, Result)
				var used *bool
				var captured *generatedOrdinaryComparisonCrypto
				var residuePermit *admittedGeneratedCreateResidue
				switch stage {
				case "Plan":
					closed, _ := selectPrivateOwnedUnusableAggregate(t, env, s, []string{"old"})
					s = generatedLifecycleReopen(t, ctx, closed, env.Store)
					input := generatedPlanInputForGenerations(t, s, testID("cancellation next operation"), []string{"fresh"}, defaultGeneratedFixtureProfile())
					plan, err := s.generatedPlanRequest(ctx, input)
					if err != nil {
						t.Fatal("Plan request", err)
					}
					graph, err := contract.EncodeGeneratorPlanBundle(input.graph)
					if err != nil {
						t.Fatal(err)
					}
					public, err := s.publicProjection()
					if err != nil {
						t.Fatal(err)
					}
					output, err := s.generatedOutputTransition(ctx)
					if err != nil {
						t.Fatal("Plan selected output predecessor", err)
					}
					deadline := time.Unix(0, int64(input.context.Expiry))
					currentIntents := generatedCurrentIntentInputs(t.Context(), t, s, graph, input.declaration)
					if err := env.Custody.AdmitGeneratedPlan(plan.request, currentControlOf(s),
						custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: output},
						custody.GeneratedPlanInput{Declaration: input.declaration, CurrentIntents: currentIntents}, deadline); err != nil {
						t.Fatal("Plan private admission", err)
					}
					captured = &generatedOrdinaryComparisonCrypto{inner: env.Custody.Crypto()}
					permit := &admittedGeneratedPlan{session: s, plan: plan, crypto: captured, instance: captured.InstanceID(), deadline: deadline}
					used = &permit.used
					prepare = func(c context.Context, receiver *StateSession) (bool, Result) {
						p, result := receiver.PrepareGeneratedPlan(c, permit)
						return p != nil, result
					}
				case "Record", "Final":
					a := newGeneratedResultFixture(t, 0, false)
					env = a.env
					env.Context = ctx
					s = generatedLifecycleReopen(t, ctx, a.f.session, env.Store)
					plan := generatedRecordPlanForResult(t, s, a.expected.Template.AttemptID, a.result, "cancellation record")
					if stage == "Record" {
						permit := admitPrivateGeneratedRecord(ctx, t, env.Custody, s, plan)
						captured = &generatedOrdinaryComparisonCrypto{inner: permit.crypto}
						permit.crypto = captured
						used = &permit.used
						prepare = func(c context.Context, receiver *StateSession) (bool, Result) {
							p, result := receiver.PrepareGeneratedRecord(c, permit)
							return p != nil, result
						}
					} else {
						p := preparePrivateGeneratedRecord(t, env, s, plan)
						selected, result := s.selectCandidate(ctx, p.reservation.candidate)
						if selected == nil || result.Outcome != ObservedCurrent {
							t.Fatal("Record selection", result)
						}
						env.Custody.RetireGenerated()
						s = generatedLifecycleReopen(t, ctx, selected, env.Store)
						final, err := s.generatedFinalRequest(ctx, generatedPlanInputFixture(t, s).context)
						if err != nil {
							t.Fatal("Final request", err)
						}
						permit := admitPrivateGeneratedFinal(t, env, s, final)
						captured = &generatedOrdinaryComparisonCrypto{inner: permit.crypto}
						permit.crypto = captured
						used = &permit.used
						prepare = func(c context.Context, receiver *StateSession) (bool, Result) {
							p, result := receiver.PrepareGeneratedFinal(c, permit)
							return p != nil, result
						}
					}
				case "CreateResidue", "SuccessorReservation", "Producer":
					var attempt contract.ID
					var packet []byte
					s, attempt, _, packet = generatedTwoLineageUnfinishedFirst(t, ctx, env, s, custody.GeneratedConfirmedNoEffect)
					if stage == "CreateResidue" {
						plan, err := s.generatedCreateResidueRequest(context.Background(), attempt, generatedPlanInputFixture(t, s).context)
						if err != nil {
							t.Fatal("Residue request", err)
						}
						permit := &admittedGeneratedCreateResidue{session: s, plan: plan}
						residuePermit = permit
						used = &permit.used
						prepare = func(c context.Context, receiver *StateSession) (bool, Result) {
							candidate, result := receiver.PrepareGeneratedCreateResidue(c, permit, env.Trust)
							return candidate != nil, result
						}
					} else {
						s = selectGeneratedNoEffectPlan(t, ctx, env, s, attempt, packet)
						admitted := generatedPlanInputFixture(t, s).context
						admitted.AdmissionID, admitted.SessionID = testID("cancel successor admission"), testID("cancel successor session")
						plan, err := s.generatedSuccessorReservationRequest(t.Context(), admitted)
						if err != nil {
							t.Fatal("Successor request", err)
						}
						permit := &admittedGeneratedSuccessorReservation{session: s, plan: plan}
						if stage == "SuccessorReservation" {
							used = &permit.used
							prepare = func(c context.Context, receiver *StateSession) (bool, Result) {
								p, result := receiver.PrepareGeneratedSuccessorReservation(c, permit)
								return p != nil, result
							}
						} else {
							prior, result := s.PrepareGeneratedSuccessorReservation(ctx, permit)
							if prior == nil || result.Outcome != ObservedCurrent {
								t.Fatal("Successor preparation", result)
							}
							steps := generatedProducerFixtureSteps{request: s.generatedProducerRequestForAttempt}
							producer, _ := admitPrivateGeneratedProducerWithAdmission(t, env, s, prior, env.Custody, plan.attempt, custody.StandardValue, nil, nil, steps)
							captured = &generatedOrdinaryComparisonCrypto{inner: producer.crypto}
							producer.crypto = captured
							used = &producer.used
							prepare = func(c context.Context, receiver *StateSession) (bool, Result) {
								p, result := receiver.PrepareGeneratedProducer(c, producer)
								return p != nil, result
							}
						}
					}
				case "OriginalProducer":
					input := generatedPlanInputForGenerations(t, s, testID("cancel original operation"), []string{"fresh"}, defaultGeneratedFixtureProfile())
					prior, _ := preparePrivateGeneratedReservation(t, env, s, input, nil)
					steps := generatedProducerFixtureSteps{request: s.generatedOriginalProducerRequest}
					permit, _ := admitPrivateGeneratedProducerWithAdmission(t, env, s, prior, env.Custody, input.requestBindings[0].AttemptID, custody.StandardValue, nil, nil, steps)
					captured = &generatedOrdinaryComparisonCrypto{inner: permit.crypto}
					permit.crypto = captured
					used = &permit.used
					prepare = func(c context.Context, receiver *StateSession) (bool, Result) {
						p, result := receiver.PrepareGeneratedOriginalProducer(c, permit)
						return p != nil, result
					}
				}
				store := env.Store.(*memoryStore)
				trust := env.Trust.(*fixtureTrust)
				creates, cas, signs := store.creates, store.cas, trust.signs
				public, private := env.Custody.Calls()
				assertNoEffects := func() {
					t.Helper()
					if store.creates != creates || store.cas != cas || trust.signs != signs || captured != nil && len(captured.kinds) != 0 {
						t.Error("rejected preparation reached Crypto, signing or Store writes")
					}
					if p, k := env.Custody.Calls(); p != public || k != private {
						t.Error("rejected preparation reached key custody")
					}
				}
				if cut == "expired_deadline" {
					residuePermit.plan.context.Expiry = uint64(time.Now().Add(-time.Second).UnixNano())
					reads := store.reads
					present, result := prepare(ctx, s)
					if present || result != refused(AdmissionInvalid) || *used || store.reads != reads {
						t.Error("expired residue admission consumed the permit or entered preflight", result, *used)
					}
					assertNoEffects()
					env.Custody.RetireGenerated()
					return
				}
				if cut == "foreign_session" || cut == "prepared_session" || cut == "nil_context" {
					receiver, invalidContext := s, ctx
					switch cut {
					case "foreign_session":
						foreign := *s
						receiver = &foreign
					case "prepared_session":
						s.prepared = true
					default:
						invalidContext = nil
					}
					reads := store.reads
					present, result := prepare(invalidContext, receiver)
					if present || result != refused(AdmissionInvalid) || *used || store.reads != reads {
						t.Error("invalid admission consumed the permit or entered preflight", result, *used)
					}
					assertNoEffects()
					if cut == "prepared_session" {
						s.prepared = false
					}
				}
				canceled, cancel := context.WithCancel(ctx)
				defer cancel()
				want := refused(AdmissionInvalid)
				readInterrupted := false
				if cut == "selected_read" {
					fragmentKeys := make(map[string]bool)
					for _, fact := range s.fragmentFacts {
						key, err := format.Key(store.desc.Prefix, fact.ref)
						if err != nil {
							t.Fatal("selected fragment key", err)
						}
						fragmentKeys[key] = true
					}
					store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
						if fragmentKeys[key] {
							readInterrupted = true
							cancel()
						}
						return result
					}
					want = failure(EvidenceUnavailable, ReadUnavailable)
				} else {
					cancel()
				}
				present, result := prepare(canceled, s)
				store.readHook = nil
				if cut == "selected_read" && !readInterrupted {
					t.Fatal("selected-read interruption did not reach an authenticated fragment")
				}
				if present || result != want {
					t.Error("canceled preparation crossed the admission boundary", result)
				}
				assertNoEffects()
				reads := store.reads
				present, result = prepare(ctx, s)
				if present || result != refused(AdmissionInvalid) || !*used || store.reads != reads {
					t.Error("accepted failed permit remained usable with a valid context", result, *used)
				}
				assertNoEffects()
				env.Custody.RetireGenerated()
			})
		}
	}
}
