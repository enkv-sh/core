package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// This observer checks the real private handoff. It does not choose which
// results Core admits or alter a request/reply at the Crypto boundary.
type generatedRecoveredFinalEvidence struct {
	t        *testing.T
	inner    contract.Crypto
	expected contract.DescriptorVector
	frozen   contract.CryptoGeneratedFreezeRequest
	freezes  int
	claims   int
}

func (c *generatedRecoveredFinalEvidence) InstanceID() contract.ID { return c.inner.InstanceID() }
func (c *generatedRecoveredFinalEvidence) Exchange(ctx context.Context, request contract.CryptoRequest) contract.CryptoResponse {
	switch request.Kind {
	case contract.CryptoFreeze:
		frozen, err := contract.InspectCryptoGeneratedFreezeRequest(request.Body)
		if err != nil || frozen.ActualResults != c.expected || c.freezes != c.claims {
			c.t.Fatal("Final Freeze omitted complete authenticated results", frozen.ActualResults, c.expected, err)
		}
		c.frozen = frozen
	case contract.CryptoClaim:
		claim, err := contract.InspectCryptoGeneratedClaimRequest(request.Body)
		if err != nil || contract.CryptoGeneratedFreezeRequest(claim) != c.frozen || c.freezes != c.claims+1 {
			c.t.Fatal("Final Claim differs from its complete frozen evidence", err)
		}
	}
	reply := c.inner.Exchange(ctx, request)
	if reply.ResultCode == contract.CryptoSuccess {
		if request.Kind == contract.CryptoFreeze {
			c.freezes++
		}
		if request.Kind == contract.CryptoClaim {
			c.claims++
		}
	}
	return reply
}

// full_only: false
func TestGeneratedRecoveredLineagesReachExactFinal(t *testing.T) {
	// Steps are immutable create outcomes: 1=qualified no effect,
	// 2=lost result followed by residue, 3=complete success. The expected
	// counts below come from those paths, not Final's computed row set.
	for _, tc := range []struct {
		name      string
		steps     [2][]uint8
		branches  [2][]uint8
		selecting bool
		results   int
		hazards   uint32
	}{
		{"no-effect-then-success", [2][]uint8{{1, 3}, {3}}, [2][]uint8{{0, 1}, {0}}, true, 3, 0},
		{"resultless-first", [2][]uint8{{2, 2}, {3}}, [2][]uint8{{0, 2}, {0}}, false, 1, 2},
		{"resultless-last", [2][]uint8{{3}, {2, 2}}, [2][]uint8{{0}, {0, 2}}, false, 1, 2},
		{"all-resultless", [2][]uint8{{2, 2}, {2, 2}}, [2][]uint8{{0, 2}, {0, 2}}, false, 0, 4},
		{"exhausted-no-effect-branch1", [2][]uint8{{1, 1}, {3}}, [2][]uint8{{0, 1}, {0}}, false, 3, 0},
		{"exhausted-no-effect-branch3", [2][]uint8{{1, 2, 1}, {3}}, [2][]uint8{{0, 1, 3}, {0}}, false, 3, 1},
		{"exhausted-no-effect-branch4", [2][]uint8{{2, 1, 1}, {3}}, [2][]uint8{{0, 2, 4}, {0}}, false, 3, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, true)
			before := newEnvironmentFixture(t, t.Context(), env, nil, false).session
			input := generatedPlanInputForGenerations(t, before, generatedVectorID(230), []string{"alpha", "omega"}, defaultGeneratedFixtureProfile())
			reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
			facts := acquireGeneratedProducerFixtureFacts(t, env, before, reservation)
			keys := [2]*custody.Fixture{env.Custody, env.Custody.ForkGenerated(t)}
			var originals [2]*generatedPreparation
			for i := range originals {
				choice := uint8(custody.StandardValue)
				if tc.steps[i][0] == 1 {
					choice = custody.GeneratedConfirmedNoEffect
				}
				originals[i], _ = preparePrivateGeneratedOriginalProducerForAttempt(t, env, before, reservation,
					keys[i], input.requestBindings[i].AttemptID, facts, choice, nil, nil)
				t.Cleanup(keys[i].RetireGenerated)
			}
			if candidate, result := before.ClaimGeneratedOriginalSet(t.Context(), originals[:], env.Trust); candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("complete original set Claim", result)
			}
			var authority contract.ID
			if !originals[0].reservation.candidate.bindFirstSend(originals[0], func(_ context.Context, admitted contract.ID) contract.CryptoResultCode {
				authority = admitted
				return contract.CryptoSuccess
			}) {
				t.Fatal("retained initial capability handoff")
			}
			selected, result := before.selectCandidate(t.Context(), originals[0].reservation.candidate)
			if selected == nil || result.Outcome != ObservedCurrent || authority.IsZero() {
				t.Fatal("initial complete-set selection", result)
			}
			var packets [2][]byte
			for i := range originals {
				if tc.steps[i][0] != 2 {
					var code contract.CryptoResultCode
					packets[i], _, code = keys[i].InvokeGeneratedProducer(t.Context(), originals[i].operation.context.AdmissionID, originals[i].producerLocator, authority)
					if code != contract.CryptoSuccess || len(packets[i]) == 0 {
						t.Fatal("exact retained original dispatch", i, code)
					}
				}
				keys[i].RetireGenerated()
			}
			selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
			complete := make(map[contract.ID]contract.GeneratorResultReference)
			successful := make(map[contract.ID]bool)
			for lineage, steps := range tc.steps {
				for index, step := range steps {
					work := mustSelectedGeneratedWork(t, selected)
					attempt := work.phase.FrontierAttemptID
					if int(work.phase.LineageIndex) >= len(work.bundles[0].Lineages) ||
						work.bundles[0].Lineages[work.phase.LineageIndex].Name != []string{"alpha", "omega"}[lineage] ||
						work.phase.Branch != tc.branches[lineage][index] {
						t.Fatal("recovery path changed exact lineage/frontier", lineage, index, work.phase.Branch)
					}
					packet := packets[lineage]
					if index != 0 {
						prior := preparePrivateGeneratedSuccessorReservation(t, env, selected)
						if step == 2 {
							var expected contract.GeneratorResultExpectation
							selected, expected = generatedRetainedClosureEnterWithoutPacket(t, env, selected, prior)
							if expected.Template.AttemptID != attempt {
								t.Fatal("residue successor dispatched another Attempt")
							}
						} else {
							choice := uint8(custody.StandardValue)
							if step == 1 {
								choice = custody.GeneratedConfirmedNoEffect
							}
							var expected contract.GeneratorResultExpectation
							selected, _, expected, packet = selectActualGeneratedPacketRecord(t, env, selected, prior, choice, true, nil)
							if expected.Template.AttemptID != attempt {
								t.Fatal("recovery result belongs to another Attempt")
							}
						}
					}
					if step == 2 {
						selected = selectGeneratedResiduePlan(t, t.Context(), env, selected, attempt)
						continue
					}
					decoded, err := contract.InspectGeneratedResultRecord(packet)
					if err != nil || decoded.Core.AttemptID != attempt {
						t.Fatal("independent complete result identity", err)
					}
					complete[decoded.Core.ResultID] = contract.GeneratorResultReference{Schema: 1, ResultID: decoded.Core.ResultID,
						ResultBodyDigest: contract.Hash(packet), ResultLength: uint32(len(packet))}
					if step == 3 {
						successful[decoded.Core.ResultID] = true
					}
					if index == 0 {
						admitted := generatedPlanInputFixture(t, selected).context
						label := fmt.Sprintf("%s original %d Record", t.Name(), lineage)
						admitted.AdmissionID, admitted.SessionID = testID(label+" admission"), testID(label+" session")
						plan, err := selected.generatedRecordRequest(t.Context(), attempt, packet, admitted)
						if err != nil {
							t.Fatal("original Record request", err)
						}
						prepared := preparePrivateGeneratedRecord(t, env, selected, plan)
						selected, result = selected.selectCandidate(t.Context(), prepared.reservation.candidate)
						if selected == nil || result.Outcome != ObservedCurrent {
							t.Fatal("original Record selection", result)
						}
						env.Custody.RetireGenerated()
					}
					selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
				}
				if lineage == 0 {
					work := mustSelectedGeneratedWork(t, selected)
					if work.phase.Stage == contract.GeneratedStageTerminal || work.phase.FrontierAttemptID != originals[1].attempt {
						t.Fatal("terminal first lineage did not advance to its admitted sibling")
					}
				}
			}
			if len(complete) != tc.results {
				t.Fatal("fixture did not establish the independent complete evidence set", len(complete), tc.results)
			}
			admitted := generatedPlanInputFixture(t, selected).context
			admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" final admission"), testID(t.Name()+" final session")
			plan, err := selected.generatedFinalRequest(t.Context(), admitted)
			if err != nil || plan == nil || plan.selecting != tc.selecting || len(plan.results) != tc.results {
				t.Fatal("complete mixed-lineage Final request", err)
			}
			var references []contract.GeneratorResultReference
			for _, result := range plan.results {
				if expected, present := complete[result.reference.ResultID]; !present || expected != result.reference {
					t.Fatal("Final evidence differs from an actual authenticated result")
				}
				references = append(references, result.reference)
			}
			entries, duties := 0, uint32(len(successful))
			if tc.selecting {
				entries, duties = 2, 0
			}
			if len(plan.entryPlans) != entries {
				t.Fatal("complete evidence was confused with the successful selected entries")
			}
			for _, entry := range plan.entryPlans {
				if !successful[entry.Generated.CreateResultID] {
					t.Fatal("Final selected a no-effect predecessor")
				}
			}
			slices.SortFunc(references, func(a, b contract.GeneratorResultReference) int { return bytes.Compare(a.ResultID[:], b.ResultID[:]) })
			expected, err := contract.GeneratorResultReferencesDescriptor(references)
			if err != nil {
				t.Fatal(err)
			}
			observer := &generatedRecoveredFinalEvidence{t: t, inner: env.Custody.Crypto(), expected: expected}
			selected, final := preparePrivateGeneratedFinal(t, env, selected, plan, observer)
			wantHandoffs := 1
			if tc.selecting {
				wantHandoffs = 2 // Checkpoint, then fresh actual Final.
			}
			if observer.freezes != wantHandoffs || observer.claims != wantHandoffs || !final.claimed {
				t.Fatal("Final did not complete exact private Freeze/Claim", observer.freezes, observer.claims)
			}
			observed := selected.head.Core.Revision
			selected, result = selected.selectCandidate(t.Context(), final.reservation.candidate)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("Final selected HEAD", result)
			}
			env.Custody.RetireGenerated()
			cold := generatedLifecycleReopen(t, t.Context(), selected, env.Store)
			if _, err := cold.validateRelationsMode(t.Context(), false); err != nil || cold.validateGeneratedSelection(t.Context(), nil) != nil ||
				!cold.root.Generated.ActiveOwner.IsZero() || cold.root.ValueEntryCount != uint32(entries) ||
				cold.root.Generated.Duties != duties || cold.root.Generated.Hazards != tc.hazards {
				t.Fatal("cold Final lost exact selected entries or terminal owners", err, cold.root.Generated)
			}
			body, status := cold.MutationReceipt(t.Context(), input.graph.Request.OperationID)
			receipt, err := contract.InspectCompactMutationReceipt(body)
			if tc.selecting {
				observed = cold.head.Core.Revision
			}
			if status.Outcome != ObservedCurrent || err != nil || receipt.PredecessorRevisionID != before.head.Core.Revision ||
				receipt.RequestedRevisionID != cold.head.Core.Revision || receipt.ObservedRevisionID != observed ||
				receipt.PredecessorRevisionID == receipt.ObservedRevisionID {
				t.Fatal("Final receipt confused original predecessor with actual observed revision", status, err)
			}
		})
	}
}

func generatedTwoLineageUnfinishedFirst(t *testing.T, operationCtx context.Context, env fixtureEnvironment, before *StateSession,
	firstDisposition uint8) (*StateSession, contract.ID, contract.ID, []byte) {
	t.Helper()
	input := generatedPlanInputForGenerations(t, before, generatedVectorID(230), []string{"alpha", "omega"}, defaultGeneratedFixtureProfile())
	if len(input.requestBindings) != 2 {
		t.Fatal("two original request bindings required")
	}
	firstID, secondID := input.requestBindings[0].AttemptID, input.requestBindings[1].AttemptID
	reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
	if firstID.IsZero() || secondID.IsZero() || firstID == secondID ||
		len(reservation.reservation.originalAttempts) != 2 || reservation.reservation.originalAttempts[0] != firstID ||
		reservation.reservation.originalAttempts[1] != secondID {
		t.Fatal("two independent original Attempts must match their request bindings")
	}
	firstKeys, secondKeys := env.Custody, env.Custody.ForkGenerated(t)
	facts := acquireGeneratedProducerFixtureFacts(t, env, before, reservation)
	first, _ := preparePrivateGeneratedOriginalProducerForAttempt(t, env, before, reservation, firstKeys, firstID, facts,
		firstDisposition, nil, nil)
	second, _ := preparePrivateGeneratedOriginalProducerForAttempt(t, env, before, reservation, secondKeys, secondID, facts,
		custody.StandardValue, nil, nil)
	if candidate, result := before.ClaimGeneratedOriginalSet(context.Background(), []*generatedPreparation{first, second}, env.Trust); candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("complete original create set claim", result)
	}
	var packet []byte
	if !first.reservation.candidate.bindFirstSend(first, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		if firstDisposition == custody.GeneratedConfirmedNoEffect {
			var code contract.CryptoResultCode
			packet, _, code = firstKeys.InvokeGeneratedProducer(ctx, first.operation.context.AdmissionID, first.producerLocator, authority)
			return code
		}
		return contract.CryptoSuccess // A crash before entry leaves both Attempts transmitted and unobserved.
	}) {
		t.Fatal("complete original set did not grant one local send handoff")
	}
	selected, result := before.selectCandidate(context.Background(), first.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent ||
		(firstDisposition == custody.GeneratedConfirmedNoEffect) != (len(packet) != 0) {
		t.Fatal("first original entry/result", result)
	}
	firstKeys.RetireGenerated()
	secondKeys.RetireGenerated()
	return generatedLifecycleReopen(t, operationCtx, selected, env.Store), firstID, secondID, packet
}

func selectGeneratedNoEffectPlan(t *testing.T, operationCtx context.Context, env fixtureEnvironment, s *StateSession, attempt contract.ID, packet []byte) *StateSession {
	t.Helper()
	plan, err := s.generatedRecordRequest(context.Background(), attempt, packet, generatedPlanInputFixture(t, s).context)
	if err != nil {
		t.Fatal("qualified no-effect Record request", err)
	}
	p := preparePrivateGeneratedRecord(t, env, s, plan)
	selected, result := s.selectCandidate(context.Background(), p.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("qualified no-effect plan selection", result)
	}
	env.Custody.RetireGenerated()
	return generatedLifecycleReopen(t, operationCtx, selected, env.Store)
}

func selectGeneratedResiduePlan(t *testing.T, operationCtx context.Context, env fixtureEnvironment, s *StateSession, attempt contract.ID) *StateSession {
	t.Helper()
	plan, err := s.generatedCreateResidueRequest(context.Background(), attempt, generatedPlanInputFixture(t, s).context)
	if err != nil {
		t.Fatal("exact residue plan request", err)
	}
	candidate, result := s.PrepareGeneratedCreateResidue(context.Background(),
		&admittedGeneratedCreateResidue{session: s, plan: plan}, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent || candidate.firstSend != nil {
		t.Fatal("residue plan gained a send right", result)
	}
	selected, result := s.selectCandidate(context.Background(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("exact residue plan selection", result)
	}
	return generatedLifecycleReopen(t, operationCtx, selected, env.Store)
}

// full_only: false
func TestGeneratedPrivateRecoverySuccessorReservationAdvancesSecondLineage(t *testing.T) {
	paths := []struct {
		name  string
		steps []uint8 // 1: no effect; 2: no result followed by residue.
		want  uint8
	}{
		{"no-effect", []uint8{1}, 1},
		{"residue", []uint8{2}, 2},
		{"no-effect-then-residue", []uint8{1, 2}, 3},
		{"residue-then-no-effect", []uint8{2, 1}, 4},
	}
	for _, recovery := range []bool{false, true} {
		for _, path := range paths {
			for _, terminal := range []struct {
				name   string
				choice uint8
				state  uint8
			}{
				{"success", custody.StandardValue, contract.GeneratedEffectSucceeded},
				{"owned-unusable", custody.GeneratedTerminalFailure, contract.GeneratedEffectFailedTerminal},
			} {
				for _, lostRecordReply := range []bool{false, true} {
					t.Run(fmt.Sprintf("recovery=%t/%s/%s/lost-record-reply=%t", recovery, path.name, terminal.name, lostRecordReply), func(t *testing.T) {
						env, _ := genesisEnvironment(t, contract.GCP, recovery)
						before := newEnvironmentFixture(t, context.Background(), env, nil, false).session
						choice := uint8(custody.StandardValue)
						if path.steps[0] == 1 {
							choice = custody.GeneratedConfirmedNoEffect
						}
						s, firstID, secondID, packet := generatedTwoLineageUnfinishedFirst(t, t.Context(), env, before, choice)
						current := firstID
						var pendingNoEffect *generatedPreparation
						for i, step := range path.steps {
							if step == 1 {
								if pendingNoEffect == nil {
									s = selectGeneratedNoEffectPlan(t, t.Context(), env, s, current, packet)
								} else {
									planned, result := s.selectCandidate(context.Background(), pendingNoEffect.reservation.candidate)
									if planned == nil || result.Outcome != ObservedCurrent {
										t.Fatal("successor no-effect Record selection", result)
									}
									env.Custody.RetireGenerated()
									s = generatedLifecycleReopen(t, t.Context(), planned, env.Store)
									pendingNoEffect = nil
								}
							} else {
								s = selectGeneratedResiduePlan(t, t.Context(), env, s, current)
							}
							g := mustSelectedGeneratedWork(t, s)
							plannedID := g.phase.FrontierAttemptID
							lineage := g.bundles[0].Lineages[g.phase.LineageIndex]
							row, err := contract.InspectGeneratedLineageRecord(g.records[generatedRecordKey{kind: 8, id: lineage.LineageID}].Body)
							if err != nil || row.Branch == row.Frontier || !plannedID.IsZero() && g.attempts[plannedID].record.AttemptID == plannedID {
								t.Fatal("recovery transition dispatched an unreserved successor", err)
							}
							prior := preparePrivateGeneratedSuccessorReservation(t, env, s)
							if i+1 < len(path.steps) && path.steps[i+1] == 2 {
								producer, expected := preparePrivateGeneratedProducer(t, env, s, prior, nil)
								if !producer.reservation.candidate.bindFirstSend(producer, func(context.Context, contract.ID) contract.CryptoResultCode { return contract.CryptoSuccess }) {
									t.Fatal("unknown successor could not reserve its one-use entry")
								}
								entered, result := s.selectCandidate(context.Background(), producer.reservation.candidate)
								if entered == nil || result.Outcome != ObservedCurrent || expected.Template.AttemptID != plannedID {
									t.Fatal("unknown successor reservation", result)
								}
								s = generatedLifecycleReopen(t, t.Context(), entered, env.Store)
								current, packet = plannedID, nil
								continue
							}
							outcome := custody.GeneratedConfirmedNoEffect
							if i+1 == len(path.steps) {
								outcome = terminal.choice
							}
							var expected contract.GeneratorResultExpectation
							var produced *generatedPreparation
							s, produced, expected, packet = selectActualGeneratedPacketRecord(t, env, s, prior, outcome, false, nil)
							if expected.Template.AttemptID != plannedID {
								t.Fatal("successor reservation sent another Attempt")
							}
							if i+1 == len(path.steps) {
								store := env.Store.(*memoryStore)
								if lostRecordReply {
									store.casMode = "lost-after"
								}
								selected, result := s.selectCandidate(context.Background(), produced.reservation.candidate)
								store.casMode = ""
								if selected == nil || result.Outcome != ObservedCurrent {
									t.Fatal("terminal Record selection or lost-reply readback", result)
								}
								env.Custody.RetireGenerated()
								s = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
							} else {
								pendingNoEffect = produced
							}
							current = plannedID
						}
						g := mustSelectedGeneratedWork(t, generatedLifecycleReopen(t, t.Context(), s, env.Store))
						if g.phase.FrontierAttemptID != secondID || g.phase.Branch != 0 ||
							g.phase.NoEffectUsed != 0 || g.phase.ResidueUsed != 0 ||
							g.attempts[current].record.State != terminal.state {
							t.Fatal("terminal recovered branch did not advance to the next original lineage")
						}
					})
				}
			}
		}
	}
}

// full_only: false
func TestGeneratedSuccessorReservationCASReplyAndStalePredecessor(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, mode := range []string{"acknowledged", "lost-after", "stale"} {
			t.Run(fmt.Sprintf("recovery=%t/%s", recovery, mode), func(t *testing.T) {
				env, _ := genesisEnvironment(t, contract.GCP, recovery)
				before := newEnvironmentFixture(t, context.Background(), env, nil, false).session
				s, firstID, _, packet := generatedTwoLineageUnfinishedFirst(t, t.Context(), env, before, custody.GeneratedConfirmedNoEffect)
				s = selectGeneratedNoEffectPlan(t, t.Context(), env, s, firstID, packet)
				g := mustSelectedGeneratedWork(t, s)
				successor := g.phase.FrontierAttemptID
				prior := preparePrivateGeneratedSuccessorReservation(t, env, s)
				producer, _ := preparePrivateGeneratedProducer(t, env, s, prior, nil)
				calls := 0
				if !producer.reservation.candidate.bindFirstSend(producer, func(context.Context, contract.ID) contract.CryptoResultCode {
					calls++
					return contract.CryptoSuccess
				}) {
					t.Fatal("successor first-send handoff")
				}
				store := env.Store.(*memoryStore)
				switch mode {
				case "stale":
					store.mu.Lock()
					store.put(store.desc.HeadKey, s.body)
					store.mu.Unlock()
				case "lost-after":
					store.casMode = mode
				}
				selected, result := s.selectCandidate(context.Background(), producer.reservation.candidate)
				if mode == "stale" {
					if selected != nil || result.Outcome != Contention || calls != 0 {
						t.Fatal("stale predecessor reached successor send", result, calls)
					}
					return
				}
				wantCalls := 1
				if mode == "lost-after" {
					wantCalls = 0
				}
				if selected == nil || result.Outcome != ObservedCurrent || calls != wantCalls {
					t.Fatal("successor CAS reply did not preserve the exact selection and send boundary", result, calls)
				}
				cold := generatedLifecycleReopen(t, t.Context(), selected, env.Store)
				selectedWork := mustSelectedGeneratedWork(t, cold)
				if selectedWork.phase.FrontierAttemptID != successor || selectedWork.attempts[successor].record.State != contract.GeneratedEffectTransmitted {
					t.Fatal("cold successor state lost its transmitted reservation")
				}
			})
		}
	}
}
