package core

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedLateOlderDeleteAcknowledgementKeepsLaterInvocationAndConfirmationBasis(t *testing.T) {
	for _, hazard := range []bool{false, true} {
		t.Run(fmt.Sprintf("hazard=%t", hazard), func(t *testing.T) {
			s, source, ids := generatedUnknownCleanupPair(t, hazard)
			admitted := generatedLifecycleFixture(t, s)
			g := mustSelectedGeneratedWork(t, s)
			older, later := g.attempts[ids[0]], g.attempts[ids[1]]
			before, err := g.vectors.resolve(source.Record.Kind, source.SourceID, contract.GeneratorVectorHistory, source.History)
			if err != nil || len(before) < 2 {
				t.Fatal("source must retain both real delete invocations", err)
			}
			index := -1
			for i, body := range before {
				h, err := contract.InspectGeneratorHistory(body)
				if err != nil {
					t.Fatal(err)
				}
				if h.PredecessorAttemptID == older.record.AttemptID {
					index = i
					if h.Edge != 4 || h.NextAttemptID != later.record.AttemptID || h.Outcome != contract.GeneratedEffectUnknown {
						t.Fatal("older unknown delete must have its actual later-invocation edge")
					}
				}
			}
			if index < 0 || index == len(before)-1 {
				t.Fatal("fixture must target a historical, nonfinal row")
			}
			packet := generatedRetirementResultFixture(t, s, older, contract.GeneratorDispositionRetirementAcknowledged)
			selection, ok, err := g.selectGeneratedCleanup(t.Context(), map[contract.ID][]byte{older.record.ResultID: packet})
			if err != nil || !ok || selection.kind != generatedCleanupReflection || selection.closeOwner ||
				selection.attempt.record.AttemptID != older.record.AttemptID || selection.sourceKey() != (generatedRecordKey{source.Record.Kind, source.SourceID}) {
				t.Fatal("qualified old ACK must have reflection priority without closing confirmed cleanup", err)
			}
			plan, err := s.generatedReflectionPlan(t.Context(), older.record.ResultID, packet, admitted)
			if err != nil {
				t.Fatal("qualified old ACK must remain recordable after a later invocation exists", err)
			}
			reflected, err := s.deriveGeneratedReflection(t.Context(), plan)
			if err != nil {
				t.Fatal("derive exact historical ACK reflection", err)
			}
			s = reflected.state
			g = mustSelectedGeneratedWork(t, s)
			afterSource, err := contract.InspectGeneratedDeleteSource(g.records[generatedRecordKey{source.Record.Kind, source.SourceID}])
			if err != nil {
				t.Fatal(err)
			}
			after, err := g.vectors.resolve(source.Record.Kind, source.SourceID, contract.GeneratorVectorHistory, afterSource.History)
			if err != nil || len(after) != len(before) {
				t.Fatal("reflection changed history length", err)
			}
			for i := range before {
				want := before[i]
				if i == index {
					h, err := contract.InspectGeneratorHistory(want)
					if err != nil {
						t.Fatal(err)
					}
					h.ResultID, h.ResultDigest, h.Outcome = older.record.ResultID, contract.Hash(packet), contract.GeneratedEffectSucceeded
					want, err = contract.EncodeGeneratorHistory(h)
					if err != nil {
						t.Fatal(err)
					}
				}
				if !bytes.Equal(after[i], want) {
					t.Fatal("reflection changed another history row or the original successor edge", i)
				}
			}
			if g.parent != nil || g.phase != nil || !bytes.Equal(g.attempts[older.record.AttemptID].result, packet) ||
				g.attempts[later.record.AttemptID].record != later.record || len(g.attempts[later.record.AttemptID].result) != 0 ||
				afterSource.Target != source.Target || afterSource.Consumers != source.Consumers || len(g.releases) != 0 {
				t.Fatal("reflection changed later uncertainty, target, private consumers or release ownership")
			}
			progress, err := g.controlledDeleteSourceProgress(afterSource, nil, true)
			if err != nil || progress.contradiction || len(progress.rows) != 1 || progress.ack.record.AttemptID != older.record.AttemptID {
				t.Fatal("current progress must retain exactly the authenticated old ACK", err)
			}
			ackRow, err := contract.InspectGeneratorProgress(progress.rows[0])
			if err != nil || ackRow.AttemptID != older.record.AttemptID || ackRow.ResultID != older.record.ResultID ||
				ackRow.CompletedSteps != contract.GeneratorProgressAcknowledged || ackRow.Evidence.Digest != contract.Hash(packet) || ackRow.Evidence.Length != uint64(len(packet)) {
				t.Fatal("old ACK progress has changed original result coordinates or bytes", err)
			}

			// The next real probe must inherit this exact ACK and bind its request
			// to these bytes. The pre-ACK later invocation remains unchanged above.
			input := generatedOrdinaryCleanupReservationInput(t, s, afterSource, generatedVectorID(182))
			x := input.graph.Lineages[0].Templates[0]
			scope := contract.GeneratorControlledRetirementScope(x.DescriptorID, x.ConfigContractID, x.ResultContractID)
			wantRequest := contract.GeneratorControlledRetirementProbeDigest(s.root.Domain, afterSource.ResourceID, older.expected.TargetResourceDigest, scope,
				older.record.ResultID, contract.Hash(packet))
			input.requestBindings = generatedFixtureRequestBindings(input.graph, wantRequest)
			probe, err := s.deriveGeneratedReservation(t.Context(), input)
			if err != nil {
				t.Fatal("reserve confirmation from the exact historical ACK", err)
			}
			s = probe.state
			g = mustSelectedGeneratedWork(t, s)
			a := g.attempts[g.phase.FrontierAttemptID]
			rows, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.record.AttemptID, contract.GeneratorVectorProgress, a.record.Progress)
			if err != nil || a.record.RequestDigest != wantRequest || !slices.EqualFunc(rows, progress.rows, bytes.Equal) {
				t.Fatal("confirmation invocation lost its selected ACK basis", err)
			}
			confirmed := generatedHistoricalAckConfirmationFixture(t, s, a, older.record.ResultID, contract.Hash(packet))
			record, err := s.generatedRecordRequest(t.Context(), a.record.AttemptID, confirmed, generatedLifecycleFixture(t, s))
			if err != nil {
				t.Fatal("admit exact confirmation", err)
			}
			recorded, err := s.deriveGeneratedRecord(t.Context(), record)
			if err != nil {
				t.Fatal("record exact confirmation", err)
			}
			g = mustSelectedGeneratedWork(t, recorded.state)
			source, err = g.generatedDeleteSource(afterSource.OwnerID)
			if err != nil {
				t.Fatal(err)
			}
			complete, err := g.controlledDeleteSourceProgress(source, nil, true)
			if err != nil || complete.contradiction || len(complete.rows) != 2 || complete.ack.record.AttemptID != older.record.AttemptID {
				t.Fatal("confirmation must complete using the same original ACK", err)
			}
			if _, err := g.generatedOrdinaryCleanupClosure(t.Context(), a.record.AttemptID, recorded.state.head.Core.Revision); err != nil {
				t.Fatal("exact historical ACK and later confirmation must permit cleanup closure", err)
			}
			s = recorded.state
			closePlan, err := s.generatedOrdinaryCleanupClosePlan(t.Context(), a.record.AttemptID, generatedLifecycleFixture(t, s))
			if err != nil {
				t.Fatal("plan confirmed cleanup closure", err)
			}
			closed, err := s.deriveGeneratedCleanupClose(t.Context(), closePlan)
			if err != nil {
				t.Fatal("derive confirmed cleanup closure", err)
			}
			s = closed.state
			g = mustSelectedGeneratedWork(t, s)
			if _, live := g.attempts[a.record.AttemptID]; live {
				t.Fatal("confirmed attempt must use the released inspection branch")
			}
			inspection, err := s.inspectGeneratedWork(t.Context())
			if err != nil {
				t.Fatal("inspect released confirmation", err)
			}
			effect := slices.IndexFunc(inspection.effects, func(e generatedInspectedEffect) bool {
				return e.attempt.AttemptID == a.record.AttemptID
			})
			if effect < 0 || len(inspection.effects[effect].progress) != 2 {
				t.Fatal("released confirmation must expose both exact progress steps")
			}
			wantACK := bytes.Clone(inspection.effects[effect].progress[0])
			inspection.effects[effect].progress[0][0] ^= 1
			again, err := s.inspectGeneratedWork(t.Context())
			if err != nil {
				t.Fatal("released inspection exposed mutable selected ACK evidence", err)
			}
			if effect >= len(again.effects) || again.effects[effect].attempt.AttemptID != a.record.AttemptID ||
				len(again.effects[effect].progress) != 2 || !bytes.Equal(again.effects[effect].progress[0], wantACK) {
				t.Fatal("released inspection changed authenticated ACK evidence")
			}
			if err := s.validateGeneratedSelection(t.Context(), nil); err != nil {
				t.Fatal("caller mutation invalidated released selected state", err)
			}
		})
	}
}

func generatedHistoricalAckConfirmationFixture(t testing.TB, s *StateSession, a generatedAttempt, resultID, digest contract.ID) []byte {
	t.Helper()
	r, err := contract.DecodeGeneratedResultRecord(generatedRetirementResultFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged))
	if err != nil {
		t.Fatal(err)
	}
	r.SafeFacts.Schema, r.SafeFacts.Disposition = contract.GeneratorSafeFactsSchema, contract.GeneratorDispositionScopedUnusability
	r.SafeFacts.ScopeID = contract.GeneratorControlledRetirementScope(a.record.DescriptorID, a.record.ConfigContractID, a.record.ResultContractID)
	r.SafeFacts.PrecedingResultID, r.SafeFacts.PrecedingResultBodyDigest = resultID, digest
	r.SafeFacts.ObservedResourceID, r.SafeFacts.ObservedResourceDigest, r.SafeFacts.ObservedScopeID = a.record.ResourceID, a.expected.TargetResourceDigest, r.SafeFacts.ScopeID
	r.Core, err = contract.ExpectedGeneratedResultCore(a.expected, a.material, r.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	r.Transfer.Core.ResultCoreDigest, err = contract.GeneratedResultCoreDigest(r.Core)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeGeneratedResultRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func generatedUnknownCleanupPair(t *testing.T, hazard bool) (*StateSession, contract.GeneratedDeleteSource, []contract.ID) {
	t.Helper()
	s, source := generatedOrdinaryCleanupSourceState(t, contract.GeneratedCompletionConfirmed, hazard)
	var ids []contract.ID
	for invocation := byte(0); invocation < 2; invocation++ {
		reserved, err := s.deriveGeneratedReservation(t.Context(), generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(180+invocation)))
		if err != nil {
			t.Fatal("reserve actual cleanup invocation", err)
		}
		s = reserved.state
		g := mustSelectedGeneratedWork(t, s)
		a := g.attempts[g.phase.FrontierAttemptID]
		ids = append(ids, a.record.AttemptID)
		facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, a, contract.GeneratorDispositionUnknown))
		if err != nil {
			t.Fatal(err)
		}
		plan, err := s.generatedOrdinaryCleanupAmbiguityPlan(t.Context(), a.record.AttemptID, facts, generatedLifecycleFixture(t, s))
		if err != nil {
			t.Fatal("plan actual unknown cleanup", err)
		}
		parked, err := s.deriveGeneratedOrdinaryCleanupAmbiguity(t.Context(), plan)
		if err != nil {
			t.Fatal("derive actual unknown cleanup", err)
		}
		s = parked.state
		g = mustSelectedGeneratedWork(t, s)
		source, err = contract.InspectGeneratedDeleteSource(g.records[generatedRecordKey{source.Record.Kind, source.SourceID}])
		if err != nil {
			t.Fatal(err)
		}
	}
	return s, source, ids
}

// full_only: false
func TestGeneratedLateDeleteAcknowledgementsPreserveReservedConfirmationInEitherOrder(t *testing.T) {
	for _, hazard := range []bool{false, true} {
		for _, first := range []int{0, 1} {
			t.Run(fmt.Sprintf("hazard=%t/first=%d", hazard, first), func(t *testing.T) {
				s, source, ids := generatedUnknownCleanupPair(t, hazard)
				g := mustSelectedGeneratedWork(t, s)
				ack := g.attempts[ids[first]]
				packet := generatedRetirementResultFixture(t, s, ack, contract.GeneratorDispositionRetirementAcknowledged)
				plan, err := s.generatedReflectionPlan(t.Context(), ack.record.ResultID, packet, generatedLifecycleFixture(t, s))
				if err != nil {
					t.Fatal("first late ACK", err)
				}
				reflected, err := s.deriveGeneratedReflection(t.Context(), plan)
				if err != nil {
					t.Fatal("first ACK selection", err)
				}
				s = reflected.state
				g = mustSelectedGeneratedWork(t, s)
				source, err = g.generatedDeleteSource(source.OwnerID)
				if err != nil {
					t.Fatal(err)
				}
				input := generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(183))
				x := input.graph.Lineages[0].Templates[0]
				scope := contract.GeneratorControlledRetirementScope(x.DescriptorID, x.ConfigContractID, x.ResultContractID)
				request := contract.GeneratorControlledRetirementProbeDigest(s.root.Domain, source.ResourceID, ack.expected.TargetResourceDigest, scope, ack.record.ResultID, contract.Hash(packet))
				input.requestBindings = generatedFixtureRequestBindings(input.graph, request)
				reserved, err := s.deriveGeneratedReservation(t.Context(), input)
				if err != nil {
					t.Fatal("reserve exact confirmation", err)
				}
				s = reserved.state
				g = mustSelectedGeneratedWork(t, s)
				probe := g.attempts[g.phase.FrontierAttemptID]
				facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, probe, contract.GeneratorDispositionUnknown))
				if err != nil {
					t.Fatal(err)
				}
				park, err := s.generatedOrdinaryCleanupAmbiguityPlan(t.Context(), probe.record.AttemptID, facts, generatedLifecycleFixture(t, s))
				if err != nil {
					t.Fatal("park confirmation", err)
				}
				parked, err := s.deriveGeneratedOrdinaryCleanupAmbiguity(t.Context(), park)
				if err != nil {
					t.Fatal("select parked confirmation", err)
				}
				s = parked.state
				g = mustSelectedGeneratedWork(t, s)
				frozen := g.attempts[probe.record.AttemptID].record
				other := g.attempts[ids[1-first]]
				otherPacket := generatedRetirementResultFixture(t, s, other, contract.GeneratorDispositionRetirementAcknowledged)
				plan, err = s.generatedReflectionPlan(t.Context(), other.record.ResultID, otherPacket, generatedLifecycleFixture(t, s))
				if err != nil {
					t.Fatal("second late ACK must remain recordable", err)
				}
				reflected, err = s.deriveGeneratedReflection(t.Context(), plan)
				if err != nil {
					t.Fatal("second ACK selection", err)
				}
				s = reflected.state
				g = mustSelectedGeneratedWork(t, s)
				if g.attempts[probe.record.AttemptID].record != frozen || frozen.RequestDigest != request {
					t.Fatal("late ACK rewrote reserved confirmation or its original basis")
				}
				confirmed := generatedHistoricalAckConfirmationFixture(t, s, probe, ack.record.ResultID, contract.Hash(packet))
				plan, err = s.generatedReflectionPlan(t.Context(), probe.record.ResultID, confirmed, generatedLifecycleFixture(t, s))
				if err != nil {
					t.Fatal("late confirmation must use its originally selected ACK", err)
				}
				closed, err := s.deriveGeneratedCleanupClose(t.Context(), plan)
				if err != nil || closed.state.validateGeneratedSelection(t.Context(), nil) != nil {
					t.Fatal("late confirmation closure", err)
				}
			})
		}
	}
}
