package core

import (
	"bytes"
	stdcontext "context"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedPlannedSuccessorHasNoFirstSendBeforeCryptoClaim(t *testing.T) {
	predecessor := generatedEmptyPredecessor(t)
	initial, err := predecessor.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputFixture(t, predecessor))
	if err != nil {
		t.Fatal(err)
	}
	s := initial.state
	g := mustSelectedGeneratedWork(t, s)
	first := g.attempts[g.phase.FrontierAttemptID]
	record, err := s.generatedRecordRequest(stdcontext.Background(), first.record.AttemptID, generatedPublicResultFixture(t, first, 3),
		generatedContinuationContext(t, s, 230, 231))
	if err != nil {
		t.Fatal(err)
	}
	planned, err := s.deriveGeneratedRecord(stdcontext.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	s = planned.state
	plan, err := s.generatedSuccessorReservationRequest(t.Context(), generatedContinuationContext(t, s, 232, 233))
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := s.deriveGeneratedSuccessorReservation(stdcontext.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	reserved.state.generatedWork = nil
	if reserved.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("cold successor reservation did not validate")
	}
	changedState := *reserved.state
	changedState.generatedWork = nil
	changedSubject := *changedState.head.Generator
	changedSubject.PredecessorAttemptID = generatedVectorID(237)
	changedState.head.Generator = &changedSubject
	if changedState.validateGeneratedSelection(t.Context(), nil) == nil {
		t.Fatal("cold successor reservation accepted a changed predecessor")
	}
	prior := &generatedPreparation{plannedSuccessor: true, reservation: reserved, producerPhase: &plan.phase,
		producerBaseContext: plan.context}
	reserved.candidate.generated = &generatedCandidateFacts{reservation: reserved}
	reserved.candidate.producer = prior
	if reserved.candidate.generatedReady() || prior.reservation.candidate.bindFirstSend(prior, func(stdcontext.Context, contract.ID) contract.CryptoResultCode {
		return contract.CryptoSuccess
	}) {
		t.Fatal("unclaimed successor precursor acquired first-send authority")
	}
	if candidate, _ := s.persistCandidate(stdcontext.Background(), reserved.candidate, nil); candidate != nil {
		t.Fatal("unclaimed successor precursor signed a candidate")
	}
	if selected, _ := s.selectCandidate(stdcontext.Background(), reserved.candidate); selected != nil {
		t.Fatal("unclaimed successor precursor selected a candidate")
	}
	admitted := plan.context
	admitted.AdmissionID, admitted.SessionID = generatedVectorID(234), generatedVectorID(235)
	if _, preparation, err := s.generatedProducerRequest(stdcontext.Background(), prior, admitted); err != nil || preparation.AttemptID != plan.attempt {
		t.Fatal("exact planned candidate did not admit producer preparation", err)
	}
	changed := *reserved.candidate.head.Generator
	changed.PredecessorAttemptID = generatedVectorID(236)
	reserved.candidate.head.Generator = &changed
	if _, _, err := s.generatedProducerRequest(stdcontext.Background(), prior, admitted); err == nil {
		t.Fatal("changed successor candidate admitted producer preparation")
	}
}

func generatedReservePlannedSuccessor(t *testing.T, s *StateSession, nonce byte) *StateSession {
	t.Helper()
	before := mustSelectedGeneratedWork(t, s)
	planned := before.phase.FrontierAttemptID
	if _, entered := before.attempts[planned]; entered {
		t.Fatal("planned successor entered before its reservation")
	}
	plan, err := s.generatedSuccessorReservationRequest(t.Context(), generatedContinuationContext(t, s, nonce, nonce+1))
	if err != nil || plan.attempt != planned || plan.phase.TransitionKind != contract.GeneratorAuthorityReservation {
		t.Fatal("successor reservation request", err)
	}
	reserved, err := s.deriveGeneratedSuccessorReservation(stdcontext.Background(), plan)
	if err != nil || reserved.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("successor reservation", err)
	}
	after := mustSelectedGeneratedWork(t, reserved.state)
	if after.attempts[planned].record.State != contract.GeneratedEffectTransmitted ||
		after.phase.FrontierAttemptID != planned || after.phase.Phase != before.phase.Phase+1 {
		t.Fatal("successor reservation did not enter the planned Attempt")
	}
	return reserved.state
}

// full_only: false
func TestGeneratedRecordReservesNextOriginalLineageInGraphOrder(t *testing.T) {
	predecessor := generatedEmptyPredecessor(t)
	reservation, err := predecessor.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputForGenerations(t, predecessor,
		generatedVectorID(10), []string{"alpha", "omega"}))
	if err != nil {
		t.Fatal("initial generated reservation", err)
	}
	s := reservation.state
	before, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal("initial generated selection", err)
	}
	first := before.attempts[before.phase.FrontierAttemptID]
	result := generatedPublicResultFixture(t, first, 1)
	admitted := contract.ApplyContext{OperationClass: contract.CryptoGeneratedClass, AdmissionID: generatedVectorID(230),
		SessionID: generatedVectorID(231), DomainID: s.admission.domain,
		CompatibilityID: s.root.CurrentAccess.Core.CompatibilityID, Expiry: uint64(time.Now().Add(time.Minute).UnixNano()),
		PredecessorHEADDigest: contract.Hash(s.body), CurrentAccessRoot: s.root.CurrentAccess.AccessRoot}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(admitted.PredecessorRootRef[:], root)
	admitted.OriginalConditionDigest, err = contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.generatedRecordRequest(stdcontext.Background(), first.record.AttemptID, result, admitted)
	if err != nil {
		t.Fatal("record request", err)
	}
	next, err := s.deriveGeneratedRecord(stdcontext.Background(), plan)
	if err != nil {
		t.Fatal("record and schedule", err)
	}
	after, err := next.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal("scheduled selection", err)
	}
	if after.phase.Phase != 2 || after.phase.LineageIndex <= before.phase.LineageIndex ||
		after.phase.Stage != contract.GeneratedStageRetainedResult || after.phase.AcceptedResultID != (contract.ID{}) ||
		after.phase.ResultDigest != (contract.ID{}) || len(after.attempts) != 2 {
		t.Fatal("next original lineage was not reserved")
	}
	if recorded := after.attempts[first.record.AttemptID]; len(recorded.result) == 0 || recorded.record.State != contract.GeneratedEffectSucceeded {
		t.Fatal("first successful result was not retained")
	}
	frontier := after.attempts[after.phase.FrontierAttemptID]
	if frontier.record.State != contract.GeneratedEffectTransmitted || frontier.record.Stage != contract.GeneratedStageRetainedResult ||
		frontier.expected.Template.Branch != 0 || frontier.expected.Template.Action != 1 {
		t.Fatal("scheduler did not reserve the next original attempt")
	}
}

// full_only: false
func TestGeneratedRecoveredLineageAdvancesToNextOriginal(t *testing.T) {
	for _, path := range []struct {
		name   string
		steps  []uint8 // 1: qualified no effect; 2: possible-live residue.
		branch uint8
	}{
		{"no-effect", []uint8{1}, 1},
		{"residue", []uint8{2}, 2},
		{"no-effect-then-residue", []uint8{1, 2}, 3},
		{"residue-then-no-effect", []uint8{2, 1}, 4},
	} {
		outcomes := []struct {
			name        string
			disposition uint8
			state       uint8
		}{
			{"success", 1, contract.GeneratedEffectSucceeded},
			{"owned-unusable", 2, contract.GeneratedEffectFailedTerminal},
		}
		if path.branch != contract.GeneratorBranchResidue {
			outcomes = append(outcomes, struct {
				name        string
				disposition uint8
				state       uint8
			}{"exhausted-no-effect", 3, contract.GeneratedEffectConfirmedNoEffect})
		}
		for _, outcome := range outcomes {
			t.Run(path.name+"/"+outcome.name, func(t *testing.T) {
				predecessor := generatedEmptyPredecessor(t)
				reservation, err := predecessor.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputForGenerations(t, predecessor,
					generatedVectorID(10), []string{"alpha", "omega"}))
				if err != nil {
					t.Fatal(err)
				}
				s := reservation.state
				initial := mustSelectedGeneratedWork(t, s)
				initialAttempts := len(initial.attempts)
				firstLineage := initial.bundles[0].Lineages[initial.phase.LineageIndex].LineageID
				secondIndex := -1
				for i, lineage := range initial.bundles[0].Lineages {
					if lineage.Purpose == contract.GeneratorLineageCreate && lineage.LineageID != firstLineage {
						secondIndex = i
						break
					}
				}
				if secondIndex < 0 {
					t.Fatal("fixture has no second create lineage")
				}
				for i, step := range path.steps {
					g := mustSelectedGeneratedWork(t, s)
					frontier := g.attempts[g.phase.FrontierAttemptID]
					nonce := uint8(210 + i*2)
					if step == 1 {
						plan, err := s.generatedRecordRequest(stdcontext.Background(), frontier.record.AttemptID, generatedPublicResultFixture(t, frontier, 3),
							generatedContinuationContext(t, s, nonce, nonce+1))
						if err != nil {
							t.Fatal("no-effect recovery request", err)
						}
						next, err := s.deriveGeneratedRecord(stdcontext.Background(), plan)
						if err != nil {
							t.Fatal("no-effect recovery", err)
						}
						s = next.state
					} else {
						plan, err := s.generatedCreateResidueRequest(stdcontext.Background(), frontier.record.AttemptID,
							generatedContinuationContext(t, s, nonce, nonce+1))
						if err != nil {
							t.Fatal("residue recovery request", err)
						}
						next, err := s.deriveGeneratedCreateResidue(stdcontext.Background(), plan)
						if err != nil {
							t.Fatal("residue recovery", err)
						}
						s = next.state
					}
					if s.validateGeneratedSelection(t.Context(), nil) != nil {
						t.Fatal("recovery branch has invalid selected state")
					}
					planned := mustSelectedGeneratedWork(t, s)
					if _, entered := planned.attempts[planned.phase.FrontierAttemptID]; entered ||
						len(planned.attempts) != initialAttempts+i {
						t.Fatal("recovery branch entered a successor before reservation")
					}
					s = generatedReservePlannedSuccessor(t, s, uint8(240+i*2))
				}
				g := mustSelectedGeneratedWork(t, s)
				branch := g.attempts[g.phase.FrontierAttemptID]
				if branch.expected.Template.Branch != path.branch || branch.record.LineageID != firstLineage ||
					len(g.attempts) != initialAttempts+len(path.steps) {
					t.Fatal("recovery did not enter the exact first-lineage branch")
				}
				plan, err := s.generatedRecordRequest(stdcontext.Background(), branch.record.AttemptID,
					generatedPublicResultFixture(t, branch, outcome.disposition), generatedContinuationContext(t, s, 216, 217))
				if err != nil {
					t.Fatal("terminal branch request", err)
				}
				next, err := s.deriveGeneratedRecord(stdcontext.Background(), plan)
				if err != nil || next.state.validateGeneratedSelection(t.Context(), nil) != nil {
					t.Fatal("recovered lineage did not advance to a valid next original", err)
				}
				after := mustSelectedGeneratedWork(t, next.state)
				second := after.bundles[0].Lineages[secondIndex].Templates[0]
				if after.phase.LineageIndex != uint16(secondIndex) || after.phase.Branch != 0 ||
					after.phase.NoEffectUsed != 0 || after.phase.ResidueUsed != 0 ||
					after.phase.FrontierAttemptID != second.AttemptID || len(after.attempts) != len(g.attempts) ||
					after.attempts[branch.record.AttemptID].record.State != outcome.state {
					t.Fatal("next lineage did not start at its own original frontier and counters")
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedRecordCandidateCannotPrepareAnotherOriginalFirstSend(t *testing.T) {
	predecessor := generatedEmptyPredecessor(t)
	reservation, err := predecessor.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputForGenerations(t, predecessor,
		generatedVectorID(10), []string{"alpha", "omega"}))
	if err != nil {
		t.Fatal(err)
	}
	s := reservation.state
	g, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	first := g.attempts[g.phase.FrontierAttemptID]
	record, err := s.generatedRecordRequest(stdcontext.Background(), first.record.AttemptID, generatedPublicResultFixture(t, first, 1), generatedContinuationContext(t, s, 246, 247))
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := s.deriveGeneratedRecord(stdcontext.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	prior := &generatedPreparation{claimed: true, operation: &cryptoOperation{context: record.request.Context},
		reservation: recorded, producerPhase: new(contract.GeneratorPhaseIdentity)}
	*prior.producerPhase = record.phase
	authority, err := contract.GeneratorAuthorityDigest(*recorded.candidate.head.Generator)
	if err != nil {
		t.Fatal(err)
	}
	recorded.candidate.generated = &generatedCandidateFacts{reservation: recorded, authority: authority, claimed: true}
	recorded.candidate.producer = prior
	admitted := record.request.Context
	admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = generatedVectorID(248), generatedVectorID(249), contract.DescriptorVector{}
	after, err := recorded.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	if after.phase.FrontierAttemptID == first.record.AttemptID || after.attempts[after.phase.FrontierAttemptID].record.State != contract.GeneratedEffectTransmitted {
		t.Fatal("Record did not advance to the already transmitted original")
	}
	if _, _, err := s.generatedProducerRequest(stdcontext.Background(), prior, admitted); err == nil {
		t.Fatal("Record created another original first-send permission")
	}
	if _, _, err := s.generatedOriginalProducerRequest(stdcontext.Background(), prior, after.phase.FrontierAttemptID, admitted); err == nil {
		t.Fatal("Record admitted complete-original preparation")
	}
	if !recorded.candidate.generatedReady() || recorded.candidate.generated.producerMode.Load() == uint32(generatedOriginalSetMode) {
		t.Fatal("producer refusal changed Record candidate readiness")
	}
	bad := *prior.producerPhase
	bad.AfterPhase++
	prior.producerPhase = &bad
	if _, _, err := s.generatedProducerRequest(stdcontext.Background(), prior, admitted); err == nil {
		t.Fatal("changed scheduling phase granted first-send preparation")
	}
	if _, _, err := recorded.state.generatedProducerRequest(stdcontext.Background(), nil, admitted); err == nil {
		t.Fatal("cold selected reservation reconstructed a first-send permit")
	}
}

// full_only: false
func TestGeneratedFinalPlanBindsCompleteSuccessfulResultSet(t *testing.T) {
	predecessor := generatedEmptyPredecessor(t)
	reservation, err := predecessor.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputFixture(t, predecessor))
	if err != nil {
		t.Fatal("initial generated reservation", err)
	}
	s := reservation.state
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[g.phase.FrontierAttemptID]
	result := generatedPublicResultFixture(t, a, 1)
	admitted := generatedContinuationContext(t, s, 232, 233)
	record, err := s.generatedRecordRequest(stdcontext.Background(), a.record.AttemptID, result, admitted)
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := s.deriveGeneratedRecord(stdcontext.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	finalContext := generatedContinuationContext(t, recorded.state, 234, 235)
	plan, err := recorded.state.generatedFinalRequest(t.Context(), finalContext)
	if err != nil {
		t.Fatal("final plan", err)
	}
	if plan.request.Purpose != 3 || plan.phase.TransitionKind != contract.GeneratorAuthorityFinal ||
		plan.phase.BeforePhase != 2 || plan.phase.AfterPhase != 3 || len(plan.results) != 1 || len(plan.entryPlans) != 1 ||
		plan.results[0].reference.ResultID != a.record.ResultID || plan.entryPlans[0].Generated.CreateResultID != a.record.ResultID ||
		plan.entryPlans[0].ValueCore.ValueStateID != plan.entryPlans[0].Generated.GenerationID {
		t.Fatal("final plan omitted aggregate result or generated member")
	}
	if recorded.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("terminal selection was not valid before finalization")
	}
	selected := mustSelectedGeneratedWork(t, recorded.state)
	selected.bundles[0].Request.OperationKind = 31
	if wrong, err := recorded.state.generatedFinalRequest(t.Context(), finalContext); wrong != nil || err == nil {
		t.Fatal("create finalization accepted a cleanup operation kind")
	}
}

// full_only: false
func TestGeneratedNoEffectBranchRetainsOrderedPredecessorResult(t *testing.T) {
	predecessor := generatedEmptyPredecessor(t)
	reservation, err := predecessor.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputFixture(t, predecessor))
	if err != nil {
		t.Fatal("initial generated reservation", err)
	}
	s := reservation.state
	g := mustSelectedGeneratedWork(t, s)
	first := g.attempts[g.phase.FrontierAttemptID]
	record, err := s.generatedRecordRequest(stdcontext.Background(), first.record.AttemptID, generatedPublicResultFixture(t, first, 3), generatedContinuationContext(t, s, 210, 211))
	if err != nil || record.phase.TransitionKind != contract.GeneratorAuthorityNoEffectBranch {
		t.Fatal("no-effect branch request", err)
	}
	recovered, err := s.deriveGeneratedRecord(stdcontext.Background(), record)
	if err != nil {
		t.Fatal("schedule no-effect successor", err)
	}
	g = mustSelectedGeneratedWork(t, recovered.state)
	if len(g.attempts) != 1 || g.phase.Branch != 1 || g.phase.NoEffectUsed != 1 || g.phase.ResidueUsed != 0 ||
		g.phase.Stage != contract.GeneratedStageRetainedResult || !g.phase.AcceptedResultID.IsZero() || !g.phase.ResultDigest.IsZero() {
		t.Fatal("no-effect successor did not consume exactly one allowance")
	}
	if _, entered := g.attempts[g.phase.FrontierAttemptID]; entered {
		t.Fatal("no-effect plan dispatched before reservation")
	}
	if _, err := recovered.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recovered.state, 253, 254)); err == nil {
		t.Fatal("unentered no-effect successor allowed Final")
	}
	s = generatedReservePlannedSuccessor(t, recovered.state, 250)
	g = mustSelectedGeneratedWork(t, s)
	successor := g.attempts[g.phase.FrontierAttemptID]
	historyBodies, err := g.vectors.resolve(9, successor.record.AttemptID, contract.GeneratorVectorHistory, successor.record.History)
	if err != nil || len(historyBodies) != 2 {
		t.Fatal("successor lost exact predecessor history", err)
	}
	h0, err := contract.InspectGeneratorHistory(historyBodies[0])
	if err != nil || h0.PredecessorAttemptID != first.record.AttemptID || h0.NextAttemptID != successor.record.AttemptID ||
		h0.ResultID != first.record.ResultID || h0.ResultDigest != contract.Hash(record.result) ||
		h0.Outcome != contract.GeneratedEffectConfirmedNoEffect || h0.Edge != 1 {
		t.Fatal("successor history did not bind the qualified no-effect result")
	}
	record, err = s.generatedRecordRequest(stdcontext.Background(), successor.record.AttemptID, generatedPublicResultFixture(t, successor, 1), generatedContinuationContext(t, s, 212, 213))
	if err != nil {
		t.Fatal("successor result request", err)
	}
	terminal, err := s.deriveGeneratedRecord(stdcontext.Background(), record)
	if err != nil {
		t.Fatal("record successor result", err)
	}
	g = mustSelectedGeneratedWork(t, terminal.state)
	if len(g.attempts) != 2 || g.phase.Stage != contract.GeneratedStageTerminal {
		t.Fatal("successful recovery installed an extra Attempt")
	}
	plan, err := terminal.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, terminal.state, 214, 215))
	if err != nil {
		t.Fatal("aggregate recovered lineage", err)
	}
	if !plan.selecting || len(plan.results) != 2 || len(plan.entryPlans) != 1 ||
		plan.results[0].attempt.record.AttemptID != first.record.AttemptID ||
		plan.results[1].attempt.record.AttemptID != successor.record.AttemptID ||
		plan.entryPlans[0].Generated.OriginAttemptID != successor.record.AttemptID {
		t.Fatal("final aggregate did not retain predecessor order and select the terminal frontier")
	}
}

// full_only: false
func TestGeneratedCreateResidueInstallsOnlyFixedSuccessor(t *testing.T) {
	predecessor := generatedEmptyPredecessor(t)
	reservation, err := predecessor.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputFixture(t, predecessor))
	if err != nil {
		t.Fatal("initial generated reservation", err)
	}
	s := reservation.state
	g := mustSelectedGeneratedWork(t, s)
	first := g.attempts[g.phase.FrontierAttemptID]
	plan, err := s.generatedCreateResidueRequest(stdcontext.Background(), first.record.AttemptID, generatedContinuationContext(t, s, 216, 217))
	if err != nil || plan.phase.TransitionKind != contract.GeneratorAuthorityResidue {
		t.Fatal("residue request", err)
	}
	recovered, err := s.deriveGeneratedCreateResidue(stdcontext.Background(), plan)
	if err != nil {
		t.Fatal("residue transition", err)
	}
	g = mustSelectedGeneratedWork(t, recovered.state)
	if recovered.state.validateGeneratedSelection(t.Context(), nil) != nil || len(g.attempts) != 1 || recovered.state.root.Generated.Hazards != 1 ||
		g.phase.Branch != 2 || g.phase.NoEffectUsed != 0 || g.phase.ResidueUsed != 1 ||
		g.phase.Stage != contract.GeneratedStageRetainedResult || !g.phase.AcceptedResultID.IsZero() || !g.phase.ResultDigest.IsZero() {
		t.Fatal("residue successor did not consume exactly one allowance")
	}
	closed := g.attempts[first.record.AttemptID]
	if closed.record.State != contract.GeneratedEffectClosedWithResidue || len(closed.result) != 0 {
		t.Fatal("residue changed the original result coordinate")
	}
	hazard, ok := g.records[generatedRecordKey{kind: 11, id: first.expected.Template.HazardID}]
	if !ok {
		t.Fatal("residue lost the exact possible-live Hazard")
	}
	h, err := contract.InspectGeneratedHazardRecord(hazard.Body)
	if err != nil || h.OriginalAttemptID != first.record.AttemptID || h.OwnerID != first.record.OwnerID || h.Fenced != 1 {
		t.Fatal("residue Hazard was retargeted", err)
	}
	if _, entered := g.attempts[g.phase.FrontierAttemptID]; entered {
		t.Fatal("residue plan dispatched before reservation")
	}
	if _, err := recovered.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recovered.state, 253, 254)); err == nil {
		t.Fatal("unentered residue successor allowed Final")
	}
	s = generatedReservePlannedSuccessor(t, recovered.state, 252)
	g = mustSelectedGeneratedWork(t, s)
	successor := g.attempts[g.phase.FrontierAttemptID]
	if successor.expected.Template.Branch != 2 || successor.expected.Template.PredecessorAttemptID != first.record.AttemptID {
		t.Fatal("residue did not install the fixed branch")
	}
}

// full_only: false
func TestGeneratedRecoveryOrdersConsumeEachAllowanceOnce(t *testing.T) {
	for _, order := range []string{"no-effect-then-residue", "residue-then-no-effect"} {
		t.Run(order, func(t *testing.T) {
			predecessor := generatedEmptyPredecessor(t)
			reservation, err := predecessor.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputFixture(t, predecessor))
			if err != nil {
				t.Fatal(err)
			}
			s := reservation.state
			var firstResult contract.ID
			stepNoEffect := func(input *StateSession, nonce byte) *StateSession {
				g := mustSelectedGeneratedWork(t, input)
				a := g.attempts[g.phase.FrontierAttemptID]
				record, err := input.generatedRecordRequest(stdcontext.Background(), a.record.AttemptID, generatedPublicResultFixture(t, a, 3),
					generatedContinuationContext(t, input, nonce, nonce+1))
				if err != nil {
					t.Fatal("no-effect request", err)
				}
				firstResult = a.record.ResultID
				next, err := input.deriveGeneratedRecord(stdcontext.Background(), record)
				if err != nil {
					t.Fatal("no-effect transition", err)
				}
				return next.state
			}
			stepResidue := func(input *StateSession, nonce byte) *StateSession {
				g := mustSelectedGeneratedWork(t, input)
				plan, err := input.generatedCreateResidueRequest(stdcontext.Background(), g.phase.FrontierAttemptID,
					generatedContinuationContext(t, input, nonce, nonce+1))
				if err != nil {
					t.Fatal("residue request", err)
				}
				next, err := input.deriveGeneratedCreateResidue(stdcontext.Background(), plan)
				if err != nil {
					t.Fatal("residue transition", err)
				}
				return next.state
			}
			if order == "no-effect-then-residue" {
				s = stepNoEffect(s, 218)
				s = generatedReservePlannedSuccessor(t, s, 244)
				s = stepResidue(s, 220)
			} else {
				s = stepResidue(s, 222)
				s = generatedReservePlannedSuccessor(t, s, 246)
				s = stepNoEffect(s, 224)
			}
			s = generatedReservePlannedSuccessor(t, s, 248)
			g := mustSelectedGeneratedWork(t, s)
			if len(g.attempts) != 3 || g.phase.NoEffectUsed != 1 || g.phase.ResidueUsed != 1 ||
				(order == "no-effect-then-residue" && g.phase.Branch != 3) ||
				(order == "residue-then-no-effect" && g.phase.Branch != 4) {
				t.Fatal("recovery order did not consume exact independent allowances")
			}
			frontier := g.attempts[g.phase.FrontierAttemptID]
			record, err := s.generatedRecordRequest(stdcontext.Background(), frontier.record.AttemptID, generatedPublicResultFixture(t, frontier, 1),
				generatedContinuationContext(t, s, 226, 227))
			if err != nil {
				t.Fatal("frontier success request", err)
			}
			terminal, err := s.deriveGeneratedRecord(stdcontext.Background(), record)
			if err != nil {
				t.Fatal("frontier success", err)
			}
			g = mustSelectedGeneratedWork(t, terminal.state)
			if len(g.attempts) != 3 || g.phase.Stage != contract.GeneratedStageTerminal {
				t.Fatal("recovery entered a fourth Attempt")
			}
			final, err := terminal.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, terminal.state, 228, 229))
			if err != nil {
				t.Fatal("terminal aggregate", err)
			}
			if !final.selecting || len(final.results) != 2 || len(final.entryPlans) != 1 ||
				final.results[0].reference.ResultID != firstResult || final.results[1].reference.ResultID != frontier.record.ResultID ||
				final.entryPlans[0].Generated.OriginAttemptID != frontier.record.AttemptID {
				t.Fatal("terminal aggregate lost predecessor order or selected the wrong frontier")
			}
			prepared := []contract.CryptoGeneratedValueEntryResult{generatedPreparedValueEntryFixture(t, terminal.state, final.entryPlans[0])}
			selected, err := terminal.state.deriveGeneratedFinal(t.Context(), final, prepared)
			if err != nil {
				t.Fatal("terminal selected aggregate", err)
			}
			closed := mustSelectedGeneratedWork(t, selected.state)
			if closed.parent != nil || closed.phase != nil || len(closed.attempts) != 1 ||
				selected.state.root.Generated.Attempts != 1 || selected.state.root.Generated.Hazards != 1 ||
				selected.state.root.Generated.Materials != 1 || selected.state.root.Generated.Graphs.Count != 1 ||
				selected.state.validateGeneratedSelection(t.Context(), nil) != nil {
				t.Fatal("selected aggregate dropped its exact possible-live effect")
			}
			for _, retained := range closed.attempts {
				if retained.record.State != contract.GeneratedEffectClosedWithResidue || len(retained.result) != 0 {
					t.Fatal("selected aggregate retained the wrong effect")
				}
			}
			if _, ok := selected.state.materialAccess(3, final.request.MaterialID); !ok {
				t.Fatal("selected aggregate dropped the possible-live effect seed")
			}
			windows, err := selected.state.receiptWindows(t.Context())
			if err != nil || len(windows.Successes) != 1 {
				t.Fatal("selected aggregate receipt", err)
			}
			receipt := windows.Successes[0]
			if receipt.OperationID != final.request.Parent.OperationID || receipt.RequestIdentityDigest != final.request.Parent.RequestIdentityDigest ||
				receipt.StateResult != 1 || receipt.EffectSummary != 2 || receipt.WarningBits != contract.ReceiptWarningPossibleLive ||
				receipt.SummaryCounts[contract.ReceiptEffectCount] != 3 || receipt.SummaryCounts[contract.ReceiptSummarySuccessCount] != 1 ||
				receipt.SummaryCounts[contract.ReceiptPreservedResidueCount] != 1 || receipt.SummaryCounts[contract.ReceiptNoEffectPredecessorCount] != 1 ||
				receipt.UnknownCount != 1 {
				t.Fatal("selected aggregate receipt lost complete ordered effect classes", receipt)
			}
		})
	}
}

// full_only: false
func TestGeneratedFinalCandidateContainsOneCompleteCanonicalSet(t *testing.T) {
	predecessor := generatedEmptyPredecessor(t)
	reservation, err := predecessor.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputForGenerations(t, predecessor,
		generatedVectorID(10), []string{"alpha", "omega"}))
	if err != nil {
		t.Fatal("initial generated reservation", err)
	}
	s := reservation.state
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := g.attempts[g.phase.FrontierAttemptID]
	record, err := s.generatedRecordRequest(stdcontext.Background(), first.record.AttemptID, generatedPublicResultFixture(t, first, 1), generatedContinuationContext(t, s, 236, 237))
	if err != nil {
		t.Fatal("record request", err)
	}
	recorded, err := s.deriveGeneratedRecord(stdcontext.Background(), record)
	if err != nil {
		t.Fatal("record result", err)
	}
	g, err = recorded.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	second := g.attempts[g.phase.FrontierAttemptID]
	record, err = recorded.state.generatedRecordRequest(stdcontext.Background(), second.record.AttemptID, generatedPublicResultFixtureWithRawToken(t, second, 1, 1, generatedVectorID(98)), generatedContinuationContext(t, recorded.state, 238, 239))
	if err != nil {
		t.Fatal("second record request", err)
	}
	recorded, err = recorded.state.deriveGeneratedRecord(stdcontext.Background(), record)
	if err != nil {
		t.Fatal("record second result", err)
	}
	plan, err := recorded.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded.state, 244, 245))
	if err != nil {
		t.Fatal("final plan", err)
	}
	if len(plan.entryPlans) != 2 || len(plan.results) != 2 {
		t.Fatal("final plan did not bind both completed lineages")
	}
	prepared := make([]contract.CryptoGeneratedValueEntryResult, len(plan.entryPlans))
	for i := range plan.entryPlans {
		prepared[i] = generatedPreparedValueEntryFixture(t, recorded.state, plan.entryPlans[i])
	}
	if _, err := recorded.state.deriveGeneratedFinal(t.Context(), plan, prepared[:1]); err == nil {
		t.Fatal("partial generated entry set accepted in final candidate")
	}
	changed := append([]contract.CryptoGeneratedValueEntryResult(nil), prepared...)
	changed[1].ResultDigest[0] ^= 1
	if _, err := recorded.state.deriveGeneratedFinal(t.Context(), plan, changed); err == nil {
		t.Fatal("changed generated entry set accepted in final candidate")
	}
	final, err := recorded.state.deriveGeneratedFinal(t.Context(), plan, prepared)
	if err != nil {
		t.Fatal("final candidate construction", err)
	}
	if final.candidate.head.Generator == nil || final.candidate.head.Generator.Purpose != contract.GeneratorAuthorityFinal ||
		final.state.validateGeneratedSelection(t.Context(), nil) != nil || final.state.root.Generated.GeneratedCurrent != 2 ||
		!final.state.root.Generated.ActiveOwner.IsZero() || !final.state.root.Generated.ActivePhase.IsZero() ||
		!final.state.root.Generated.ActiveGraph.IsZero() || final.state.root.ValueEntryCount != 2 || final.state.root.AccessRecordCount != 2 {
		t.Fatal("final candidate did not contain the complete canonical generated set")
	}
	for _, entryPlan := range plan.entryPlans {
		entry := final.state.valueEntry(entryPlan.Slot)
		if entry == nil || entry.Generated != entryPlan.Generated || entry.ValueState != entryPlan.ValueCore.ValueStateID {
			t.Fatal("final candidate generated entry differs from the prepared result")
		}
	}
	selected, err := final.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil || selected.parent != nil || selected.phase != nil || len(selected.attempts) != 0 {
		t.Fatal("final candidate retained active operation state", err)
	}
	for _, row := range final.state.accessRecords() {
		if row.MaterialKind == 3 {
			t.Fatal("final candidate retained the completed operation seed")
		}
	}
	replayed, err := recorded.state.deriveGeneratedFinal(t.Context(), plan, prepared)
	if err != nil || replayed.state.head.Core != final.state.head.Core || replayed.state.root.CurrentAccess.AccessRoot != final.state.root.CurrentAccess.AccessRoot {
		t.Fatal("identical terminal replay derived a different final candidate state", err)
	}
}

// full_only: false
func TestGeneratedRotationCandidateRetainsExactOldResourceRetirement(t *testing.T) {
	predecessor := generatedEmptyPredecessor(t)
	selected := deriveGeneratedSingleFinalFixture(t, predecessor, generatedReservationInputFixture(t, predecessor), 180)
	old := *selected.valueEntry(0)
	nextProfile := defaultGeneratedFixtureProfile()
	nextProfile.ConfigContractID, nextProfile.ResourceContractID = generatedVectorID(188), generatedVectorID(189)
	input := generatedReservationInputForState(t, selected, generatedVectorID(181), []string{old.Name}, nextProfile,
		old.Generated.Epoch+1, map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old})
	declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil {
		t.Fatal(err)
	}
	withoutRetirement := input.graph
	withoutRetirement.Lineages = slices.DeleteFunc(slices.Clone(withoutRetirement.Lineages), func(v contract.GeneratorLineageTemplate) bool { return v.Purpose == 2 })
	withoutRetirement.Header.TemplateCount--
	if _, err := selected.generatedAdmissionShape(t.Context(), withoutRetirement, declaration, mustSelectedGeneratedWork(t, selected)); err == nil {
		t.Fatal("rotation admission omitted the old-resource retirement template")
	}
	context := generatedContinuationContext(t, selected, 182, 183)
	public := generatedPlanInput{graph: input.graph, declaration: input.declaration, registry: input.graph.Request.Registry,
		recoveryPolicy: input.graph.Request.RecoveryPolicyID, context: context, requestBindings: slices.Clone(input.requestBindings)}
	if _, err := selected.generatedPlanRequest(t.Context(), public); err != nil {
		t.Fatal("exact rotation admission refused", err)
	}
	reservation, err := selected.deriveGeneratedReservation(stdcontext.Background(), input)
	if err != nil {
		t.Fatal("rotation reservation", err)
	}
	active := reservation.state
	g := mustSelectedGeneratedWork(t, active)
	a := g.attempts[g.phase.FrontierAttemptID]
	record, err := active.generatedRecordRequest(stdcontext.Background(), a.record.AttemptID, generatedPublicResultFixture(t, a, 1), generatedContinuationContext(t, active, 184, 185))
	if err != nil {
		t.Fatal("rotation result request", err)
	}
	recorded, err := active.deriveGeneratedRecord(stdcontext.Background(), record)
	if err != nil {
		t.Fatal("rotation result", err)
	}
	plan, err := recorded.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded.state, 186, 187))
	if err != nil {
		t.Fatal("rotation final plan", err)
	}
	if len(plan.retirements) != 1 || plan.retirements[0].target.ResourceID != old.Generated.ResourceIncarnationID ||
		plan.entryPlans[0].Generated.RetiringDutyPresent != 1 || plan.entryPlans[0].Generated.RetiringDutyID != plan.retirements[0].template.DutyID {
		t.Fatal("final plan did not bind the exact displaced generation")
	}
	prepared := []contract.CryptoGeneratedValueEntryResult{generatedPreparedValueEntryFixture(t, recorded.state, plan.entryPlans[0])}
	final, err := recorded.state.deriveGeneratedFinal(t.Context(), plan, prepared)
	if err != nil {
		t.Fatal("rotation final candidate construction", err)
	}
	next := final.state.valueEntry(0)
	if next == nil || next.Generated.RetiringDutyPresent != 1 || next.Generated.RetiringDutyID != plan.retirements[0].template.DutyID ||
		next.Generated.ResourceIncarnationID == old.Generated.ResourceIncarnationID || final.state.root.Generated.Retiring != 1 {
		t.Fatal("final candidate generation did not retain one exact retirement handoff")
	}
	closure := mustSelectedGeneratedWork(t, final.state)
	dutyRow, ok := closure.records[generatedRecordKey{kind: 10, id: next.Generated.RetiringDutyID}]
	if !ok {
		t.Fatal("detached retirement duty missing")
	}
	duty, err := contract.InspectGeneratedDutyRecord(dutyRow.Body)
	if err != nil || duty.Kind != contract.GeneratedDutyRetirement || duty.Status != contract.GeneratedEffectNotStarted ||
		duty.OriginalOperationID != old.Generated.OriginOperationID || duty.OriginalAttemptID != old.Generated.OriginAttemptID {
		t.Fatal("detached retirement duty changed the old owner", err)
	}
	target, err := closure.retirementTarget(t.Context(), duty)
	if err != nil || target.Name != old.Name || target.IncarnationID != old.Incarnation || target.Epoch != old.Generated.Epoch ||
		target.ResourceID != old.Generated.ResourceIncarnationID || target.ResourceDigest != old.Generated.ResourceDigest ||
		target.ConfigContractID != old.Generated.ConfigContractID || target.ResourceContractID != old.Generated.ResourceContractID || target.CompletionClass != old.Generated.CompletionClass {
		t.Fatal("detached retirement target did not preserve the exact old resource", err)
	}
	if _, ok := final.state.materialAccess(1, old.ValueState); ok {
		t.Fatal("detached retirement retained the displaced private value")
	}
}

// full_only: false
func TestGeneratedFailedRotationPreservesOldSelectionWithoutRetirement(t *testing.T) {
	predecessor := generatedEmptyPredecessor(t)
	selected := deriveGeneratedSingleFinalFixture(t, predecessor, generatedReservationInputFixture(t, predecessor), 180)
	old := *selected.valueEntry(0)
	profile := defaultGeneratedFixtureProfile()
	profile.ConfigContractID, profile.ResourceContractID = generatedVectorID(188), generatedVectorID(189)
	input := generatedReservationInputForState(t, selected, generatedVectorID(181), []string{old.Name}, profile,
		old.Generated.Epoch+1, map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old})
	reservation, err := selected.deriveGeneratedReservation(stdcontext.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	active := reservation.state
	g := mustSelectedGeneratedWork(t, active)
	a := g.attempts[g.phase.FrontierAttemptID]
	result := generatedPublicResultFixtureWithRawToken(t, a, 2, 0, generatedVectorID(98))
	record, err := active.generatedRecordRequest(stdcontext.Background(), a.record.AttemptID, result, generatedContinuationContext(t, active, 184, 185))
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := active.deriveGeneratedRecord(stdcontext.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := recorded.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded.state, 186, 187))
	if err != nil || plan.selecting || len(plan.retirements) != 0 {
		t.Fatal("failed rotation planned retirement of the selected predecessor", err)
	}
	final, err := recorded.state.deriveGeneratedFinal(t.Context(), plan, nil)
	if err != nil || final.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("failed rotation did not close", err)
	}
	if entry := final.state.valueEntry(0); entry == nil || !sameRetainedEntryValue(*entry, old) ||
		final.state.root.Generated.Retiring != selected.root.Generated.Retiring ||
		final.state.root.Generated.FailureWindow.Count != selected.root.Generated.FailureWindow.Count+1 {
		t.Fatal("failed rotation changed the old value or omitted its failure receipt")
	}
	work := mustSelectedGeneratedWork(t, final.state)
	for key, row := range work.records {
		if key.kind != 10 {
			continue
		}
		duty, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil || duty.Kind == contract.GeneratedDutyRetirement {
			t.Fatal("failed rotation installed a phantom retirement", err)
		}
	}
	locations, err := format.ResolveGeneratedSlices(final.state.root.Domain, final.state.root.Snapshot,
		final.state.root.Generated, final.state.support)
	if err != nil {
		t.Fatal("failed-final slice locations", err)
	}
	groups, err := generatedReservationGroupsForState(final.state, final.state.supportRecords(), locations, work.bundles)
	if err != nil {
		t.Fatal("failed-final support groups", err)
	}
	occupied := generatedNonSupportChildCount(final.state.root, len(final.state.root.CurrentAccess.Core.AccessPageRefs))
	packed, err := format.PackRequiredSupportRows(final.state.root.Domain, groups, occupied)
	if err != nil || len(packed) != len(final.state.root.RequiredSupport) || occupied+uint32(len(packed)) != final.state.root.ChildCount {
		t.Fatal("failed-final successor packing differs from selected closure", err)
	}
	assertGeneratedPackingBoundary(t, final.state.root.Domain, groups, len(packed))
}

// The groups come from a real successor. Vary only its already occupied
// non-support child count to test the packer's exact root-child limit.
func assertGeneratedPackingBoundary(t *testing.T, domain contract.ID, groups []format.RequiredSupportGroup, supportPages int) {
	t.Helper()
	if supportPages < 1 || supportPages > 255 {
		t.Fatalf("boundary fixture has %d support pages", supportPages)
	}
	for _, total := range []int{255, 256, 257} {
		occupied := uint32(total - supportPages)
		pages, err := format.PackRequiredSupportRows(domain, groups, occupied)
		if total <= contract.MaxChildPages {
			if err != nil || len(pages) != supportPages || occupied+uint32(len(pages)) != uint32(total) {
				t.Fatalf("real successor groups rejected %d-child fit: pages=%d error=%v", total, len(pages), err)
			}
		} else if err != format.ErrFormat {
			t.Fatalf("real successor groups accepted %d children: pages=%d error=%v", total, len(pages), err)
		}
	}
}

func deriveGeneratedSingleFinalFixture(t testing.TB, predecessor *StateSession, input generatedReservationInput, id byte) *StateSession {
	t.Helper()
	reservation, err := predecessor.deriveGeneratedReservation(stdcontext.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	g := mustSelectedGeneratedWork(t, reservation.state)
	a := g.attempts[g.phase.FrontierAttemptID]
	record, err := reservation.state.generatedRecordRequest(stdcontext.Background(), a.record.AttemptID, generatedPublicResultFixture(t, a, 1),
		generatedContinuationContext(t, reservation.state, id, id+1))
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := reservation.state.deriveGeneratedRecord(stdcontext.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := recorded.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded.state, id+2, id+3))
	if err != nil {
		t.Fatal(err)
	}
	prepared := []contract.CryptoGeneratedValueEntryResult{generatedPreparedValueEntryFixture(t, recorded.state, plan.entryPlans[0])}
	final, err := recorded.state.deriveGeneratedFinal(t.Context(), plan, prepared)
	if err != nil {
		t.Fatal(err)
	}
	generatedInstallFixtureSupportReader(t, final.state)
	generatedVerifySelectedFixtureSlices(t, final.state)
	return final.state
}

func mustSelectedGeneratedWork(t testing.TB, s *StateSession) *generatedSelection {
	t.Helper()
	g, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// full_only: false
func TestGeneratedTerminalFailureClosesAfterSiblingAndPreservesPredecessor(t *testing.T) {
	predecessor := generatedEmptyPredecessor(t)
	reservation, err := predecessor.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputForGenerations(t, predecessor,
		generatedVectorID(10), []string{"alpha", "omega"}))
	if err != nil {
		t.Fatal(err)
	}
	s := reservation.state
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := g.attempts[g.phase.FrontierAttemptID]
	firstPlan, err := s.generatedRecordRequest(stdcontext.Background(), first.record.AttemptID, generatedPublicResultFixture(t, first, 1), generatedContinuationContext(t, s, 250, 251))
	if err != nil {
		t.Fatal(err)
	}
	firstRecord, err := s.deriveGeneratedRecord(stdcontext.Background(), firstPlan)
	if err != nil {
		t.Fatal(err)
	}
	g, err = firstRecord.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	second := g.attempts[g.phase.FrontierAttemptID]
	secondPlan, err := firstRecord.state.generatedRecordRequest(stdcontext.Background(), second.record.AttemptID, generatedPublicResultFixtureWithRawToken(t, second, 2, 0, generatedVectorID(98)), generatedContinuationContext(t, firstRecord.state, 252, 253))
	if err != nil {
		t.Fatal(err)
	}
	secondRecord, err := firstRecord.state.deriveGeneratedRecord(stdcontext.Background(), secondPlan)
	if err != nil {
		t.Fatal(err)
	}
	finalPlan, err := secondRecord.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, secondRecord.state, 254, 255))
	if err != nil {
		t.Fatal("failed final request", err)
	}
	if finalPlan.selecting || len(finalPlan.results) != 2 || len(finalPlan.entryPlans) != 0 {
		t.Fatal("failed aggregate exposed a partial selected set")
	}
	final, err := secondRecord.state.deriveGeneratedFinal(t.Context(), finalPlan, nil)
	if err != nil {
		t.Fatal("failed final closure", err)
	}
	if final.state.validateGeneratedSelection(t.Context(), nil) != nil || final.state.root.ValueEntryCount != predecessor.root.ValueEntryCount ||
		final.state.root.Generated.GeneratedCurrent != predecessor.root.Generated.GeneratedCurrent ||
		!final.state.root.Generated.ActiveOwner.IsZero() || !final.state.root.Generated.ActivePhase.IsZero() ||
		!final.state.root.Generated.ActiveGraph.IsZero() {
		t.Fatal("failed aggregate changed the selected predecessor")
	}
	selected, err := final.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil || selected.parent != nil || selected.phase != nil || len(selected.attempts) != 2 {
		t.Fatal("failed aggregate did not retain every entered owner", err)
	}
	cleanup := selected.attempts[first.record.AttemptID]
	dutyRow, ok := selected.records[generatedRecordKey{kind: 10, id: cleanup.record.OwnerID}]
	if !ok {
		t.Fatal("successful unselected create lost its cleanup Duty")
	}
	duty, err := contract.InspectGeneratedDutyRecord(dutyRow.Body)
	if err != nil || duty.Kind != contract.GeneratedDutyUnselectedCleanup || duty.Status != contract.GeneratedEffectSucceeded {
		t.Fatal("successful unselected create did not become nondispatchable cleanup", err)
	}
	failed, ok := selected.attempts[second.record.AttemptID]
	if !ok || failed.expected != second.expected || failed.record.State != contract.GeneratedEffectFailedTerminal ||
		failed.record.Stage != contract.GeneratedStageTerminal || !bytes.Equal(failed.result, secondPlan.result) {
		t.Fatal("owned-unusable failure lost its exact terminal attempt")
	}
	hazardRow, ok := selected.records[generatedRecordKey{kind: 11, id: failed.expected.Template.HazardID}]
	if !ok {
		t.Fatal("owned-unusable failure lost its Hazard")
	}
	hazard, err := contract.InspectGeneratedHazardRecord(hazardRow.Body)
	if err != nil || hazard.Exposure != contract.GeneratedExposureLateEffect || hazard.HazardID != failed.expected.Template.HazardID ||
		hazard.OriginalAttemptID != second.record.AttemptID || hazard.OwnerID != failed.record.OwnerID || hazard.ResourceID != second.record.ResourceID {
		t.Fatal("owned-unusable failure changed its exact Hazard", err)
	}
	if _, fabricated := selected.records[generatedRecordKey{kind: 10, id: failed.record.OwnerID}]; fabricated {
		t.Fatal("owned-unusable failure fabricated a cleanup Duty")
	}
	if _, ok := final.state.materialAccess(3, finalPlan.request.MaterialID); !ok {
		t.Fatal("live cleanup lost its operation seed")
	}
}

// full_only: false
func TestGeneratedExhaustedUnknownFinalRetainsEveryEnteredAttempt(t *testing.T) {
	s := generatedActiveExhaustedUnknownState(t)
	g := mustSelectedGeneratedWork(t, s)
	if !generatedLineageTerminalUncertain(g, g.bundles[0].Lineages[0]) {
		t.Fatal("exhausted unknown lineage was not terminal")
	}
	context := generatedContinuationContext(t, s, 191, 192)
	if !s.generatedContextValid(context) {
		t.Fatal("exhausted unknown context invalid")
	}
	plan, err := s.generatedFinalRequest(t.Context(), context)
	if err != nil {
		t.Fatal("exhausted unknown final request", err)
	}
	if plan.selecting || len(plan.entryPlans) != 0 || len(plan.results) != 0 {
		t.Fatal("exhausted unknown exposed a selectable or fabricated result")
	}
	final, err := s.deriveGeneratedFinal(t.Context(), plan, nil)
	if err != nil {
		t.Fatal("exhausted unknown final closure", err)
	}
	if final.state.validateGeneratedSelection(t.Context(), nil) != nil || final.state.root.ValueEntryCount != 0 ||
		!final.state.root.Generated.ActiveOwner.IsZero() || !final.state.root.Generated.ActivePhase.IsZero() ||
		!final.state.root.Generated.ActiveGraph.IsZero() {
		t.Fatal("unknown final changed members or retained an active parent")
	}
	closure := mustSelectedGeneratedWork(t, final.state)
	if closure.parent != nil || closure.phase != nil || len(closure.attempts) != 2 || final.state.root.Generated.Hazards != 2 ||
		final.state.root.Generated.Duties != 0 || final.state.root.Generated.Materials != 1 || len(closure.bundles) != 1 {
		t.Fatal("unknown final stranded an entered attempt or dropped an exact Hazard")
	}
	for _, attempt := range closure.attempts {
		if attempt.record.State != contract.GeneratedEffectClosedWithResidue || attempt.record.Stage != contract.GeneratedStageTerminal ||
			len(attempt.result) != 0 {
			t.Fatal("unknown final changed an entered uncertain Attempt")
		}
		if _, ok := closure.records[generatedRecordKey{kind: 11, id: attempt.expected.Template.HazardID}]; !ok {
			t.Fatal("unknown final lost an Attempt Hazard")
		}
	}
	if _, ok := final.state.materialAccess(3, plan.request.MaterialID); !ok {
		t.Fatal("unknown final released the live inbox material")
	}
}

func generatedActiveExhaustedUnknownState(t testing.TB) *StateSession {
	t.Helper()
	predecessor := generatedEmptyPredecessor(t)
	reservation, err := predecessor.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputFixture(t, predecessor))
	if err != nil {
		t.Fatal(err)
	}
	return generatedExhaustedUnknownState(t, reservation.state)
}

func generatedExhaustedUnknownState(t testing.TB, s *StateSession) *StateSession {
	t.Helper()
	generatedMaterializeFixtureSupport(t, s)
	g := mustSelectedGeneratedWork(t, s)
	bundle := g.bundles[0]
	locations, err := format.ResolveGeneratedSlices(s.root.Domain, s.root.Snapshot, s.root.Generated, s.support)
	if err != nil {
		t.Fatal(err)
	}
	first, successor := bundle.Lineages[0].Templates[0], bundle.Lineages[0].Templates[2]
	firstHistory := []contract.GeneratorHistory{{Schema: 1, PredecessorAttemptID: first.AttemptID,
		OwnerID: first.DutyID, Outcome: contract.GeneratedEffectClosedWithResidue}}
	generatedCloseCreateAsUnknown(t, s, first, firstHistory)
	_, use, ok := generatedTemplate(bundle, successor.AttemptID)
	if !ok {
		t.Fatal("missing residue successor use")
	}
	rows, err := generatedScheduledCreateRows(*g.parent, successor, use, g.attempts[first.AttemptID].record.RequestDigest)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	lineage, err := contract.DecodeGeneratedLineageRecord(g.records[generatedRecordKey{kind: 8, id: first.LineageID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	lineage.Branch, lineage.Frontier, lineage.ResidueUsed = 2, 2, 1
	body, err := contract.EncodeGeneratedLineageRecord(lineage)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 8, lineage.LineageID, body)
	phase := *g.phase
	phase.Phase, phase.PhaseID = 2, generatedVectorID(199)
	s.root.Generated.ActivePhase = phase.PhaseID
	phase.FrontierAttemptID, phase.Branch, phase.Stage, phase.ResidueUsed = successor.AttemptID, 2, contract.GeneratedStageRetainedResult, 1
	phase.AcceptedResultID, phase.ResultDigest = contract.ID{}, contract.ID{}
	body, err = contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 5, phase.OperationID, body)
	successorHistory := []contract.GeneratorHistory{{Schema: 1, PredecessorAttemptID: first.AttemptID,
		NextAttemptID: successor.AttemptID, OwnerID: first.DutyID, Outcome: contract.GeneratedEffectClosedWithResidue, Edge: 2}, {Schema: 1,
		PredecessorAttemptID: successor.AttemptID, OwnerID: successor.DutyID, Outcome: contract.GeneratedEffectTransmitted}}
	generatedSetHistoryUnrefreshed(t, s, 9, successor.AttemptID, successorHistory)
	generatedSetHistoryUnrefreshed(t, s, 10, successor.DutyID, successorHistory)
	generatedRefreshClosureCounts(&s.root.Generated, s.supportRecords())
	generatedRefreshPhaseSetsUnrefreshed(t, s)
	generatedRepackSupportAtLocations(t, s, s.supportRecords(), []contract.GeneratorPlanBundle{bundle}, locations)
	generatedVerifySelectedFixtureSlices(t, s)
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err != nil {
		t.Fatal("invalid entered residue successor", err)
	}
	g = mustSelectedGeneratedWork(t, s)
	phase = *g.phase
	successorHistory[len(successorHistory)-1].Outcome = contract.GeneratedEffectClosedWithResidue
	generatedCloseCreateAsUnknown(t, s, successor, successorHistory)
	phase.Stage, phase.AcceptedResultID, phase.ResultDigest = contract.GeneratedStageTerminal, contract.ID{}, contract.ID{}
	body, err = contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 5, phase.OperationID, body)
	generatedRefreshPhaseSetsUnrefreshed(t, s)
	generatedRepackSupportAtLocations(t, s, s.supportRecords(), []contract.GeneratorPlanBundle{bundle}, locations)
	generatedVerifySelectedFixtureSlices(t, s)
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err != nil {
		t.Fatal("invalid exhausted unknown fixture", err)
	}
	return s
}

func generatedCloseCreateAsUnknown(t testing.TB, s *StateSession, x contract.GeneratorAttemptTemplate, history []contract.GeneratorHistory) {
	t.Helper()
	g := mustSelectedGeneratedWork(t, s)
	a := g.attempts[x.AttemptID]
	duty, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{kind: 10, id: a.record.OwnerID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	consumerRows, err := g.vectors.resolve(10, duty.DutyID, contract.GeneratorVectorConsumers, duty.Consumers)
	if err != nil {
		t.Fatal(err)
	}
	var late [][]byte
	for _, body := range consumerRows {
		consumer, err := contract.InspectGeneratorConsumer(body)
		if err != nil {
			t.Fatal(err)
		}
		if consumer.Purpose != 4 {
			continue
		}
		consumer.OwnerID = x.HazardID
		body, err = contract.EncodeGeneratorConsumer(consumer)
		if err != nil {
			t.Fatal(err)
		}
		late = append(late, body)
	}
	consumers, carriers, err := generatedCarrierRows(s.root.Domain, 11, x.HazardID, contract.GeneratorVectorConsumers, late)
	if err != nil {
		t.Fatal(err)
	}
	hazard := contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema, DomainID: duty.DomainID, HazardID: x.HazardID,
		OriginalOperationID: duty.OriginalOperationID, OriginalAttemptID: duty.OriginalAttemptID, OwnerID: duty.OwnerID,
		ResourceID: duty.ResourceID, ConfigContractID: duty.ConfigContractID, ResourceContractID: duty.ResourceContractID, ExecutorID: duty.ExecutorID,
		CredentialRouteID: duty.CredentialRouteID, DescriptorID: duty.DescriptorID, ResultContractID: duty.ResultContractID,
		Exposure: contract.GeneratedExposurePossibleLive, CompletionClass: duty.CompletionClass, Fenced: 1,
		CapacityReservation: duty.CapacityReservation,
		OriginalResults:     contract.EmptyGeneratorRecordSet(contract.GeneratorHazardResults),
		Target:              contract.EmptyGeneratorVector(contract.GeneratorVectorTargets), History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory),
		Support: duty.Support, Consumers: consumers}
	a.record.State, a.record.Stage, a.record.Facts = contract.GeneratedEffectClosedWithResidue, contract.GeneratedStageTerminal,
		contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(a.record)
	if err != nil {
		t.Fatal(err)
	}
	hazardBody, err := contract.EncodeGeneratedHazardRecord(hazard)
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind == 10 && row.RecordID == duty.DutyID {
				return true
			}
			if row.Kind != contract.GeneratorVectorSupportKind {
				return false
			}
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			return carrier.OwnerKind == 10 && carrier.OwnerID == duty.DutyID
		})
		for j := range s.support[i].Records {
			if s.support[i].Records[j].Kind == 9 && s.support[i].Records[j].RecordID == a.record.AttemptID {
				s.support[i].Records[j].Body = attemptBody
			}
		}
	}
	s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records,
		contract.SupportRecordView(contract.SupportRecord{Kind: 11, RecordID: hazard.HazardID, Body: hazardBody}))
	for _, row := range carriers {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	generatedSetHistoryUnrefreshed(t, s, 9, a.record.AttemptID, history)
	generatedSetHistoryUnrefreshed(t, s, 11, hazard.HazardID, history)
	generatedRefreshClosureCounts(&s.root.Generated, s.supportRecords())
}

func generatedPreparedValueEntryFixture(t testing.TB, s *StateSession, plan contract.CryptoGeneratedValueEntryPlan) contract.CryptoGeneratedValueEntryResult {
	t.Helper()
	payload := contract.CanonicalPayload{Profile: 2, CryptoSupportID: plan.ValueCore.CryptoSupportID,
		DataKeyID: plan.ValueCore.DataKeyID, DataKeyEpoch: plan.ValueCore.DataKeyEpoch,
		CommitmentKeyID: plan.ValueCore.CommitmentKeyID, CommitmentKeyEpoch: plan.ValueCore.CommitmentKeyEpoch,
		ContentLength: plan.ValueCore.ContentLength, SemanticCommitment: generatedVectorID(240), PackageCheck: generatedVectorID(241),
		Ciphertext: bytes.Repeat([]byte{242}, int(plan.ValueCore.ContentLength)+16), InputEncoding: contract.InputEncodingRaw, RetainedLength: plan.ValueCore.ContentLength}
	body, err := contract.EncodeCanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	entry := contract.ValueEntry{Name: plan.ValueCore.Name, Incarnation: plan.ValueCore.EntryIncarnationID,
		ValueState: plan.ValueCore.ValueStateID, OriginSnapshot: plan.ValueCore.OriginSnapshotID,
		OriginTransition: plan.ValueCore.OriginTransitionID, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret,
		Generated: plan.Generated, Recipients: append([]contract.ID(nil), plan.Recipients...), ValueBytes: body, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len(body) - contract.CanonicalPayloadOverhead), RetainedLength: uint32(len(body) - contract.CanonicalPayloadOverhead)}
	context, err := contract.ValueMaterialContextDigest(plan.ValueCore)
	if err != nil {
		t.Fatal(err)
	}
	access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: plan.ValueCore.ValueStateID,
		MaterialContextDigest: context, PackageCheck: payload.PackageCheck}
	bindings, err := s.currentBindings()
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range bindings {
		if binding.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(plan.Recipients, binding.SubjectID) {
			continue
		}
		digest, err := contract.PublicBindingDigest(binding.Binding)
		if err != nil {
			t.Fatal(err)
		}
		access.Wraps = append(access.Wraps, contract.WrapRow{SubjectKind: binding.SubjectKind, SubjectID: binding.SubjectID, BindingID: binding.Binding.BindingID,
			BindingSerial: binding.Binding.BindingSerial, PublicBindingDigest: digest, RSACiphertext: bytes.Repeat([]byte{243}, 384)})
	}
	return contract.CryptoGeneratedValueEntryResult{Slot: plan.Slot, ResultID: plan.Generated.CreateResultID,
		ResultDigest: contract.Hash(plan.Result), ValueCore: plan.ValueCore, Entry: entry, Access: access}
}

func generatedContinuationContext(t testing.TB, s *StateSession, admission, session byte) contract.ApplyContext {
	t.Helper()
	if s.supportFacts == nil && s.fragmentFacts == nil {
		generatedInstallFixtureSupportReader(t, s)
	}
	c := contract.ApplyContext{OperationClass: contract.CryptoGeneratedClass, AdmissionID: generatedVectorID(admission),
		SessionID: generatedVectorID(session), DomainID: s.admission.domain,
		CompatibilityID: s.root.CurrentAccess.Core.CompatibilityID, Expiry: uint64(time.Now().Add(time.Minute).UnixNano()),
		PredecessorHEADDigest: contract.Hash(s.body), CurrentAccessRoot: s.root.CurrentAccess.AccessRoot}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.PredecessorRootRef[:], root)
	c.OriginalConditionDigest, err = contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// full_only: false
func TestGeneratedProducerPreparationModesAreExclusive(t *testing.T) {
	for _, originalSet := range []bool{false, true} {
		t.Run(map[bool]string{false: "single first", true: "original set first"}[originalSet], func(t *testing.T) {
			s, prior := observationInitialProducerFixture(t, false, "alpha", "omega")
			if err := prior.reservation.state.validateGeneratedSelection(t.Context(), nil); err != nil {
				t.Fatal("producer fixture selected state", err)
			}
			admitted := prior.operation.context
			admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = generatedVectorID(132), generatedVectorID(133), contract.DescriptorVector{}
			attempts := prior.reservation.originalAttempts
			// The retained permit predates the parent's mode choice.
			q, preparation, err := s.generatedProducerRequestChecked(t.Context(), prior, attempts[0], admitted)
			if err != nil {
				t.Fatal("preissued producer request", err)
			}
			custody := observationFailingCustody()
			permit := &admittedGeneratedProducer{session: s, prior: prior, attempt: attempts[0], request: q, preparation: preparation,
				crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(q.Context.Expiry))}
			chosen, other := s.generatedProducerRequestForAttempt, s.generatedOriginalProducerRequest
			prepareOther := s.prepareGeneratedOriginalProducer
			if originalSet {
				chosen, other = other, chosen
				prepareOther = s.prepareGeneratedProducer
			}
			if _, _, err := chosen(t.Context(), prior, attempts[0], admitted); err != nil {
				t.Fatal("chosen mode refused", err)
			}
			if _, _, err := other(t.Context(), prior, attempts[0], admitted); err == nil {
				t.Error("retained parent admitted the other preparation mode")
			}
			if p, result := prepareOther(t.Context(), permit); p != nil || result.Outcome != AdmissionRefused || len(custody.calls) != 0 {
				t.Fatal("preissued other-mode permit reached Crypto", result, len(custody.calls))
			}
			if _, _, err := chosen(t.Context(), prior, attempts[0], admitted); err != nil {
				t.Fatal("refused mode prevented chosen continuation", err)
			}
			if originalSet {
				if _, _, err := chosen(t.Context(), prior, attempts[1], admitted); err != nil {
					t.Fatal("chosen complete set lost its sibling", err)
				}
				if prior.reservation.candidate.generatedReady() {
					t.Fatal("incomplete original set gained candidate authority")
				}
			}
		})
	}
}
