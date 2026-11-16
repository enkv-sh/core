package core

import (
	"bytes"
	stdcontext "context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedActiveOwnerAndResultContractColdRead(t *testing.T) {
	for _, family := range []string{"create", "retirement"} {
		for _, damage := range []string{"owner", "result contract"} {
			t.Run(family+"/"+damage, func(t *testing.T) {
				var s *StateSession
				if family == "create" {
					s = generatedReservationState(t)
				} else {
					s, _, _, _ = generatedEnteredRetirementState(t, false)
				}
				s.generatedWork = nil
				selected, err := s.selectedGeneratedWork(stdcontext.Background())
				if err != nil {
					t.Fatal("valid active owner cold read", err)
				}
				attempt := selected.attempts[selected.phase.FrontierAttemptID].record
				if damage == "owner" {
					attempt.OwnerID = generatedVectorID(96)
				} else {
					attempt.ResultContractID = generatedVectorID(96)
				}
				body, err := contract.EncodeGeneratedAttemptRecord(attempt)
				if err != nil {
					t.Fatal(err)
				}
				generatedReplaceRecord(t, s, 9, attempt.AttemptID, body)
				generatedRefreshPhaseSets(t, s)
				s.generatedWork = nil
				if wrong, err := s.selectedGeneratedWork(stdcontext.Background()); wrong != nil || err == nil {
					t.Fatal("cold read accepted a changed owner or result contract")
				}
			})
		}
	}
}

func generatedActiveOwnedUnusableHazard(t testing.TB) (*StateSession, generatedAttempt, contract.GeneratedHazardRecord) {
	t.Helper()
	s := generatedReservationState(t)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	hazard, a, h := generatedCreateHazardState(t, 0, 2)
	a.record.State, h.Fenced = contract.GeneratedEffectFailedTerminal, 0
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(a.record)
	if err != nil {
		t.Fatal(err)
	}
	hazardBody, err := contract.EncodeGeneratedHazardRecord(h)
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind == 9 || row.Kind == 10 {
				return true
			}
			if row.Kind == contract.GeneratorVectorSupportKind {
				v, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				return v.OwnerKind == 9 || v.OwnerKind == 10
			}
			return false
		})
	}
	for _, row := range hazard.supportRecords() {
		switch row.Kind {
		case 4:
		case 9:
			row.Body = attemptBody
		case 11:
			row.Body = hazardBody
		case contract.GeneratorVectorSupportKind:
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if v.OwnerKind != 9 && v.OwnerKind != 11 {
				continue
			}
		default:
			continue
		}
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	phase := *g.phase
	phase.Phase, phase.PhaseID, phase.Stage = 2, generatedVectorID(94), a.record.Stage
	phase.AcceptedResultID, phase.ResultDigest = a.record.ResultID, contract.Hash(a.result)
	body, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 5, phase.OperationID, body)
	s.root.Generated.ActivePhase = phase.PhaseID
	s.root.Generated.Duties, s.root.Generated.Hazards, s.root.Generated.Results = 0, 1, 1
	owners := []contract.ID{g.parent.OperationID, h.HazardID}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	generatedRefreshPhaseSetsUnrefreshed(t, s)
	generatedRepackSupport(t, s, s.supportRecords(), g.bundles)
	return s, a, h
}

// full_only: false
func TestGeneratedActivePhaseRetainsItsOwnedUnusableHazard(t *testing.T) {
	s, a, h := generatedActiveOwnedUnusableHazard(t)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal("active phase lost its owned-unusable Hazard", err)
	}
	if g.phase.Hazards.Count != 1 || g.phase.Attempts.Count != 1 || g.phase.AcceptedResults.Count != 1 || g.phase.Duties.Count != 0 ||
		!g.hasRecord(generatedRecordKey{11, h.HazardID}) || len(g.attempts) != 1 || !bytes.Equal(g.attempts[a.record.AttemptID].result, a.result) {
		t.Fatal("active Hazard changed its result, owner set or seed access")
	}
	if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.access[0].Records); coverageErr != nil {
		t.Fatal("active Hazard changed its result, owner set or seed access")
	}
	consumers := g.consumers[materialIdentity{3, a.material.Core.OperationMaterialID}]
	if len(consumers) != 1 || consumers[0].OwnerID != h.HazardID || consumers[0].Purpose != 4 || consumers[0].SubjectID != a.record.ResultID {
		t.Fatal("active Hazard acquired selected derivation or lost original-result adoption")
	}
}

// full_only: false
func TestGeneratedActivePhaseCannotOmitOwnedHazard(t *testing.T) {
	s, _, _ := generatedActiveOwnedUnusableHazard(t)
	for _, row := range s.supportRecords() {
		if row.Kind != 5 {
			continue
		}
		phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		phase.Hazards = contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseHazards)
		body, err := contract.EncodeGeneratedPhaseRecord(phase)
		if err != nil {
			t.Fatal(err)
		}
		generatedReplaceRecord(t, s, 5, phase.OperationID, body)
	}
	generatedRefreshSupport(t, s)
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
		t.Fatal("active phase omitted its original Hazard from the exact set")
	}
}

func generatedActiveHazardRelease(t testing.TB, releaseState uint8) (*StateSession, generatedAttempt, contract.PendingInboxReleaseRecord) {
	t.Helper()
	s, a, h := generatedActiveOwnedUnusableHazard(t)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	r, err := contract.DecodeGeneratedResultRecord(a.result)
	if err != nil {
		t.Fatal(err)
	}
	core, err := contract.EncodeGeneratedResultCore(r.Core)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := contract.EncodeGeneratorSafeFacts(r.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	location := g.content.locations[generatedContentKey{contract.GeneratorContentIntent, r.SafeFacts.IntentDigest}]
	intent, err := contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{location.Logical()})
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeGeneratedCreateEvidence(contract.GeneratedCreateEvidence{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedCreateEvidenceSchema, OriginalResultID: a.record.ResultID, CredentialRouteID: a.expected.Template.CredentialRouteID,
		ResultCore: core, SafeFacts: facts, Intent: intent, CompletionClass: a.record.CompletionClass})
	if err != nil {
		t.Fatal(err)
	}
	evidence := contract.SupportRecord{Kind: 13, RecordID: a.record.ResultID, Body: body}
	h.OriginalResults, err = contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, h.DomainID, []contract.SupportRecord{evidence})
	if err != nil {
		t.Fatal(err)
	}
	h.Consumers = contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers)
	a.record.Facts = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
	body, err = contract.EncodeGeneratedHazardRecord(h)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 11, h.HazardID, body)
	body, err = contract.EncodeGeneratedAttemptRecord(a.record)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 9, a.record.AttemptID, body)
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind == 4 {
				return true
			}
			if row.Kind != contract.GeneratorVectorSupportKind {
				return false
			}
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			return v.OwnerKind == 9 && v.VectorKind == contract.GeneratorVectorFacts || v.OwnerKind == 11 && v.VectorKind == contract.GeneratorVectorConsumers
		})
	}
	release := contract.PendingInboxReleaseRecord{Schema: 1, DomainID: s.root.Domain, InboxID: a.record.InboxID,
		OriginalResultID: a.record.ResultID, SelectedHandoffDigest: contract.Hash(a.result), HandoffRevisionID: generatedVectorID(93),
		CapacityReservation: h.CapacityReservation, ObjectLength: uint32(len(a.result)), State: releaseState}
	body, err = contract.EncodePendingInboxReleaseRecord(release)
	if err != nil {
		t.Fatal(err)
	}
	s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(evidence),
		contract.SupportRecordView{Kind: 12, RecordID: release.InboxID, Body: body})
	phase := *g.phase
	phase.Phase, phase.PhaseID = 3, generatedVectorID(92)
	body, err = contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 5, phase.OperationID, body)
	s.root.Generated.ActivePhase = phase.PhaseID
	s.root.Generated.Results, s.root.Generated.PendingReleases = 0, 1
	owners := []contract.ID{g.parent.OperationID, h.HazardID, release.InboxID}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	generatedRefreshPhaseSetsUnrefreshed(t, s)
	generatedRepackSupport(t, s, s.supportRecords(), g.bundles)
	return s, a, release
}

// full_only: false
func TestGeneratedActivePhaseRetainsReleaseWithoutOriginalAdoption(t *testing.T) {
	for _, state := range []uint8{contract.GeneratedReleasePending, contract.GeneratedReleaseUnknown} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			s, a, release := generatedActiveHazardRelease(t, state)
			g, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal("active phase lost its exact released original result", err)
			}
			if g.phase.Attempts.Count != 1 || g.phase.Hazards.Count != 1 || g.phase.PendingReleases.Count != 1 || g.phase.AcceptedResults.Count != 0 ||
				g.phase.FrontierAttemptID != a.record.AttemptID || g.phase.AcceptedResultID != release.OriginalResultID || g.phase.ResultDigest != release.SelectedHandoffDigest ||
				len(g.attempts) != 0 || len(g.consumers) != 0 || !g.hasRecord(generatedRecordKey{12, release.InboxID}) ||
				!g.hasRecord(generatedRecordKey{13, a.record.ResultID}) {
				t.Fatal("release changed phase ownership or restored original-result adoption")
			}
			if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.access[0].Records); coverageErr != nil {
				t.Fatal("release changed phase ownership or restored original-result adoption")
			}
		})
	}
}

// full_only: false
func TestGeneratedActivePhaseCannotHideAcceptedFrontierResult(t *testing.T) {
	for _, released := range []bool{false, true} {
		for name, change := range map[string]func(*contract.GeneratedPhaseRecord){
			"absent": func(p *contract.GeneratedPhaseRecord) {
				p.AcceptedResultID, p.ResultDigest = contract.ID{}, contract.ID{}
			},
			"result":  func(p *contract.GeneratedPhaseRecord) { p.AcceptedResultID = generatedVectorID(99) },
			"digest":  func(p *contract.GeneratedPhaseRecord) { p.ResultDigest = generatedVectorID(99) },
			"attempt": func(p *contract.GeneratedPhaseRecord) { p.FrontierAttemptID = generatedVectorID(99) },
			"lineage": func(p *contract.GeneratedPhaseRecord) { p.LineageIndex = 1 },
			"branch":  func(p *contract.GeneratedPhaseRecord) { p.Branch, p.ResidueUsed = 2, 1 },
		} {
			t.Run(fmt.Sprintf("released%t/%s", released, name), func(t *testing.T) {
				var s *StateSession
				if released {
					s, _, _ = generatedActiveHazardRelease(t, contract.GeneratedReleasePending)
				} else {
					s, _, _ = generatedActiveOwnedUnusableHazard(t)
				}
				selected, err := s.selectedGeneratedWork(stdcontext.Background())
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range s.supportRecords() {
					if row.Kind != 5 {
						continue
					}
					phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					change(&phase)
					body, err := contract.EncodeGeneratedPhaseRecord(phase)
					if err != nil {
						t.Fatal(err)
					}
					generatedReplaceRecord(t, s, 5, phase.OperationID, body)
				}
				generatedRepackSupport(t, s, s.supportRecords(), selected.bundles)
				if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
					t.Fatal("phase changed the exact accepted result of its frontier")
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedActiveReleaseKeepsCompletePhaseSets(t *testing.T) {
	for _, missing := range []uint8{9, 11, 12} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			s, _, _ := generatedActiveHazardRelease(t, contract.GeneratedReleaseUnknown)
			selected, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range s.supportRecords() {
				if row.Kind != 5 {
					continue
				}
				p, err := contract.InspectGeneratedPhaseRecord(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				switch missing {
				case 9:
					p.Attempts = contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseAttempts)
				case 11:
					p.Hazards = contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseHazards)
				case 12:
					p.PendingReleases = contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseReleases)
				}
				body, err := contract.EncodeGeneratedPhaseRecord(p)
				if err != nil {
					t.Fatal(err)
				}
				generatedReplaceRecord(t, s, 5, p.OperationID, body)
			}
			generatedRepackSupport(t, s, s.supportRecords(), selected.bundles)
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("release-only handoff lost an owned phase row")
			}
		})
	}
}

// full_only: false
func TestGeneratedActiveReleaseCannotRestoreOriginalResultConsumer(t *testing.T) {
	s, a, _ := generatedActiveHazardRelease(t, contract.GeneratedReleasePending)
	context, err := contract.GeneratorResultUseDigest(a.expected.Use)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: a.expected.Template.HazardID,
		MaterialID: a.material.Core.OperationMaterialID, ContextDigest: context, SubjectKind: 3, SubjectID: a.record.ResultID, Purpose: 4})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, rows := generatedVectorRows(t, 11, a.expected.Template.HazardID, contract.GeneratorVectorConsumers, [][]byte{body})
	for _, row := range s.supportRecords() {
		if row.Kind != 11 {
			continue
		}
		h, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		h.Consumers = descriptor
		body, err := contract.EncodeGeneratedHazardRecord(h)
		if err != nil {
			t.Fatal(err)
		}
		generatedReplaceRecord(t, s, 11, h.HazardID, body)
	}
	for _, row := range rows {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	generatedRefreshPhaseSetsUnrefreshed(t, s)
	s.generatedWork = nil
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
		t.Fatal("active release restored a live original-result consumer")
	}
}

func generatedActiveCreateBranches(t testing.TB, branches ...uint8) *StateSession {
	t.Helper()
	s := generatedReservationState(t)
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil || len(branches) == 0 {
		t.Fatal("branch fixture", err)
	}
	original := g.attempts[g.phase.FrontierAttemptID]
	duty, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, original.record.OwnerID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind == 9 || row.Kind == 10 {
				return true
			}
			if row.Kind == contract.GeneratorVectorSupportKind {
				v, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				return v.OwnerKind == 9 || v.OwnerKind == 10
			}
			return false
		})
	}
	owners := []contract.ID{g.parent.OperationID}
	phase := *g.phase
	phase.Phase, phase.PhaseID = 2, generatedVectorID(99)
	for _, branch := range branches {
		x := g.bundles[0].Lineages[0].Templates[branch]
		_, use, ok := generatedTemplate(g.bundles[0], x.AttemptID)
		if !ok {
			t.Fatal("branch template")
		}
		a := original.record
		a.AttemptID, a.PredecessorAttemptID, a.OwnerID, a.ResourceID = x.AttemptID, x.PredecessorAttemptID, x.DutyID, x.ResourceIncarnationID
		a.TransmissionID, a.ResultID, a.InboxID = x.TransmissionID, x.ResultID, x.InboxID
		a.TemplateDigest, err = contract.GeneratorTemplateID(x)
		if err != nil {
			t.Fatal(err)
		}
		d := duty
		d.DutyID, d.OwnerID, d.OriginalAttemptID, d.ResourceID = a.OwnerID, a.OwnerID, a.AttemptID, a.ResourceID
		context, err := contract.GeneratorResultUseDigest(use)
		if err != nil {
			t.Fatal(err)
		}
		var consumers [][]byte
		for _, purpose := range []uint8{3, 4} {
			body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: d.DutyID, MaterialID: original.material.Core.OperationMaterialID,
				ContextDigest: context, SubjectKind: 3, SubjectID: a.ResultID, Purpose: purpose})
			if err != nil {
				t.Fatal(err)
			}
			consumers = append(consumers, body)
		}
		var rows []contract.SupportRecord
		d.Consumers, rows = generatedVectorRows(t, 10, d.DutyID, contract.GeneratorVectorConsumers, consumers)
		body, err := contract.EncodeGeneratedAttemptRecord(a)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.SupportRecord{Kind: 9, RecordID: a.AttemptID, Body: body})
		body, err = contract.EncodeGeneratedDutyRecord(d)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.SupportRecord{Kind: 10, RecordID: d.DutyID, Body: body})
		for _, row := range rows {
			s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
		}
		owners = append(owners, d.DutyID)
		phase.FrontierAttemptID, phase.Branch = a.AttemptID, branch
		phase.NoEffectUsed, phase.ResidueUsed = 0, 0
		if branch == 1 || branch >= 3 {
			phase.NoEffectUsed = 1
		}
		if branch >= 2 {
			phase.ResidueUsed = 1
		}
	}
	body, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 5, phase.OperationID, body)
	s.root.Generated.ActivePhase = phase.PhaseID
	lineage, err := contract.DecodeGeneratedLineageRecord(g.records[generatedRecordKey{8, original.record.LineageID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	lineage.Branch, lineage.Frontier = phase.Branch, phase.Branch
	lineage.NoEffectUsed, lineage.ResidueUsed = phase.NoEffectUsed, phase.ResidueUsed
	body, err = contract.EncodeGeneratedLineageRecord(lineage)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 8, lineage.LineageID, body)
	s.root.Generated.Attempts, s.root.Generated.Duties = uint32(len(branches)), uint32(len(branches))
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	generatedRefreshPhaseSets(t, s)
	return s
}

// full_only: false
func TestGeneratedActivePhaseRejectsIncompatibleEnteredBranches(t *testing.T) {
	for _, branches := range [][]uint8{{0, 1, 2}, {0, 2, 3}, {1, 4}, {2, 3}, {3, 4}, {0, 1, 3, 4}, {0, 1, 2, 3, 4}} {
		t.Run(fmt.Sprintf("%v", branches), func(t *testing.T) {
			s := generatedActiveCreateBranches(t, branches...)
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("reserved alternatives became incompatible entered Attempts")
			}
		})
	}
}

// full_only: false
func TestGeneratedInitialPhaseCannotSkipRetainedResultStage(t *testing.T) {
	for stage := contract.GeneratedStageObservation; stage <= contract.GeneratedStageTerminal; stage++ {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			s := generatedReservationState(t)
			g, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal(err)
			}
			a := g.attempts[g.phase.FrontierAttemptID].record
			a.Stage = stage
			body, err := contract.EncodeGeneratedAttemptRecord(a)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 9, a.AttemptID, body)
			p := *g.phase
			p.Stage = stage
			body, err = contract.EncodeGeneratedPhaseRecord(p)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 5, p.OperationID, body)
			generatedRefreshPhaseSets(t, s)
			if _, err := s.selectedGeneratedWork(stdcontext.Background()); err == nil {
				t.Fatal("initial reservation skipped the retained-result stage")
			}
		})
	}
}
