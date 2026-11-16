package core

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

func generatedSetHistory(t testing.TB, s *StateSession, ownerKind uint8, owner contract.ID, history []contract.GeneratorHistory) {
	t.Helper()
	bundles := generatedFixtureBundles(t, s)
	generatedSetHistoryUnrefreshed(t, s, ownerKind, owner, history)
	if s.root.Generated.ActiveOwner.IsZero() {
		generatedRefreshSupport(t, s, bundles...)
	} else {
		generatedRefreshPhaseSetsUnrefreshed(t, s)
		generatedRefreshSupport(t, s, bundles...)
	}
}

func generatedSetHistoryUnrefreshed(t testing.TB, s *StateSession, ownerKind uint8, owner contract.ID, history []contract.GeneratorHistory) {
	t.Helper()
	var bodies [][]byte
	for _, row := range history {
		body, err := contract.EncodeGeneratorHistory(row)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
	}
	descriptor, rows, err := generatedCarrierRows(s.root.Domain, ownerKind, owner, contract.GeneratorVectorHistory, bodies)
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind != contract.GeneratorVectorSupportKind {
				return false
			}
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			return v.OwnerKind == ownerKind && v.OwnerID == owner && v.VectorKind == contract.GeneratorVectorHistory
		})
		for j, row := range s.support[i].Records {
			if row.Kind != ownerKind || row.RecordID != owner {
				continue
			}
			var body []byte
			var err error
			switch ownerKind {
			case 9:
				v, e := contract.InspectGeneratedAttemptRecord(row.Body)
				if e != nil {
					t.Fatal(e)
				}
				v.History = descriptor
				body, err = contract.EncodeGeneratedAttemptRecord(v)
			case 10:
				v, e := contract.InspectGeneratedDutyRecord(row.Body)
				if e != nil {
					t.Fatal(e)
				}
				v.History = descriptor
				body, err = contract.EncodeGeneratedDutyRecord(v)
			case 11:
				v, e := contract.InspectGeneratedHazardRecord(row.Body)
				if e != nil {
					t.Fatal(e)
				}
				v.History = descriptor
				body, err = contract.EncodeGeneratedHazardRecord(v)
			default:
				t.Fatal("unsupported history owner")
			}
			if err != nil {
				t.Fatal(err)
			}
			s.support[i].Records[j].Body = body
		}
	}
	for _, row := range rows {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
}

func generatedResidueSuccessorState(t testing.TB) (*StateSession, contract.GeneratorPlanBundle) {
	t.Helper()
	s := generatedActiveCreateBranches(t, 2)
	old, _, hazard := generatedCreateHazardState(t, 0, 0)
	bundle, _, _ := generatedEffectPlanFixture(t)
	for _, row := range old.supportRecords() {
		if row.Kind == contract.GeneratorVectorSupportKind {
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if v.OwnerKind != 9 && v.OwnerKind != 11 {
				continue
			}
		} else if row.Kind != 9 && row.Kind != 11 {
			continue
		}
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	s.root.Generated.Attempts, s.root.Generated.Hazards = 2, 1
	owners := []contract.ID{s.root.Generated.ActiveOwner, bundle.Lineages[0].Templates[2].DutyID, hazard.HazardID}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	var err error
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	generatedRefreshPhaseSets(t, s)
	return s, bundle
}

// full_only: false
func TestGeneratedCreateSuccessorRequiresBoundHistory(t *testing.T) {
	s, _ := generatedResidueSuccessorState(t)
	if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
		t.Fatal("entered successor lost its predecessor history")
	}
}

// full_only: false
func TestGeneratedCreateHistoryRejectsUnboundRows(t *testing.T) {
	for _, ownerKind := range []uint8{9, 10, 11} {
		for name, damage := range map[string]func(*contract.GeneratorHistory){
			"owner":   func(v *contract.GeneratorHistory) { v.OwnerID = generatedVectorID(96) },
			"attempt": func(v *contract.GeneratorHistory) { v.PredecessorAttemptID = generatedVectorID(96) },
			"outcome": func(v *contract.GeneratorHistory) { v.Outcome = contract.GeneratedEffectClosedWithResidue },
			"result": func(v *contract.GeneratorHistory) {
				v.ResultID, v.ResultDigest = generatedVectorID(96), generatedVectorID(97)
			},
		} {
			t.Run(fmt.Sprintf("owner%d/%s", ownerKind, name), func(t *testing.T) {
				s := generatedReservationState(t)
				if ownerKind == 11 {
					s, _, _ = generatedActiveOwnedUnusableHazard(t)
				}
				g, err := s.selectedGeneratedWork(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				a := g.attempts[g.phase.FrontierAttemptID].record
				v := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: a.AttemptID, OwnerID: a.OwnerID, Outcome: a.State}
				if result := g.attempts[a.AttemptID].result; len(result) != 0 {
					v.ResultID, v.ResultDigest = a.ResultID, contract.Hash(result)
				}
				owner := a.AttemptID
				switch ownerKind {
				case 10:
					owner = a.OwnerID
				case 11:
					owner = g.attempts[a.AttemptID].expected.Template.HazardID
				}
				generatedSetHistory(t, s, ownerKind, owner, []contract.GeneratorHistory{v})
				if _, err := s.selectedGeneratedWork(context.Background()); err != nil {
					t.Fatal("bound history refused before mutation", err)
				}
				damage(&v)
				generatedSetHistoryUnrefreshed(t, s, ownerKind, owner, []contract.GeneratorHistory{v})
				generatedRefreshPhaseSetsUnrefreshed(t, s)
				s.generatedWork = nil
				if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
					t.Fatal("history substituted an unbound owner, Attempt, result or outcome")
				}
			})
		}
	}
}

func generatedBoundResidueSuccessorState(t testing.TB) (*StateSession, contract.GeneratorPlanBundle, []contract.GeneratorHistory) {
	t.Helper()
	s, bundle := generatedResidueSuccessorState(t)
	first, next := bundle.Lineages[0].Templates[0], bundle.Lineages[0].Templates[2]
	history := []contract.GeneratorHistory{
		{Schema: 1, PredecessorAttemptID: first.AttemptID, NextAttemptID: next.AttemptID, OwnerID: first.DutyID, Outcome: contract.GeneratedEffectClosedWithResidue, Edge: 2},
		{Schema: 1, PredecessorAttemptID: next.AttemptID, OwnerID: next.DutyID, Outcome: contract.GeneratedEffectTransmitted},
	}
	generatedSetHistory(t, s, 9, next.AttemptID, history)
	generatedSetHistory(t, s, 10, next.DutyID, history)
	original := history[0]
	original.NextAttemptID, original.Edge = contract.ID{}, 0
	generatedSetHistory(t, s, 11, first.HazardID, []contract.GeneratorHistory{original})
	return s, bundle, history
}

// full_only: false
func TestGeneratedResidueSuccessorRetainsExactHistory(t *testing.T) {
	s, _, _ := generatedBoundResidueSuccessorState(t)
	if _, err := s.selectedGeneratedWork(context.Background()); err != nil {
		t.Fatal("exact successor and original Hazard history refused", err)
	}
}

// full_only: false
func TestGeneratedSuccessorDutyRetainsCreateAncestry(t *testing.T) {
	for name, damage := range map[string]func([]contract.GeneratorHistory) []contract.GeneratorHistory{
		"empty":               func([]contract.GeneratorHistory) []contract.GeneratorHistory { return nil },
		"missing predecessor": func(v []contract.GeneratorHistory) []contract.GeneratorHistory { return v[1:] },
		"changed predecessor": func(v []contract.GeneratorHistory) []contract.GeneratorHistory {
			v[0].PredecessorAttemptID = generatedVectorID(96)
			return v
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, bundle, history := generatedBoundResidueSuccessorState(t)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("valid predecessor", err)
			}
			next := bundle.Lineages[0].Templates[2]
			duty, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{contract.GeneratedDutySupportKind, next.DutyID}].Body)
			if err != nil {
				t.Fatal(err)
			}
			builder := &generatedSelectionBuilder{facts: g, vectors: newGeneratedVectorValidation(&g.vectors)}
			if err := builder.validateCreateHistory(g.attempts[next.AttemptID], contract.GeneratedDutySupportKind, next.DutyID, duty.History); err != nil {
				t.Fatal("valid successor Duty history", err)
			}
			generatedSetHistoryUnrefreshed(t, s, contract.GeneratedDutySupportKind, next.DutyID, damage(slices.Clone(history)))
			generatedRefreshPhaseSetsUnrefreshed(t, s)
			s.generatedWork = nil
			// The writer rejects some damaged histories before it can rebuild
			// the index. Check the history reader independently of that index.
			rows := s.supportRecords()
			fixture := *g
			fixture.vectors, err = newGeneratedVectorSet(s.root.Domain, rows)
			if err != nil {
				t.Fatal("damaged history vector framing", err)
			}
			for _, row := range rows {
				if row.Kind == contract.GeneratedDutySupportKind && row.RecordID == next.DutyID {
					duty, err = contract.InspectGeneratedDutyRecord(row.Body)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			builder = &generatedSelectionBuilder{facts: &fixture, vectors: newGeneratedVectorValidation(&fixture.vectors)}
			if err := builder.validateCreateHistory(g.attempts[next.AttemptID], contract.GeneratedDutySupportKind, next.DutyID, duty.History); err == nil {
				t.Fatal("successor Duty history reader accepted changed ancestry")
			}
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("successor duty lost exact create ancestry")
			}
		})
	}
	if _, err := generatedReservationState(t).selectedGeneratedWork(context.Background()); err != nil {
		t.Fatal("original create with empty history refused", err)
	}
}

// full_only: false
func TestGeneratedSuccessorHazardRetainsCreateAncestry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]contract.GeneratorHistory) []contract.GeneratorHistory
		valid  bool
	}{
		{"exact", func(v []contract.GeneratorHistory) []contract.GeneratorHistory { return v }, true},
		{"empty", func([]contract.GeneratorHistory) []contract.GeneratorHistory { return nil }, false},
		{"missing", func(v []contract.GeneratorHistory) []contract.GeneratorHistory { return v[1:] }, false},
		{"changed", func(v []contract.GeneratorHistory) []contract.GeneratorHistory {
			v[0].PredecessorAttemptID = generatedVectorID(96)
			return v
		}, false},
		{"reordered", func(v []contract.GeneratorHistory) []contract.GeneratorHistory {
			v[0], v[1] = v[1], v[0]
			return v
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, bundle, history := generatedBoundResidueSuccessorState(t)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			next := bundle.Lineages[0].Templates[2]
			var bodies [][]byte
			for _, row := range tc.change(slices.Clone(history)) {
				body, err := contract.EncodeGeneratorHistory(row)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, body)
			}
			if tc.name == "reordered" {
				if _, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorHistory, bodies); err == nil {
					t.Fatal("reordered ancestry passed the canonical vector boundary")
				}
				return
			}
			descriptor, carriers := generatedVectorRows(t, 11, next.HazardID, contract.GeneratorVectorHistory, bodies)
			rows := append(s.supportRecords(), carriers...)
			fixture := *g
			fixture.vectors, err = newGeneratedVectorSet(s.root.Domain, rows)
			if err != nil {
				t.Fatal(err)
			}
			builder := &generatedSelectionBuilder{facts: &fixture, vectors: newGeneratedVectorValidation(&fixture.vectors)}
			err = builder.validateCreateHistory(g.attempts[next.AttemptID], 11, next.HazardID, descriptor)
			if (err == nil) != tc.valid {
				t.Fatal("successor Hazard ancestry result", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedCreateHistoryBindsExactBranchPath(t *testing.T) {
	for name, damage := range map[string]func([]contract.GeneratorHistory) []contract.GeneratorHistory{
		"missing predecessor": func(v []contract.GeneratorHistory) []contract.GeneratorHistory { return v[1:] },
		"wrong guard": func(v []contract.GeneratorHistory) []contract.GeneratorHistory {
			v[0].Edge = 1
			return v
		},
		"invented predecessor result": func(v []contract.GeneratorHistory) []contract.GeneratorHistory {
			v[0].ResultID, v[0].ResultDigest = generatedVectorID(96), generatedVectorID(97)
			return v
		},
		"unfinished predecessor": func(v []contract.GeneratorHistory) []contract.GeneratorHistory {
			v[0].Outcome = contract.GeneratedEffectTransmitted
			return v
		},
		"substituted predecessor": func(v []contract.GeneratorHistory) []contract.GeneratorHistory {
			v[0].PredecessorAttemptID = generatedVectorID(96)
			return v
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, bundle, history := generatedBoundResidueSuccessorState(t)
			generatedSetHistory(t, s, 9, bundle.Lineages[0].Templates[2].AttemptID, damage(history))
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("history did not preserve the exact admitted predecessor path")
			}
		})
	}
}

// full_only: false
func TestGeneratedHistoryCannotReplaceUnresolvedOriginal(t *testing.T) {
	s, bundle, _ := generatedBoundResidueSuccessorState(t)
	first, next := bundle.Lineages[0].Templates[0], bundle.Lineages[0].Templates[2]
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("valid unresolved original", err)
	}
	builder := &generatedSelectionBuilder{facts: g, vectors: newGeneratedVectorValidation(&g.vectors)}
	if err := builder.validateCreateHistory(g.attempts[next.AttemptID], contract.GeneratedAttemptSupportKind, next.AttemptID, g.attempts[next.AttemptID].record.History); err != nil {
		t.Fatal("valid unresolved original history", err)
	}
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind == 9 && row.RecordID == first.AttemptID || row.Kind == 11 && row.RecordID == first.HazardID {
				return true
			}
			if row.Kind != contract.GeneratorVectorSupportKind {
				return false
			}
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			return v.OwnerKind == 9 && v.OwnerID == first.AttemptID || v.OwnerKind == 11 && v.OwnerID == first.HazardID
		})
	}
	s.root.Generated.Attempts, s.root.Generated.Hazards = 1, 0
	owners := []contract.ID{s.root.Generated.ActiveOwner, next.DutyID}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	generatedRefreshPhaseSetsUnrefreshed(t, s)
	s.generatedWork = nil
	// Removing the unresolved original cannot form a new ownership index.
	// Keep the history-reader check independent of those stale commitments.
	fixture := *g
	fixture.attempts = maps.Clone(g.attempts)
	delete(fixture.attempts, first.AttemptID)
	if _, released := fixture.releases[first.AttemptID]; released {
		t.Fatal("unresolved original fixture unexpectedly has release provenance")
	}
	fixture.vectors, err = newGeneratedVectorSet(s.root.Domain, s.supportRecords())
	if err != nil {
		t.Fatal("remaining history vector framing", err)
	}
	builder = &generatedSelectionBuilder{facts: &fixture, vectors: newGeneratedVectorValidation(&fixture.vectors)}
	if err := builder.validateCreateHistory(g.attempts[next.AttemptID], contract.GeneratedAttemptSupportKind, next.AttemptID, g.attempts[next.AttemptID].record.History); err == nil {
		t.Fatal("history reader replaced an unresolved original Attempt and Hazard")
	}
	if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
		t.Fatal("history replaced an unresolved original Attempt and Hazard")
	}
}

// full_only: false
func TestGeneratedResultRecordingUpdatesRetainedHistory(t *testing.T) {
	for _, disposition := range []uint8{1, 2} {
		t.Run(fmt.Sprint(disposition), func(t *testing.T) {
			s, _, _ := generatedBoundResidueSuccessorState(t)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			a := g.attempts[g.phase.FrontierAttemptID]
			result := generatedPublicResultFixture(t, a, disposition)
			plan := &generatedRecordPlan{expected: a.expected, result: result, phase: contract.GeneratorPhaseIdentity{AfterPhase: g.phase.Phase + 1},
				reference: contract.GeneratorResultReference{Schema: 1, ResultID: a.record.ResultID, ResultBodyDigest: contract.Hash(result), ResultLength: uint32(len(result))}}
			rows, err := generatedRecordedRows(g, plan, generatedVectorID(95))
			if err != nil {
				t.Fatal(err)
			}
			vectors, err := resolveGeneratedVectorOwners(s.root.Domain, s.root.Snapshot, s.root.Generated, rows, nil, g.bundles)
			if err != nil {
				t.Fatal("recorded history left missing or unreferenced carriers", err)
			}
			for _, row := range rows {
				var descriptor contract.GeneratorDescriptor
				if row.Kind == 9 && row.RecordID == a.record.AttemptID {
					v, err := contract.InspectGeneratedAttemptRecord(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					descriptor = v.History
				} else if row.Kind == 10 && row.RecordID == a.record.OwnerID {
					v, err := contract.InspectGeneratedDutyRecord(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					descriptor = v.History
				} else {
					continue
				}
				history, err := vectors.resolve(row.Kind, row.RecordID, contract.GeneratorVectorHistory, descriptor)
				if err != nil || len(history) != 2 {
					t.Fatal("recording changed ancestry length", err)
				}
				before, err := g.vectors.resolve(row.Kind, row.RecordID, contract.GeneratorVectorHistory, a.record.History)
				if err != nil || !bytes.Equal(history[0], before[0]) {
					t.Fatal("recording rewrote predecessor history", err)
				}
				last, err := contract.InspectGeneratorHistory(history[1])
				state := uint8(contract.GeneratedEffectSucceeded)
				if disposition == 2 {
					state = contract.GeneratedEffectFailedTerminal
				}
				if err != nil || last.PredecessorAttemptID != a.record.AttemptID || last.ResultID != a.record.ResultID ||
					last.ResultDigest != contract.Hash(result) || last.Outcome != state || last.OwnerID != a.record.OwnerID {
					t.Fatal("recording left a stale history frontier", err)
				}
			}
			generatedRepackSupport(t, s, rows, g.bundles)
			s.root.Generated.ActivePhase, s.root.Generated.Results = generatedVectorID(95), 1
			generatedRefreshSupport(t, s)
			after, err := s.selectedGeneratedWork(context.Background())
			if err != nil || after.phase.AcceptedResultID != a.record.ResultID || !bytes.Equal(after.attempts[a.record.AttemptID].result, result) {
				t.Fatal("packed state lost recorded successor history", err)
			}
			for stage := contract.GeneratedStageRetainedResult; stage < contract.GeneratedStageTerminal; stage++ {
				t.Run(fmt.Sprintf("reject-stage%d", stage), func(t *testing.T) {
					changed := after.attempts[a.record.AttemptID].record
					changed.Stage = stage
					body, err := contract.EncodeGeneratedAttemptRecord(changed)
					if err != nil {
						t.Fatal(err)
					}
					generatedReplaceRecord(t, s, 9, changed.AttemptID, body)
					phase := *after.phase
					phase.Stage = stage
					body, err = contract.EncodeGeneratedPhaseRecord(phase)
					if err != nil {
						t.Fatal(err)
					}
					generatedReplaceRecord(t, s, 5, phase.OperationID, body)
					generatedRefreshPhaseSets(t, s)
					if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
						t.Fatal("recorded result restored an unfinished recovery stage")
					}
				})
			}
		})
	}
}
