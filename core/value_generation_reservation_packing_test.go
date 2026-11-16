package core

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedReleasePackingUsesOriginalAction(t *testing.T) {
	for _, action := range []uint8{1, 2} {
		t.Run(fmt.Sprint(action), func(t *testing.T) {
			s, a, _ := generatedInboxReleaseTemplateState(t, action, 2, contract.GeneratedReleasePending)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			locations, err := format.ResolveGeneratedSlices(s.root.Domain, s.root.Snapshot, s.root.Generated, s.support)
			if err != nil {
				t.Fatal(err)
			}
			groups, err := generatedReservationGroups(s.supportRecords(), locations, g.bundles)
			if err != nil {
				t.Fatal(err)
			}
			class := format.CreateContinuationSupport
			if action == 2 {
				class = format.DeleteContinuationSupport
			}
			found := 0
			for _, group := range groups {
				for _, row := range group.Records {
					if row.Kind != 9 && row.Kind != 12 {
						continue
					}
					if group.Class != class || group.Owner != a.record.AttemptID {
						t.Fatal("original Attempt and release used the wrong continuation group", row.Kind, group.Class)
					}
					found++
				}
			}
			if found != 2 {
				t.Fatal("missing original Attempt or release")
			}
		})
	}
}

// full_only: false
func TestGeneratedResultPackingUsesReservedActionGroup(t *testing.T) {
	for _, action := range []uint8{1, 2} {
		t.Run(fmt.Sprint(action), func(t *testing.T) {
			var s *StateSession
			var a generatedAttempt
			var class format.SupportStorageGroup
			var owner contract.ID
			if action == 1 {
				s, a = generatedUnselectedCleanupState(t, 0)
				class, owner = format.ResultSupport, a.record.ResultID
			} else {
				s, a, _, _ = generatedEnteredRetirementState(t, true)
				class, owner = format.DeleteContinuationSupport, a.record.AttemptID
			}
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			locations, err := format.ResolveGeneratedSlices(s.root.Domain, s.root.Snapshot, s.root.Generated, s.support)
			if err != nil {
				t.Fatal(err)
			}
			groups, err := generatedReservationGroups(s.supportRecords(), locations, g.bundles)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, group := range groups {
				for _, row := range group.Records {
					if row.Kind != 4 || row.RecordID != a.record.ResultID {
						continue
					}
					if found || group.Class != class || group.Owner != owner {
						t.Fatal("result used space outside its reserved action group", group.Class, class)
					}
					found = true
				}
			}
			if !found {
				t.Fatal("original result was dropped")
			}
			if _, err := format.PackRequiredSupportRows(s.root.Domain, groups, 0); err != nil {
				t.Fatal("reserved result group could not be packed", err)
			}
			row := g.records[generatedRecordKey{4, a.record.ResultID}]
			if _, err := generatedReservationGroups([]contract.SupportRecord{row}, nil, nil); err == nil {
				t.Fatal("result packed without its original action")
			}
			row.RecordID = generatedVectorID(98)
			if _, err := generatedReservationGroups([]contract.SupportRecord{row}, nil, g.bundles); err == nil {
				t.Fatal("result packed under a different record identity")
			}
		})
	}
}

// full_only: false
func TestGeneratedHistoryPackingUsesPredecessorAttempt(t *testing.T) {
	bundle, _, _ := generatedEffectPlanFixture(t)
	for _, tc := range []struct {
		name         string
		predecessors []contract.GeneratorAttemptTemplate
		class        format.SupportStorageGroup
	}{
		{"create", []contract.GeneratorAttemptTemplate{bundle.Lineages[0].Templates[0], bundle.Lineages[0].Templates[2]}, format.CreateContinuationSupport},
		{"delete", []contract.GeneratorAttemptTemplate{bundle.Lineages[1].Templates[0], bundle.Lineages[2].Templates[0]}, format.DeleteContinuationSupport},
	} {
		for _, ownerKind := range []uint8{9, 10, 11} {
			t.Run(fmt.Sprintf("%s/owner%d", tc.name, ownerKind), func(t *testing.T) {
				var history [][]byte
				for i, x := range tc.predecessors {
					v := contract.GeneratorHistory{Schema: 1, PredecessorAttemptID: x.AttemptID, OwnerID: generatedVectorID(91), Outcome: contract.GeneratedEffectClosedWithResidue}
					if i+1 < len(tc.predecessors) {
						v.NextAttemptID, v.Edge = tc.predecessors[i+1].AttemptID, 2
					}
					body, err := contract.EncodeGeneratorHistory(v)
					if err != nil {
						t.Fatal(err)
					}
					history = append(history, body)
				}
				_, rows := generatedVectorRows(t, ownerKind, generatedVectorID(92), contract.GeneratorVectorHistory, history)
				groups, err := generatedReservationGroups(rows, nil, []contract.GeneratorPlanBundle{bundle})
				if err != nil {
					t.Fatal(err)
				}
				if len(groups) != len(tc.predecessors) {
					t.Fatal("history imposed a whole-owner continuation bound", len(groups))
				}
				for _, group := range groups {
					if group.Class != tc.class || len(group.Records) != 1 {
						t.Fatal("wrong history group")
					}
					carrier, err := contract.InspectGeneratorVectorCarrier(group.Records[0].Body)
					if err != nil {
						t.Fatal(err)
					}
					v, err := contract.InspectGeneratorHistory(carrier.Row)
					if err != nil || group.Owner != v.PredecessorAttemptID {
						t.Fatal("history charged its container instead of its predecessor", err)
					}
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedPhasePackingUsesFirstEnteredAttempt(t *testing.T) {
	s := generatedReservationState(t)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	locations, err := format.ResolveGeneratedSlices(s.root.Domain, s.root.Snapshot, s.root.Generated, s.support)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := generatedReservationGroups(s.supportRecords(), locations, g.bundles)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		for _, row := range group.Records {
			if row.Kind == 5 {
				if group.Class != format.CreateContinuationSupport || group.Owner != g.phase.FrontierAttemptID {
					t.Fatal("phase charged an operation group instead of its first entered Attempt")
				}
				return
			}
		}
	}
	t.Fatal("phase missing")
}

// full_only: false
func TestGeneratedLineagePackingUsesInstalledBranch(t *testing.T) {
	s := generatedReservationState(t)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lineage := g.bundles[0].Lineages[0]
	row := g.records[generatedRecordKey{8, lineage.LineageID}]
	initial, err := contract.DecodeGeneratedLineageRecord(row.Body)
	if err != nil {
		t.Fatal(err)
	}
	for branch := uint8(0); branch < lineage.TemplateCount; branch++ {
		v := initial
		v.Branch = branch
		if branch == 1 || branch >= 3 {
			v.NoEffectUsed = 1
		}
		if branch >= 2 {
			v.ResidueUsed = 1
		}
		row.Body, err = contract.EncodeGeneratedLineageRecord(v)
		if err != nil {
			t.Fatal(err)
		}
		groups, err := generatedReservationGroups([]contract.SupportRecord{row}, nil, g.bundles)
		if err != nil || len(groups) != 1 || groups[0].Class != format.CreateContinuationSupport || groups[0].Owner != lineage.Templates[branch].AttemptID {
			t.Fatal("Lineage charged a predecessor or operation instead of its installed branch", branch, err)
		}
	}
	if _, err := generatedReservationGroups([]contract.SupportRecord{row}, nil, nil); err == nil {
		t.Fatal("Lineage packed without its immutable graph")
	}
	wrong := initial
	wrong.OperationID = generatedVectorID(99)
	row.Body, err = contract.EncodeGeneratedLineageRecord(wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := generatedReservationGroups([]contract.SupportRecord{row}, nil, g.bundles); err == nil {
		t.Fatal("Lineage packed under a different operation")
	}
}

// full_only: false
func TestGeneratedPhasePackingSkipsUnretainedTemplates(t *testing.T) {
	bundle, _, _ := generatedEffectPlanFixture(t)
	for _, branches := range [][]uint8{{0, 2, 4}, {2, 4}, {1, 3}, {4}} {
		t.Run(fmt.Sprintf("%v", branches), func(t *testing.T) {
			// This exercises storage order, not successor-entry authority.
			s := generatedActiveCreateBranches(t, branches...)
			locations, err := format.ResolveGeneratedSlices(s.root.Domain, s.root.Snapshot, s.root.Generated, s.support)
			if err != nil {
				t.Fatal(err)
			}
			rows := s.supportRecords()
			slices.Reverse(rows)
			groups, err := generatedReservationGroups(rows, locations, []contract.GeneratorPlanBundle{bundle})
			if err != nil {
				t.Fatal(err)
			}
			for _, group := range groups {
				for _, row := range group.Records {
					if row.Kind == 5 {
						if group.Class != format.CreateContinuationSupport || group.Owner != bundle.Lineages[0].Templates[branches[0]].AttemptID {
							t.Fatal("phase used row order, the frontier or an unretained template")
						}
						return
					}
				}
			}
			t.Fatal("phase missing")
		})
	}
}

// full_only: false
func TestGeneratedFactsAndProgressPackingUseTheirAttempt(t *testing.T) {
	bundle, _, _ := generatedEffectPlanFixture(t)
	for _, x := range []contract.GeneratorAttemptTemplate{bundle.Lineages[0].Templates[2], bundle.Lineages[1].Templates[0]} {
		progress, err := contract.EncodeGeneratorProgress(contract.GeneratorProgress{Schema: 1, AttemptID: x.AttemptID, ResultID: x.ResultID,
			Evidence: contract.EmptyGeneratorVector(contract.GeneratorVectorProofs), RequiredSteps: 1, CompletionClass: x.CompletionClass})
		if err != nil {
			t.Fatal(err)
		}
		safeFacts := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Disposition: contract.GeneratorDispositionUnknown, Reason: 8,
			Action: x.Action, LifecycleMode: x.LifecycleMode, ResourceContractID: x.ResourceContractID, RequestDigest: generatedVectorID(91), IntentDigest: x.IntentDigest}
		if x.Action == contract.GeneratorActionDelete {
			safeFacts.Target, safeFacts.ResourceData = []byte("fixture-target"), []byte("fixture-resource")
		}
		facts, err := contract.EncodeGeneratorSafeFacts(safeFacts)
		if err != nil {
			t.Fatal(err)
		}
		facts, err = contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: x.ResultID, Facts: facts})
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			kind      contract.GeneratorVectorKind
			ownerKind uint8
			owner     contract.ID
			body      []byte
		}{
			{contract.GeneratorVectorFacts, 9, x.AttemptID, facts},
			{contract.GeneratorVectorProgress, 9, x.AttemptID, progress},
			{contract.GeneratorVectorProgress, 10, x.DutyID, progress},
		} {
			t.Run(fmt.Sprintf("action%d/vector%d/owner%d", x.Action, tc.kind, tc.ownerKind), func(t *testing.T) {
				_, rows := generatedVectorRows(t, tc.ownerKind, tc.owner, tc.kind, [][]byte{tc.body})
				groups, err := generatedReservationGroups(rows, nil, []contract.GeneratorPlanBundle{bundle})
				class := format.CreateContinuationSupport
				if x.Action == 2 {
					class = format.DeleteContinuationSupport
				}
				if err != nil || len(groups) != 1 || groups[0].Owner != x.AttemptID || groups[0].Class != class {
					t.Fatal("facts or progress charged the wrong Attempt group", err)
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedProofPackingUsesItsSubject(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	input := generatedReservationInputFixture(t, s)
	reservation, err := s.deriveGeneratedReservation(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []uint8{0, 1, 2} {
		t.Run(fmt.Sprint(action), func(t *testing.T) {
			subject := *reservation.candidate.head.Generator
			want, class := input.graph.Lineages[0].Templates[0].AttemptID, format.CreateContinuationSupport
			if action != 0 {
				x := input.graph.Lineages[0].Templates[2]
				if action == 2 {
					x, class = input.graph.Lineages[1].Templates[0], format.DeleteContinuationSupport
				}
				subject.Purpose, subject.BeforePhase, subject.AfterPhase = contract.GeneratorAuthorityRecord, 1, 2
				subject.LineageID, subject.AttemptID, subject.PredecessorAttemptID = x.LineageID, x.AttemptID, x.PredecessorAttemptID
				subject.ResultID, subject.ResultDigest = x.ResultID, generatedVectorID(98)
				subject.DescriptorID, subject.ConfigContractID, subject.ResultContractID = x.DescriptorID, x.ConfigContractID, x.ResultContractID
				want = x.AttemptID
			}
			body, err := contract.EncodeGeneratorAuthoritySubject(subject)
			if err != nil {
				t.Fatal(err)
			}
			// A syntactic signature supplies packing input, not authority evidence.
			body, err = contract.EncodeGeneratorProof(contract.GeneratorProof{Schema: 1, Purpose: subject.Purpose, Subject: body,
				Signature: []byte{0x30, 6, 2, 1, 1, 2, 1, 1}, SupportBindingID: generatedVectorID(99)})
			if err != nil {
				t.Fatal(err)
			}
			_, rows := generatedVectorRows(t, 2, subject.OperationID, contract.GeneratorVectorProofs, [][]byte{body})
			proofID := rows[0].RecordID
			for _, row := range reservation.state.supportRecords() {
				if row.Kind == 9 {
					rows = append(rows, row)
				}
			}
			groups, err := generatedReservationGroups(rows, nil, []contract.GeneratorPlanBundle{input.graph})
			if err != nil {
				t.Fatal(err)
			}
			for _, group := range groups {
				for _, row := range group.Records {
					if row.RecordID == proofID {
						if group.Class != class || group.Owner != want {
							t.Fatal("proof charged the wrong continuation")
						}
						return
					}
				}
			}
			t.Fatal("proof missing")
		})
	}
}

// full_only: false
func TestGeneratedPackingRejectsUnboundAttempt(t *testing.T) {
	s := generatedReservationState(t)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	original := g.attempts[g.phase.FrontierAttemptID].record
	for name, mutate := range map[string]func(*contract.GeneratedAttemptRecord){
		"domain":    func(a *contract.GeneratedAttemptRecord) { a.DomainID = generatedVectorID(96) },
		"operation": func(a *contract.GeneratedAttemptRecord) { a.OperationID = generatedVectorID(96) },
		"attempt":   func(a *contract.GeneratedAttemptRecord) { a.AttemptID = generatedVectorID(96) },
		"template":  func(a *contract.GeneratedAttemptRecord) { a.TemplateDigest = generatedVectorID(96) },
		"result":    func(a *contract.GeneratedAttemptRecord) { a.ResultID = generatedVectorID(96) },
	} {
		t.Run(name, func(t *testing.T) {
			a := original
			mutate(&a)
			body, err := contract.EncodeGeneratedAttemptRecord(a)
			if err != nil {
				t.Fatal(err)
			}
			rows := []contract.SupportRecord{{Kind: 9, RecordID: a.AttemptID, Body: body}}
			if _, err := generatedReservationGroups(rows, nil, g.bundles); err == nil {
				t.Fatal("unbound Attempt acquired a continuation allowance")
			}
		})
	}
	body, err := contract.EncodeGeneratedAttemptRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	rows := []contract.SupportRecord{{Kind: 9, RecordID: original.AttemptID, Body: body}}
	if _, err := generatedReservationGroups(rows, nil, nil); err == nil {
		t.Fatal("Attempt without an immutable graph acquired a continuation allowance")
	}
	if _, err := generatedReservationGroups(append(slices.Clone(rows), rows...), nil, g.bundles); err == nil {
		t.Fatal("duplicate Attempt acquired a continuation allowance")
	}
	if _, err := generatedReservationGroups(rows, nil, append(slices.Clone(g.bundles), g.bundles...)); err == nil {
		t.Fatal("duplicate operation graph accepted")
	}
}
