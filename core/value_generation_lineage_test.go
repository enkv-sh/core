package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedEnteredCreateBranchSets(t *testing.T) {
	// The subsets of {0,1,3} and {0,2,4}, encoded as branch-bit masks.
	valid := map[uint8]bool{0: true, 1: true, 2: true, 3: true, 4: true, 5: true, 8: true,
		9: true, 10: true, 11: true, 16: true, 17: true, 20: true, 21: true}
	bundle, _, _ := generatedEffectPlanFixture(t)
	for mask := uint8(0); mask < 32; mask++ {
		for placement := 0; placement < 3; placement++ {
			t.Run(fmt.Sprintf("mask%d/placement%d", mask, placement), func(t *testing.T) {
				g := &generatedSelection{attempts: make(map[contract.ID]generatedAttempt), releases: make(map[contract.ID]generatedReleasedAttempt)}
				for branch, template := range bundle.Lineages[0].Templates {
					if mask&(1<<branch) == 0 {
						continue
					}
					if placement == 1 || placement == 2 && branch%2 == 0 {
						g.releases[template.AttemptID] = generatedReleasedAttempt{template: template}
					} else {
						g.attempts[template.AttemptID] = generatedAttempt{expected: contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Template: template}}
					}
				}
				if err := (&generatedSelectionBuilder{facts: g}).validateEnteredCreateBranches(); (err == nil) != valid[mask] {
					t.Fatal("entered branches did not preserve one fixed path", err)
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedActiveLineageRejectsChangedDefinition(t *testing.T) {
	for name, change := range map[string]func(*contract.GeneratedLineageRecord){
		"operation":                  func(v *contract.GeneratedLineageRecord) { v.OperationID[0] ^= 1 },
		"incarnation":                func(v *contract.GeneratedLineageRecord) { v.IncarnationID[0] ^= 1 },
		"name":                       func(v *contract.GeneratedLineageRecord) { v.Name += "-other" },
		"epoch":                      func(v *contract.GeneratedLineageRecord) { v.Epoch++ },
		"intent":                     func(v *contract.GeneratedLineageRecord) { v.Intent.Digest[0] ^= 1 },
		"membership":                 func(v *contract.GeneratedLineageRecord) { v.Membership.Digest[0] ^= 1 },
		"templates":                  func(v *contract.GeneratedLineageRecord) { v.Templates.Digest[0] ^= 1 },
		"frontier":                   func(v *contract.GeneratedLineageRecord) { v.Frontier = 2 },
		"unentered no-effect branch": func(v *contract.GeneratedLineageRecord) { v.Branch, v.NoEffectUsed = 1, 1 },
		"unentered residue branch":   func(v *contract.GeneratedLineageRecord) { v.Branch, v.ResidueUsed = 2, 1 },
	} {
		t.Run(name, func(t *testing.T) {
			s := generatedReservationState(t)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("valid lineage refused", err)
			}
			id := g.bundles[0].Lineages[0].LineageID
			v, err := contract.DecodeGeneratedLineageRecord(g.records[generatedRecordKey{8, id}].Body)
			if err != nil {
				t.Fatal(err)
			}
			change(&v)
			body, err := contract.EncodeGeneratedLineageRecord(v)
			if err != nil {
				t.Fatal("mutation failed before selected relations", err)
			}
			generatedReplaceRecord(t, s, 8, id, body)
			s.generatedWork = nil
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("changed active lineage accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedLineageEnvelopeBindsDomainAndRecordID(t *testing.T) {
	for _, field := range []string{"domain", "lineage"} {
		t.Run(field, func(t *testing.T) {
			s := generatedReservationState(t)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			row := g.records[generatedRecordKey{8, g.bundles[0].Lineages[0].LineageID}]
			v, err := contract.DecodeGeneratedLineageRecord(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if field == "domain" {
				v.DomainID[0] ^= 1
			} else {
				v.LineageID[0] ^= 1
			}
			row.Body, err = contract.EncodeGeneratedLineageRecord(v)
			if err != nil {
				t.Fatal(err)
			}
			page := format.RequiredSupportPage{Domain: s.root.Domain, Object: generatedVectorID(99), Records: []contract.SupportRecord{row}}
			if _, err := format.EncodeRequiredSupportPage(page); err == nil {
				t.Fatal("Lineage changed its support envelope")
			}
		})
	}
}

// full_only: false
func TestGeneratedActiveLineageCannotBeOmittedOrRetainedWithoutParent(t *testing.T) {
	s := generatedReservationState(t)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	row := g.records[generatedRecordKey{8, g.bundles[0].Lineages[0].LineageID}]
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(v contract.SupportRecordView) bool { return v.Kind == 8 })
	}
	generatedRefreshSupport(t, s)
	if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
		t.Fatal("active parent lost its lineage")
	}
	detached, _ := generatedUnselectedCleanupState(t, 0)
	if _, err := detached.selectedGeneratedWork(context.Background()); err != nil {
		t.Fatal("detached cleanup refused", err)
	}
	detached.support[len(detached.support)-1].Records = append(detached.support[len(detached.support)-1].Records, contract.SupportRecordView(row))
	detached.generatedWork = nil
	if _, err := detached.selectedGeneratedWork(context.Background()); err == nil {
		t.Fatal("detached graph retained a dead active lineage")
	}
}

// full_only: false
func TestGeneratedActiveLineageTracksEnteredSuccessor(t *testing.T) {
	s, bundle, _ := generatedBoundResidueSuccessorState(t)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id := bundle.Lineages[0].LineageID
	v, err := contract.DecodeGeneratedLineageRecord(g.records[generatedRecordKey{8, id}].Body)
	if err != nil || v.Branch != 2 || v.Frontier != 2 || v.ResidueUsed != 1 || v.NoEffectUsed != 0 {
		t.Fatal("lineage did not retain its entered successor and consumed allowance", err)
	}
	v.Branch, v.Frontier, v.ResidueUsed = 0, 0, 0
	body, err := contract.EncodeGeneratedLineageRecord(v)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 8, id, body)
	generatedRefreshSupport(t, s)
	if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
		t.Fatal("lineage restored a consumed allowance")
	}
}

// full_only: false
func TestGeneratedCreateBranchLimitsArePerLineage(t *testing.T) {
	bundle, _, _ := generatedEffectPlanFixture(t)
	n, r := bundle.Lineages[0].Templates[1], bundle.Lineages[0].Templates[2]
	r.LineageID, r.AttemptID = generatedVectorID(90), generatedVectorID(91)
	g := &generatedSelection{attempts: map[contract.ID]generatedAttempt{
		n.AttemptID: {expected: contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Template: n}},
		r.AttemptID: {expected: contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Template: r}},
	}}
	if err := (&generatedSelectionBuilder{facts: g}).validateEnteredCreateBranches(); err != nil {
		t.Fatal("independent lineages shared an allowance", err)
	}
	r.LineageID = n.LineageID
	delete(g.attempts, r.AttemptID)
	g.releases = map[contract.ID]generatedReleasedAttempt{r.AttemptID: {template: r}}
	if err := (&generatedSelectionBuilder{facts: g}).validateEnteredCreateBranches(); err == nil {
		t.Fatal("released predecessor hid incompatible branches")
	}
}

// full_only: false
func TestGeneratedReservationStoresActiveLineage(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	input := generatedReservationInputFixture(t, s)
	reservation, err := s.deriveGeneratedReservation(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	g, err := reservation.state.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lineage := input.graph.Lineages[0]
	row, present := g.records[generatedRecordKey{8, lineage.LineageID}]
	if !present {
		t.Fatal("reservation omitted its active lineage")
	}
	v, err := contract.DecodeGeneratedLineageRecord(row.Body)
	if err != nil || v.DomainID != s.root.Domain || v.OperationID != input.parent.OperationID || v.Name != lineage.Name ||
		v.IncarnationID != lineage.EntryIncarnationID || v.Epoch != lineage.Epoch || v.Branch != 0 || v.Frontier != 0 ||
		v.NoEffectUsed != 0 || v.ResidueUsed != 0 || !g.hasRecord(generatedRecordKey{8, lineage.LineageID}) {
		t.Fatal("initial lineage changed its identity or consumed a branch allowance", err)
	}
	templates, err := contract.GeneratorLineageTemplatesDescriptor([]contract.GeneratorLineageTemplate{lineage})
	if err != nil || v.Templates != templates || v.Membership != input.graph.ValueEntryPlans[0].IntendedMembership {
		t.Fatal("initial lineage changed its template or membership commitment", err)
	}
	intent, err := g.readSelectedLogicalSlice(t.Context(), contract.GeneratorContentIntent, lineage.IntentDigest, v.Intent, contract.GeneratorIntentMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := contract.GeneratorIntentDigest(intent)
	if err != nil || digest != lineage.IntentDigest {
		t.Fatal("initial lineage changed its intent", err)
	}
	generatedRepackSupport(t, reservation.state, reservation.state.supportRecords(), g.bundles)
	if _, err := reservation.state.selectedGeneratedWork(context.Background()); err != nil {
		t.Fatal("packed lineage refused", err)
	}
}

// full_only: false
func TestGeneratedReservationEntersEveryOriginalBeforeDispatch(t *testing.T) {
	for _, count := range []int{2, 128} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			names := make([]string, count)
			for i := range names {
				names[i] = fmt.Sprintf("generated-%03d", i)
			}
			s := generatedEmptyPredecessor(t)
			input := generatedReservationInputForGenerations(t, s, generatedVectorID(10), names)
			r, err := s.deriveGeneratedReservation(context.Background(), input)
			if err != nil {
				t.Fatal("multi-lineage reservation", err)
			}
			g, err := r.state.selectedGeneratedWork(context.Background())
			if err != nil || len(g.attempts) != count || g.phase.Attempts.Count != uint32(count) {
				t.Fatal("lineage plan did not reserve every original Attempt", err)
			}
			seen := 0
			for _, lineage := range input.graph.Lineages {
				row, ok := g.records[generatedRecordKey{8, lineage.LineageID}]
				if lineage.Purpose != 1 {
					if ok {
						t.Fatal("cleanup container acquired a create Lineage record")
					}
					continue
				}
				v, err := contract.InspectGeneratedLineageRecord(row.Body)
				if !ok || err != nil || string(v.Name) != lineage.Name || v.Branch != 0 || v.Frontier != 0 || v.NoEffectUsed != 0 || v.ResidueUsed != 0 ||
					g.attempts[lineage.Templates[0].AttemptID].record.State != contract.GeneratedEffectTransmitted {
					t.Fatal("initial lineage or transmitted original omitted", err)
				}
				seen++
			}
			if seen != count || r.state.validateGeneratedSelection(t.Context(), nil) != nil {
				t.Fatal("lineage set did not preserve the complete initial reservation")
			}
			last := input.graph.ValueEntryPlans[count-1].LineageID
			rows := slices.DeleteFunc(r.state.supportRecords(), func(row contract.SupportRecord) bool {
				return row.Kind == 8 && row.RecordID == last
			})
			generatedRepackSupport(t, r.state, rows, g.bundles)
			if _, err := r.state.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("entered sibling lineage was not required")
			}
		})
	}
}

func generatedPlannedResidueSuccessorState(t testing.TB) (*StateSession, contract.GeneratorPlanBundle) {
	t.Helper()
	s, bundle, _ := generatedBoundResidueSuccessorState(t)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	x := bundle.Lineages[0].Templates[2]
	for i := range s.support {
		s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
			if row.Kind == 9 && row.RecordID == x.AttemptID || row.Kind == 10 && row.RecordID == x.DutyID {
				return true
			}
			if row.Kind != contract.GeneratorVectorSupportKind {
				return false
			}
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			return v.OwnerKind == 9 && v.OwnerID == x.AttemptID || v.OwnerKind == 10 && v.OwnerID == x.DutyID
		})
	}
	lineage, err := contract.DecodeGeneratedLineageRecord(g.records[generatedRecordKey{8, x.LineageID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	lineage.Frontier = 0
	body, err := contract.EncodeGeneratedLineageRecord(lineage)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 8, x.LineageID, body)
	s.root.Generated.Attempts, s.root.Generated.Duties = 1, 0
	owners := []contract.ID{g.parent.OperationID, bundle.Lineages[0].Templates[0].HazardID}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	generatedRefreshPhaseSets(t, s)
	return s, bundle
}

// full_only: false
func TestGeneratedPlannedSuccessorRetainsPredecessorWithoutEntry(t *testing.T) {
	s, bundle := generatedPlannedResidueSuccessorState(t)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("planned successor refused", err)
	}
	first, next := bundle.Lineages[0].Templates[0], bundle.Lineages[0].Templates[2]
	if len(g.attempts) != 1 || g.attempts[first.AttemptID].record.State != contract.GeneratedEffectClosedWithResidue ||
		!g.hasRecord(generatedRecordKey{11, first.HazardID}) || g.phase.FrontierAttemptID != next.AttemptID ||
		g.phase.ResidueUsed != 1 || g.phase.NoEffectUsed != 0 || g.phase.Attempts.Count != 1 ||
		!g.phase.AcceptedResultID.IsZero() || !g.phase.ResultDigest.IsZero() {
		t.Fatal("planned successor lost its predecessor or consumed allowance")
	}
	if _, entered := g.records[generatedRecordKey{9, next.AttemptID}]; entered {
		t.Fatal("plan installed a transmitted successor")
	}
	if _, owner := g.records[generatedRecordKey{10, next.DutyID}]; owner {
		t.Fatal("plan installed a successor result consumer")
	}
	consumers := g.consumers[materialIdentity{3, bundle.Header.MaterialID}]
	if len(consumers) != 1 || consumers[0].OwnerID != first.HazardID || consumers[0].SubjectID != first.ResultID || consumers[0].Purpose != 4 {
		t.Fatal("planned successor changed the original late-result reader or seed coverage")
	}
	if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.access[0].Records); coverageErr != nil {
		t.Fatal("planned successor changed the original late-result reader or seed coverage")
	}
	generatedRepackSupport(t, s, s.supportRecords(), g.bundles)
	if _, err := s.selectedGeneratedWork(context.Background()); err != nil {
		t.Fatal("packed planned successor refused", err)
	}
}

// full_only: false
func TestGeneratedPlannedSuccessorRejectsChangedFrontier(t *testing.T) {
	for _, change := range []string{"entered marker", "no-effect guard", "wrong planned attempt", "terminal stage", "accepted result"} {
		t.Run(change, func(t *testing.T) {
			s, bundle := generatedPlannedResidueSuccessorState(t)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("valid planned successor refused", err)
			}
			v, err := contract.DecodeGeneratedLineageRecord(g.records[generatedRecordKey{8, bundle.Lineages[0].LineageID}].Body)
			if err != nil {
				t.Fatal(err)
			}
			p := *g.phase
			switch change {
			case "entered marker":
				v.Frontier = 2
			case "no-effect guard":
				v.Branch, v.NoEffectUsed, v.ResidueUsed = 1, 1, 0
				p.Branch, p.NoEffectUsed, p.ResidueUsed = 1, 1, 0
				p.FrontierAttemptID = bundle.Lineages[0].Templates[1].AttemptID
			case "wrong planned attempt":
				p.FrontierAttemptID = bundle.Lineages[0].Templates[1].AttemptID
			case "terminal stage":
				p.Stage = contract.GeneratedStageTerminal
			case "accepted result":
				p.AcceptedResultID, p.ResultDigest = bundle.Lineages[0].Templates[2].ResultID, generatedVectorID(97)
			}
			body, err := contract.EncodeGeneratedLineageRecord(v)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 8, v.LineageID, body)
			body, err = contract.EncodeGeneratedPhaseRecord(p)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 5, p.OperationID, body)
			generatedRefreshSupport(t, s)
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("planned frontier accepted a different predecessor, result or entry state")
			}
		})
	}
}
