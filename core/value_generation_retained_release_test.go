package core

import (
	"bytes"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedInboxReleasePreservesIndependentDeleteGraph(t *testing.T) {
	s, _, release := generatedInboxReleaseState(t, 0, contract.GeneratedReleasePending)
	old, deleteAttempt, _ := generatedParkedRetirementState(t)
	var rows []contract.SupportRecord
	var locations []contract.GeneratorSliceLocation
	var bundles []contract.GeneratorPlanBundle
	seen := make(map[generatedRecordKey][]byte)
	seenBundle := make(map[contract.ID]bool)
	for _, state := range []*StateSession{s, old} {
		generatedMaterializeFixtureSupport(t, state)
		g := mustSelectedGeneratedWork(t, state)
		for _, bundle := range g.bundles {
			if !seenBundle[bundle.Header.OperationID] {
				bundles = append(bundles, bundle)
				seenBundle[bundle.Header.OperationID] = true
			}
		}
		selected, e := state.resolveSelectedGeneratedSlices()
		if e != nil {
			t.Fatal(e)
		}
		locations = append(locations, selected...)
		for _, row := range state.supportRecords() {
			if row.Kind == contract.GeneratorVectorSupportKind {
				c, e := contract.InspectGeneratorVectorCarrier(row.Body)
				if e != nil {
					t.Fatal(e)
				}
				if c.VectorKind == contract.GeneratorVectorSlices {
					continue
				}
			}
			key := generatedRecordKey{row.Kind, row.RecordID}
			if body, ok := seen[key]; ok {
				if !bytes.Equal(body, row.Body) {
					t.Fatal("fixture merge conflicting record", key)
				}
				continue
			}
			seen[key] = row.Body
			rows = append(rows, row)
		}
	}
	var e error
	locations, e = generatedUniqueLocations(locations)
	if e != nil {
		t.Fatal(e)
	}
	var bodies [][]byte
	for _, l := range locations {
		b, e := contract.EncodeGeneratorSliceLocation(l)
		if e != nil {
			t.Fatal(e)
		}
		bodies = append(bodies, b)
	}
	directory, carriers, e := generatedCarrierRows(s.root.Domain, contract.GeneratorSnapshotOwner, s.adminIndex.SliceSnapshot, contract.GeneratorVectorSlices, bodies)
	if e != nil {
		t.Fatal(e)
	}
	rows = append(rows, carriers...)
	s.access = old.access
	generatedCommitFixtureAccess(t, s)
	s.root.Generated.Slices = directory
	s.root.Generated.ActiveOwner, s.root.Generated.ActivePhase, s.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	generatedRefreshClosureCounts(&s.root.Generated, rows)
	var graphs []contract.ID
	for _, bundle := range bundles {
		graphs = append(graphs, bundle.UsePlan.PlanGraphID)
	}
	slices.SortFunc(graphs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.Graphs, e = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, slices.Compact(graphs))
	if e != nil {
		t.Fatal(e)
	}
	generatedRepackSupportAtLocations(t, s, rows, bundles, locations)
	if !s.indexSelectedMaterials() {
		t.Fatal("combined access indexing")
	}
	s.generatedWork = nil
	g := mustSelectedGeneratedWork(t, s)
	if _, ok := g.attempts[deleteAttempt.record.AttemptID]; !ok || len(g.releases) != 1 {
		t.Fatal("invalid combined predecessor")
	}
	closure, e := g.generatedInboxReleaseClosure(release.InboxID)
	if e != nil {
		t.Fatal(e)
	}
	var graphKept bool
	for _, bundle := range closure.bundles {
		graphKept = graphKept || bundle.Header.OperationID == deleteAttempt.record.OperationID
	}
	if !graphKept {
		t.Fatal("release dropped a surviving delete's exact graph")
	}
	var attemptKept bool
	for _, row := range closure.rows {
		attemptKept = attemptKept || row.Kind == 9 && row.RecordID == deleteAttempt.record.AttemptID
	}
	if !attemptKept {
		t.Fatal("surviving delete was removed")
	}
	if _, e := generatedReservationGroupsForState(s, closure.rows, closure.locations, closure.bundles); e != nil {
		t.Fatal("retained delete refused complete reservation grouping", e)
	}
}
