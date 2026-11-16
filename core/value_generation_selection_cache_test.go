package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestValidatedGeneratedSelectionCachePublishesSharedFacts(t *testing.T) {
	before := generatedEmptyPredecessor(t)
	reservation, err := before.deriveGeneratedReservation(context.Background(), generatedReservationInputFixture(t, before))
	if err != nil {
		t.Fatal("derive generated reservation", err)
	}
	state := reservation.state
	selected, err := state.validateRelationsMode(t.Context(), false)
	if err != nil || selected == nil || selected.session != state {
		t.Fatal("ordinary relations did not return accepted selection facts", err)
	}
	if partial, err := state.validateRelationsMode(t.Context(), true); err != nil || partial != nil {
		t.Fatal("administrative relations did not retain optional generated selection", err)
	}
	if err := state.validateGeneratedSelection(t.Context(), selected); err != nil || state.generatedWork == nil {
		t.Fatal("valid generated state did not retain its validated selection", err)
	}
	if state.generatedWork.selection != selected {
		t.Fatal("generated proof did not retain the accepted relation facts")
	}

	first, err := state.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("first selected generated work", err)
	}
	second, err := state.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("second selected generated work", err)
	}
	if first != second || first != state.generatedWork.selection {
		t.Fatal("cache did not publish one finished fact image")
	}

	var recordKey generatedRecordKey
	for key := range first.records {
		if key.kind != contract.GeneratedFragmentSupportKind && key.kind != contract.GeneratorVectorSupportKind {
			recordKey = key
			break
		}
	}
	var contentKey generatedContentKey
	var contentLimit uint32
	for key, location := range first.content.locations {
		contentKey, contentLimit = key, location.Length
		break
	}
	var vectorKey generatedVectorKey
	for key, vector := range first.vectors.entries {
		if len(vector.rows) > 0 {
			vectorKey = key
			break
		}
	}
	if recordKey.id.IsZero() || contentKey.id.IsZero() || vectorKey.owner.IsZero() || first.parent == nil {
		t.Fatal("fixture did not contain record, content, vector, and graph facts")
	}
	operation := first.parent.OperationID
	wantGraph, err := first.content.graphForOperation(operation)
	if err != nil {
		t.Fatal("selected graph", err)
	}
	wantRecords, wantContent, wantVectors := len(first.records), len(first.content.locations), len(first.vectors.entries)
	wantGraphs, wantMaterials := len(first.content.graphs), len(first.materials)

	check := func(g *generatedSelection) error {
		if g != first {
			return fmt.Errorf("cache returned a different fact image")
		}
		if _, ok := g.record(recordKey.kind, recordKey.id); !ok {
			return fmt.Errorf("record fact disappeared")
		}
		body, err := g.readSelectedSlice(t.Context(), contentKey.kind, contentKey.id, contentLimit)
		if err != nil || uint32(len(body)) != contentLimit {
			return fmt.Errorf("content fact changed: %w", err)
		}
		rows, err := g.vectors.resolve(vectorKey.ownerKind, vectorKey.owner, vectorKey.kind, vectorKey.vector)
		if err != nil || len(rows) == 0 {
			return fmt.Errorf("vector fact changed: %w", err)
		}
		graph, err := g.content.graphForOperation(operation)
		if err != nil || !reflect.DeepEqual(graph, wantGraph) {
			return fmt.Errorf("graph fact changed: %w", err)
		}
		retained, err := g.retainedGraph(operation)
		if err != nil || !reflect.DeepEqual(retained, wantGraph) {
			return fmt.Errorf("retained graph fact changed: %w", err)
		}
		return nil
	}
	for range 32 {
		if err := check(first); err != nil {
			t.Fatal(err)
		}
	}

	const readers = 32
	errs := make(chan error, readers)
	var group sync.WaitGroup
	for range readers {
		group.Add(1)
		go func() {
			defer group.Done()
			g, err := state.selectedGeneratedWork(context.Background())
			if err == nil {
				err = check(g)
			}
			if err != nil {
				errs <- err
			}
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if len(first.records) != wantRecords || len(first.content.locations) != wantContent || len(first.vectors.entries) != wantVectors ||
		len(first.content.graphs) != wantGraphs || len(first.materials) != wantMaterials {
		t.Fatal("concurrent reads changed published facts")
	}

	state.generatedGraphs[contract.ID{}] = validatedGeneratorGraph{}
	if len(first.content.graphs) != wantGraphs {
		t.Fatal("published graph cache shares its map container with selected facts")
	}
	delete(state.generatedGraphs, contract.ID{})

	rows, err := first.vectors.resolve(vectorKey.ownerKind, vectorKey.owner, vectorKey.kind, vectorKey.vector)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(rows[0])
	rows[0] = nil
	again, err := first.vectors.resolve(vectorKey.ownerKind, vectorKey.owner, vectorKey.kind, vectorKey.vector)
	if err != nil || len(again) == 0 || !bytes.Equal(again[0], want) {
		t.Fatal("caller-owned vector container changed shared facts", err)
	}

	records := state.generatedCoverageRecords()
	one := newGeneratedCoverageValidation(first)
	two := newGeneratedCoverageValidation(first)
	if !one.consume(records) || one.consume(records) || !two.consume(records) || len(first.materials) != len(records) {
		t.Fatal("operation-local material consumption changed shared facts or another workspace")
	}
}

// full_only: false
func TestValidatedGeneratedSelectionCacheBindsSessionRootAndAuthority(t *testing.T) {
	before := generatedEmptyPredecessor(t)
	reservation, err := before.deriveGeneratedReservation(context.Background(), generatedReservationInputFixture(t, before))
	if err != nil {
		t.Fatal("derive generated reservation", err)
	}
	state := reservation.state
	if state.validateGeneratedSelection(t.Context(), nil) != nil || state.generatedWork == nil {
		t.Fatal("valid generated state did not retain its validated selection")
	}
	cached := state.generatedWork.selection

	other := *state
	other.generatedWork = state.generatedWork
	fresh, err := other.selectedGeneratedWork(context.Background())
	if err != nil || fresh == cached {
		t.Fatal("different session reused cached selected facts", err)
	}

	changed := *state
	changed.root.Generated.ActivePhase = contract.Hash([]byte("different active phase"))
	if _, err := changed.selectedGeneratedWork(context.Background()); err == nil {
		t.Fatal("changed generated root reused a prior validated selection")
	}

	bad := *state
	bad.generatedWork, bad.generatedGraphs = nil, nil
	subject := *bad.head.Generator
	subject.RequiredAuthoritySet ^= 2
	bad.head.Generator = &subject
	if bad.validateGeneratedSelection(t.Context(), nil) == nil || bad.generatedWork != nil || bad.generatedGraphs != nil {
		t.Fatal("failed authority check published selected facts")
	}
	again, err := state.selectedGeneratedWork(context.Background())
	if err != nil || again != cached {
		t.Fatal("failed authority check changed the valid session cache", err)
	}
}

// full_only: false
func TestGeneratedSelectedTargetsRemainStableAcrossConcurrentReads(t *testing.T) {
	for _, retainedEvidence := range []bool{false, true} {
		t.Run(fmt.Sprintf("retained-evidence=%t", retainedEvidence), func(t *testing.T) {
			var state *StateSession
			var target contract.GeneratorTarget
			var operation contract.ID
			var readTarget func(*generatedSelection) (contract.GeneratorTarget, error)
			if retainedEvidence {
				var attempt generatedAttempt
				var duty contract.GeneratedDutyRecord
				state, attempt, duty, target = generatedEnteredRetirementState(t, false)
				operation = attempt.record.OperationID
				readTarget = func(g *generatedSelection) (contract.GeneratorTarget, error) {
					selected, err := g.retirementTarget(t.Context(), duty)
					if err != nil || selected != target {
						return contract.GeneratorTarget{}, contract.ErrRecord
					}
					bundle, err := g.retainedGraph(operation)
					if err != nil {
						return contract.GeneratorTarget{}, err
					}
					return g.generatedDeleteAttemptTarget(t.Context(), bundle, attempt.record)
				}
			} else {
				var attempt generatedAttempt
				state, attempt = generatedUnselectedCleanupState(t, 0)
				operation = attempt.record.OperationID
				readTarget = func(g *generatedSelection) (contract.GeneratorTarget, error) {
					source, err := g.generatedDeleteSource(attempt.record.OwnerID)
					if err != nil {
						return contract.GeneratorTarget{}, err
					}
					return g.generatedCleanupTarget(source.Record.Kind, source.SourceID, source.Target)
				}
			}
			g, err := state.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !retainedEvidence {
				target, err = readTarget(g)
				if err != nil {
					t.Fatal(err)
				}
			}
			result, err := generatedCreateResultID(state.root.Domain, target.OriginalOperationID, target.OriginalAttemptID)
			if err != nil {
				t.Fatal(err)
			}
			if _, present := g.record(contract.GeneratedCreateEvidenceSupportKind, result); present != retainedEvidence {
				t.Fatal("fixture did not select the required target evidence form")
			}
			facts, err := g.createTargetEvidence(t.Context(), target)
			if err != nil {
				t.Fatal(err)
			}
			graph, err := g.retainedGraph(operation)
			if err != nil {
				t.Fatal(err)
			}
			intent, err := g.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, facts.IntentDigest, contract.GeneratorIntentMaxLength)
			if err != nil {
				t.Fatal(err)
			}
			intent = bytes.Clone(intent)
			wantRecords, wantGraphs, wantVectors, wantMaterials := len(g.records), len(g.content.graphs), len(g.vectors.entries), len(g.materials)
			check := func() error {
				actual, err := readTarget(g)
				if err != nil || actual != target {
					return fmt.Errorf("target changed: %w", err)
				}
				actualFacts, err := g.createTargetEvidence(t.Context(), actual)
				if err != nil || !reflect.DeepEqual(actualFacts, facts) {
					return fmt.Errorf("target evidence changed: %w", err)
				}
				actualGraph, err := g.content.graphForOperation(operation)
				if err != nil || !reflect.DeepEqual(actualGraph, graph) {
					return fmt.Errorf("shared graph changed: %w", err)
				}
				actualIntent, err := g.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, facts.IntentDigest, contract.GeneratorIntentMaxLength)
				if err != nil || !bytes.Equal(actualIntent, intent) {
					return fmt.Errorf("target intent changed: %w", err)
				}
				return nil
			}
			for range 32 {
				if err := check(); err != nil {
					t.Fatal(err)
				}
			}
			const readers = 32
			errs := make(chan error, readers)
			var group sync.WaitGroup
			for range readers {
				group.Add(1)
				go func() {
					defer group.Done()
					if err := check(); err != nil {
						errs <- err
					}
				}()
			}
			group.Wait()
			close(errs)
			for err := range errs {
				t.Fatal(err)
			}
			if len(g.records) != wantRecords || len(g.content.graphs) != wantGraphs || len(g.vectors.entries) != wantVectors || len(g.materials) != wantMaterials {
				t.Fatal("target reads changed completed facts")
			}
			owned, err := g.content.graph(graph.UsePlan.PlanGraphID)
			if err != nil || len(owned.Lineages) == 0 {
				t.Fatal("fixture graph has no lineage container", err)
			}
			owned.Lineages[0].Name = "changed by caller"
			again, err := g.content.graph(graph.UsePlan.PlanGraphID)
			if err != nil || !reflect.DeepEqual(again, graph) {
				t.Fatal("published graph lookup shared its lineage container", err)
			}
		})
	}
}
