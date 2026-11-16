package core

import (
	"errors"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedSelectionBuilderTransfersFactsAndClosesAllHandles(t *testing.T) {
	bundle, declaration, parent := generatedContentPlanFixture(t)
	state := generatedPlanContentState(t, bundle, declaration)
	content, err := newGeneratedContentValidation(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	vectors, err := newGeneratedVectorSet(state.root.Domain, state.supportRecords())
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeGeneratedParentRecord(parent)
	if err != nil {
		t.Fatal(err)
	}
	key := generatedRecordKey{contract.GeneratedParentSupportKind, parent.OperationID}
	facts := &generatedSelection{session: state, image: state.selectedImage(), content: content.facts, vectors: vectors,
		records:   map[generatedRecordKey]contract.SupportRecord{key: {Kind: key.kind, RecordID: key.id, Body: body}},
		materials: make(map[materialIdentity]bool)}
	vectorClaims := newGeneratedVectorValidation(&facts.vectors)
	builder := &generatedSelectionBuilder{facts: facts, content: content, vectors: vectorClaims,
		claimed: make(map[generatedRecordKey]bool)}
	refuse := func(stage string) {
		t.Helper()
		if got, err := builder.finish(contract.ID{}); got != nil || !errors.Is(err, contract.ErrRecord) {
			t.Fatal(stage, "returned incomplete facts", got, err)
		}
		if state.generatedWork != nil || state.generatedGraphs != nil {
			t.Fatal(stage, "published a session cache")
		}
	}
	refuse("unclaimed record")
	if _, ok := builder.claimRecord(key.kind, key.id); !ok || !builder.recordClaimed(key) {
		t.Fatal("exact record claim refused")
	}
	refuse("unclaimed content")
	if _, err := content.graph(generatedVectorID(99)); err == nil || len(facts.content.graphs) != 0 {
		t.Fatal("missing graph created selected facts")
	}
	if _, err := content.parent(parent); err != nil {
		t.Fatal(err)
	}
	refuse("unclaimed vector")
	if _, err := vectorClaims.resolve(contract.GeneratorSnapshotOwner, generatedVectorID(99), contract.GeneratorVectorSlices, state.root.Generated.Slices); err == nil || vectorClaims.complete() {
		t.Fatal("wrong vector owner acquired coverage")
	}
	if _, err := vectorClaims.resolve(contract.GeneratorSnapshotOwner, state.root.Snapshot, contract.GeneratorVectorSlices, state.root.Generated.Slices); err != nil {
		t.Fatal(err)
	}
	selected, err := builder.finish(contract.ID{})
	if err != nil || selected != facts {
		t.Fatal("finish did not transfer the same selected facts", err)
	}
	if state.generatedWork != nil || state.generatedGraphs != nil {
		t.Fatal("closure completion published before authority and access checks")
	}
	if got, err := builder.finish(contract.ID{}); got != nil || !errors.Is(err, contract.ErrRecord) {
		t.Fatal("second finish accepted", err)
	}
	if _, ok := builder.claimRecord(key.kind, key.id); ok || builder.recordClaimed(key) || builder.claimMaterial(materialIdentity{contract.ValueMaterialKind, generatedVectorID(98)}) {
		t.Fatal("finished selection builder retained claims")
	}
	if _, err := builder.operationMaterial(bundle); !errors.Is(err, contract.ErrRecord) {
		t.Fatal("finished selection builder resolved material", err)
	}
	if _, err := builder.retainedGraph(parent.OperationID); !errors.Is(err, contract.ErrRecord) {
		t.Fatal("finished selection builder resolved a retained graph", err)
	}
	if _, err := content.read(contract.GeneratorContentDeclaration, parent.OperationID, contract.GeneratorDeclarationMaxLength); !errors.Is(err, contract.ErrRecord) {
		t.Fatal("saved content builder read after finish", err)
	}
	if _, err := content.graph(parent.PlanGraphID); !errors.Is(err, contract.ErrRecord) {
		t.Fatal("saved content builder resolved a graph after finish", err)
	}
	if _, err := content.graphForOperation(parent.OperationID); !errors.Is(err, contract.ErrRecord) {
		t.Fatal("saved content builder rebuilt graph inventory after finish", err)
	}
	if _, err := content.parent(parent); !errors.Is(err, contract.ErrRecord) || content.complete(contract.ID{}) {
		t.Fatal("saved content builder claimed a parent after finish", err)
	}
	if _, err := vectorClaims.resolve(contract.GeneratorSnapshotOwner, state.root.Snapshot, contract.GeneratorVectorSlices, state.root.Generated.Slices); !errors.Is(err, contract.ErrRecord) || vectorClaims.complete() {
		t.Fatal("saved vector builder resolved after finish", err)
	}
	if _, err := selected.content.graph(parent.PlanGraphID); err != nil {
		t.Fatal("builder invalidation damaged selected graph facts", err)
	}
	if _, err := selected.vectors.resolve(contract.GeneratorSnapshotOwner, state.root.Snapshot, contract.GeneratorVectorSlices, state.root.Generated.Slices); err != nil {
		t.Fatal("builder invalidation damaged selected vector facts", err)
	}
}

// full_only: false
func TestGeneratedSelectionBuilderRefusesUnusedAndInvalidGraphContent(t *testing.T) {
	for _, graphContent := range []bool{false, true} {
		t.Run(map[bool]string{false: "unused content", true: "invalid graph"}[graphContent], func(t *testing.T) {
			body := []byte("content without a live owner")
			kind := uint8(contract.GeneratorContentIntent)
			if graphContent {
				kind = contract.GeneratorContentGraph
			}
			location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: kind, ContentID: generatedVectorID(3),
				BlobID: generatedVectorID(4), Length: uint32(len(body)), Digest: contract.Hash(body)}
			state := generatedContentState(t, []generatedContentFixtureBlob{{location.BlobID, body}}, []contract.GeneratorSliceLocation{location})
			content, err := newGeneratedContentValidation(t.Context(), state)
			if err != nil {
				t.Fatal(err)
			}
			facts := &generatedSelection{session: state, image: state.selectedImage(), content: content.facts}
			builder := &generatedSelectionBuilder{facts: facts, content: content, vectors: newGeneratedVectorValidation(&facts.vectors)}
			if graphContent {
				if _, err := content.graph(location.ContentID); err == nil || len(facts.content.graphs) != 0 {
					t.Fatal("invalid graph acquired validated facts")
				}
			}
			if selected, err := builder.finish(contract.ID{}); selected != nil || !errors.Is(err, contract.ErrRecord) || state.generatedWork != nil || state.generatedGraphs != nil {
				t.Fatal("unfinished content published facts or cache", err)
			}
		})
	}
}
