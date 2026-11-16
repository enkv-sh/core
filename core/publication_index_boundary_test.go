package core

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPublicationIndexRewriteSmallBacklog(t *testing.T) {
	t.Run("reserve-bound", func(t *testing.T) {
		// 1024 coordinates at 745 bytes and 2048 markers at 828+3072 bytes
		// reserve 8750080 framed bytes, with a largest row of 3900 bytes.
		// Two classes plus floor(8750079/2093178) reserve six pages.
		// The two-string no-effect image still packs into four pages.
		pages, err := publicationPageBound(3072, 8750080, 3900)
		if err != nil || pages != 6 {
			t.Fatalf("worst publication reserve pages=%d want=6 err=%v", pages, err)
		}
	})
	t.Run("split-small", func(t *testing.T) {
		state, _, originals := publicationBoundaryBacklog(t, 4, 1)
		originals = slices.Clone(originals)
		for i := range originals {
			originals[i].Body = bytes.Clone(originals[i].Body)
		}
		before := publicationBoundaryIndexLength(t, state.adminIndex)
		generated := state.root.Generated
		generated.Fragments = slices.Clone(generated.Fragments)
		publicationBoundarySplitPairs(t, state, 2)
		after := publicationBoundaryIndexLength(t, state.adminIndex)
		if before != 3383 || after != 3599 || len(state.adminIndex.Pages) != 8 || state.root.ChildCount != 10 || !reflect.DeepEqual(state.root.Generated, generated) {
			t.Fatalf("actual unchanged-row splits: index=%d->%d pages=%d children=%d", before, after, len(state.adminIndex.Pages), state.root.ChildCount)
		}
		selected, err := state.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, original := range originals {
			row, ok := selected.records[generatedRecordKey{original.Kind, original.RecordID}]
			if !ok || !bytes.Equal(row.Body, original.Body) {
				t.Fatal("split changed selected original mapping", original.Kind)
			}
		}
		predecessorRoot, err := format.EncodeRoot(state.root)
		if err != nil {
			t.Fatal(err)
		}
		predecessorIndex, err := format.EncodeAdministrativeIndex(state.adminIndex)
		if err != nil {
			t.Fatal(err)
		}
		configuration, warnings := state.root.OutputConfiguration, state.root.WarningBits
		var predecessorPublication []contract.SupportRecord
		for _, row := range selected.records {
			if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
				row.Body = bytes.Clone(row.Body)
				predecessorPublication = append(predecessorPublication, row)
			}
		}
		publication := publicationNoEffectRows(t, state)
		expectedPublication := slices.Clone(publication)
		for i := range expectedPublication {
			expectedPublication[i].Body = bytes.Clone(expectedPublication[i].Body)
		}
		next := *state
		next.root.Snapshot, next.root.Transition = publicationJointID(state.root.Domain, "split-close-snapshot", 0), publicationJointID(state.root.Domain, "split-close-transition", 0)
		candidate := Candidate{session: state}
		construction, constructionErr := state.preparePublicationConstruction(t.Context(), publication)
		if constructionErr == nil {
			constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, publicationJointPageIDs(state.root.Domain, "split-close-page", 2))
		}
		if err := constructionErr; err != nil {
			t.Fatal("split actual publication rewrite", err)
		}
		for _, session := range []*StateSession{state, &next} {
			actual, err := session.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("rewritten selected relation", err)
			}
			for _, original := range originals {
				row, ok := actual.records[generatedRecordKey{original.Kind, original.RecordID}]
				if !ok || !bytes.Equal(row.Body, original.Body) {
					t.Fatal("rewrite changed original mapping", session == state, original.Kind)
				}
			}
			publication := predecessorPublication
			if session == &next {
				publication = expectedPublication
			}
			for _, expected := range publication {
				row, ok := actual.records[generatedRecordKey{expected.Kind, expected.RecordID}]
				if !ok || !bytes.Equal(row.Body, expected.Body) {
					t.Fatal("rewrite changed intended publication row", session == state, expected.Kind)
				}
			}
			if !reflect.DeepEqual(session.root.Generated, generated) || session.root.OutputConfiguration != configuration || session.root.WarningBits != warnings {
				t.Fatal("rewrite changed detached preserved descriptors", session == state)
			}
		}
		rootAfter, err := format.EncodeRoot(state.root)
		if err != nil || !bytes.Equal(rootAfter, predecessorRoot) {
			t.Fatal("rewrite changed predecessor root", err)
		}
		indexAfter, err := format.EncodeAdministrativeIndex(state.adminIndex)
		if err != nil || !bytes.Equal(indexAfter, predecessorIndex) {
			t.Fatal("rewrite changed predecessor index", err)
		}
		if _, relationErr := next.validateRelationsMode(t.Context(), false); relationErr != nil || !reflect.DeepEqual(next.root.Generated, generated) || publicationBoundaryIndexLength(t, next.adminIndex) != after {
			t.Fatal("split close changed generated peers or framing")
		}
		t.Run("mandatory_missing_index", func(t *testing.T) {
			publicationBoundaryMissingIndex(t, &next, candidate, next.root.AdministrativeIndex)
		})
	})

	t.Run("batched-small", func(t *testing.T) {
		state, owners, originals := publicationBoundaryBacklog(t, 2, 1)
		selected, err := state.selectedGeneratedWork(context.Background())
		if err != nil || len(selected.releases) != 2 || len(selected.attempts) != 0 || len(selected.materials) != 0 || len(selected.consumers) != 0 || len(selected.bundles) != 1 || len(selected.content.locations) != 1 || len(state.root.Generated.Fragments) != 1 {
			t.Fatal("batched release relation", err)
		}
		for _, original := range originals {
			row, ok := selected.records[generatedRecordKey{original.Kind, original.RecordID}]
			if !ok || !bytes.Equal(row.Body, original.Body) {
				t.Fatal("batched release changed original mapping", original.Kind)
			}
		}
		if err := state.reserveFirstEndWork(t.Context()); err != nil {
			t.Fatal("batched first exit reserve", err)
		}
		remaining, err := state.administrativeWorkDisposition(owners[0])
		if err != nil || len(remaining.Groups) != 4 {
			t.Fatal("batched first disposition", err)
		}
		closure, _, err := state.administrativeGeneratedProjection(remaining)
		if err != nil || closure.Attempts != 1 || closure.PendingReleases != 1 || closure.Graphs != state.root.Generated.Graphs || closure.Slices != state.root.Generated.Slices || !slices.Equal(closure.Fragments, state.root.Generated.Fragments) {
			t.Fatal("batched exit changed shared graph", err)
		}
		if !slices.ContainsFunc(remaining.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == owners[1] }) {
			t.Fatal("batched exit removed independent release")
		}
		length := publicationBoundaryIndexLength(t, state.adminIndex)
		t.Logf("batched actual writer: owners=%d graphs=%d fragments=%d groups=%d pages=%d index_bytes=%d children=%d", len(owners), state.root.Generated.Graphs.Count, len(state.root.Generated.Fragments), len(state.adminIndex.Groups), len(state.adminIndex.Pages), length, state.root.ChildCount)
	})
	t.Run("small", func(t *testing.T) {
		state := generatedEmptyPredecessor(t)
		rows := state.supportRecords()
		var owners, graphs []contract.ID
		var bundles []contract.GeneratorPlanBundle
		var locations []contract.GeneratorSliceLocation
		var blob []byte
		for i := 0; i < 2; i++ {
			before := generatedEmptyPredecessor(t)
			input := generatedReservationInputForOperation(t, before, publicationJointID(state.root.Domain, "backlog-operation", i))
			reserved, err := before.deriveGeneratedReservation(context.Background(), input)
			if err != nil {
				t.Fatal("original reserve", i, err)
			}
			cleanup, attempt := generatedUnselectedCleanupFromReservation(t, reserved.state)
			released, attempt, release := generatedInboxReleaseFromCleanup(t, cleanup, attempt, contract.GeneratedReleaseUnknown)
			selected, err := released.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("original release relation", i, err)
			}
			if _, coverageErr := released.validateGeneratedCoverage(t.Context(), released.generatedCoverageRecords()); coverageErr != nil {
				t.Fatal("original release relation", i, err)
			}
			if len(selected.bundles) != 1 || len(selected.content.locations) != 1 || len(selected.attempts) != 0 || len(selected.materials) != 0 || len(selected.consumers) != 0 {
				t.Fatal("release retained private work or lost graph", i)
			}
			owners = append(owners, release.InboxID)
			bundles = append(bundles, selected.bundles[0])
			graph := selected.bundles[0].UsePlan.PlanGraphID
			graphs = append(graphs, graph)
			location := selected.content.locations[generatedContentKey{contract.GeneratorContentGraph, graph}]
			body, err := selected.readSelectedSlice(t.Context(), location.ContentKind, location.ContentID, location.Length)
			if err != nil {
				t.Fatal("original graph", i, err)
			}
			location.Offset = uint64(len(blob))
			locations = append(locations, location)
			blob = append(blob, body...)
			for _, row := range released.supportRecords() {
				if row.Kind == contract.GeneratedAttemptSupportKind || row.Kind == contract.PendingInboxReleaseSupportKind {
					rows = append(rows, row)
				}
			}
			if !selected.hasRecord(generatedRecordKey{contract.GeneratedAttemptSupportKind, attempt.record.AttemptID}) {
				t.Fatal("release lost original Attempt", i)
			}
		}
		blobID := contract.Hash(blob)
		for i := range locations {
			locations[i].BlobID = blobID
		}
		content := generatedContentStateAtSnapshot(t, state.root.Snapshot, []generatedContentFixtureBlob{{blobID, blob}}, locations)
		rows = append(rows, content.supportRecords()...)
		state.root.Generated = content.root.Generated
		state.root.Generated.Attempts = 2
		state.root.Generated.PendingReleases = 2
		slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		slices.SortFunc(graphs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		var err error
		state.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
		if err != nil {
			t.Fatal(err)
		}
		state.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, graphs)
		if err != nil {
			t.Fatal(err)
		}
		publication, order := publicationJointRows(t, state.root.Domain, 1)
		rows = append(rows, publication...)
		state.adminIndex.PublicationOrder = order
		generatedRepackSupportAtLocations(t, state, rows, bundles, locations)
		generatedSealSelectedFixture(t, state)
		generatedVerifySelectedFixtureSlices(t, state)
		if err := state.bindPreservedOutputConfiguration(state); err != nil {
			t.Fatal("selected configuration proof", err)
		}
		if err := state.bindPreservedPublication(t.Context(), state); err != nil {
			t.Fatal("selected publication proof", err)
		}
		if !state.indexSelectedMaterials() {
			t.Fatal("selected material index refused")
		}
		if _, relationErr := state.validateRelationsMode(t.Context(), false); relationErr != nil {
			_, graphErr := state.selectedGeneratedWork(context.Background())
			_, publicationErr := selectedPublicationRelation(state.selectedImage())
			_, valuesValid := selectedValueRelations(state.head, state.selectedImage(), state.admission.recipient, selectedMaterialFacts{accessLocations: state.accessLocations, valueReaders: state.valueReaders})
			support, supportErr := state.supportDescriptor()
			_, coverageErr := state.validateGeneratedCoverage(t.Context(), state.generatedCoverageRecords())
			t.Fatalf("complete selected relation refused: output=%t coverage=%t values=%t graph=%v publication=%v support=%v count=%d/%d", state.selectedOutputComplete(), coverageErr == nil, valuesValid, graphErr, publicationErr, supportErr, support.Count, state.root.RequiredSupportRecordCount)
		}
		selected, err := state.selectedGeneratedWork(context.Background())
		if err != nil || len(selected.bundles) != 2 || len(selected.content.locations) != 2 || len(selected.attempts) != 0 || len(selected.materials) != 0 {
			t.Fatal("merged generated relation", err)
		}
		published, err := selectedPublicationRelation(state.selectedImage())
		if err != nil || len(published.coordinates) != 1 || len(published.markers) != 2 || len(state.adminIndex.Groups) != 5 {
			t.Fatal("merged publication relation", err)
		}
		if len(state.root.Generated.Fragments) != 1 {
			t.Fatal("small graphs did not share one real fragment")
		}
		if err := state.reserveFirstEndWork(t.Context()); err != nil {
			t.Fatal("first exit reserve", err)
		}
		remaining, err := state.administrativeWorkDisposition(owners[0])
		if err != nil || len(remaining.Groups) != 4 {
			t.Fatal("first release disposition", err)
		}
		closure, _, err := state.administrativeGeneratedProjection(remaining)
		if err != nil || closure.PendingReleases != 1 || closure.Graphs.Count != 1 || closure.Slices.Count != 1 || len(closure.Fragments) != 1 {
			t.Fatal("first exit lost independent shared graph", err)
		}
		if !slices.ContainsFunc(remaining.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == owners[1] }) {
			t.Fatal("first exit removed the other backlog owner")
		}
		// Independent framing: fixed header 115, group 247, page 108,
		// span 7 plus u16 owner indexes, optional summary 37, marker 40,
		// and per-coordinate order 34 plus 32 for each retained incarnation.
		want := 115 + 247*len(state.adminIndex.Groups) + 108*len(state.adminIndex.Pages)
		for _, group := range state.adminIndex.Groups {
			want += 2 * len(group.RelatedGroupIndexes)
			if group.OwnerKind == format.AdministrativePublicationMarker {
				want += 40
			}
		}
		for _, page := range state.adminIndex.Pages {
			want += 37 * len(page.Rows)
			for _, span := range page.Spans {
				want += 7 + 2*len(span.GroupIndexes)
			}
		}
		for _, row := range order {
			want += 34 + 32*len(row.Incarnations)
		}
		encoded, err := format.EncodeAdministrativeIndex(state.adminIndex)
		if err != nil || len(encoded) != want {
			t.Fatal("typed writer index framing", len(encoded), want, err)
		}
		shards, err := format.EncodeAdministrativeIndexPages(state.adminIndex)
		if err != nil || len(shards) != 1 || len(shards[0].Body) != 116+want {
			t.Fatal("small actual index shard framing", err)
		}
		t.Logf("actual typed writer: groups=%d pages=%d rows=%d index_bytes=%d shared_graph_bytes=%d first_exit_groups=%d children=%d", len(state.adminIndex.Groups), len(state.adminIndex.Pages), state.root.RequiredSupportRecordCount, want, len(blob), len(remaining.Groups), state.root.ChildCount)
	})
}

// full_only: true
// The real maximum backlog/history complements the small behavior cases.
func TestPublicationIndexShardBoundaryMaximumBacklog(t *testing.T) {
	t.Run("boundary", func(t *testing.T) {
		// Twenty complete 128-name graphs have two fragments each. Their
		// page/span shape is independent of blob digest order. Keep all
		// 1024 publication coordinates and 2048 markers alongside them.
		const releaseCount = 20 * 128
		const indexPayload = 2097152 - 116
		state, owners, originals := publicationBoundaryBacklog(t, releaseCount, 1024)
		originals = slices.Clone(originals)
		for i := range originals {
			originals[i].Body = bytes.Clone(originals[i].Body)
		}
		initialLength := publicationBoundaryIndexLength(t, state.adminIndex)
		// Twenty full graphs produce 40 fragments and 20 slice rows.
		// Each release has two actual rows; publication has 3072 rows,
		// with one configuration row and 26 actual support pages.
		if initialLength >= indexPayload || len(state.adminIndex.Pages) != 26 || state.root.ChildCount != 28 || state.root.RequiredSupportRecordCount != 2*releaseCount+3072+40+20+1 {
			t.Fatalf("boundary source shape: index=%d pages=%d children=%d rows=%d", initialLength, len(state.adminIndex.Pages), state.root.ChildCount, state.root.RequiredSupportRecordCount)
		}
		if state.root.Generated.Graphs.Count != 20 || len(state.root.Generated.Fragments) != 40 || len(state.adminIndex.Groups) != releaseCount+3072 {
			t.Fatal("boundary generated shape changed")
		}
		// One optional span is 7 bytes plus one u16 owner index. Moving
		// an actual pair's rows around an intact independent pair changes
		// one count 2 span into two count 1 spans: exactly 9 extra bytes.
		// No page, row, body or owner is added. The complete independent
		// frame sum selects the last such separation below the edge.
		const extraSpan = 7 + 2
		separations := (indexPayload - initialLength - 1) / extraSpan
		if separations < 1 {
			t.Fatal("boundary fixture has no complete span separation")
		}
		publicationBoundarySeparatePairs(t, state, separations)
		beforeLength := publicationBoundaryIndexLength(t, state.adminIndex)
		const beforePages = 26
		if beforeLength != initialLength+extraSpan*separations || beforeLength >= indexPayload || indexPayload-beforeLength > extraSpan || len(state.root.AdministrativeIndexShards) != 0 || len(state.adminIndex.Pages) != beforePages || state.root.ChildCount != uint32(beforePages+2) {
			t.Fatalf("below-edge predecessor: index=%d shards=%d pages=%d children=%d", beforeLength, 1+len(state.root.AdministrativeIndexShards), len(state.adminIndex.Pages), state.root.ChildCount)
		}
		if state.root.AdministrativeIndex.Length != uint32(116+beforeLength) {
			t.Fatal("below-edge physical index charge", state.root.AdministrativeIndex.Length)
		}
		selected, err := state.selectedGeneratedWork(context.Background())
		if err != nil || len(selected.releases) != releaseCount || len(selected.attempts) != 0 || len(selected.materials) != 0 || len(selected.consumers) != 0 {
			t.Fatal("boundary release relation", err)
		}
		for _, original := range originals {
			row, ok := selected.records[generatedRecordKey{original.Kind, original.RecordID}]
			if !ok || !bytes.Equal(row.Body, original.Body) {
				t.Fatal("boundary original mapping changed", original.Kind)
			}
		}
		if err := state.reserveFirstEndWork(t.Context()); err != nil {
			t.Fatal("below-edge first exit reserve", err)
		}
		remaining, err := state.administrativeWorkDisposition(owners[0])
		if err != nil || len(remaining.Groups) != releaseCount+3071 {
			t.Fatal("boundary first release disposition", err)
		}
		closure, _, err := state.administrativeGeneratedProjection(remaining)
		if err != nil || closure.Attempts != releaseCount-1 || closure.PendingReleases != releaseCount-1 || closure.Graphs != state.root.Generated.Graphs || closure.Slices != state.root.Generated.Slices || !slices.Equal(closure.Fragments, state.root.Generated.Fragments) {
			t.Fatal("boundary first exit changed independently owned graphs", err)
		}
		plan, err := state.planPublicationRewrite(t.Context(), state.adminIndex)
		if err != nil {
			t.Fatal(err)
		}
		bound, err := plan.capacity()
		if err != nil || bound.pages != 6 || bound.pageDelta != 4 || bound.framedBytes != 8750080 {
			t.Fatalf("future evidence reserve: pages=%d delta=%d framed=%d err=%v", bound.pages, bound.pageDelta, bound.framedBytes, err)
		}
		predecessorRoot, err := format.EncodeRoot(state.root)
		if err != nil {
			t.Fatal(err)
		}
		predecessorIndex, err := format.EncodeAdministrativeIndex(state.adminIndex)
		if err != nil {
			t.Fatal(err)
		}
		configuration, warnings := state.root.OutputConfiguration, state.root.WarningBits
		generated := state.root.Generated
		generated.Fragments = slices.Clone(generated.Fragments)
		var predecessorPublication []contract.SupportRecord
		for _, row := range selected.records {
			if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
				row.Body = bytes.Clone(row.Body)
				predecessorPublication = append(predecessorPublication, row)
			}
		}
		publication := publicationNoEffectRows(t, state)
		expectedPublication := slices.Clone(publication)
		for i := range expectedPublication {
			expectedPublication[i].Body = bytes.Clone(expectedPublication[i].Body)
		}
		next := *state
		next.root.Snapshot, next.root.Transition = publicationJointID(state.root.Domain, "boundary-close-snapshot", 0), publicationJointID(state.root.Domain, "boundary-close-transition", 0)
		candidate := Candidate{session: state}
		construction, constructionErr := state.preparePublicationConstruction(t.Context(), publication)
		if constructionErr == nil {
			constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, publicationJointPageIDs(state.root.Domain, "boundary-close-page", 4))
		}
		if err := constructionErr; err != nil {
			t.Fatal("actual boundary-crossing writer", err)
		}
		for _, session := range []*StateSession{state, &next} {
			actual, err := session.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("rewritten selected relation", err)
			}
			for _, original := range originals {
				row, ok := actual.records[generatedRecordKey{original.Kind, original.RecordID}]
				if !ok || !bytes.Equal(row.Body, original.Body) {
					t.Fatal("rewrite changed original mapping", session == state, original.Kind)
				}
			}
			publication := predecessorPublication
			if session == &next {
				publication = expectedPublication
			}
			for _, expected := range publication {
				row, ok := actual.records[generatedRecordKey{expected.Kind, expected.RecordID}]
				if !ok || !bytes.Equal(row.Body, expected.Body) {
					t.Fatal("rewrite changed intended publication row", session == state, expected.Kind)
				}
			}
			if !reflect.DeepEqual(session.root.Generated, generated) || session.root.OutputConfiguration != configuration || session.root.WarningBits != warnings {
				t.Fatal("rewrite changed detached preserved descriptors", session == state)
			}
		}
		rootAfter, err := format.EncodeRoot(state.root)
		if err != nil || !bytes.Equal(rootAfter, predecessorRoot) {
			t.Fatal("rewrite changed predecessor root", err)
		}
		indexAfter, err := format.EncodeAdministrativeIndex(state.adminIndex)
		if err != nil || !bytes.Equal(indexAfter, predecessorIndex) {
			t.Fatal("rewrite changed predecessor index", err)
		}
		afterLength := publicationBoundaryIndexLength(t, next.adminIndex)
		if afterLength != beforeLength+216 || afterLength <= indexPayload || len(next.root.AdministrativeIndexShards) != 1 || len(next.adminIndex.Pages) != beforePages+2 || next.root.ChildCount != uint32(beforePages+5) {
			t.Fatalf("actual crossed edge: index=%d shards=%d pages=%d children=%d", afterLength, 1+len(next.root.AdministrativeIndexShards), len(next.adminIndex.Pages), next.root.ChildCount)
		}
		if next.root.AdministrativeIndex.Length != 2097152 || next.root.AdministrativeIndexShards[0].Length != uint32(116+afterLength-indexPayload) {
			t.Fatal("crossed physical index framing", next.root.AdministrativeIndex.Length, next.root.AdministrativeIndexShards[0].Length)
		}
		// Two 1024-byte result strings per 2048 markers add 4194304 bytes.
		// Two extra support headers add 150; index growth 216 and its new
		// shard header 116 add 332. All three selected children are charged.
		if next.root.ChildEncodedBytes != state.root.ChildEncodedBytes+4194786 {
			t.Fatal("next selected physical byte charge", next.root.ChildEncodedBytes, state.root.ChildEncodedBytes)
		}
		beforeRefs := publicationBoundaryChildRefs(state.root)
		afterRefs := publicationBoundaryChildRefs(next.root)
		union := make(map[format.Ref]bool)
		var beforeBytes, afterBytes, unionBytes uint64
		for _, ref := range beforeRefs {
			beforeBytes += uint64(ref.Length)
			union[ref] = true
		}
		for _, ref := range afterRefs {
			afterBytes += uint64(ref.Length)
			union[ref] = true
		}
		for ref := range union {
			unionBytes += uint64(ref.Length)
		}
		if len(beforeRefs) != beforePages+2 || len(afterRefs) != beforePages+5 || len(union) != beforePages+8 || beforeBytes != state.root.ChildEncodedBytes || afterBytes != next.root.ChildEncodedBytes || unionBytes != beforeBytes+uint64(afterLength+2*116+6652928+4*75) || len(candidate.objects) != 6 {
			t.Fatalf("replacement coexistence: before=%d/%d after=%d/%d union=%d/%d staged=%d", len(beforeRefs), beforeBytes, len(afterRefs), afterBytes, len(union), unionBytes, len(candidate.objects))
		}
		for _, object := range candidate.objects {
			if err := format.CheckReference(object.ref, object.body); err != nil {
				t.Fatal("actual successor object", err)
			}
		}
		if _, relationErr := next.validateRelationsMode(t.Context(), false); relationErr != nil || next.root.OutputConfiguration != state.root.OutputConfiguration || !reflect.DeepEqual(next.root.Generated, state.root.Generated) || next.root.WarningBits != state.root.WarningBits {
			t.Fatal("boundary rewrite changed preserved selected state")
		}
		if err := next.reserveFirstEndWork(t.Context()); err != nil {
			t.Fatal("crossed edge lost next exit reserve", err)
		}
		t.Logf("actual publication growth: index=%d->%d shards=1->2 support_pages=%d->%d children=%d->%d physical_delta=%d replacement_union_bytes=%d", beforeLength, afterLength, beforePages, beforePages+2, len(beforeRefs), len(afterRefs), afterBytes-beforeBytes, unionBytes)
		t.Run("mandatory_missing_index_shard", func(t *testing.T) {
			publicationBoundaryMissingIndex(t, &next, candidate, next.root.AdministrativeIndexShards[0])
		})
	})
	t.Run("batched-128", func(t *testing.T) {
		state, owners, originals := publicationBoundaryBacklog(t, 128, 1)
		selected, err := state.selectedGeneratedWork(context.Background())
		if err != nil || len(selected.releases) != 128 || len(selected.attempts) != 0 || len(selected.materials) != 0 || len(selected.consumers) != 0 || len(selected.bundles) != 1 || len(selected.content.locations) != 1 || len(state.root.Generated.Fragments) != 2 || len(originals) != 256 {
			t.Fatal("128-owner release relation", err)
		}
		for _, original := range originals {
			row, ok := selected.records[generatedRecordKey{original.Kind, original.RecordID}]
			if !ok || !bytes.Equal(row.Body, original.Body) {
				t.Fatal("128-owner release changed original mapping", original.Kind)
			}
		}
		if err := state.reserveFirstEndWork(t.Context()); err != nil {
			t.Fatal("128-owner first exit reserve", err)
		}
		remaining, err := state.administrativeWorkDisposition(owners[0])
		if err != nil || len(remaining.Groups) != 130 {
			t.Fatal("128-owner first disposition", err)
		}
		closure, _, err := state.administrativeGeneratedProjection(remaining)
		if err != nil || closure.Attempts != 127 || closure.PendingReleases != 127 || closure.Graphs != state.root.Generated.Graphs || closure.Slices != state.root.Generated.Slices || !slices.Equal(closure.Fragments, state.root.Generated.Fragments) {
			t.Fatal("128-owner exit changed shared graph", err)
		}
		length := publicationBoundaryIndexLength(t, state.adminIndex)
		if length != 44836 || len(state.adminIndex.Pages) != 6 || state.root.ChildCount != 8 || state.root.RequiredSupportRecordCount != 263 {
			t.Fatalf("128-owner exact shape: index=%d pages=%d children=%d rows=%d", length, len(state.adminIndex.Pages), state.root.ChildCount, state.root.RequiredSupportRecordCount)
		}
		t.Logf("128-owner actual writer: graphs=%d fragments=%d groups=%d pages=%d index_bytes=%d children=%d", state.root.Generated.Graphs.Count, len(state.root.Generated.Fragments), len(state.adminIndex.Groups), len(state.adminIndex.Pages), length, state.root.ChildCount)
	})
}

func publicationBoundaryMissingIndex(t *testing.T, state *StateSession, candidate Candidate, missing format.Ref) {
	t.Helper()
	store := &generatedFixtureSupportStore{t: t, descriptor: state.admission.store,
		objects: maps.Clone(state.store.(*generatedFixtureSupportStore).objects)}
	put := func(ref format.Ref, body []byte, err error) {
		t.Helper()
		if err != nil || format.CheckReference(ref, body) != nil {
			t.Fatal("boundary read source does not match selected Ref", ref.Kind, ref.Index, err)
		}
		key, err := format.Key(store.descriptor.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		if before, present := store.objects[key]; present && !bytes.Equal(before, body) {
			t.Fatal("boundary read source changed an immutable object", ref.Kind, ref.Index)
		}
		store.objects[key] = body
	}
	for _, object := range candidate.objects {
		put(object.ref, object.body, nil)
	}
	var preceding []format.Ref
	for i, ref := range state.root.ValueEntryPages {
		if ref != nil {
			if state.pages[i] == nil {
				t.Fatal("boundary read source lacks selected value page", i)
			}
			body, err := format.EncodeValueEntryPage(*state.pages[i])
			put(*ref, body, err)
			preceding = append(preceding, *ref)
		}
	}
	for i, ref := range state.root.Recipients {
		if ref != nil {
			if state.recipients[i] == nil {
				t.Fatal("boundary read source lacks selected recipient page", i)
			}
			body, err := format.EncodeRecipientPage(*state.recipients[i])
			put(*ref, body, err)
			preceding = append(preceding, *ref)
		}
	}
	for _, ref := range state.root.CurrentAccess.Core.AccessPageRefs {
		if int(ref.Index) >= len(state.access) || state.access[ref.Index] == nil {
			t.Fatal("boundary read source lacks selected access page", ref.Index)
		}
		body, err := format.EncodeAccessPage(*state.access[ref.Index])
		put(ref, body, err)
		preceding = append(preceding, ref)
	}
	indexBefore, err := format.EncodeAdministrativeIndexPages(state.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	indexRefs := append([]format.Ref{state.root.AdministrativeIndex}, state.root.AdministrativeIndexShards...)
	if len(indexBefore) != len(indexRefs) || !slices.Contains(indexRefs, missing) {
		t.Fatal("boundary missing target is not a selected index page", len(indexBefore), len(indexRefs))
	}
	for i, page := range indexBefore {
		key, err := format.Key(store.descriptor.Prefix, page.Ref)
		if err != nil || page.Ref != indexRefs[i] || !bytes.Equal(store.objects[key], page.Body) {
			t.Fatal("boundary staged index differs from selected page", i, err)
		}
	}
	preceding = append(preceding, indexRefs[:slices.Index(indexRefs, missing)+1]...)
	var missingKeys []string
	var missingLimits []uint32
	for _, ref := range preceding {
		key, err := format.Key(store.descriptor.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		missingKeys = append(missingKeys, key)
		missingLimits = append(missingLimits, ref.Length)
	}
	missingKey := missingKeys[len(missingKeys)-1]
	missingBody := store.objects[missingKey]
	rootBefore, err := format.EncodeRoot(state.root)
	if err != nil {
		t.Fatal(err)
	}
	headBefore, tokenBefore := bytes.Clone(state.body), state.token
	objectsBefore := make(map[string]contract.ID, len(store.objects))
	for key, body := range store.objects {
		objectsBefore[key] = contract.Hash(body)
	}
	assertUnchanged := func(t *testing.T, absent bool) {
		t.Helper()
		rootAfter, err := format.EncodeRoot(state.root)
		wantObjects := len(objectsBefore)
		if absent {
			wantObjects--
		}
		if err != nil || !bytes.Equal(rootAfter, rootBefore) || !bytes.Equal(state.body, headBefore) || state.token != tokenBefore || len(store.objects) != wantObjects {
			t.Fatalf("boundary read changed source: root=%t head=%t token=%t objects=%d want=%d err=%v", bytes.Equal(rootAfter, rootBefore), bytes.Equal(state.body, headBefore), state.token == tokenBefore, len(store.objects), wantObjects, err)
		}
		for key, digest := range objectsBefore {
			body, present := store.objects[key]
			if absent && key == missingKey {
				if present {
					t.Fatal("boundary missing index page became readable")
				}
				continue
			}
			if !present || contract.Hash(body) != digest {
				t.Fatal("boundary read changed an immutable source object", present)
			}
		}
	}
	for _, mode := range []struct {
		name string
		mode selectedScanMode
	}{{"complete", selectedComplete}, {"administrative", selectedAdministrativePartial}} {
		t.Run(mode.name, func(t *testing.T) {
			reader := selectedObjectReader{domain: state.root.Domain, descriptor: store.descriptor, source: store}
			before, result := scanSelectedImage(t.Context(), reader, state.root, false, mode.mode, nil)
			if result != (Result{}) || !reflect.DeepEqual(before.root, state.root) {
				t.Fatal("boundary complete source scan", result)
			}
			pages, err := format.EncodeAdministrativeIndexPages(before.adminIndex)
			if err != nil || !reflect.DeepEqual(pages, indexBefore) {
				t.Fatalf("boundary positive read changed selected index: pages=%d want=%d exact=%t err=%v", len(pages), len(indexBefore), reflect.DeepEqual(pages, indexBefore), err)
			}
			assertUnchanged(t, false)
			delete(store.objects, missingKey)
			defer func() { store.objects[missingKey] = missingBody }()
			store.keys, store.limits = nil, nil
			image, result := scanSelectedImage(t.Context(), reader, state.root, false, mode.mode, nil)
			if result != (Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}) || !reflect.DeepEqual(image, selectedImage{}) || !slices.Equal(store.keys, missingKeys) || !slices.Equal(store.limits, missingLimits) {
				t.Fatalf("boundary missing index refusal: result=%v empty=%t exact-reads=%t exact-limits=%t reads=%d want=%d", result, reflect.DeepEqual(image, selectedImage{}), slices.Equal(store.keys, missingKeys), slices.Equal(store.limits, missingLimits), len(store.keys), len(missingKeys))
			}
			assertUnchanged(t, true)
			store.objects[missingKey] = missingBody
			after, result := scanSelectedImage(t.Context(), reader, state.root, false, mode.mode, nil)
			if result != (Result{}) || !reflect.DeepEqual(after, before) {
				t.Fatalf("boundary restored read changed selected image: result=%v root=%t index=%t values=%t recipients=%t access=%t support=%t row-facts=%t fragments=%t proof=%t slices=%t cache=%t", result,
					reflect.DeepEqual(after.root, before.root), reflect.DeepEqual(after.adminIndex, before.adminIndex), reflect.DeepEqual(after.pages, before.pages), reflect.DeepEqual(after.recipients, before.recipients), reflect.DeepEqual(after.access, before.access), reflect.DeepEqual(after.support, before.support), reflect.DeepEqual(after.supportFacts, before.supportFacts), reflect.DeepEqual(after.fragmentFacts, before.fragmentFacts), reflect.DeepEqual(after.publicationProof, before.publicationProof), reflect.DeepEqual(after.generatedSliceLocations, before.generatedSliceLocations), reflect.DeepEqual(after.cache, before.cache))
			}
			assertUnchanged(t, false)
		})
	}
}

// publicationBoundarySeparatePairs changes physical row order, not logical
// evidence. A page retains one intact pair between selected Attempt rows and
// their matching release rows, so each selected owner gains exactly one span.
func publicationBoundarySeparatePairs(t *testing.T, state *StateSession, count int) {
	t.Helper()
	selected, err := state.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("separate selected pairs", err)
	}
	bundles := slices.Clone(selected.bundles)
	generatedMaterializeFixtureSupport(t, state)
	remaining := count
	for i := range state.support {
		page := &state.support[i]
		if len(page.Records) < 4 || page.Records[0].Kind != contract.GeneratedAttemptSupportKind {
			continue
		}
		indexed := state.adminIndex.Pages[i]
		pairs := len(page.Records) / 2
		if indexed.ReadRequired || len(page.Records)%2 != 0 || len(indexed.Spans) != pairs {
			t.Fatal("separation requires complete optional owner pairs")
		}
		for j, span := range indexed.Spans {
			first, second := page.Records[2*j], page.Records[2*j+1]
			if span.First != uint16(2*j) || span.Count != 2 || span.Mandatory || len(span.GroupIndexes) != 1 ||
				state.adminIndex.Groups[span.GroupIndexes[0]].OwnerKind != format.AdministrativeInboxRelease ||
				first.Kind != contract.GeneratedAttemptSupportKind || second.Kind != contract.PendingInboxReleaseSupportKind {
				t.Fatal("separation owner/span precondition")
			}
			attempt, err := contract.InspectGeneratedAttemptRecord(first.Body)
			if err != nil || attempt.InboxID != second.RecordID || state.adminIndex.Groups[span.GroupIndexes[0]].GroupID != second.RecordID {
				t.Fatal("separation pair is not one authenticated owner", err)
			}
		}
		take := min(remaining, pairs-1) // Leave an independent intact pair as the separator.
		if take == 0 {
			continue
		}
		reordered := make([]contract.SupportRecordView, 0, len(page.Records))
		for j := 0; j < take; j++ {
			reordered = append(reordered, page.Records[2*j])
		}
		reordered = append(reordered, page.Records[2*take:]...)
		for j := 0; j < take; j++ {
			reordered = append(reordered, page.Records[2*j+1])
		}
		page.Records = reordered
		remaining -= take
	}
	if remaining != 0 {
		t.Fatal("complete pair span capacity cannot reach index edge", count, remaining)
	}
	generatedRefreshSupport(t, state, bundles...)
	generatedSealSelectedFixture(t, state)
	generatedVerifySelectedFixtureSlices(t, state)
	if err := state.bindPreservedOutputConfiguration(state); err != nil {
		t.Fatal("separated configuration proof", err)
	}
	if err := state.bindPreservedPublication(t.Context(), state); err != nil {
		t.Fatal("separated publication proof", err)
	}
	if _, err := state.validateRelationsMode(t.Context(), false); err != nil {
		t.Fatal("pair separation changed complete selected relation", err)
	}
}

func publicationBoundarySplitPairs(t *testing.T, state *StateSession, count int) {
	t.Helper()
	selected, err := state.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	bundles := slices.Clone(selected.bundles)
	generatedMaterializeFixtureSupport(t, state)
	for split := 0; split < count; split++ {
		page := slices.IndexFunc(state.support, func(page format.RequiredSupportPageView) bool {
			return len(page.Records) >= 4 && page.Records[0].Kind == contract.GeneratedAttemptSupportKind && page.Records[1].Kind == contract.PendingInboxReleaseSupportKind
		})
		if page < 0 {
			t.Fatal("no actual continuation pair to split")
		}
		pair := slices.Clone(state.support[page].Records[:2])
		attempt, err := contract.InspectGeneratedAttemptRecord(pair[0].Body)
		if err != nil || attempt.InboxID != pair[1].RecordID {
			t.Fatal("split pair is not one owner", err)
		}
		state.support[page].Records = slices.Clone(state.support[page].Records[2:])
		index := generatedFixtureFreeSupportIndex(t, state)
		state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationJointID(state.root.Domain, "unchanged-pair-page", split), Index: index, Records: pair})
	}
	generatedRefreshSupport(t, state, bundles...)
	generatedSealSelectedFixture(t, state)
	generatedVerifySelectedFixtureSlices(t, state)
	if err := state.bindPreservedOutputConfiguration(state); err != nil {
		t.Fatal("split configuration proof", err)
	}
	if err := state.bindPreservedPublication(t.Context(), state); err != nil {
		t.Fatal("split publication proof", err)
	}
	if _, relationErr := state.validateRelationsMode(t.Context(), false); relationErr != nil {
		t.Fatal("split changed complete selected relation")
	}
}

func publicationBoundaryChildRefs(root format.Root) []format.Ref {
	refs := []format.Ref{root.AdministrativeIndex}
	refs = append(refs, root.AdministrativeIndexShards...)
	refs = append(refs, root.RequiredSupport...)
	refs = append(refs, root.CurrentAccess.Core.AccessPageRefs...)
	for _, pages := range [][]*format.Ref{root.ValueEntryPages[:], root.Recipients[:]} {
		for _, ref := range pages {
			if ref != nil {
				refs = append(refs, *ref)
			}
		}
	}
	return refs
}

func publicationBoundaryInitialAttempts(t *testing.T, input generatedReservationInput) map[contract.ID]generatedAttempt {
	t.Helper()
	declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil {
		t.Fatal(err)
	}
	request, err := contract.GeneratorRequestCoreDigest(input.graph.Request)
	if err != nil {
		t.Fatal(err)
	}
	phase, err := contract.GeneratorInitialPhaseID(request)
	if err != nil {
		t.Fatal(err)
	}
	index, ok := generatedFirstCreateIndex(input.graph)
	if !ok {
		t.Fatal("initial graph has no create lineage")
	}
	x := input.graph.Lineages[index].Templates[0]
	_, use, ok := generatedTemplate(input.graph, x.AttemptID)
	if !ok {
		t.Fatal("initial graph has no result use")
	}
	rows, err := generatedInitialRows(input, declaration, phase, index, x, use)
	if err != nil {
		t.Fatal("actual initial row constructor", err)
	}
	attempts := make(map[contract.ID]generatedAttempt)
	for _, row := range rows {
		if row.Kind != contract.GeneratedAttemptSupportKind {
			continue
		}
		record, err := contract.InspectGeneratedAttemptRecord(row.Body)
		if err != nil || row.RecordID != record.AttemptID {
			t.Fatal("initial Attempt mapping", err)
		}
		x, use, ok := generatedTemplate(input.graph, record.AttemptID)
		if !ok || x.Action != contract.GeneratorActionCreate || x.Branch != contract.GeneratorBranchInitial {
			t.Fatal("initial Attempt graph join")
		}
		attempts[record.AttemptID] = generatedAttempt{record: record, material: input.finished.Material,
			expected: contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Plan: input.graph.UsePlan, Template: x, Use: use, RequestDigest: record.RequestDigest}}
	}
	if len(attempts) != len(input.graph.ValueEntryPlans) {
		t.Fatal("initial Attempt cohort count", len(attempts), len(input.graph.ValueEntryPlans))
	}
	return attempts
}

func publicationBoundaryBacklog(t *testing.T, count, publicationCount int) (*StateSession, []contract.ID, []contract.SupportRecord) {
	t.Helper()
	state := generatedEmptyPredecessor(t)
	rows := state.supportRecords()
	var owners, graphs []contract.ID
	var originals []contract.SupportRecord
	var bundles []contract.GeneratorPlanBundle
	var locations []contract.GeneratorSliceLocation
	var blobs []generatedContentFixtureBlob
	for batch, start := 0, 0; start < count; batch, start = batch+1, start+128 {
		names := make([]string, min(128, count-start))
		for i := range names {
			names[i] = fmt.Sprintf("generated%03d", i)
		}
		before := generatedEmptyPredecessor(t)
		input := generatedReservationInputForGenerations(t, before, publicationJointID(state.root.Domain, "batched-backlog-operation", batch), names)
		started := time.Now()
		attempts := publicationBoundaryInitialAttempts(t, input)
		t.Logf("initial row constructor names=%d elapsed=%s", len(names), time.Since(started))
		// The bounded fixtures compare the constructor with the complete
		// real reservation. The full boundary avoids repeated index setup.
		if count <= 128 {
			reserved, err := before.deriveGeneratedReservation(context.Background(), input)
			if err != nil {
				t.Fatal("batched original reserve", batch, err)
			}
			selected, err := reserved.state.selectedGeneratedWork(context.Background())
			if err != nil || len(selected.attempts) != len(names) || len(selected.bundles) != 1 {
				t.Fatal("batched initial cohort", batch, err)
			}
			for id, attempt := range attempts {
				actual, ok := selected.attempts[id]
				body, err := contract.EncodeGeneratedAttemptRecord(attempt.record)
				row, present := selected.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, id}]
				if err != nil || !ok || !present || !bytes.Equal(body, row.Body) || !reflect.DeepEqual(attempt.expected, actual.expected) || !reflect.DeepEqual(attempt.material, actual.material) {
					t.Fatal("initial constructor differs from actual reservation", batch, err)
				}
			}
		}
		bundle := input.graph
		body, err := contract.EncodeGeneratorPlanBundle(bundle)
		if err != nil {
			t.Fatal(err)
		}
		// Closed framing uses the actual typed rows and literal field widths;
		// it does not ask the bundle-length implementation for its expectation.
		want := 2 + 3*4 + 348 + 168 + 248 + 5*4
		for _, plan := range bundle.ValueEntryPlans {
			want += 4 + 236 + len(plan.Name)
			if plan.ValueSource == contract.Generated {
				want++ // Generated plans carry one lifecycle tag.
			}
		}
		// Attempt framing is schema, lifecycle/branch/action, 19 IDs, target
		// kind/source, four tags and ResultReaderID: 2+1+2+19*32+1+32+4+32.
		for _, lineage := range bundle.Lineages {
			want += 4 + 208 + len(lineage.Name) + int(lineage.TemplateCount)*(4+682)
		}
		want += len(bundle.Edges)*(4+102) + len(bundle.ResultUses)*(4+235) + len(bundle.SourceUses)*(4+187)
		if len(body) != want {
			t.Fatal("batched graph framing", batch, len(body), want)
		}
		graph, blob := bundle.UsePlan.PlanGraphID, contract.Hash(body)
		graphs = append(graphs, graph)
		bundles = append(bundles, bundle)
		blobs = append(blobs, generatedContentFixtureBlob{blob, body})
		locations = append(locations, contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentGraph, ContentID: graph, BlobID: blob, Length: uint32(len(body)), Digest: blob})
		for _, attempt := range attempts {
			if attempt.expected.Template.Action != contract.GeneratorActionCreate || attempt.expected.Template.Branch != 0 {
				t.Fatal("batched cohort is not original create work")
			}
			result := generatedPublicResultFixture(t, attempt, contract.GeneratorDispositionCompleteCreate)
			decoded, err := contract.DecodeGeneratedResultRecord(result)
			if err != nil || contract.ValidateGeneratedResult(attempt.expected, attempt.material, decoded) != nil {
				t.Fatal("batched original handoff", err)
			}
			attempt.record.State, attempt.record.Stage = contract.GeneratedEffectSucceeded, contract.GeneratedStageTerminal
			attempt.record.Facts = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
			body, err := contract.EncodeGeneratedAttemptRecord(attempt.record)
			if err != nil {
				t.Fatal(err)
			}
			original := contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: attempt.record.AttemptID, Body: body}
			rows = append(rows, original)
			originals = append(originals, original)
			release := contract.PendingInboxReleaseRecord{Schema: 1, DomainID: state.root.Domain, InboxID: attempt.record.InboxID, OriginalResultID: attempt.record.ResultID,
				SelectedHandoffDigest: contract.Hash(result), HandoffRevisionID: contract.Hash(append([]byte("publication boundary handoff/"), attempt.record.InboxID[:]...)),
				CapacityReservation: input.parent.Capacity, ObjectLength: uint32(len(result)), State: contract.GeneratedReleaseUnknown}
			body, err = contract.EncodePendingInboxReleaseRecord(release)
			if err != nil {
				t.Fatal(err)
			}
			original = contract.SupportRecord{Kind: contract.PendingInboxReleaseSupportKind, RecordID: release.InboxID, Body: body}
			rows = append(rows, original)
			originals = append(originals, original)
			owners = append(owners, release.InboxID)
		}
		t.Logf("backlog batch=%d names=%d graph_bytes=%d templates=%d lineages=%d edges=%d uses=%d", batch, len(names), want, bundle.Header.TemplateCount, len(bundle.Lineages), len(bundle.Edges), len(bundle.ResultUses))
	}
	content := generatedContentStateAtSnapshot(t, state.root.Snapshot, blobs, locations)
	rows = append(rows, content.supportRecords()...)
	state.root.Generated = content.root.Generated
	state.root.Generated.Attempts, state.root.Generated.PendingReleases = uint32(count), uint32(count)
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	slices.SortFunc(graphs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	var err error
	state.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	state.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, graphs)
	if err != nil {
		t.Fatal(err)
	}
	publication, order := publicationJointRows(t, state.root.Domain, publicationCount)
	rows = append(rows, publication...)
	state.adminIndex.PublicationOrder = order
	generatedRepackSupportAtLocations(t, state, rows, bundles, locations)
	generatedSealSelectedFixture(t, state)
	generatedVerifySelectedFixtureSlices(t, state)
	if err := state.bindPreservedOutputConfiguration(state); err != nil {
		t.Fatal("batched selected configuration", err)
	}
	if err := state.bindPreservedPublication(t.Context(), state); err != nil {
		t.Fatal("batched selected publication", err)
	}
	if !state.indexSelectedMaterials() {
		_, graphErr := state.selectedGeneratedWork(context.Background())
		t.Fatal("batched complete selected relation", graphErr)
	}
	if _, relationErr := state.validateRelationsMode(t.Context(), false); relationErr != nil {
		_, graphErr := state.selectedGeneratedWork(context.Background())
		t.Fatal("batched complete selected relation", graphErr)
	}
	return state, owners, originals
}

func publicationBoundaryIndexLength(t *testing.T, index format.AdministrativeIndex) int {
	t.Helper()
	want := 115 + 247*len(index.Groups) + 108*len(index.Pages)
	for _, group := range index.Groups {
		want += 2 * len(group.RelatedGroupIndexes)
		if group.OwnerKind == format.AdministrativePublicationMarker {
			want += 40
		}
	}
	for _, page := range index.Pages {
		want += 37 * len(page.Rows)
		for _, span := range page.Spans {
			want += 7 + 2*len(span.GroupIndexes)
		}
	}
	for _, order := range index.PublicationOrder {
		want += 34 + 32*len(order.Incarnations)
	}
	encoded, err := format.EncodeAdministrativeIndex(index)
	if err != nil || len(encoded) != want {
		t.Fatal("independent actual index framing", len(encoded), want, err)
	}
	return want
}
