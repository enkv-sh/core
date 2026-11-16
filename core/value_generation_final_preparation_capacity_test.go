package core

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: true
func TestGeneratedFinalPreparationRetainedCapacityExactAndOneByteOver(t *testing.T) {
	// Capacity-owner witness: a lawful retained physical blob can contain
	// padding outside its authenticated logical intent. This is not the
	// separately signed maximum selecting lifecycle or an all-maxima claim.
	// At 457 full fragments the new declaration makes 458 rows/229 pages;
	// one extra byte makes 459 rows/230 pages. The remaining envelope includes
	// prepared output/image, retained Duty/evidence, graph, seed and index.
	const oldFragments = 457
	const exactBytes = oldFragments * contract.GeneratedFragmentMaxPayload
	for _, extra := range []int{0, 1} {
		name := "exact"
		if extra != 0 {
			name = "one_byte_over"
		}
		t.Run(name, func(t *testing.T) {
			s := generatedEmptyPredecessor(t)
			old, _, _ := generatedDetachedRetirementState(t, "absent", 0)
			selected := mustSelectedGeneratedWork(t, old)
			var locations []contract.GeneratorSliceLocation
			var blobs []generatedContentFixtureBlob
			for key, location := range selected.content.locations {
				intent, err := selected.readSelectedSlice(t.Context(), key.kind, key.id, location.Length)
				if err != nil || key.kind != contract.GeneratorContentIntent {
					t.Fatal("retained intent", err)
				}
				body := bytes.Repeat([]byte{' '}, exactBytes+extra)
				copy(body, intent)
				location.BlobID, location.Offset = contract.Hash(body), 0
				locations = append(locations, location)
				blobs = append(blobs, generatedContentFixtureBlob{location.BlobID, body})
			}
			if len(blobs) != 1 {
				t.Fatal("expected one complete retained blob")
			}
			content := generatedContentStateAtSnapshot(t, s.root.Snapshot, blobs, locations)
			s.support, s.root.Generated = content.support, old.root.Generated
			s.root.Generated.Fragments, s.root.Generated.Slices = content.root.Generated.Fragments, content.root.Generated.Slices
			for _, row := range old.supportRecords() {
				_, carrier, err := snapshotSliceRecord(row, old.root.Domain, old.root.Snapshot)
				if err != nil {
					t.Fatal(err)
				}
				if row.Kind != contract.GeneratedFragmentSupportKind && row.Kind != contract.OutputConfigurationSliceSupportKind && !carrier {
					s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
				}
			}
			generatedRepackSupportAtLocations(t, s, s.supportRecords(), selected.bundles, locations)
			s.recountChildren()
			if _, err := s.validateRelationsMode(t.Context(), false); err != nil {
				t.Fatal("retained predecessor full relations", err)
			}
			input := generatedPlanInputForOperation(t, s, generatedVectorID(98))
			before := s.prepared
			plan, err := s.generatedPlanRequest(t.Context(), input)
			if extra == 1 {
				if err != contract.ErrRecordCapacity || plan != nil || s.prepared != before {
					t.Fatal("one-byte-over retained/image envelope reached preparation", err)
				}
				return
			}
			if err != nil || plan == nil || s.prepared != before {
				t.Fatal("exact retained/image envelope refused", err)
			}
			group := plan.capacity.Groups[contract.GeneratorCapacityIntents]
			if group.MaxCount != 458 || group.MaxPages != 229 || group.MaxFramedBytes != uint64(exactBytes+len(input.declaration)+458*123) {
				t.Fatal("whole retained blob framing", group)
			}
			var pages uint32
			for _, group := range plan.capacity.Groups {
				pages += group.MaxPages
			}
			declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
			if err != nil {
				t.Fatal(err)
			}
			shape, err := s.generatedAdmissionShape(t.Context(), input.graph, declaration, mustSelectedGeneratedWork(t, s))
			if err != nil {
				t.Fatal("qualified shape", err)
			}
			// The public shape inspector leaves declaration framing to the
			// request owner, which already supplied this exact length above.
			shape.DeclarationBytes = uint64(len(input.declaration))
			shards, err := s.generatedAdministrativeShardReserve(shape)
			if err != nil || shards != 1 || pages+shards != ordinaryChildPageLimit {
				t.Fatal("exact complete page/image/index boundary", pages, shards, err)
			}
		})
	}
}
