package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedCurrentIntentProjectionFixture(t *testing.T, shared bool) (*StateSession, *generatedSelection, []contract.GeneratorSliceLocation, []byte) {
	t.Helper()
	id := generatedVectorID
	a := bytes.Repeat([]byte{0xa1}, contract.GeneratorIntentMaxLength)
	b := bytes.Repeat([]byte{0xb2}, 91)
	first := contract.GeneratedFragmentMaxPayload - 12
	second := first + len(a) + 50
	oldBlob := bytes.Repeat([]byte{0x39}, second+len(b))
	copy(oldBlob[first:], a)
	copy(oldBlob[second:], b)
	locations := []contract.GeneratorSliceLocation{
		{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: id(4), BlobID: id(3), Offset: uint64(first), Length: uint32(len(a)), Digest: contract.Hash(a)},
		{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: id(5), BlobID: id(3), Offset: uint64(second), Length: uint32(len(b)), Digest: contract.Hash(b)},
	}
	if shared {
		locations = append(locations, contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentSource,
			ContentID: id(6), BlobID: id(3), Length: 8, Digest: contract.Hash(oldBlob[:8])})
	}
	s := generatedContentState(t, []generatedContentFixtureBlob{{id(3), oldBlob}}, locations)
	s.root.Names = []format.NameEntry{{Name: "a", Slot: 0}, {Name: "b", Slot: 1}}
	s.pages[0] = &format.ValueEntryPage{}
	for i, intent := range []contract.ID{id(4), id(5)} {
		s.pages[0].Slots[i] = &format.ValueEntry{Name: string(rune('a' + i)), ValueState: id(uint8(10 + i)),
			ValueSource: contract.Generated, Generated: contract.GeneratedEntryMetadata{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedEntryMetadataSchema, IntentDigest: intent}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	}
	facts, err := newGeneratedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	return s, &generatedSelection{session: s, image: s.selectedImage(), content: facts}, locations, append(a, b...)
}

// full_only: false
func TestGeneratedCurrentIntentProjectionStreamsExactSharedAndExclusiveBlobs(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "exclusive", true: "shared"}[shared], func(t *testing.T) {
			s, selected, locations, expected := generatedCurrentIntentProjectionFixture(t, shared)
			plan, err := planBodyBackedGeneratedCurrentIntents(t.Context(), s, selected, locations)
			if err != nil || !plan.changed || plan.total != uint64(len(expected)) || plan.blob != contract.Hash(expected) || plan.fragments != 1 {
				t.Fatal("wrong logical projection", plan, err)
			}
			if plan.dropBlobs[generatedVectorID(3)] == shared || !plan.emit {
				t.Fatal("wrong old-blob reachability", plan.dropBlobs, plan.emit)
			}
			if len(plan.after) != len(locations) || plan.after[0].BlobID != plan.blob || plan.after[0].Offset != 0 ||
				plan.after[1].BlobID != plan.blob || plan.after[1].Offset != contract.GeneratorIntentMaxLength {
				t.Fatal("wrong physical relocation", plan.after)
			}
			rows, err := emitBodyBackedGeneratedCurrentIntents(t.Context(), selected, plan)
			if err != nil || len(rows) != 1 {
				t.Fatal("fragment emission", len(rows), err)
			}
			fragment, err := contract.InspectGeneratedFragment(rows[0].Body)
			if err != nil || fragment.BlobID != plan.blob || !bytes.Equal(fragment.Payload, expected) {
				t.Fatal("emitted bytes changed", err)
			}
			plan.predecessor = generatedVectorID(99)
			if _, err := emitBodyBackedGeneratedCurrentIntents(t.Context(), selected, plan); err == nil {
				t.Fatal("different predecessor used the projection")
			}
			selected.content.fragments[contract.Hash(expected)] = selected.content.fragments[generatedVectorID(3)]
			if _, err := planBodyBackedGeneratedCurrentIntents(t.Context(), s, selected, locations); err == nil {
				t.Fatal("same BlobID reused different physical bytes")
			}
			delete(selected.content.fragments, contract.Hash(expected))
		})
	}
}

// full_only: false
func TestGeneratedCurrentIntentProjectionKeepsAlreadyPackedImage(t *testing.T) {
	id := generatedVectorID
	a, b := []byte("first intent"), []byte("second intent")
	blob := append(bytes.Clone(a), b...)
	locations := []contract.GeneratorSliceLocation{
		{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: id(4), BlobID: contract.Hash(blob), Length: uint32(len(a)), Digest: contract.Hash(a)},
		{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: id(5), BlobID: contract.Hash(blob), Offset: uint64(len(a)), Length: uint32(len(b)), Digest: contract.Hash(b)},
	}
	s := generatedContentState(t, []generatedContentFixtureBlob{{contract.Hash(blob), blob}}, locations)
	s.root.Names = []format.NameEntry{{Name: "a", Slot: 0}, {Name: "b", Slot: 1}}
	s.pages[0] = &format.ValueEntryPage{}
	for i, intent := range []contract.ID{id(4), id(5)} {
		s.pages[0].Slots[i] = &format.ValueEntry{Name: string(rune('a' + i)), ValueState: id(uint8(10 + i)),
			ValueSource: contract.Generated, Generated: contract.GeneratedEntryMetadata{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedEntryMetadataSchema, IntentDigest: intent}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	}
	facts, err := newGeneratedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	selected := &generatedSelection{session: s, image: s.selectedImage(), content: facts}
	plan, err := planBodyBackedGeneratedCurrentIntents(t.Context(), s, selected, locations)
	if err != nil || plan.changed || plan.emit || len(plan.dropBlobs) != 0 {
		t.Fatal("already packed image changed", plan, err)
	}
	rows, err := emitBodyBackedGeneratedCurrentIntents(t.Context(), selected, plan)
	if err != nil || len(rows) != 0 {
		t.Fatal("unchanged image emitted rows", err)
	}
}

// full_only: false
func TestGeneratedCurrentIntentProjectionStreamsSeveralOldBlobsIntoTwoFragments(t *testing.T) {
	id := generatedVectorID
	var blobs []generatedContentFixtureBlob
	var locations []contract.GeneratorSliceLocation
	s := &StateSession{}
	s.root.Names = []format.NameEntry{{Name: "a", Slot: 0}, {Name: "b", Slot: 1}, {Name: "c", Slot: 2}}
	s.pages[0] = &format.ValueEntryPage{}
	var expected []byte
	for i := 0; i < 3; i++ {
		intent := id(uint8(4 + i))
		body := bytes.Repeat([]byte{byte(0x80 + i)}, contract.GeneratorIntentMaxLength)
		blob := id(uint8(20 + i))
		blobs = append(blobs, generatedContentFixtureBlob{blob, body})
		locations = append(locations, contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentIntent,
			ContentID: intent, BlobID: blob, Length: uint32(len(body)), Digest: contract.Hash(body)})
		name := string(rune('a' + i))
		s.pages[0].Slots[i] = &format.ValueEntry{Name: name, ValueState: id(uint8(10 + i)), ValueSource: contract.Generated,
			Generated: contract.GeneratedEntryMetadata{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedEntryMetadataSchema, IntentDigest: intent}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
		expected = append(expected, body...)
	}
	selectedState := generatedContentState(t, blobs, locations)
	selectedState.root.Names, selectedState.pages = s.root.Names, s.pages
	content, err := newGeneratedContent(selectedState)
	if err != nil {
		t.Fatal(err)
	}
	selected := &generatedSelection{session: selectedState, image: selectedState.selectedImage(), content: content}
	plan, err := planBodyBackedGeneratedCurrentIntents(t.Context(), selectedState, selected, locations)
	if err != nil || !plan.changed || plan.fragments != 2 || plan.blob != contract.Hash(expected) || len(plan.dropBlobs) != 3 {
		t.Fatal("multi-blob projection", plan, err)
	}
	rows, err := emitBodyBackedGeneratedCurrentIntents(t.Context(), selected, plan)
	if err != nil || len(rows) != 2 {
		t.Fatal("multi-fragment emission", len(rows), err)
	}
	var actual []byte
	for i, row := range rows {
		fragment, inspectErr := contract.InspectGeneratedFragment(row.Body)
		if inspectErr != nil || fragment.Index != uint16(i) || fragment.Count != 2 || fragment.Offset != uint32(i*contract.GeneratedFragmentMaxPayload) {
			t.Fatal("fragment location", i, inspectErr)
		}
		actual = append(actual, fragment.Payload...)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("logical bytes changed across the fragment boundary")
	}
	packed, err := format.PackRequiredSupportRows(selectedState.root.Domain, []format.RequiredSupportGroup{{Class: format.IntentFragmentSupport,
		Owner: plan.blob, Mandatory: true, Records: rows}}, 0)
	if err != nil || len(packed) != 1 || len(packed[0]) != 2 {
		t.Fatal("two full fragment rows must share one physical page", len(packed), err)
	}
}

// full_only: false
func TestGeneratedCurrentIntentProjectionChargesPhysicalReachabilityBeforeEffects(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "exclusive", true: "shared"}[shared], func(t *testing.T) {
			s, selected, locations, _ := generatedCurrentIntentProjectionFixture(t, shared)
			selected.records = make(map[generatedRecordKey]contract.SupportRecord)
			for _, row := range s.supportRecords() {
				selected.records[generatedRecordKey{kind: row.Kind, id: row.RecordID}] = row
			}
			plan, err := planBodyBackedGeneratedCurrentIntents(t.Context(), s, selected, locations)
			if err != nil {
				t.Fatal(err)
			}
			shape := generatedCapacityShape{ValueEntryCount: 2, ValueEntryPageCount: 1, Recipients: 1,
				Secrets: 2, Memberships: 2, SecretMemberships: 2, Generated: 2, OldGenerated: 2,
				ValueEntryPlanCount: 2, DeclarationBytes: 512, OldIntentBytes: plan.total,
				ProjectedCurrentIntentFragments: uint64(plan.fragments)}
			groups, err := generatedCapacityWithProjectedBacklog(shape, selected, &plan)
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(2) // One new declaration fragment and one compact current fragment.
			if shared {
				want += 2 // The old blob still carries another selected logical slice.
			}
			if groups[contract.GeneratorCapacityIntents].MaxCount != want {
				t.Fatal("projected physical fragment count", groups[contract.GeneratorCapacityIntents], want)
			}
		})
	}
}

// full_only: false
func TestGeneratedCurrentIntentProjectionUsesSelectedCurrentEvidence(t *testing.T) {
	s := generatedSelectedEntryState(t)
	selected, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("selected current generated entry", err)
	}
	plan, err := planGeneratedCurrentIntents(t.Context(), s, selected, selectedGeneratedLocations(selected))
	if err != nil || !plan.changed || len(plan.intents) != 1 || plan.total != 73 || plan.blob != selectedConversionLiteralID(t, "ad1ccae61cfbccdf41ad11ef7647e26a20dae2c5ce0d80bbe7fd4411ad957e7a") {
		t.Fatal("selected intent projection", plan, err)
	}
	rows, err := emitGeneratedCurrentIntents(t.Context(), selected, plan)
	if err != nil || len(rows) != 1 {
		t.Fatal("selected intent fragment", len(rows), err)
	}
}

// full_only: false
func TestAdministrativeCurrentIntentProjectionNeedsOnlyMandatorySelectedBytes(t *testing.T) {
	s := generatedSelectedEntryState(t)
	generatedRepackSupport(t, s, s.supportRecords(), nil)
	plan, err := s.planAdministrativeCurrentIntents(t.Context(), s.adminIndex)
	if err != nil || !plan.changed || plan.total != 73 || plan.blob != selectedConversionLiteralID(t, "ad1ccae61cfbccdf41ad11ef7647e26a20dae2c5ce0d80bbe7fd4411ad957e7a") {
		t.Fatal("mandatory administrative intent projection", plan, err)
	}
	current := s.valueEntry(0)
	if current == nil || current.ValueSource != contract.Generated {
		t.Fatal("fixture has no generated current intent")
	}
	var oldBlob contract.ID
	for _, location := range plan.before {
		if location.ContentKind == contract.GeneratorContentIntent && location.ContentID == current.Generated.IntentDigest {
			oldBlob = location.BlobID
		}
	}
	if oldBlob.IsZero() {
		t.Fatal("fixture has no old current blob")
	}
	for _, location := range s.root.Generated.Fragments {
		if location.BlobID != oldBlob {
			continue
		}
		for page := range s.support {
			if s.support[page].Index != location.SupportPageIndex {
				continue
			}
			fragment, err := contract.InspectGeneratedFragment(s.support[page].Records[location.RowSlot].Body)
			if err != nil {
				t.Fatal(err)
			}
			fragment.WholeDigest = generatedVectorID(247)
			body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment(fragment))
			if err != nil {
				t.Fatal(err)
			}
			s.support[page].Records[location.RowSlot].Body = body
			if _, err := s.planAdministrativeCurrentIntents(t.Context(), s.adminIndex); err == nil {
				t.Fatal("mandatory old blob with false whole digest entered physical projection")
			}
			return
		}
	}
	t.Fatal("mandatory current fragment was not selected")
}
