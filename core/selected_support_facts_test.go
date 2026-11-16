package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestSelectedFragmentReadUsesPhysicalOrdinalAfterSparseExit(t *testing.T) {
	domain := generatedVectorID(1)
	pageObject := generatedVectorID(2)
	type fragmentRow struct {
		row     contract.SupportRecord
		payload []byte
		blob    contract.ID
	}
	var rows []fragmentRow
	for i, payload := range [][]byte{[]byte("removed physical row"), []byte("retained physical row")} {
		blob := generatedVectorID(uint8(10 + i))
		body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: contract.GeneratorRecordSchema,
			BlobID: blob, Index: 0, Count: 1, TotalLength: uint64(len(payload)), WholeDigest: contract.Hash(payload), Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorFragmentID(blob, 0)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, fragmentRow{row: contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: body},
			payload: payload, blob: blob})
	}
	slices.SortFunc(rows, func(a, b fragmentRow) int { return bytes.Compare(a.row.RecordID[:], b.row.RecordID[:]) })
	physical := format.RequiredSupportPage{Domain: domain, Object: pageObject, Index: 0,
		Records: []contract.SupportRecord{rows[0].row, rows[1].row}}
	body, err := format.EncodeRequiredSupportPage(physical)
	if err != nil {
		t.Fatal(err)
	}
	ref := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: domain, Object: pageObject,
		Index: 0, Length: uint32(len(body)), Digest: contract.Hash(body)}
	location := format.FragmentLocation{BlobID: rows[1].blob, FragmentIndex: 0, SupportPageIndex: 0, RowSlot: 0}
	fact, err := contract.InspectSupportRecordDigest(domain, rows[1].row)
	if err != nil {
		t.Fatal(err)
	}
	store := &readFailureStore{results: []contract.ReadResult{{Status: contract.ReadOK, Body: body}}}
	s := &StateSession{admission: openAdmission{domain: domain, expires: time.Now().Add(time.Minute),
		store: contract.Descriptor{Prefix: "sparse"}}, store: store,
		root: format.Root{Domain: domain, RequiredSupport: []format.Ref{ref},
			Generated: format.GeneratedClosure{Fragments: []format.FragmentLocation{location}}},
		supportFacts: []selectedSupportPageFacts{{ref: ref, rows: []contract.SupportRecordDigest{fact}, ordinals: []uint16{1}}},
		fragmentFacts: map[format.FragmentLocation]selectedFragmentFact{location: {
			ref: ref, row: fact, physical: 1, logical: 0, blob: rows[1].blob, index: 0, count: 1,
			total: uint64(len(rows[1].payload)), whole: contract.Hash(rows[1].payload), payloadLength: uint32(len(rows[1].payload))}}}
	var selected []byte
	result, err := s.withSelectedFragment(context.Background(), location, func(payload []byte) error {
		selected = bytes.Clone(payload)
		return nil
	})
	if err != nil || result.Outcome != 0 || !bytes.Equal(selected, rows[1].payload) || len(store.keys) != 1 {
		t.Fatal("logical slot zero did not resolve physical ordinal one", result, err)
	}
	wrong := s.fragmentFacts[location]
	wrong.physical = 0
	s.fragmentFacts[location] = wrong
	selected = nil
	result, err = s.withSelectedFragment(context.Background(), location, func(payload []byte) error {
		selected = bytes.Clone(payload)
		return nil
	})
	if err != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidRelation || selected != nil {
		t.Fatal("wrong physical ordinal reached selected consumer", result, err)
	}
	physical.Index = 7
	body, err = format.EncodeRequiredSupportPage(physical)
	if err != nil {
		t.Fatal(err)
	}
	ref.Index, ref.Length, ref.Digest = 7, uint32(len(body)), contract.Hash(body)
	location.SupportPageIndex = 7
	sparse := *s
	sparse.root.RequiredSupport = []format.Ref{ref}
	sparse.root.Generated.Fragments = []format.FragmentLocation{location}
	sparse.supportFacts = []selectedSupportPageFacts{{ref: ref, rows: []contract.SupportRecordDigest{fact}, ordinals: []uint16{1}}}
	sparse.fragmentFacts = map[format.FragmentLocation]selectedFragmentFact{location: {
		ref: ref, row: fact, physical: 1, logical: 0, blob: rows[1].blob, index: 0, count: 1,
		total: uint64(len(rows[1].payload)), whole: contract.Hash(rows[1].payload), payloadLength: uint32(len(rows[1].payload))}}
	sparse.store = &readFailureStore{results: []contract.ReadResult{{Status: contract.ReadOK, Body: body}}}
	selected = nil
	result, err = sparse.withSelectedFragment(context.Background(), location, func(payload []byte) error {
		selected = bytes.Clone(payload)
		return nil
	})
	if err != nil || result.Outcome != 0 || !bytes.Equal(selected, rows[1].payload) {
		t.Fatal("sparse page index did not resolve compact Root position", result, err)
	}
	// An administrative exit must use the authenticated physical row and body
	// length even though the cold selected view has no fragment payload.
	sparse.support = []format.RequiredSupportPageView{{Domain: domain, Object: pageObject, Index: 7,
		Records: []contract.SupportRecordView{{Kind: contract.GeneratedFragmentSupportKind,
			RecordID: rows[1].row.RecordID}}}}
	sparse.adminIndex.Pages = []format.AdministrativePage{{Ref: ref,
		Spans: []format.AdministrativeSpan{{First: 1, Count: 1, Mandatory: true}},
		Rows: []format.AdministrativeRowSummary{{Kind: contract.GeneratedFragmentSupportKind,
			RecordID: rows[1].row.RecordID, BodyLength: uint32(len(rows[1].row.Body))}}}}
	selectedRows, err := sparse.administrativeSelectedRows(sparse.adminIndex.Pages[0])
	if err != nil || len(selectedRows) != 1 || selectedRows[0].physical != 1 ||
		selectedRows[0].blob != rows[1].blob || selectedRows[0].summary.BodyLength != uint32(len(rows[1].row.Body)) {
		t.Fatal("cold administrative summary lost its exact fragment fact", selectedRows, err)
	}
	projected := sparse.adminIndex.Pages[0]
	projected.Rows = slices.Clone(projected.Rows)
	projected.Rows[0].BodyLength++
	if _, err := sparse.administrativeSelectedRows(projected); err != contract.ErrRecord {
		t.Fatal("changed projected fragment length was accepted", err)
	}
	broken := sparse
	broken.supportFacts = slices.Clone(sparse.supportFacts)
	broken.supportFacts[0].ordinals = []uint16{0}
	if _, err := broken.administrativeSelectedRows(broken.adminIndex.Pages[0]); err != contract.ErrRecord {
		t.Fatal("changed physical ordinal was accepted", err)
	}
	broken = sparse
	broken.fragmentFacts = nil
	if _, err := broken.administrativeSelectedRows(broken.adminIndex.Pages[0]); err != contract.ErrRecord {
		t.Fatal("missing fragment fact was accepted", err)
	}
	t.Run("prospective_administrative_facts", func(t *testing.T) {
		newPayload := []byte("new unpublished fragment")
		newBlob := generatedVectorID(20)
		fragmentBody, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1,
			BlobID: newBlob, Count: 1, TotalLength: uint64(len(newPayload)), WholeDigest: contract.Hash(newPayload), Payload: newPayload})
		if err != nil {
			t.Fatal(err)
		}
		newID, err := contract.GeneratorFragmentID(newBlob, 0)
		if err != nil {
			t.Fatal(err)
		}
		newBody, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: domain,
			Object: generatedVectorID(21), Index: 9, Records: []contract.SupportRecord{{Kind: contract.GeneratedFragmentSupportKind, RecordID: newID, Body: fragmentBody}}})
		if err != nil {
			t.Fatal(err)
		}
		newView, err := format.InspectRequiredSupportPage(newBody)
		if err != nil {
			t.Fatal(err)
		}
		newRef, err := format.Reference(contract.RequiredSupportKind, domain, newView.Object, 9, newBody)
		if err != nil {
			t.Fatal(err)
		}
		opaqueBlob := generatedVectorID(22)
		opaqueID, err := contract.GeneratorFragmentID(opaqueBlob, 0)
		if err != nil {
			t.Fatal(err)
		}
		opaqueRef := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: domain,
			Object: generatedVectorID(23), Index: 8, Length: 1024, Digest: generatedVectorID(24)}
		descriptor := contract.GeneratorDescriptor{Digest: generatedVectorID(25), Length: 4}
		groupID := generatedVectorID(26)
		group := format.AdministrativeGroup{GroupID: groupID, OwnerID: groupID, TargetID: groupID,
			OwnerKind: format.AdministrativeGeneratedHazard, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
			Affected: descriptor, Dependencies: descriptor, Disposable: descriptor}
		opaquePage := format.AdministrativePage{Ref: opaqueRef, Spans: []format.AdministrativeSpan{{Count: 1, GroupIndexes: []uint16{0}}},
			Rows: []format.AdministrativeRowSummary{{Kind: contract.GeneratedFragmentSupportKind, RecordID: opaqueID, BodyLength: 87}}}
		// The predecessor selected both physical rows. Only ordinal one survives;
		// its new logical slot is zero. The opaque page is never in the read Store.
		prior := sparse
		prior.support = []format.RequiredSupportPageView{{Domain: domain, Object: pageObject, Index: 7,
			Records: []contract.SupportRecordView{{Kind: rows[0].row.Kind, RecordID: rows[0].row.RecordID},
				{Kind: rows[1].row.Kind, RecordID: rows[1].row.RecordID}}}, {Domain: domain, Object: opaqueRef.Object, Index: 8}}
		firstFact, err := contract.InspectSupportRecordDigest(domain, rows[0].row)
		if err != nil {
			t.Fatal(err)
		}
		prior.root.RequiredSupport = []format.Ref{ref, opaqueRef}
		prior.root.Generated.Fragments = []format.FragmentLocation{
			{BlobID: rows[0].blob, SupportPageIndex: 7, RowSlot: 0},
			{BlobID: rows[1].blob, SupportPageIndex: 7, RowSlot: 1},
			{BlobID: opaqueBlob, SupportPageIndex: 8, RowSlot: 0}}
		prior.supportFacts = []selectedSupportPageFacts{{ref: ref, rows: []contract.SupportRecordDigest{firstFact, fact}, ordinals: []uint16{0, 1}}, {ref: opaqueRef}}
		prior.fragmentFacts = make(map[format.FragmentLocation]selectedFragmentFact)
		for i, row := range rows {
			loc := prior.root.Generated.Fragments[i]
			digest := prior.supportFacts[0].rows[i]
			prior.fragmentFacts[loc] = selectedFragmentFact{ref: ref, row: digest, physical: uint16(i), logical: uint8(i),
				blob: row.blob, count: 1, total: uint64(len(row.payload)), whole: contract.Hash(row.payload), payloadLength: uint32(len(row.payload))}
		}
		prior.adminIndex = format.AdministrativeIndex{Domain: domain, Object: generatedVectorID(27), SliceSnapshot: generatedVectorID(28),
			Groups: []format.AdministrativeGroup{group}, Pages: []format.AdministrativePage{{Ref: ref,
				Spans: []format.AdministrativeSpan{{Count: 2, Mandatory: true}}, Rows: []format.AdministrativeRowSummary{
					{Kind: rows[0].row.Kind, RecordID: rows[0].row.RecordID, BodyLength: uint32(len(rows[0].row.Body))},
					{Kind: rows[1].row.Kind, RecordID: rows[1].row.RecordID, BodyLength: uint32(len(rows[1].row.Body))}}}, opaquePage}}
		makeNext := func() StateSession {
			next := prior
			next.root.RequiredSupport = []format.Ref{ref, opaqueRef, newRef}
			next.root.Generated.Fragments = []format.FragmentLocation{location, {BlobID: opaqueBlob, SupportPageIndex: 8}, {BlobID: newBlob, SupportPageIndex: 9}}
			next.support = []format.RequiredSupportPageView{sparse.support[0], prior.support[1], newView}
			next.adminIndex.Pages = []format.AdministrativePage{sparse.adminIndex.Pages[0], opaquePage,
				{Ref: newRef, Spans: []format.AdministrativeSpan{{Count: 1, Mandatory: true}},
					Rows: []format.AdministrativeRowSummary{{Kind: contract.GeneratedFragmentSupportKind, RecordID: newID, BodyLength: uint32(len(fragmentBody))}}}}
			next.generatedWork = &validatedGeneratedSelection{session: &prior}
			next.generatedSliceLocations = []contract.GeneratorSliceLocation{{ContentID: generatedVectorID(29)}}
			next.generatedSlicesRoot = generatedVectorID(30)
			return next
		}
		images := []objectImage{{ref: newRef, body: newBody}}
		next := makeNext()
		if err := prior.bindEndWorkSupportFacts(&next, images); err != nil {
			t.Fatal("prospective binding", err)
		}
		if len(next.supportFacts) != 3 || !slices.Equal(next.supportFacts[0].ordinals, []uint16{1}) ||
			!slices.Equal(next.supportFacts[0].rows, []contract.SupportRecordDigest{fact}) ||
			len(next.supportFacts[1].rows) != 0 || len(next.supportFacts[1].ordinals) != 0 || next.supportFacts[1].ref != opaqueRef ||
			!slices.Equal(next.supportFacts[2].ordinals, []uint16{0}) || len(next.fragmentFacts) != 2 ||
			next.generatedWork != nil || next.generatedSliceLocations != nil || !next.generatedSlicesRoot.IsZero() {
			t.Fatal("prospective facts or root-bound caches did not match the selected successor")
		}
		retained := next.fragmentFacts[location]
		if retained.logical != 0 || retained.physical != 1 || retained.ref != ref || retained.row != fact ||
			len(prior.supportFacts[0].rows) != 2 || prior.fragmentFacts[prior.root.Generated.Fragments[1]].logical != 1 {
			t.Fatal("binding changed immutable predecessor facts or lost the physical ordinal")
		}
		expectedKey, err := format.Key(prior.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		readStore := &readFailureStore{results: []contract.ReadResult{{Status: contract.ReadOK, Body: body}}}
		next.store = readStore
		var got []byte
		result, err := next.withSelectedFragmentForOpen(t.Context(), location, func(payload []byte) error { got = bytes.Clone(payload); return nil })
		if err != nil || result.Outcome != 0 || !bytes.Equal(got, rows[1].payload) || !slices.Equal(readStore.keys, []string{expectedKey}) || !slices.Equal(readStore.limits, []uint32{ref.Length}) {
			t.Fatal("retained fragment did not use its exact physical Store row", result, err)
		}
		got = nil
		newLocation := next.root.Generated.Fragments[2]
		result, err = next.withSelectedFragmentForOpen(t.Context(), newLocation, func(payload []byte) error { got = bytes.Clone(payload); return nil })
		if err != nil || result.Outcome != 0 || !bytes.Equal(got, newPayload) || !slices.Equal(readStore.keys, []string{expectedKey}) || !slices.Equal(readStore.limits, []uint32{ref.Length}) {
			t.Fatal("unpublished fragment did not use its authenticated owned body", result, err)
		}
		for _, damage := range []string{"prior_ref", "prior_ordinal", "missing_fragment_fact", "owned_bytes", "owned_view", "directory_slot", "missing_directory", "opaque_mandatory"} {
			t.Run(damage, func(t *testing.T) {
				before := prior
				after := makeNext()
				owned := slices.Clone(images)
				switch damage {
				case "prior_ref":
					before.supportFacts = slices.Clone(prior.supportFacts)
					before.supportFacts[0].ref.Digest = generatedVectorID(31)
				case "prior_ordinal":
					before.supportFacts = slices.Clone(prior.supportFacts)
					before.supportFacts[0].ordinals = []uint16{1, 1}
				case "missing_fragment_fact":
					before.fragmentFacts = nil
				case "owned_bytes":
					owned[0].body = bytes.Clone(newBody)
					owned[0].body[len(newBody)-1] ^= 1
				case "owned_view":
					after.support[2].Records = slices.Clone(newView.Records)
					after.support[2].Records[0].Body = bytes.Clone(fragmentBody)
					after.support[2].Records[0].Body[len(fragmentBody)-1] ^= 1
				case "directory_slot":
					after.root.Generated.Fragments[0].RowSlot = 1
				case "missing_directory":
					after.root.Generated.Fragments = after.root.Generated.Fragments[1:]
				case "opaque_mandatory":
					after.adminIndex.Pages[1].Spans = []format.AdministrativeSpan{{Count: 1, Mandatory: true}}
				}
				if err := before.bindEndWorkSupportFacts(&after, owned); err == nil {
					t.Fatal("malformed prospective facts were accepted")
				}
			})
		}
	})

}

// full_only: false
func TestSelectedFragmentFactsByRecordPreservesBindings(t *testing.T) {
	blob := generatedVectorID(3)
	payload := bytes.Repeat([]byte{13}, contract.GeneratedFragmentMaxPayload+17)
	fixture := generatedContentState(t, []generatedContentFixtureBlob{{id: blob, body: payload}}, nil)
	if len(fixture.support) != 2 || len(fixture.root.Generated.Fragments) != 2 {
		t.Fatal("fixture does not contain exactly two real fragments")
	}
	firstID := selectedConversionLiteralID(t, "c1149cd90d5a955980ea7a71ccb4095c70b023caf5feea207e612e869df0f620")
	secondID := selectedConversionLiteralID(t, "bef2766b315da2fd525c02f29aa8d04d9c8b02d15d0e490d307ea4ee34be3444")
	firstLocation, secondLocation := fixture.root.Generated.Fragments[0], fixture.root.Generated.Fragments[1]
	firstRow, secondRow := contract.SupportRecord(fixture.support[0].Records[0]), contract.SupportRecord(fixture.support[1].Records[0])
	if firstRow.RecordID != firstID || secondRow.RecordID != secondID {
		t.Fatal("real fragment records differ from independent identities")
	}
	firstDigest, err := contract.InspectSupportRecordDigest(fixture.root.Domain, firstRow)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := contract.InspectSupportRecordDigest(fixture.root.Domain, secondRow)
	if err != nil {
		t.Fatal(err)
	}
	refs := make([]format.Ref, 2)
	for i, page := range fixture.support {
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index,
			Records: []contract.SupportRecord{contract.SupportRecord(page.Records[0])}})
		if err != nil {
			t.Fatal(err)
		}
		refs[i], err = format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
	}
	first := selectedFragmentFact{ref: refs[0], row: firstDigest, blob: blob, index: 0, count: 2,
		total: uint64(len(payload)), whole: contract.Hash(payload), offset: 0, payloadLength: contract.GeneratedFragmentMaxPayload}
	second := selectedFragmentFact{ref: refs[1], row: secondDigest, blob: blob, index: 1, count: 2,
		total: uint64(len(payload)), whole: contract.Hash(payload), offset: contract.GeneratedFragmentMaxPayload, payloadLength: 17}
	output := generatedEmptyPredecessor(t)
	boundOutput := *output
	if err := output.bindPreservedOutputConfiguration(&boundOutput); err != nil {
		t.Fatal(err)
	}
	outputID := selectedConversionLiteralID(t, "5abe180a7fe425259d49d3c8cfaedda15f0e5f47ee64457c4ce75c6ab29fd3bb")
	outputDigest, err := contract.InspectSupportRecordDigest(output.root.Domain, contract.SupportRecord(output.support[0].Records[0]))
	if err != nil {
		t.Fatal(err)
	}
	outputFact := selectedFragmentFact{ref: output.root.RequiredSupport[0], row: outputDigest,
		blob: selectedConversionLiteralID(t, "b6ebf3ec634bccca8adc79b2475c1b952e135676f84ebd8828eae1d7a6394a16")}
	for _, condition := range []string{"complete", "nil receiver", "zero receiver", "empty map", "missing second fact", "sparse physical ordinal",
		"location blob", "location index", "fact blob", "fact index", "wrong record", "wrong kind", "zero blob", "index out of range", "duplicate identity",
		"with output", "incomplete output"} {
		t.Run(condition, func(t *testing.T) {
			state := &StateSession{root: fixture.root, support: fixture.support,
				supportFacts: []selectedSupportPageFacts{{ref: refs[0], rows: []contract.SupportRecordDigest{firstDigest}, ordinals: []uint16{0}},
					{ref: refs[1], rows: []contract.SupportRecordDigest{secondDigest}, ordinals: []uint16{0}}},
				fragmentFacts: map[format.FragmentLocation]selectedFragmentFact{firstLocation: first, secondLocation: second}}
			state.root.RequiredSupport = slices.Clone(refs)
			want := map[contract.ID]selectedFragmentFact{firstID: first, secondID: second}
			wantError, wantNil := false, false
			mutateFact := func(change func(*selectedFragmentFact)) {
				fact := state.fragmentFacts[firstLocation]
				change(&fact)
				state.fragmentFacts[firstLocation] = fact
			}
			switch condition {
			case "nil receiver":
				state, want, wantError, wantNil = nil, nil, true, true
			case "zero receiver":
				state, want = &StateSession{}, map[contract.ID]selectedFragmentFact{}
			case "empty map":
				state.fragmentFacts, want = map[format.FragmentLocation]selectedFragmentFact{}, map[contract.ID]selectedFragmentFact{}
			case "missing second fact":
				delete(state.fragmentFacts, secondLocation)
				delete(want, secondID)
			case "sparse physical ordinal":
				delete(state.fragmentFacts, firstLocation)
				location := firstLocation
				location.SupportPageIndex = 7
				body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: fixture.root.Domain, Object: generatedVectorID(7), Index: 7,
					Records: []contract.SupportRecord{secondRow, firstRow}})
				if err != nil {
					t.Fatal(err)
				}
				ref, err := format.Reference(contract.RequiredSupportKind, fixture.root.Domain, generatedVectorID(7), 7, body)
				if err != nil {
					t.Fatal(err)
				}
				fact := first
				fact.ref, fact.physical, fact.logical = ref, 1, 0
				state.fragmentFacts[location], want[firstID] = fact, fact
			case "location blob", "location index":
				delete(state.fragmentFacts, firstLocation)
				location := firstLocation
				if condition == "location blob" {
					location.BlobID = generatedVectorID(4)
				} else {
					location.FragmentIndex++
				}
				state.fragmentFacts[location] = first
				wantError = true
			case "fact blob":
				mutateFact(func(f *selectedFragmentFact) { f.blob = generatedVectorID(4) })
				wantError = true
			case "fact index":
				mutateFact(func(f *selectedFragmentFact) { f.index = 1 })
				wantError = true
			case "wrong record":
				mutateFact(func(f *selectedFragmentFact) { f.row = secondDigest })
				wantError = true
			case "wrong kind":
				mutateFact(func(f *selectedFragmentFact) { f.row = outputDigest })
				wantError = true
			case "zero blob":
				mutateFact(func(f *selectedFragmentFact) { f.blob = contract.ID{} })
				wantError = true
			case "index out of range":
				mutateFact(func(f *selectedFragmentFact) { f.index = contract.GeneratedFragmentLocationLimit })
				wantError = true
			case "duplicate identity":
				location := firstLocation
				location.SupportPageIndex = 7
				state.fragmentFacts[location] = first
				wantError = true
			case "with output", "incomplete output":
				state.root, state.support, state.supportFacts, state.outputConfigurationRoot = boundOutput.root, boundOutput.support, boundOutput.supportFacts, boundOutput.outputConfigurationRoot
				want[outputID] = outputFact
				if condition == "incomplete output" {
					state.support = selectedConversionBodylessSupport(state.support)
					state.outputConfigurationRoot = contract.ID{}
					wantError = true
				}
			}
			if wantError {
				want, wantNil = nil, true
			}
			for _, entry := range []string{"session", "selected image"} {
				t.Run(entry, func(t *testing.T) {
					convert := state.selectedFragmentFactsByRecord
					snapshot := func() selectedConversionInputSnapshot { return selectedConversionSnapshot(state) }
					if entry == "selected image" {
						var image *selectedImage
						if state != nil {
							image = &selectedImage{root: state.root, support: state.support, supportFacts: state.supportFacts,
								fragmentFacts: state.fragmentFacts, outputConfigurationRoot: state.outputConfigurationRoot}
						}
						convert = image.selectedFragmentFactsByRecord
						snapshot = func() selectedConversionInputSnapshot { return selectedConversionImageSnapshot(image) }
					}
					before := snapshot()
					got, err := convert()
					selectedConversionAssertResult(t, got, err, want, wantError, wantNil)
					if !reflect.DeepEqual(snapshot(), before) {
						t.Fatal("conversion changed its input facts")
					}
					if !wantError {
						selectedConversionDamageResult(got)
						again, err := convert()
						selectedConversionAssertResult(t, again, err, want, false, false)
						if !reflect.DeepEqual(snapshot(), before) {
							t.Fatal("result-map mutation changed input facts")
						}
					}
				})
			}
		})
	}
}

func selectedConversionLiteralID(t testing.TB, literal string) contract.ID {
	t.Helper()
	bytes, err := hex.DecodeString(literal)
	if err != nil || len(bytes) != 32 {
		t.Fatal("invalid identity literal", err)
	}
	return contract.ID(bytes)
}

func selectedConversionAssertResult(t testing.TB, got map[contract.ID]selectedFragmentFact, err error,
	want map[contract.ID]selectedFragmentFact, wantError, wantNil bool) {
	t.Helper()
	if wantError {
		if !errors.Is(err, contract.ErrRecord) || got != nil {
			t.Fatal("invalid facts did not return nil and ErrRecord", err)
		}
		return
	}
	if err != nil || (got == nil) != wantNil || !maps.Equal(got, want) {
		t.Fatal("conversion did not return the exact independent facts", err)
	}
}

func selectedConversionDamageResult(result map[contract.ID]selectedFragmentFact) {
	for id, fact := range result {
		fact.physical++
		fact.blob = generatedVectorID(99)
		result[id] = fact
		delete(result, id)
		break
	}
	result[generatedVectorID(98)] = selectedFragmentFact{blob: generatedVectorID(97)}
}

func selectedConversionBodylessSupport(input []format.RequiredSupportPageView) []format.RequiredSupportPageView {
	output := slices.Clone(input)
	for i := range output {
		output[i].Records = slices.Clone(input[i].Records)
		for j := range output[i].Records {
			output[i].Records[j].Body = nil
		}
	}
	return output
}

type selectedConversionRowSnapshot struct {
	kind           contract.SupportRecordKind
	id, bodyDigest contract.ID
	bodyLength     int
	bodyNil        bool
}

type selectedConversionPageSnapshot struct {
	domain, object contract.ID
	index          uint16
	rows           []selectedConversionRowSnapshot
}

type selectedConversionInputSnapshot struct {
	nilReceiver bool
	domain      contract.ID
	output      contract.OutputConfigurationDescriptor
	outputRoot  contract.ID
	refs        []format.Ref
	locations   []format.FragmentLocation
	support     []selectedConversionPageSnapshot
	pages       []selectedSupportPageFacts
	fragments   map[format.FragmentLocation]selectedFragmentFact
}

func selectedConversionSnapshot(state *StateSession) selectedConversionInputSnapshot {
	if state == nil {
		return selectedConversionInputSnapshot{nilReceiver: true}
	}
	snapshot := selectedConversionInputSnapshot{domain: state.root.Domain, output: state.root.OutputConfiguration,
		outputRoot: state.outputConfigurationRoot, refs: slices.Clone(state.root.RequiredSupport), locations: slices.Clone(state.root.Generated.Fragments),
		pages: slices.Clone(state.supportFacts), fragments: maps.Clone(state.fragmentFacts)}
	for i := range snapshot.pages {
		snapshot.pages[i].rows = slices.Clone(state.supportFacts[i].rows)
		snapshot.pages[i].ordinals = slices.Clone(state.supportFacts[i].ordinals)
	}
	for _, page := range state.support {
		copy := selectedConversionPageSnapshot{domain: page.Domain, object: page.Object, index: page.Index}
		for _, row := range page.Records {
			copy.rows = append(copy.rows, selectedConversionRowSnapshot{kind: row.Kind, id: row.RecordID,
				bodyDigest: contract.Hash(row.Body), bodyLength: len(row.Body), bodyNil: row.Body == nil})
		}
		snapshot.support = append(snapshot.support, copy)
	}
	return snapshot
}

// selectedConversionImageSnapshot observes the concrete selected owner without
// calling a session operation or constructing receipt windows.
func selectedConversionImageSnapshot(image *selectedImage) selectedConversionInputSnapshot {
	if image == nil {
		return selectedConversionInputSnapshot{nilReceiver: true}
	}
	return selectedConversionSnapshot(&StateSession{root: image.root, support: image.support,
		supportFacts: image.supportFacts, fragmentFacts: image.fragmentFacts, outputConfigurationRoot: image.outputConfigurationRoot})
}
