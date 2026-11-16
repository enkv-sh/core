package core

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPrivateReplacementChecksCurrentOnlyIndexOwnersBeforeBodyCapture(t *testing.T) {
	for _, change := range []string{"orphan-generated-group"} {
		t.Run(change, func(t *testing.T) {
			reader, root, index, _ := publicationSparseRetentionFixture(t)
			reader.replacementRead = true
			switch change {
			case "orphan-generated-group":
				group := index.Groups[0]
				copy(group.GroupID[:], bytes.Repeat([]byte{255}, len(group.GroupID)))
				group.OwnerID, group.TargetID = group.GroupID, group.GroupID
				group.OwnerKind, group.DutyKind = format.AdministrativeGeneratedHazard, 0
				group.PublicationIncarnationID, group.AdmissionOrdinal = contract.ID{}, 0
				group.RelatedGroupIndexes = nil
				group.SelectedEvidenceSummary = contract.AdministrativeEvidenceMissing
				index.Groups = append(index.Groups, group)
			}
			root = replacementFixtureIndex(t, reader, root, index)
			store := reader.source.(*generatedFixtureSupportStore)
			store.keys = nil
			if _, result := scanSelectedImage(t.Context(), reader, root, false, selectedComplete, nil); result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
				t.Error("current-only index ownership was not refused", result)
			}
			for _, ref := range root.RequiredSupport {
				key, _ := format.Key(reader.descriptor.Prefix, ref)
				if slices.Contains(store.keys, key) {
					t.Error("contradictory index owners reached support body capture")
				}
			}
		})
	}
}

// full_only: false
func TestPrivateReplacementAdministrativeChecksCurrentSliceLiveness(t *testing.T) {
	for _, change := range []string{"valid-current", "unused-extra", "wrong-kind"} {
		t.Run(change, func(t *testing.T) {
			state := generatedSelectedEntryState(t)
			locations, err := format.ResolveGeneratedSliceLocations(state.root.Domain, state.adminIndex.SliceSnapshot, state.root.Generated.Slices, state.support)
			if err != nil || len(locations) != 1 {
				t.Fatal("current Slice location fixture", err)
			}
			switch change {
			case "unused-extra":
				unused := locations[0]
				unused.ContentKind, unused.ContentID = contract.GeneratorContentSource, generatedVectorID(220)
				locations = append(locations, unused)
			case "wrong-kind":
				locations[0].ContentKind = contract.GeneratorContentSource
			}
			encoded := make([][]byte, len(locations))
			for i, location := range locations {
				encoded[i], err = contract.EncodeGeneratorSliceLocation(location)
				if err != nil {
					t.Fatal(err)
				}
			}
			var carriers []contract.SupportRecord
			state.root.Generated.Slices, carriers, err = generatedCarrierRows(state.root.Domain, contract.GeneratorSnapshotOwner,
				state.adminIndex.SliceSnapshot, contract.GeneratorVectorSlices, encoded)
			if err != nil {
				t.Fatal(err)
			}
			position := slices.IndexFunc(state.support, func(page format.RequiredSupportPageView) bool {
				return len(page.Records) != 0 && page.Records[0].Kind == contract.GeneratorVectorSupportKind
			})
			if position < 0 {
				t.Fatal("current Slice carrier page missing")
			}
			oldCount := len(state.support[position].Records)
			state.support[position].Records = nil
			for _, carrier := range carriers {
				state.support[position].Records = append(state.support[position].Records, contract.SupportRecordView(carrier))
			}
			page := state.support[position]
			body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: carriers})
			if err != nil {
				t.Fatal(err)
			}
			ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
			if err != nil {
				t.Fatal(err)
			}
			state.root.RequiredSupport[position] = ref
			state.root.RequiredSupportRecordCount = uint32(int(state.root.RequiredSupportRecordCount) + len(carriers) - oldCount)
			state.adminIndex.Pages[position].Ref = ref
			state.adminIndex.Pages[position].Spans = []format.AdministrativeSpan{{Count: uint16(len(carriers)), Mandatory: true}}
			state.adminIndex.Pages[position].ReadRequired = true
			state.adminIndex.Pages[position].Rows = nil
			shards, err := format.EncodeAdministrativeIndexPages(state.adminIndex)
			if err != nil {
				t.Fatal("authenticated partial Slice index", err)
			}
			state.root.AdministrativeIndex, state.root.AdministrativeIndexShards = shards[0].Ref, nil
			for _, shard := range shards[1:] {
				state.root.AdministrativeIndexShards = append(state.root.AdministrativeIndexShards, shard.Ref)
			}
			state.recountChildren()
			if _, err := format.EncodeRoot(state.root); err != nil {
				t.Fatal("canonical partial Slice Root", err)
			}
			for _, private := range []bool{false, true} {
				t.Run(map[bool]string{false: "reusable", true: "private"}[private], func(t *testing.T) {
					reader := publicationRetentionReader(t, state)
					reader.replacementRead = private
					image, result := scanSelectedImage(t.Context(), reader, state.root, false, selectedAdministrativePartial, nil)
					if change != "valid-current" {
						if result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
							t.Error("unused current Slice mapping survived administrative validation", result)
						}
						return
					}
					if result != (Result{}) {
						t.Fatal("administrative Slice control refused", result)
					}
					if _, err := format.ResolveGeneratedSliceLocations(image.root.Domain, image.adminIndex.SliceSnapshot, image.root.Generated.Slices, image.support); err != nil {
						t.Fatal("administrative carrier proof control", err)
					}
					projection := &StateSession{root: image.root, pages: image.pages, support: image.support, adminIndex: image.adminIndex,
						supportFacts: image.supportFacts, fragmentFacts: image.fragmentFacts}
					if _, selected, err := projection.administrativeGeneratedProjection(image.adminIndex); err != nil || selected != image.root.RequiredSupportRecordCount {
						t.Fatal("administrative projection control", err)
					}
				})
			}
		})
	}
}

// full_only: false
func TestPrivateReplacementAdministrativeChecksCurrentCreateEvidence(t *testing.T) {
	for _, change := range []string{"valid-current", "unused-extra", "wrong-id", "missing-current", "optional-current"} {
		t.Run(change, func(t *testing.T) {
			state := generatedSelectedEntryState(t)
			if change == "optional-current" {
				_, coordinate, _, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
				coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
				coordinate.OwnerState, coordinate.LatestUnresolvedAttemptID, coordinate.PossibleRemoteObject = contract.PublicationOwnerNone, contract.ID{}, 0
				body, err := contract.EncodePublicationCoordinate(coordinate)
				if err != nil {
					t.Fatal(err)
				}
				state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain, Object: generatedVectorID(223),
					Index: generatedFixtureFreeSupportIndex(t, state), Records: []contract.SupportRecordView{{Kind: contract.PublicationCoordinateSupportKind, RecordID: coordinate.CoordinateID, Body: body}}})
				generatedSealSelectedFixture(t, state)
			}
			other := generatedSelectedEntryOrigin(t, generatedVectorID(220), generatedVectorID(221), 0)
			var extra contract.SupportRecord
			for _, page := range other.support {
				for _, row := range page.Records {
					if row.Kind == contract.GeneratedCreateEvidenceSupportKind {
						extra = contract.SupportRecord(row)
					}
				}
			}
			position := slices.IndexFunc(state.support, func(page format.RequiredSupportPageView) bool {
				return len(page.Records) != 0 && page.Records[0].Kind == contract.GeneratedCreateEvidenceSupportKind
			})
			if position < 0 || extra.RecordID.IsZero() || extra.RecordID == state.pages[0].Slots[0].Generated.CreateResultID {
				t.Fatal("independent exact create-evidence fixture missing")
			}
			page := state.support[position]
			rows := make([]contract.SupportRecord, 0, len(page.Records)+1)
			for _, row := range page.Records {
				rows = append(rows, contract.SupportRecord(row))
			}
			switch change {
			case "unused-extra":
				rows = append(rows, extra)
			case "wrong-id":
				rows[0] = extra
			}
			slices.SortFunc(rows, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
			body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
			if err != nil {
				t.Fatal(err)
			}
			ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
			if err != nil {
				t.Fatal(err)
			}
			state.support[position], err = format.InspectRequiredSupportPage(body)
			if err != nil {
				t.Fatal(err)
			}
			state.root.RequiredSupport[position] = ref
			state.root.RequiredSupportRecordCount = uint32(int(state.root.RequiredSupportRecordCount) + len(rows) - len(page.Records))
			indexed := &state.adminIndex.Pages[position]
			indexed.Ref, indexed.Spans, indexed.Rows = ref, []format.AdministrativeSpan{{Count: uint16(len(rows)), Mandatory: true}}, nil
			for _, row := range rows {
				indexed.Rows = append(indexed.Rows, format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
			}
			switch change {
			case "missing-current":
				state.support = slices.Delete(state.support, position, position+1)
				state.root.RequiredSupport = slices.Delete(state.root.RequiredSupport, position, position+1)
				state.adminIndex.Pages = slices.Delete(state.adminIndex.Pages, position, position+1)
				state.root.RequiredSupportRecordCount -= uint32(len(rows))
			case "optional-current":
				owner := slices.IndexFunc(state.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
					return group.OwnerKind == format.AdministrativePublicationCoordinate
				})
				if owner < 0 {
					t.Fatal("optional evidence owner fixture missing")
				}
				indexed.Spans[0].Mandatory, indexed.Spans[0].GroupIndexes = false, []uint16{uint16(owner)}
				var count uint32
				for _, page := range state.adminIndex.Pages {
					for _, span := range page.Spans {
						if slices.Contains(span.GroupIndexes, uint16(owner)) {
							count += uint32(span.Count)
						}
					}
				}
				digest := selectedDisposableDigest(count)
				group := &state.adminIndex.Groups[owner]
				group.ChargedPages, group.ChargedBytes = 0, 0
				for _, page := range state.adminIndex.Pages {
					logical, charged := 0, false
					for _, span := range page.Spans {
						if slices.Contains(span.GroupIndexes, uint16(owner)) {
							charged = true
							for _, row := range page.Rows[logical : logical+int(span.Count)] {
								writeSelectedDisposableRow(digest, row.Kind, row.RecordID, row.BodyLength)
								group.ChargedBytes += uint64(contract.SupportRecordOverhead) + uint64(row.BodyLength)
							}
						}
						logical += int(span.Count)
					}
					if charged {
						group.ChargedPages++
					}
				}
				group.Disposable = selectedDisposableDescriptor(digest, count)
			}
			shards, err := format.EncodeAdministrativeIndexPages(state.adminIndex)
			if err != nil {
				t.Fatal(err)
			}
			state.root.AdministrativeIndex, state.root.AdministrativeIndexShards = shards[0].Ref, nil
			for _, shard := range shards[1:] {
				state.root.AdministrativeIndexShards = append(state.root.AdministrativeIndexShards, shard.Ref)
			}
			state.recountChildren()
			if _, err := format.EncodeRoot(state.root); err != nil {
				t.Fatal("canonical partial evidence Root", err)
			}
			for _, private := range []bool{false, true} {
				t.Run(map[bool]string{false: "reusable", true: "private"}[private], func(t *testing.T) {
					reader := publicationRetentionReader(t, state)
					reader.replacementRead = private
					image, result := scanSelectedImage(t.Context(), reader, state.root, false, selectedAdministrativePartial, nil)
					if change != "valid-current" {
						if result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
							t.Error("unclaimed, missing or optional current create evidence survived administrative validation", result)
						}
						return
					}
					if result != (Result{}) {
						t.Fatal("administrative evidence control refused", result)
					}
					projection := &StateSession{root: image.root, pages: image.pages, support: image.support, adminIndex: image.adminIndex,
						supportFacts: image.supportFacts, fragmentFacts: image.fragmentFacts}
					if _, selected, err := projection.administrativeGeneratedProjection(image.adminIndex); err != nil || selected != image.root.RequiredSupportRecordCount {
						t.Fatal("administrative evidence projection control", err)
					}
				})
			}
		})
	}
}

// full_only: false
func TestPrivateReplacementKeepsSharedPublicationIndexOwners(t *testing.T) {
	reader, root, index, _ := publicationSparseRetentionFixture(t)
	reader.replacementRead = true
	position := slices.IndexFunc(index.Pages, func(page format.AdministrativePage) bool {
		return len(page.Rows) != 0 && page.Rows[0].Kind == contract.OutputConfigurationSliceSupportKind
	})
	if position < 0 || len(index.Groups) == 0 {
		t.Fatal("configuration and publication owner fixture missing")
	}
	index.Pages[position].Spans[0].GroupIndexes = []uint16{0}
	var count uint32
	for _, page := range index.Pages {
		for _, span := range page.Spans {
			if slices.Contains(span.GroupIndexes, uint16(0)) {
				count += uint32(span.Count)
			}
		}
	}
	digest := selectedDisposableDigest(count)
	group := &index.Groups[0]
	group.ChargedPages, group.ChargedBytes = 0, 0
	for _, page := range index.Pages {
		logical, charged := 0, false
		for _, span := range page.Spans {
			if slices.Contains(span.GroupIndexes, uint16(0)) {
				charged = true
				for _, row := range page.Rows[logical : logical+int(span.Count)] {
					writeSelectedDisposableRow(digest, row.Kind, row.RecordID, row.BodyLength)
					group.ChargedBytes += uint64(contract.SupportRecordOverhead) + uint64(row.BodyLength)
				}
			}
			logical += int(span.Count)
		}
		if charged {
			group.ChargedPages++
		}
	}
	group.Disposable = selectedDisposableDescriptor(digest, count)
	root = replacementFixtureIndex(t, reader, root, index)
	for _, mode := range []selectedScanMode{selectedComplete, selectedAdministrativePartial} {
		image, result := scanSelectedImage(t.Context(), reader, root, false, mode, nil)
		if result != (Result{}) || !slices.Equal(image.adminIndex.Pages[position].Spans[0].GroupIndexes, []uint16{0}) {
			t.Fatal("shared publication owner was changed or refused", result)
		}
		state := &StateSession{root: root, adminIndex: image.adminIndex, support: image.support, supportFacts: image.supportFacts, fragmentFacts: image.fragmentFacts,
			pages: image.pages, publicationFacts: image.publicationFacts}
		if _, selected, err := state.administrativeGeneratedProjection(index); err != nil || selected != root.RequiredSupportRecordCount {
			t.Fatal("shared owner does not retain exact charges and disposable rows", err, selected)
		}
	}
}

func replacementFixtureIndex(t *testing.T, reader selectedObjectReader, root format.Root, index format.AdministrativeIndex) format.Root {
	t.Helper()
	pages, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil {
		t.Fatal("structurally valid replacement index", err)
	}
	root.AdministrativeIndex, root.AdministrativeIndexShards = pages[0].Ref, nil
	store := reader.source.(*generatedFixtureSupportStore)
	for i, page := range pages {
		key, _ := format.Key(reader.descriptor.Prefix, page.Ref)
		store.objects[key] = page.Body
		reader.cache[page.Ref] = page.Body
		if i != 0 {
			root.AdministrativeIndexShards = append(root.AdministrativeIndexShards, page.Ref)
		}
	}
	projection := StateSession{root: root}
	projection.recountChildren()
	if _, err := format.EncodeRoot(projection.root); err != nil {
		t.Fatal("canonical replacement index Root", err)
	}
	return projection.root
}

// full_only: false
func TestPrivateReplacementChecksCurrentOnlySupportBeforeBodyCapture(t *testing.T) {
	for _, test := range []struct {
		name         string
		kind         byte
		count        int
		bodyLength   uint32
		readRequired bool
	}{
		{"receipts", contract.MutationReceiptSupportKind, 2*contract.MutationReceiptWindowLimit + 1, contract.CompactMutationReceiptLength, false},
		{"create-evidence", contract.GeneratedCreateEvidenceSupportKind, contract.GeneratedCurrentEntryLimit + 1, contract.GeneratedCreateEvidenceMaxLength, false},
		{"slice-carriers", contract.GeneratorVectorSupportKind, contract.GeneratedCurrentEntryLimit + 2, 231, true},
		{"other-vector-owner", contract.GeneratorVectorSupportKind, 1, 231, false},
		{"operation-material", contract.OperationMaterialSupportKind, 1, 128, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, occupied := range []bool{false, true} {
				t.Run(map[bool]string{false: "current-only", true: "other-work"}[occupied], func(t *testing.T) {
					reader, root := replacementOvercountSupportFixture(t, test.kind, test.count, test.bodyLength, test.readRequired)
					if occupied {
						root.Generated.Attempts = 1
					}
					if _, err := format.EncodeRoot(root); err != nil {
						t.Fatal("canonical claimed Root", err)
					}
					_, result := scanSelectedImage(t.Context(), reader, root, false, selectedComplete, nil)
					store := reader.source.(*generatedFixtureSupportStore)
					reads := 0
					for _, ref := range root.RequiredSupport {
						key, _ := format.Key(reader.descriptor.Prefix, ref)
						if slices.Contains(store.keys, key) {
							reads++
						}
					}
					if occupied {
						if result.Outcome != EvidenceUnavailable || reads == 0 {
							t.Fatal("other work acquired a current-only body cap", result, reads)
						}
					} else if result.Outcome != IntegrityFailure || result.Reason != InvalidRelation || reads != 0 {
						t.Error("current-only support was not refused before body capture", result, reads)
					}
				})
			}
		})
	}
}

func replacementOvercountSupportFixture(t *testing.T, kind byte, count int, bodyLength uint32, readRequired bool) (selectedObjectReader, format.Root) {
	t.Helper()
	reader, root, index, selected := publicationSparseRetentionFixture(t)
	reader.replacementRead = true
	position := slices.IndexFunc(index.Pages, func(page format.AdministrativePage) bool { return page.Ref == selected })
	if position < 0 {
		t.Fatal("selected support fixture missing")
	}
	page := &index.Pages[position]
	oldRows := len(page.Rows)
	page.Ref.Length = contract.MaxRequiredSupportPageLength
	page.Ref.Digest = contract.Hash([]byte("unread current-only support page"))
	page.Spans = []format.AdministrativeSpan{{Count: uint16(count), Mandatory: true}}
	page.ReadRequired = readRequired
	page.Rows = nil
	if !readRequired {
		page.Rows = make([]format.AdministrativeRowSummary, count)
		for i := range page.Rows {
			id := contract.Hash(binary.BigEndian.AppendUint32([]byte("current-only support row"), uint32(i)))
			page.Rows[i] = format.AdministrativeRowSummary{Kind: kind, RecordID: id, BodyLength: bodyLength}
		}
	}
	root.ChildEncodedBytes += uint64(page.Ref.Length) - uint64(root.RequiredSupport[position].Length)
	root.RequiredSupport[position] = page.Ref
	root.RequiredSupportRecordCount = uint32(int(root.RequiredSupportRecordCount) + count - oldRows)
	root.ChildEncodedBytes -= uint64(root.AdministrativeIndex.Length)
	for _, ref := range root.AdministrativeIndexShards {
		root.ChildEncodedBytes -= uint64(ref.Length)
	}
	root.ChildCount -= uint32(len(root.AdministrativeIndexShards))
	pages, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil {
		t.Fatal("structurally valid current-only index", err)
	}
	store := reader.source.(*generatedFixtureSupportStore)
	root.AdministrativeIndexShards = nil
	for i, page := range pages {
		key, _ := format.Key(reader.descriptor.Prefix, page.Ref)
		store.objects[key] = page.Body
		if i == 0 {
			root.AdministrativeIndex = page.Ref
		} else {
			root.AdministrativeIndexShards = append(root.AdministrativeIndexShards, page.Ref)
			root.ChildCount++
		}
		root.ChildEncodedBytes += uint64(page.Ref.Length)
	}
	store.keys = nil
	return reader, root
}

// full_only: false
func TestPrivateReplacementChecksCurrentOnlyAccessBeforeBodyCapture(t *testing.T) {
	for _, private := range []bool{false, true} {
		for _, mode := range []selectedScanMode{selectedComplete, selectedAdministrativePartial} {
			for _, occupied := range []bool{false, true} {
				t.Run(map[bool]string{false: "reusable/", true: "private/"}[private]+map[selectedScanMode]string{selectedComplete: "complete/", selectedAdministrativePartial: "administrative/"}[mode]+map[bool]string{false: "current-only", true: "other-work"}[occupied], func(t *testing.T) {
					state := generatedEmptyPredecessor(t)
					observationCurrentSecret(t, state, []contract.ID{state.admission.recipient}, generatedVectorID(246))
					generatedSealSelectedFixture(t, state)
					reader := publicationRetentionReader(t, state)
					reader.replacementRead = private
					root := state.root
					root.CurrentAccess.Core.AccessPageRefs = slices.Clone(root.CurrentAccess.Core.AccessPageRefs)
					ref := &root.CurrentAccess.Core.AccessPageRefs[0]
					increase := uint32(contract.AccessRecordFixedLength + contract.WrapRowWireLength)
					if root.CurrentAccess.Core.Recovery != nil {
						increase += contract.WrapRowWireLength
					}
					ref.Length += increase
					ref.Digest = contract.Hash([]byte("unread access owner"))
					root.ChildEncodedBytes += uint64(increase)
					root.AccessRecordCount++
					root.CurrentAccess.Core.AccessRecordsDescriptor.Count++
					root.CurrentAccess.Core.AccessRecordsDescriptor.Length += uint64(increase) + 4
					root.CurrentAccess.Core.AccessRecordsDescriptor.Digest = contract.Hash([]byte("extra access owner"))
					var err error
					root.CurrentAccess.AccessRoot, err = contract.AccessRoot(root.CurrentAccess.Core)
					if err != nil {
						t.Fatal("structurally valid extra access commitment", err)
					}
					if occupied {
						root.Generated.Attempts = 1
					}
					if _, err := format.EncodeRoot(root); err != nil {
						t.Fatal("canonical extra access Root", err)
					}
					_, result := scanSelectedImage(t.Context(), reader, root, false, mode, nil)
					store := reader.source.(*generatedFixtureSupportStore)
					key, _ := format.Key(reader.descriptor.Prefix, *ref)
					read := slices.Contains(store.keys, key)
					if occupied {
						if result.Outcome != IntegrityFailure || result.Reason != InvalidReference || !read {
							t.Fatal("other work acquired a current-only access cap", result, read)
						}
					} else if result.Outcome != IntegrityFailure || result.Reason != InvalidRelation || read {
						t.Error("unowned access was not refused before body capture", result, read)
					}
				})
			}
		}
	}
}
