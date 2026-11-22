package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"maps"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPrivateReplacementRejectsMalformedIndexBeforeReadingAllShards(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(map[bool]string{false: "reusable", true: "private"}[private], func(t *testing.T) {
			reader, root, index, _ := publicationSparseRetentionFixture(t)
			reader.replacementRead = private
			pages, err := format.EncodeAdministrativeIndexPages(index)
			if err != nil || len(pages) != 1 {
				t.Fatal("index header fixture", err)
			}
			const count = 32
			payload := make([]byte, format.AdministrativeIndexShardPayloadLimit)
			logicalDigest := contract.Hash(bytes.Repeat([]byte{0}, count*len(payload)))
			template := pages[0].Body[:len(pages[0].Body)-int(binary.BigEndian.Uint32(pages[0].Body[112:116]))]
			if len(template) != 116 {
				t.Fatal("physical index header length", len(template))
			}
			store := reader.source.(*generatedFixtureSupportStore)
			root.ChildCount += count - 1 - uint32(len(root.AdministrativeIndexShards))
			root.ChildEncodedBytes -= uint64(root.AdministrativeIndex.Length)
			for _, ref := range root.AdministrativeIndexShards {
				root.ChildEncodedBytes -= uint64(ref.Length)
			}
			root.AdministrativeIndexShards = nil
			keys := make(map[string]bool)
			for i := 0; i < count; i++ {
				body := append(bytes.Clone(template), payload...)
				binary.BigEndian.PutUint16(body[72:74], uint16(i))
				binary.BigEndian.PutUint16(body[74:76], count)
				binary.BigEndian.PutUint32(body[76:80], uint32(count*len(payload)))
				copy(body[80:112], logicalDigest[:])
				binary.BigEndian.PutUint32(body[112:116], uint32(len(payload)))
				object := index.Object
				if i != 0 {
					identity := append([]byte("ENKV/admin-index-shard/v1\x00"), root.Domain[:]...)
					identity = append(identity, index.Object[:]...)
					identity = binary.BigEndian.AppendUint16(identity, uint16(i))
					object = contract.Hash(identity)
				}
				ref, err := format.Reference(contract.AdministrativeIndexKind, root.Domain, object, uint16(i), body)
				if err != nil {
					t.Fatal("authenticated physical shard", err)
				}
				key, _ := format.Key(reader.descriptor.Prefix, ref)
				store.objects[key], keys[key] = body, true
				if i == 0 {
					root.AdministrativeIndex = ref
				} else {
					root.AdministrativeIndexShards = append(root.AdministrativeIndexShards, ref)
				}
				root.ChildEncodedBytes += uint64(ref.Length)
			}
			if _, err := format.EncodeRoot(root); err != nil {
				t.Fatal("canonical Root carrying malformed logical index", err)
			}
			store.keys = nil
			if _, result := scanSelectedImage(t.Context(), reader, root, false, selectedComplete, nil); result.Outcome != IntegrityFailure || result.Reason != InvalidReference {
				t.Fatal("malformed logical index refusal", result)
			}
			reads := 0
			for _, key := range store.keys {
				if keys[key] {
					reads++
				}
			}
			want := count
			if private {
				want = 1
			}
			if reads != want {
				t.Errorf("index reads before logical prefix refusal = %d, want %d", reads, want)
			}
		})
	}
}

// full_only: false
func TestPrivateReplacementChecksPublicationCountsBeforeReadingBodies(t *testing.T) {
	for _, kind := range []byte{contract.PublicationCoordinateSupportKind, contract.PublicationMarkerSupportKind} {
		t.Run(map[byte]string{contract.PublicationCoordinateSupportKind: "coordinates", contract.PublicationMarkerSupportKind: "markers"}[kind], func(t *testing.T) {
			reader, root, index, selected := publicationSparseRetentionFixture(t)
			reader.replacementRead = true
			position := slices.IndexFunc(index.Pages, func(page format.AdministrativePage) bool { return page.Ref == selected })
			if position < 0 {
				t.Fatal("selected publication page missing")
			}
			count := contract.MaxPublicationCoordinates + 1
			if kind == contract.PublicationMarkerSupportKind {
				count = contract.MaxPublicationMarkers + 1
			}
			page := &index.Pages[position]
			oldRows := len(page.Rows)
			page.Ref.Length = contract.MaxRequiredSupportPageLength
			page.Ref.Digest = contract.Hash([]byte("unread over-count publication page"))
			page.Spans = []format.AdministrativeSpan{{Count: uint16(count), Mandatory: true}}
			page.Rows = make([]format.AdministrativeRowSummary, count)
			for i := range page.Rows {
				id := contract.Hash(binary.BigEndian.AppendUint32([]byte("over-count publication row"), uint32(i)))
				page.Rows[i] = format.AdministrativeRowSummary{Kind: kind, RecordID: id, BodyLength: 512}
			}
			root.ChildEncodedBytes += uint64(page.Ref.Length) - uint64(root.RequiredSupport[position].Length)
			root.RequiredSupport[position] = page.Ref
			root.RequiredSupportRecordCount += uint32(count - oldRows)
			root.ChildEncodedBytes -= uint64(root.AdministrativeIndex.Length)
			for _, ref := range root.AdministrativeIndexShards {
				root.ChildEncodedBytes -= uint64(ref.Length)
			}
			root.ChildCount -= uint32(len(root.AdministrativeIndexShards))
			pages, err := format.EncodeAdministrativeIndexPages(index)
			if err != nil {
				t.Fatal("over-count index remains structurally valid", err)
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
			if _, err := format.EncodeRoot(root); err != nil {
				t.Fatal("canonical over-count Root", err)
			}
			store.keys = nil
			if _, result := scanSelectedImage(t.Context(), reader, root, false, selectedComplete, nil); result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
				t.Error("over-count selection must refuse before Store availability", result)
			}
			for _, ref := range root.RequiredSupport {
				key, _ := format.Key(reader.descriptor.Prefix, ref)
				if slices.Contains(store.keys, key) {
					t.Error("over-count selection read a support body before refusing")
				}
			}
		})
	}
}

// full_only: false
func TestCompleteSelectedPublicationRetainsFactsWithoutEncodedBodies(t *testing.T) {
	state, _ := publicationConfiguredImage(t, publicationRelationID(2), publicationRelationID(3), publicationRelationID(2))
	reader := publicationRetentionReader(t, state)
	reader.replacementRead = true
	for _, retain := range []bool{false, true} {
		t.Run(map[bool]string{false: "observation", true: "session"}[retain], func(t *testing.T) {
			image, result := scanSelectedImage(t.Context(), reader, state.root, retain, selectedComplete, nil)
			if result != (Result{}) || image.publicationProof == nil || !image.publicationProof.validFor(&image) {
				t.Fatal("complete selected publication", result)
			}
			selected, err := selectedPublicationRelation(&image)
			if err != nil || len(selected.coordinates) != 1 || len(selected.markers) != 1 {
				t.Fatal("retained publication relation", err)
			}
			for i, page := range image.support {
				publication := false
				for j, row := range page.Records {
					if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
						publication = true
						if len(row.Body) != 0 {
							t.Errorf("selected publication retains encoded row kind %d (%d bytes)", row.Kind, len(row.Body))
						}
						body, err := image.publicationReplayBody(i, j)
						if err != nil || len(body) != cap(body) || !bytes.Equal(body, state.support[i].Records[j].Body) {
							t.Fatal("reservation replay changed the physical record or retained excess backing", err)
						}
						key := generatedRecordKey{row.Kind, row.RecordID}
						fact := image.publicationFacts[key]
						delete(image.publicationFacts, key)
						if _, err := image.publicationReplayBody(i, j); err == nil {
							t.Fatal("reservation replay accepted a missing publication fact")
						}
						image.publicationFacts[key] = fact
						digest := image.supportFacts[i].rows[j]
						image.supportFacts[i].rows[j] = contract.SupportRecordDigest{}
						if _, err := image.publicationReplayBody(i, j); err == nil {
							t.Fatal("reservation replay accepted a different authenticated row")
						}
						image.supportFacts[i].rows[j] = digest
					}
				}
				if publication && len(image.cache[image.root.RequiredSupport[i]]) != 0 {
					t.Error("selected publication retains encoded page backing")
				}
			}
			for _, row := range state.supportRecords() {
				var encoded []byte
				switch row.Kind {
				case contract.PublicationCoordinateSupportKind:
					encoded, err = contract.EncodePublicationCoordinate(selected.coordinates[row.RecordID])
				case contract.PublicationMarkerSupportKind:
					encoded, err = contract.EncodePublicationMarker(selected.markers[row.RecordID])
				default:
					continue
				}
				if err != nil || !bytes.Equal(encoded, row.Body) {
					t.Fatal("retained facts changed exact canonical publication record", err)
				}
			}
			clear(selected.coordinates)
			clear(selected.markers)
			selected, valid := image.publicationProof.relationFor(&image)
			if !valid || len(selected.coordinates) != 1 || len(selected.markers) != 1 {
				t.Fatal("caller map mutation changed immutable publication proof")
			}
			for id, coordinate := range selected.coordinates {
				if len(coordinate.DeletionTargetData) != 0 {
					coordinate.DeletionTargetData[0] ^= 0xff
					selected.coordinates[id] = coordinate
				}
			}
			again, valid := image.publicationProof.relationFor(&image)
			if !valid {
				t.Fatal("returned coordinate bytes changed immutable publication proof")
			}
			for _, row := range state.supportRecords() {
				if row.Kind == contract.PublicationCoordinateSupportKind {
					encoded, err := contract.EncodePublicationCoordinate(again.coordinates[row.RecordID])
					if err != nil || !bytes.Equal(encoded, row.Body) {
						t.Fatal("returned coordinate bytes alias immutable publication proof", err)
					}
				}
			}
		})
	}
}

// full_only: false
func TestSelectedPublicationExactPageReuseNeedsNoNewStoreRead(t *testing.T) {
	state, _ := publicationConfiguredImage(t, publicationRelationID(2), publicationRelationID(3), publicationRelationID(2))
	reader := publicationRetentionReader(t, state)
	reader.replacementRead = true
	before, result := scanSelectedImage(t.Context(), reader, state.root, false, selectedComplete, nil)
	if result != (Result{}) {
		t.Fatal("initial publication scan", result)
	}
	reader.cache = maps.Clone(reader.cache)
	var publicationPages []int
	for i, page := range before.support {
		if slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool {
			return row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind
		}) {
			publicationPages = append(publicationPages, i)
			delete(reader.cache, before.root.RequiredSupport[i])
			key, err := format.Key(reader.descriptor.Prefix, before.root.RequiredSupport[i])
			if err != nil {
				t.Fatal(err)
			}
			delete(reader.source.(*generatedFixtureSupportStore).objects, key)
		}
	}
	if len(publicationPages) == 0 {
		t.Fatal("fixture has no publication page")
	}
	// The publication source is unavailable. Exact authenticated facts must suffice.
	for _, mode := range []selectedScanMode{selectedComplete, selectedAdministrativePartial} {
		t.Run(map[selectedScanMode]string{selectedComplete: "complete", selectedAdministrativePartial: "administrative"}[mode], func(t *testing.T) {
			observed, result := scanSelectedImage(t.Context(), reader, state.root, false, mode, &before)
			if result != (Result{}) || !before.publicationProof.validFor(&before) {
				t.Fatal("unchanged authenticated publication page acquired a new Store failure", result)
			}
			if mode == selectedComplete && !observed.publicationProof.validFor(&observed) || mode == selectedAdministrativePartial && observed.publicationProof != nil {
				t.Fatal("page reuse changed complete publication proof eligibility")
			}
		})
	}
	for _, field := range []string{"object", "digest", "length", "index"} {
		t.Run(field, func(t *testing.T) {
			changed := state.root
			changed.RequiredSupport = slices.Clone(changed.RequiredSupport)
			ref := &changed.RequiredSupport[publicationPages[0]]
			switch field {
			case "object":
				ref.Object = publicationRelationID(125)
			case "digest":
				ref.Digest = publicationRelationID(126)
			case "length":
				ref.Length++
			case "index":
				ref.Index++
			}
			if _, result := scanSelectedImage(t.Context(), reader, changed, false, selectedComplete, &before); result.Outcome == 0 {
				t.Fatal("changed selected page borrowed previous publication facts")
			}
		})
	}
}

func publicationRetentionReader(t *testing.T, state *StateSession) selectedObjectReader {
	t.Helper()
	cache := make(map[format.Ref][]byte)
	put := func(ref format.Ref, body []byte, err error) {
		t.Helper()
		if err != nil || uint32(len(body)) != ref.Length || contract.Hash(body) != ref.Digest {
			t.Fatal("publication retention fixture reference", err)
		}
		cache[ref] = body
	}
	for i, page := range state.pages {
		if page != nil {
			body, err := format.EncodeValueEntryPage(*page)
			put(*state.root.ValueEntryPages[i], body, err)
		}
	}
	for i, page := range state.recipients {
		if page != nil {
			body, err := format.EncodeRecipientPage(*page)
			put(*state.root.Recipients[i], body, err)
		}
	}
	for _, page := range state.access {
		if page != nil {
			body, err := format.EncodeAccessPage(*page)
			for _, ref := range state.root.CurrentAccess.Core.AccessPageRefs {
				if ref.Index == page.Index {
					put(ref, body, err)
				}
			}
		}
	}
	for i, page := range state.support {
		rows := make([]contract.SupportRecord, len(page.Records))
		for j, row := range page.Records {
			rows[j] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		put(state.root.RequiredSupport[i], body, err)
	}
	indexes, err := format.EncodeAdministrativeIndexPages(state.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	for _, page := range indexes {
		put(page.Ref, page.Body, nil)
	}
	store := &generatedFixtureSupportStore{t: t, descriptor: state.admission.store, objects: make(map[string][]byte)}
	for ref, body := range cache {
		key, err := format.Key(state.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		store.objects[key] = body
	}
	return selectedObjectReader{domain: state.root.Domain, descriptor: state.admission.store, cache: cache, source: store}
}

// full_only: false
func TestReusableSelectedPublicationKeepsWholePhysicalCache(t *testing.T) {
	for _, retain := range []bool{false, true} {
		t.Run(map[bool]string{false: "observation", true: "open"}[retain], func(t *testing.T) {
			reader, root, index, publication := publicationSparseRetentionFixture(t)
			want := bytes.Clone(reader.cache[publication])
			image, result := scanSelectedImage(t.Context(), reader, root, retain, selectedComplete, nil)
			if result != (Result{}) {
				t.Fatal("reusable selected scan", result)
			}
			if !bytes.Equal(image.cache[publication], want) {
				t.Error("reusable selected image dropped authenticated whole physical publication bytes")
			}
			if len(image.publicationFacts) != 0 {
				t.Error("reusable raw cache also retains duplicate typed publication data")
			}
			key, err := format.Key(reader.descriptor.Prefix, publication)
			if err != nil {
				t.Fatal(err)
			}
			delete(reader.source.(*generatedFixtureSupportStore).objects, key)
			reader.cache = image.cache
			for _, readContext := range []context.Context{nil, t.Context()} {
				body, result := reader.readOwned(readContext, publication)
				if result != (Result{}) || !bytes.Equal(body, want) {
					t.Error("cached whole physical read acquired a new Store/context failure", result)
				}
			}
			if len(index.Pages) != len(image.support) {
				t.Fatal("fixture lost its complete selected page table")
			}
		})
	}
}

// full_only: false
func TestPrivateReplacementAdministrativeFactsReuseSelectedOrdinalSubset(t *testing.T) {
	reader, root, index, publication := publicationSparseRetentionFixture(t)
	reader.replacementRead = true
	before, result := scanSelectedImage(t.Context(), reader, root, true, selectedAdministrativePartial, nil)
	if result != (Result{}) {
		t.Fatal("private administrative scan", result)
	}
	if before.publicationProof != nil {
		t.Error("administrative selected facts minted a complete publication proof")
	}
	if len(before.publicationFacts) != 2 || len(before.cache[publication]) != 0 {
		t.Error("private administrative read retained raw publication backing instead of selected typed facts")
	}
	position := slices.Index(root.RequiredSupport, publication)
	if position < 0 || len(before.support[position].Records) != 2 {
		t.Fatal("sparse selected coordinate fixture")
	}
	for _, row := range before.support[position].Records {
		if row.Body != nil {
			t.Error("private administrative selected row retained encoded body")
		}
	}
	removed := before.support[position].Records[0].RecordID
	index = clonePublicationWork(index)
	index.Object = publicationRelationID(214)
	index.Groups = slices.DeleteFunc(index.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == removed })
	index.PublicationOrder = slices.DeleteFunc(index.PublicationOrder, func(order format.PublicationCoordinateOrder) bool { return order.CoordinateID == removed })
	index.Pages[position].Rows = index.Pages[position].Rows[1:]
	index.Pages[position].Spans = index.Pages[position].Spans[1:]
	for i := range index.Pages[position].Spans {
		index.Pages[position].Spans[i].GroupIndexes = []uint16{0}
	}
	root.Snapshot, root.Transition = publicationRelationID(215), publicationRelationID(216)
	root.RequiredSupportRecordCount--
	shards, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil {
		t.Fatal("selected subset index", err)
	}
	reader.cache = maps.Clone(before.cache)
	delete(reader.cache, publication)
	root.AdministrativeIndex, root.AdministrativeIndexShards = shards[0].Ref, nil
	for i, shard := range shards {
		reader.cache[shard.Ref] = shard.Body
		if i != 0 {
			root.AdministrativeIndexShards = append(root.AdministrativeIndexShards, shard.Ref)
		}
	}
	projection := StateSession{root: root}
	projection.recountChildren()
	root = projection.root
	key, err := format.Key(reader.descriptor.Prefix, publication)
	if err != nil {
		t.Fatal(err)
	}
	store := reader.source.(*generatedFixtureSupportStore)
	delete(store.objects, key)
	store.keys = nil
	after, result := scanSelectedImage(t.Context(), reader, root, false, selectedAdministrativePartial, &before)
	if result != (Result{}) {
		t.Fatal("selected physical ordinal subset acquired a new Store failure", result)
	}
	if after.publicationProof != nil || len(after.publicationFacts) != 1 || len(after.support[position].Records) != 1 || after.supportFacts[position].ordinals[0] != 3 {
		t.Fatal("partial subset changed proof eligibility or physical ordinal")
	}
	if len(before.support[position].Records) != 2 || len(before.supportFacts[position].ordinals) != 2 {
		t.Fatal("subset read mutated reusable predecessor facts")
	}
	for _, read := range store.keys {
		if read == key {
			t.Fatal("subset read fetched unchanged authenticated physical page")
		}
	}
}

func publicationSparseRetentionFixture(t *testing.T) (selectedObjectReader, format.Root, format.AdministrativeIndex, format.Ref) {
	t.Helper()
	state, _ := publicationEmptyConfigurationImage(t, true)
	state.adminIndex.PublicationOrder = nil
	_, base, marker, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	state.support = slices.DeleteFunc(state.support, func(page format.RequiredSupportPageView) bool {
		return slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool { return publicationSupportKind(row.Kind) })
	})
	page := format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(210), Index: generatedFixtureFreeSupportIndex(t, state)}
	for i := 0; i < 2; i++ {
		coordinate := base
		coordinate.CanonicalTarget = []string{"account/first", "account/second"}[i]
		coordinate.CoordinateID, _ = contract.PublicationCoordinateID(state.root.Domain, coordinate.ServiceContractID, coordinate.CanonicalTarget)
		coordinate.CurrentPublicationIncarnationID = publicationRelationID(byte(211 + i))
		coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
		coordinate.OwnerState, coordinate.PossibleRemoteObject, coordinate.LatestUnresolvedAttemptID = contract.PublicationOwnerNone, 0, contract.ID{}
		body, err := contract.EncodePublicationCoordinate(coordinate)
		if err != nil {
			t.Fatal(err)
		}
		page.Records = append(page.Records, contract.SupportRecordView{Kind: contract.PublicationCoordinateSupportKind, RecordID: coordinate.CoordinateID, Body: body})
	}
	state.support = append(state.support, page)
	generatedRefreshSupport(t, state)
	reader := publicationRetentionReader(t, state)
	position := slices.IndexFunc(state.support, func(page format.RequiredSupportPageView) bool {
		return len(page.Records) == 2 && publicationSupportKind(page.Records[0].Kind)
	})
	if position < 0 {
		t.Fatal("two selected coordinate page missing")
	}
	var physical []contract.SupportRecord
	for i, row := range state.support[position].Records {
		stale := marker
		stale.AttemptID = publicationRelationID(byte(220 + i))
		body, err := contract.EncodePublicationMarker(stale)
		if err != nil {
			t.Fatal(err)
		}
		physical = append(physical, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: stale.AttemptID, Body: body}, contract.SupportRecord(row))
	}
	body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: state.root.Domain, Object: publicationRelationID(213), Index: page.Index, Records: physical})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, state.root.Domain, publicationRelationID(213), page.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	old := state.root.RequiredSupport[position]
	delete(reader.cache, old)
	reader.cache[ref] = body
	state.root.RequiredSupport = slices.Clone(state.root.RequiredSupport)
	state.root.RequiredSupport[position] = ref
	index := clonePublicationWork(state.adminIndex)
	index.Pages[position].Ref = ref
	for i := range index.Pages[position].Spans {
		index.Pages[position].Spans[i].First = uint16(2*i + 1)
	}
	shards, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil {
		t.Fatal(err)
	}
	state.root.AdministrativeIndex, state.root.AdministrativeIndexShards = shards[0].Ref, nil
	for i, shard := range shards {
		reader.cache[shard.Ref] = shard.Body
		if i != 0 {
			state.root.AdministrativeIndexShards = append(state.root.AdministrativeIndexShards, shard.Ref)
		}
	}
	state.adminIndex = index
	state.recountChildren()
	return reader, state.root, index, ref
}

// full_only: false
func TestPrivateReplacementRetainsOnlySelectedSmallSupportRows(t *testing.T) {
	state := generatedEmptyPredecessor(t)
	receipts, receipt, _ := receiptStateFixtureForDomain(t, state.root.Domain)
	state.root.Generated.SuccessWindow = receipts.root.Generated.SuccessWindow
	state.root.Generated.FailureWindow = receipts.root.Generated.FailureWindow
	state.root.Generated.ReceiptOrder = receipts.root.Generated.ReceiptOrder
	receiptIndex, err := selectedReceiptIndexID(state.root.Domain, state.root)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeCompactMutationReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	page := format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(230), Index: generatedFixtureFreeSupportIndex(t, state),
		Records: []contract.SupportRecordView{{Kind: contract.MutationReceiptSupportKind, RecordID: receipt.OperationID, Body: body}}}
	state.support = append(state.support, page)
	for _, source := range receipts.support {
		for _, row := range source.Records {
			if row.Kind != contract.GeneratedFragmentSupportKind {
				continue
			}
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if fragment.BlobID != receiptIndex {
				continue
			}
			retained := format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(232),
				Index: generatedFixtureFreeSupportIndex(t, state), Records: []contract.SupportRecordView{row}}
			state.support = append(state.support, retained)
			state.root.Generated.Fragments = append(state.root.Generated.Fragments, format.FragmentLocation{BlobID: fragment.BlobID,
				FragmentIndex: fragment.Index, SupportPageIndex: retained.Index})
		}
	}
	generatedRefreshSupport(t, state)
	reader := publicationRetentionReader(t, state)
	position := slices.IndexFunc(state.support, func(p format.RequiredSupportPageView) bool { return p.Index == page.Index })
	if position < 0 {
		t.Fatal("selected receipt page missing")
	}
	stale := receipt
	stale.OperationID = publicationRelationID(231)
	staleBody, err := contract.EncodeCompactMutationReceipt(stale)
	if err != nil {
		t.Fatal(err)
	}
	physical := []contract.SupportRecord{{Kind: contract.MutationReceiptSupportKind, RecordID: stale.OperationID, Body: staleBody}, contract.SupportRecord(page.Records[0])}
	encoded, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: physical})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, encoded)
	if err != nil {
		t.Fatal(err)
	}
	state.root.RequiredSupport[position] = ref
	state.adminIndex.Pages[position].Ref = ref
	state.adminIndex.Pages[position].Spans[0].First = 1
	reader.cache[ref] = encoded
	shards, err := format.EncodeAdministrativeIndexPages(state.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	state.root.AdministrativeIndex, state.root.AdministrativeIndexShards = shards[0].Ref, nil
	for i, shard := range shards {
		reader.cache[shard.Ref] = shard.Body
		if i != 0 {
			state.root.AdministrativeIndexShards = append(state.root.AdministrativeIndexShards, shard.Ref)
		}
	}
	state.recountChildren()
	for _, private := range []bool{false, true} {
		t.Run(map[bool]string{false: "reusable", true: "private"}[private], func(t *testing.T) {
			currentReader := reader
			currentReader.replacementRead = private
			image, result := scanSelectedImage(t.Context(), currentReader, state.root, true, selectedComplete, nil)
			if result != (Result{}) {
				t.Fatal("sparse receipt scan", result)
			}
			row := image.support[position].Records[0]
			if !bytes.Equal(row.Body, body) {
				t.Fatal("selected receipt changed")
			}
			if private {
				if len(image.cache[ref]) != 0 {
					t.Error("private selected receipt retains omitted physical row backing")
				}
				offset := bytes.Index(encoded, body)
				if offset < 0 {
					t.Fatal("selected physical receipt body missing")
				}
				encoded[offset] ^= 0x80
				owned := bytes.Equal(row.Body, body)
				encoded[offset] ^= 0x80
				if !owned {
					t.Error("private selected receipt borrows whole physical page")
				}
				currentReader.cache = image.cache
				observed, result := scanSelectedImage(t.Context(), currentReader, state.root, false, selectedComplete, &image)
				if result != (Result{}) || !bytes.Equal(observed.support[position].Records[0].Body, body) {
					t.Fatal("exact selected receipt acquired a new read", result)
				}
			} else if !bytes.Equal(image.cache[ref], encoded) {
				t.Error("reusable reader lost whole physical receipt cache")
			}
		})
	}
}

// full_only: false
func TestPrivateReplacementRetainsTypedAdministrativeIndex(t *testing.T) {
	for _, mode := range []selectedScanMode{selectedComplete, selectedAdministrativePartial} {
		t.Run(map[selectedScanMode]string{selectedComplete: "complete", selectedAdministrativePartial: "administrative"}[mode], func(t *testing.T) {
			reader, root, _, _ := publicationSparseRetentionFixture(t)
			reader.replacementRead = true
			before, result := scanSelectedImage(t.Context(), reader, root, true, mode, nil)
			if result != (Result{}) {
				t.Fatal("private index scan", result)
			}
			refs := append([]format.Ref{root.AdministrativeIndex}, root.AdministrativeIndexShards...)
			reader.cache = maps.Clone(before.cache)
			store := reader.source.(*generatedFixtureSupportStore)
			for _, ref := range refs {
				if len(before.cache[ref]) != 0 {
					t.Error("private scan retains encoded index beside owned decoded index")
				}
				delete(reader.cache, ref)
				key, err := format.Key(reader.descriptor.Prefix, ref)
				if err != nil {
					t.Fatal(err)
				}
				delete(store.objects, key)
			}
			store.keys = nil
			after, result := scanSelectedImage(t.Context(), reader, root, false, mode, &before)
			if result != (Result{}) {
				t.Fatal("exact authenticated index acquired a new Store failure", result)
			}
			if !reflect.DeepEqual(after.adminIndex, before.adminIndex) {
				t.Fatal("exact index reuse changed decoded selection")
			}
			for _, ref := range refs {
				key, _ := format.Key(reader.descriptor.Prefix, ref)
				if slices.Contains(store.keys, key) {
					t.Fatal("exact index reuse fetched authenticated shard")
				}
			}
			for _, change := range []string{"object", "digest", "length", "index", "extra-shard"} {
				t.Run(change, func(t *testing.T) {
					changed := root
					switch change {
					case "object":
						changed.AdministrativeIndex.Object = publicationRelationID(242)
					case "digest":
						changed.AdministrativeIndex.Digest[0] ^= 0x80
					case "length":
						changed.AdministrativeIndex.Length++
					case "index":
						changed.AdministrativeIndex.Index++
					case "extra-shard":
						changed.AdministrativeIndexShards = []format.Ref{root.AdministrativeIndex}
					}
					if _, result := scanSelectedImage(t.Context(), reader, changed, false, mode, &before); result == (Result{}) {
						t.Fatal("changed shard closure reused the prior index")
					}
				})
			}
		})
	}
}

// full_only: false
func TestPrivateReplacementAdministrativeRetainsOnlyReceiptFragment(t *testing.T) {
	state := generatedEmptyPredecessor(t)
	receipts, want, otherBlob := receiptStateFixtureForDomain(t, state.root.Domain)
	state.root.Generated.SuccessWindow = receipts.root.Generated.SuccessWindow
	state.root.Generated.FailureWindow = receipts.root.Generated.FailureWindow
	state.root.Generated.ReceiptOrder = receipts.root.Generated.ReceiptOrder
	for i, source := range receipts.support {
		page := format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(byte(245 + i)), Index: generatedFixtureFreeSupportIndex(t, state), Records: slices.Clone(source.Records)}
		state.support = append(state.support, page)
	}
	generatedRefreshSupport(t, state)
	for _, page := range state.support {
		for logical, row := range page.Records {
			if row.Kind != contract.GeneratedFragmentSupportKind {
				continue
			}
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			state.root.Generated.Fragments = append(state.root.Generated.Fragments, format.FragmentLocation{BlobID: fragment.BlobID,
				FragmentIndex: fragment.Index, SupportPageIndex: page.Index, RowSlot: uint8(logical)})
		}
	}
	slices.SortFunc(state.root.Generated.Fragments, func(a, b format.FragmentLocation) int { return bytes.Compare(a.BlobID[:], b.BlobID[:]) })
	receiptID, err := selectedReceiptIndexID(state.root.Domain, state.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"oversized", "malformed"} {
		t.Run(bad, func(t *testing.T) {
			reader := publicationRetentionReader(t, state)
			reader.replacementRead = true
			root := state.root
			root.RequiredSupport = slices.Clone(root.RequiredSupport)
			index := clonePublicationWork(state.adminIndex)
			found := false
			for position, ref := range root.RequiredSupport {
				page, err := format.InspectRequiredSupportPage(reader.cache[ref])
				if err != nil {
					t.Fatal(err)
				}
				rows := make([]contract.SupportRecord, len(page.Records))
				for i, row := range page.Records {
					rows[i] = contract.SupportRecord(row)
				}
				for logical, row := range rows {
					if row.Kind != contract.GeneratedFragmentSupportKind {
						continue
					}
					fragment, err := contract.InspectGeneratedFragment(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if fragment.BlobID != receiptID {
						continue
					}
					payload := bytes.Clone(fragment.Payload)
					if bad == "oversized" {
						payload = make([]byte, contract.MutationReceiptIndexesMaxLength+1)
					} else {
						payload[0] ^= 0x80
					}
					body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: receiptID, Count: 1,
						TotalLength: uint64(len(payload)), WholeDigest: contract.Hash(payload), Payload: payload})
					if err != nil {
						t.Fatal(err)
					}
					rows[logical].Body = body
					index.Pages[position].Rows[logical].BodyLength = uint32(len(body))
					found = true
				}
				if !found {
					continue
				}
				body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
				if err != nil {
					t.Fatal(err)
				}
				updated, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
				if err != nil {
					t.Fatal(err)
				}
				root.RequiredSupport[position], index.Pages[position].Ref = updated, updated
				reader.cache[updated] = body
				break
			}
			if !found {
				t.Fatal("receipt fragment source missing")
			}
			shards, err := format.EncodeAdministrativeIndexPages(index)
			if err != nil {
				t.Fatal(err)
			}
			root.AdministrativeIndex, root.AdministrativeIndexShards = shards[0].Ref, nil
			for i, shard := range shards {
				reader.cache[shard.Ref] = shard.Body
				if i != 0 {
					root.AdministrativeIndexShards = append(root.AdministrativeIndexShards, shard.Ref)
				}
			}
			projection := StateSession{root: root}
			projection.recountChildren()
			root = projection.root
			if _, result := scanSelectedImage(t.Context(), reader, root, true, selectedAdministrativePartial, nil); result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
				t.Fatal("invalid named receipt fragment survived its pre-retention bound", result)
			}
		})
	}
	for _, private := range []bool{false, true} {
		t.Run(map[bool]string{false: "reusable", true: "private"}[private], func(t *testing.T) {
			reader := publicationRetentionReader(t, state)
			reader.replacementRead = private
			image, result := scanSelectedImage(t.Context(), reader, state.root, true, selectedAdministrativePartial, nil)
			if result != (Result{}) {
				t.Fatal("administrative fragment scan", result)
			}
			if image.publicationProof != nil {
				t.Fatal("partial fragment read minted a complete publication proof")
			}
			var receipt, omitted bool
			for location, fact := range image.fragmentFacts {
				position := slices.Index(image.root.RequiredSupport, fact.ref)
				row := image.support[position].Records[location.RowSlot]
				switch location.BlobID {
				case receiptID:
					receipt = true
					if row.Body == nil {
						t.Error("administrative receipt index lost its bounded owned body")
					}
				case otherBlob:
					omitted = true
					if private && row.Body != nil {
						t.Error("private administrative read retains a nonreceipt fragment payload")
					}
					if !private && row.Body == nil {
						t.Error("reusable administrative reader lost retained fragment body")
					}
				}
			}
			if !receipt || !omitted {
				t.Fatal("receipt and nonreceipt fragment controls missing")
			}
			selected := &StateSession{root: image.root, support: image.support, supportFacts: image.supportFacts, adminIndex: image.adminIndex,
				fragmentFacts: image.fragmentFacts, admission: openAdmission{domain: image.root.Domain}}
			reads := len(reader.source.(*generatedFixtureSupportStore).keys)
			windows, err := selected.receiptWindowsFromAdministrativeSupport()
			if len(reader.source.(*generatedFixtureSupportStore).keys) != reads {
				t.Error("administrative receipt facts acquired a new Store read")
			}
			if err != nil || len(windows.Successes) != 1 || windows.Successes[0] != want {
				t.Fatal("administrative receipt window changed", err)
			}
			if private {
				location := slices.IndexFunc(image.root.Generated.Fragments, func(loc format.FragmentLocation) bool { return loc.BlobID == otherBlob })
				if location < 0 {
					t.Fatal("omitted fragment location missing")
				}
				var payload []byte
				result, err := withSelectedFragmentFromImage(t.Context(), &image, reader, image.root.Generated.Fragments[location], func(value []byte) error { payload = bytes.Clone(value); return nil })
				if result != (Result{}) || err != nil || !bytes.Equal(payload, []byte("retained source bytes")) {
					t.Fatal("omitted fragment lost authenticated stream", result, err)
				}
			}
		})
	}
}
