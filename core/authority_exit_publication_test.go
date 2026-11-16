package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPublicationEndWorkRefusesMissingAuthority(t *testing.T) {
	image := publicationSelectedImageFixture(t)
	state := StateSession{root: image.root, support: image.support, adminIndex: image.adminIndex}
	markerID := image.support[0].Records[1].RecordID
	work, ended, err := state.administrativeWorkClosure(markerID)
	if err != nil {
		t.Fatalf("selected marker closure: %v", err)
	}
	_, _, err = state.rebindEndWorkPublication(t.Context(), &work, ended, endWorkIDs{
		operation: publicationRelationID(95), snapshot: publicationRelationID(97),
		receipts: publicationRelationID(99), receiptIndex: publicationRelationID(100)})
	if !errors.Is(err, contract.ErrRecord) {
		t.Fatalf("incomplete authority did not return a typed refusal: %v", err)
	}
}

// full_only: false
func TestPublicationCoordinateDispositionKeepsExactHistoricalFacts(t *testing.T) {
	_, before, create, _ := publicationRelationFixture(t)
	before.LastValueAckAttemptID, before.LastValueDigest = publicationRelationID(80), publicationRelationID(81)
	before.LastValueAckIncarnationID, before.LastValueAckOrdinal = before.CurrentPublicationIncarnationID, 1
	before.LastPolicyAckAttemptID, before.LastPolicyDigest = publicationRelationID(82), publicationRelationID(83)
	before.LastPolicyAckIncarnationID, before.LastPolicyAckOrdinal = before.CurrentPublicationIncarnationID, 1
	before.LastDeleteAckAttemptID = publicationRelationID(84)
	before.LastDeleteAckIncarnationID, before.LastDeleteAckOrdinal = before.CurrentPublicationIncarnationID, 1
	ended := []format.AdministrativeGroup{{GroupID: create.AttemptID, OwnerID: before.CoordinateID,
		OwnerKind: format.AdministrativePublicationMarker}}
	retained := format.AdministrativeIndex{Groups: []format.AdministrativeGroup{{GroupID: publicationRelationID(85),
		OwnerID: before.CoordinateID, OwnerKind: format.AdministrativePublicationMarker}}}
	after := publicationCoordinateAfterDisposition(retained, before, ended)
	want := before
	want.LatestUnresolvedAttemptID, want.OwnerState = contract.ID{}, contract.PublicationOwnerNone
	if !after.Equal(want) {
		t.Fatal("uncertain-create exit changed retained coordinate facts", after, want)
	}
	if _, err := contract.EncodePublicationCoordinate(after); err != nil {
		t.Fatalf("conservative post-exit coordinate invalid: %v", err)
	}
}

// full_only: false
func TestPublicationCoordinateDispositionPreservesUnrelatedUnloadedProof(t *testing.T) {
	state := generatedEmptyPredecessor(t)
	_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	before, create := coordinate, marker
	rows := publicationRelationRows(t, before, create)
	state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain,
		Object: publicationRelationID(20), Index: 1,
		Records: []contract.SupportRecordView{contract.SupportRecordView(rows[0]), contract.SupportRecordView(rows[1])}})
	generatedRefreshSupport(t, state)
	retained := state.adminIndex
	for _, group := range retained.Groups {
		if group.GroupID == create.AttemptID && group.UncertainCreateProof != 1 {
			t.Fatal("full selected writer omitted uncertain create proof")
		}
	}
	ended := []format.AdministrativeGroup{{GroupID: publicationRelationID(90), OwnerID: before.CoordinateID,
		OwnerKind: format.AdministrativePublicationMarker}}
	after := publicationCoordinateAfterDisposition(retained, before, ended)
	if !after.Equal(before) {
		t.Fatal("unloaded optional create detail removed independently retained ownership", after, before)
	}
}

// full_only: false
func TestPublicationEndWorkRebindsUncertainCoordinateOnExactMarkerExit(t *testing.T) {
	state := generatedEmptyPredecessor(t)
	_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	coordinate.BindingState = contract.PublicationBindingRetired
	coordinate.ActiveBindingIncarnationID = contract.ID{}
	rows := publicationRelationRows(t, coordinate, marker)
	state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain,
		Object: publicationRelationID(20), Index: 1,
		Records: []contract.SupportRecordView{contract.SupportRecordView(rows[0]), contract.SupportRecordView(rows[1])}})
	generatedRefreshSupport(t, state)
	state.recountChildren()
	proof, result, err := validateSelectedPublicationConfiguration(t.Context(), state.selectedImage(), nil)
	if err != nil || result.Outcome != 0 || proof == nil {
		t.Fatal("publication predecessor proof", result, err)
	}
	state.publicationProof = proof
	if _, relationErr := state.validateRelationsMode(t.Context(), false); relationErr != nil {
		t.Fatal("combined selected predecessor invalid")
	}
	work, ended, err := state.administrativeWorkClosure(marker.AttemptID)
	if err != nil {
		t.Fatalf("selected marker closure: %v", err)
	}
	images, views, err := state.rebindEndWorkPublication(t.Context(), &work, ended, endWorkIDs{
		operation: publicationRelationID(95), transition: publicationRelationID(96),
		snapshot: publicationRelationID(97), revision: publicationRelationID(98),
		receipts: publicationRelationID(99), receiptIndex: publicationRelationID(100)})
	if err != nil {
		t.Fatalf("coordinate rebind: %v", err)
	}
	if len(images) != 1 || len(views) != 1 || len(work.Pages) != 2 || len(work.Groups) != 1 ||
		work.Groups[0].GroupID != coordinate.CoordinateID {
		t.Fatal("ended marker or old coordinate page remained selected")
	}
	var replacement format.AdministrativePage
	for _, page := range work.Pages {
		if page.Rows[0].Kind == contract.PublicationCoordinateSupportKind {
			replacement = page
		}
	}
	view, present := views[replacement.Ref]
	if !present || len(view.Records) != 1 || view.Records[0].RecordID != coordinate.CoordinateID ||
		len(replacement.Spans) != 1 || !replacement.Spans[0].Mandatory {
		t.Fatal("replacement page does not carry the exact mandatory coordinate")
	}
	coordinate, err = contract.InspectPublicationCoordinate(view.Records[0].Body)
	if err != nil || coordinate.OwnerState != contract.PublicationOwnerNone ||
		!coordinate.LatestUnresolvedAttemptID.IsZero() || coordinate.PossibleRemoteObject != 1 ||
		coordinate.DeletionTargetRowDigest.IsZero() || coordinate.DeletionConsumerLocator == "" {
		t.Fatal("marker exit lost possible remote object or frozen deletion inputs")
	}
}

type publicationWholePageStore struct {
	*readFailureStore
	descriptor contract.Descriptor
	writes     int
}

func (s *publicationWholePageStore) Descriptor() contract.Descriptor { return s.descriptor }

func (s *publicationWholePageStore) Create(context.Context, string, []byte) contract.WriteResult {
	s.writes++
	return contract.WriteResult{}
}
func (s *publicationWholePageStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	s.writes++
	return contract.WriteResult{}
}
func (s *publicationWholePageStore) CompareAndSwap(context.Context, string, contract.Token, []byte) contract.WriteResult {
	s.writes++
	return contract.WriteResult{}
}

// This is a bounded reader/owner fixture, not a producer-history or capacity
// witness. Existing typed builders supply all bodies and ownership. Only the
// physical layout changes, as in the mixed-page selected-reader controls.
func publicationWholePageOwnerFixture(t *testing.T, canonical, sparse bool) (*StateSession, contract.PublicationCoordinate, contract.PublicationMarker, format.Ref, map[string][]byte) {
	t.Helper()
	var state *StateSession
	var canonicalID contract.ID
	if canonical {
		var retained contract.RetainedCanonicalRecord
		state, retained, _ = generatedCanonicalState(t, false)
		canonicalID = retained.Entry.ValueState
	} else {
		state = generatedEmptyPredecessor(t)
	}
	_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
	rows := publicationRelationRows(t, coordinate, marker)
	index := generatedFixtureFreeSupportIndex(t, state)
	state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(20), Index: index,
		Records: []contract.SupportRecordView{contract.SupportRecordView(rows[0]), contract.SupportRecordView(rows[1])}})
	generatedRefreshSupport(t, state)
	reader := state.store.(*generatedFixtureSupportStore)
	sourceViews := make(map[format.Ref]format.RequiredSupportPageView, len(state.support))
	for i, ref := range state.root.RequiredSupport {
		sourceViews[ref] = state.support[i]
	}
	bodies := make(map[string][]byte, len(reader.objects))
	for key, body := range reader.objects {
		bodies[key] = bytes.Clone(body)
	}
	type selectedRow struct {
		row     contract.SupportRecordView
		span    format.AdministrativeSpan
		summary format.AdministrativeRowSummary
	}
	var selected []selectedRow
	var keptPages []format.AdministrativePage
	for p, page := range state.adminIndex.Pages {
		var kept format.AdministrativePage
		kept.Ref, kept.ReadRequired = page.Ref, page.ReadRequired
		logical := 0
		for _, span := range page.Spans {
			for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
				row := state.support[p].Records[logical]
				take := row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.OutputConfigurationSliceSupportKind || canonical && row.Kind == contract.RetainedCanonicalSupportKind && row.RecordID == canonicalID
				if take {
					selected = append(selected, selectedRow{row, format.AdministrativeSpan{Count: 1, Mandatory: span.Mandatory, GroupIndexes: slices.Clone(span.GroupIndexes)}, page.Rows[logical]})
				} else {
					kept.Spans = append(kept.Spans, format.AdministrativeSpan{First: uint16(ordinal), Count: 1, Mandatory: span.Mandatory, GroupIndexes: slices.Clone(span.GroupIndexes)})
					if !page.ReadRequired {
						kept.Rows = append(kept.Rows, page.Rows[logical])
					}
				}
				logical++
			}
		}
		if len(kept.Spans) != 0 {
			keptPages = append(keptPages, kept)
		}
	}
	slices.SortFunc(selected, func(a, b selectedRow) int {
		rank := func(kind uint8) int {
			if kind == contract.PublicationCoordinateSupportKind {
				return 0
			}
			if kind == contract.OutputConfigurationSliceSupportKind {
				return 1
			}
			return 2
		}
		return rank(a.row.Kind) - rank(b.row.Kind)
	})
	wantSelected := 2
	if canonical {
		wantSelected++
	}
	if len(selected) != wantSelected {
		t.Fatal("whole-page typed peer set", len(selected))
	}
	physical := make([]contract.SupportRecord, 0, 6)
	mixed := format.AdministrativePage{}
	for i, item := range selected {
		if sparse {
			stale := marker
			stale.AttemptID = contract.Hash([]byte(fmt.Sprintf("unselected physical marker %d", i)))
			body, err := contract.EncodePublicationMarker(stale)
			if err != nil {
				t.Fatal(err)
			}
			physical = append(physical, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: stale.AttemptID, Body: body})
		}
		span := item.span
		span.First = uint16(len(physical))
		mixed.Spans = append(mixed.Spans, span)
		mixed.Rows = append(mixed.Rows, item.summary)
		physical = append(physical, contract.SupportRecord(item.row))
	}
	if sparse {
		stale := marker
		stale.AttemptID = contract.Hash([]byte("unselected physical trailing marker"))
		body, err := contract.EncodePublicationMarker(stale)
		if err != nil {
			t.Fatal(err)
		}
		physical = append(physical, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: stale.AttemptID, Body: body})
	}
	mixedIndex := uint16(0)
	for slices.ContainsFunc(keptPages, func(page format.AdministrativePage) bool { return page.Ref.Index == mixedIndex }) {
		mixedIndex++
	}
	body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: state.root.Domain, Object: publicationRelationID(201), Index: mixedIndex, Records: physical})
	if err != nil {
		t.Fatal(err)
	}
	mixed.Ref, err = format.Reference(contract.RequiredSupportKind, state.root.Domain, publicationRelationID(201), mixedIndex, body)
	if err != nil {
		t.Fatal(err)
	}
	keptPages = append(keptPages, mixed)
	slices.SortFunc(keptPages, func(a, b format.AdministrativePage) int { return int(a.Ref.Index) - int(b.Ref.Index) })
	state.adminIndex.Pages = keptPages
	if err := rechargeEndWorkGroups(&state.adminIndex, sourceViews); err != nil {
		t.Fatal("whole-page fixture ownership recharge", err)
	}
	key, err := format.Key(state.admission.store.Prefix, mixed.Ref)
	if err != nil {
		t.Fatal(err)
	}
	bodies[key] = body
	state.root.RequiredSupport = nil
	for _, page := range keptPages {
		state.root.RequiredSupport = append(state.root.RequiredSupport, page.Ref)
	}
	shards, err := format.EncodeAdministrativeIndexPages(state.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	state.root.AdministrativeIndex = shards[0].Ref
	state.root.AdministrativeIndexShards = nil
	put := func(ref format.Ref, body []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		key, err := format.Key(state.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		bodies[key] = body
	}
	for _, shard := range shards {
		put(shard.Ref, shard.Body, nil)
		if shard.Ref.Index != 0 {
			state.root.AdministrativeIndexShards = append(state.root.AdministrativeIndexShards, shard.Ref)
		}
	}
	for _, page := range state.pages {
		if page != nil {
			b, e := format.EncodeValueEntryPage(*page)
			put(*state.root.ValueEntryPages[page.Index], b, e)
		}
	}
	for _, page := range state.recipients {
		if page != nil {
			b, e := format.EncodeRecipientPage(*page)
			put(*state.root.Recipients[page.Index], b, e)
		}
	}
	for _, ref := range state.root.CurrentAccess.Core.AccessPageRefs {
		b, e := format.EncodeAccessPage(*state.access[ref.Index])
		put(ref, b, e)
	}
	state.recountChildren()
	store := &publicationWholePageStore{readFailureStore: &readFailureStore{}, descriptor: state.admission.store}
	store.onReadCtx = func(context.Context) (contract.ReadResult, bool) {
		body, present := bodies[store.keys[len(store.keys)-1]]
		if !present {
			return contract.ReadResult{Status: contract.ReadMissing}, true
		}
		return contract.ReadResult{Status: contract.ReadOK, Body: body}, true
	}
	image, result := scanSelectedImage(t.Context(), selectedObjectReader{domain: state.root.Domain, descriptor: state.admission.store, source: store}, state.root, false, selectedAdministrativePartial, nil)
	if result.Outcome != 0 {
		t.Fatal("whole-page selected reader", result)
	}
	state.pages, state.recipients, state.access = image.pages, image.recipients, image.access
	state.support, state.supportFacts, state.fragmentFacts = image.support, image.supportFacts, image.fragmentFacts
	state.adminIndex, state.outputConfigurationRoot = image.adminIndex, image.outputConfigurationRoot
	state.generatedWork, state.generatedSliceLocations, state.generatedSlicesRoot = nil, nil, contract.ID{}
	state.store, state.cache = store, nil
	state.admission.endWorkInvocation = publicationRelationID(196)
	store.keys, store.limits = nil, nil
	return state, coordinate, marker, mixed.Ref, bodies
}

// full_only: false
func TestPublicationEndWorkWholePageKeepsSparseBytesAndOwnedViews(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprintf("cached=%t", cached), func(t *testing.T) {
			state, coordinate, marker, oldRef, bodies := publicationWholePageOwnerFixture(t, false, true)
			store := state.store.(*publicationWholePageStore)
			key, _ := format.Key(state.admission.store.Prefix, oldRef)
			oldBody := bytes.Clone(bodies[key])
			oldIndex := clonePublicationWork(state.adminIndex)
			borrowed := make([]byte, len(oldBody))
			store.onReadCtx = func(context.Context) (contract.ReadResult, bool) {
				if store.keys[len(store.keys)-1] != key {
					t.Fatal("coordinate rewrite read unrelated optional page")
				}
				copy(borrowed, bodies[key])
				return contract.ReadResult{Status: contract.ReadOK, Body: borrowed}, true
			}
			if cached {
				state.cache = map[format.Ref][]byte{oldRef: bytes.Clone(oldBody)}
			}
			work, ended, err := state.administrativeWorkClosure(marker.AttemptID)
			if err != nil {
				t.Fatal(err)
			}
			page := work.Pages[slices.IndexFunc(work.Pages, func(p format.AdministrativePage) bool { return p.Ref == oldRef })]
			pages, indexBytes, err := state.endWorkPublicationRewriteAllowance(work, ended)
			if err != nil || pages != 0 || indexBytes != 0 {
				t.Fatal("whole-page allowance", pages, indexBytes, err)
			}
			images, views, err := state.rebindEndWorkPublication(t.Context(), &work, ended, endWorkIDs{operation: publicationRelationID(95), transition: publicationRelationID(96), snapshot: publicationRelationID(97), revision: publicationRelationID(98), receipts: publicationRelationID(99), receiptIndex: publicationRelationID(100)})
			if err != nil || len(images) != 1 || len(views) != 1 {
				t.Fatal("whole-page rewrite", err)
			}
			for i := range borrowed {
				borrowed[i] = 0xa5
			}
			if !reflect.DeepEqual(state.adminIndex, oldIndex) || !bytes.Equal(bodies[key], oldBody) || cached && !bytes.Equal(state.cache[oldRef], oldBody) {
				t.Fatal("rewrite changed predecessor")
			}
			for ref, image := range images {
				if ref.Object == oldRef.Object || ref.Index != oldRef.Index || ref.Length != oldRef.Length || format.CheckReference(ref, image.body) != nil {
					t.Fatal("whole-page replacement identity/length")
				}
				after, err := format.InspectRequiredSupportPage(image.body)
				before, beforeErr := format.InspectRequiredSupportPage(oldBody)
				if err != nil || beforeErr != nil || len(after.Records) != len(before.Records) {
					t.Fatal("whole physical image", err, beforeErr)
				}
				for i, row := range after.Records {
					want := before.Records[i]
					if row.Kind == contract.PublicationCoordinateSupportKind && row.RecordID == coordinate.CoordinateID {
						want := coordinate
						want.OwnerState = contract.PublicationOwnerNone
						want.LatestUnresolvedAttemptID = contract.ID{}
						actual, inspectErr := contract.InspectPublicationCoordinate(row.Body)
						if inspectErr != nil || !actual.Equal(want) || len(row.Body) != len(before.Records[i].Body) {
							t.Fatal("coordinate changed beyond fixed-width typed disposition", inspectErr)
						}
					} else if row.Kind != want.Kind || row.RecordID != want.RecordID || !bytes.Equal(row.Body, want.Body) {
						t.Fatal("copied raw physical peer changed", i)
					}
				}
				found := slices.IndexFunc(work.Pages, func(p format.AdministrativePage) bool { return p.Ref == ref })
				if found < 0 || !reflect.DeepEqual(work.Pages[found].Spans, page.Spans) || !reflect.DeepEqual(work.Pages[found].Rows, page.Rows) {
					t.Fatal("selected sparse spans changed")
				}
				view := views[ref]
				if len(view.Records) != len(page.Rows) {
					t.Fatal("unselected physical bytes became selected")
				}
				start := uintptr(unsafe.Pointer(&image.body[0]))
				end := start + uintptr(len(image.body))
				for _, row := range view.Records {
					address := uintptr(unsafe.Pointer(&row.Body[0]))
					if address < start || address+uintptr(len(row.Body)) > end {
						t.Fatal("selected view does not borrow NEW owned image")
					}
				}
			}
			if store.writes != 0 {
				t.Fatal("pure coordinate rewrite wrote to Store")
			}
			wantReads := 1
			if cached {
				wantReads = 0
			}
			if len(store.keys) != wantReads {
				t.Fatal("mandatory rewrite GET count", len(store.keys), wantReads)
			}
		})
	}
}

// full_only: false
func TestPublicationEndWorkWholePagePreservesCanonicalAccessAndOutputFacts(t *testing.T) {
	state, _, marker, oldRef, _ := publicationWholePageOwnerFixture(t, true, true)
	beforeAccess := state.accessRecords()
	for i := range beforeAccess {
		beforeAccess[i].Wraps = slices.Clone(beforeAccess[i].Wraps)
		for j := range beforeAccess[i].Wraps {
			beforeAccess[i].Wraps[j].RSACiphertext = bytes.Clone(beforeAccess[i].Wraps[j].RSACiphertext)
		}
	}
	beforeEntries := make(map[uint16]contract.ValueEntry, len(state.root.Names))
	for _, named := range state.root.Names {
		entry := *state.valueEntry(named.Slot)
		entry.ValueBytes = bytes.Clone(entry.ValueBytes)
		entry.Recipients = slices.Clone(entry.Recipients)
		beforeEntries[named.Slot] = entry
	}
	beforeIndex := clonePublicationWork(state.adminIndex)
	ids := endWorkIDs{operation: publicationRelationID(180), transition: publicationRelationID(181), snapshot: publicationRelationID(182), revision: publicationRelationID(183), receipts: publicationRelationID(184), receiptIndex: publicationRelationID(185)}
	candidate, next, err := state.deriveEndWorkCandidate(t.Context(), marker.AttemptID, ids)
	if err != nil || candidate == nil || next == nil {
		t.Fatal("EndWork with copied canonical/output peer", err)
	}
	if !reflect.DeepEqual(next.accessRecords(), beforeAccess) || !reflect.DeepEqual(next.root.Names, state.root.Names) || next.root.ValueEntryCount != state.root.ValueEntryCount || !reflect.DeepEqual(state.adminIndex, beforeIndex) {
		t.Fatal("copied canonical changed readers/wraps/current/predecessor")
	}
	for slot, want := range beforeEntries {
		actual := next.valueEntry(slot)
		if actual == nil || !reflect.DeepEqual(*actual, want) {
			t.Fatal("copied peer changed exact current value", slot)
		}
	}
	position := slices.IndexFunc(next.root.RequiredSupport, func(ref format.Ref) bool { return ref.Index == oldRef.Index })
	if position < 0 || next.root.RequiredSupport[position] == oldRef || next.root.RequiredSupport[position].Length != oldRef.Length {
		t.Fatal("canonical mixed page was not replaced1:1")
	}
	if !slices.Equal(next.supportFacts[position].ordinals, []uint16{1, 3, 5}) {
		t.Fatal("EndWork completion compacted sparse facts", next.supportFacts[position].ordinals)
	}
	facts, err := next.selectedOutputFactsByRecord()
	if err != nil || len(facts) != int(next.root.OutputConfiguration.SliceCount) {
		t.Fatal("complete output has no exact facts", err)
	}
	for _, fact := range facts {
		if fact.ref != next.root.RequiredSupport[position] || fact.physical != 3 {
			t.Fatal("copied output fact lost physical ordinal")
		}
	}
	rootBody, err := format.EncodeRoot(next.root)
	if err != nil || next.outputConfigurationRoot != contract.Hash(rootBody) || next.publicationProof != nil {
		t.Fatal("EndWork output commitment/proof", err)
	}
	if state.store.(*publicationWholePageStore).writes != 0 {
		t.Fatal("pure EndWork derivation wrote to Store")
	}
	if next.root.WarningBits&WarningPossibleStoreGarbage == 0 {
		t.Fatal("replaced whole page did not record possible Store garbage")
	}
}

// full_only: false
func TestPublicationEndWorkWholePageRefusesReadAndShapeFailures(t *testing.T) {
	for _, condition := range []string{"missing", "corrupt", "cached_corrupt", "cancel_before", "cancel_after"} {
		t.Run(condition, func(t *testing.T) {
			state, _, marker, ref, bodies := publicationWholePageOwnerFixture(t, false, true)
			store := state.store.(*publicationWholePageStore)
			key, _ := format.Key(state.admission.store.Prefix, ref)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if condition == "cancel_before" {
				cancel()
			}
			if condition == "cached_corrupt" {
				cached := bytes.Clone(bodies[key])
				cached[len(cached)-1] ^= 1
				state.cache = map[format.Ref][]byte{ref: cached}
			}
			store.onReadCtx = func(context.Context) (contract.ReadResult, bool) {
				if store.keys[len(store.keys)-1] != key {
					t.Fatal("failed rewrite read optional peer")
				}
				if condition == "missing" {
					return contract.ReadResult{Status: contract.ReadMissing}, true
				}
				body := bytes.Clone(bodies[key])
				if condition == "corrupt" {
					body[len(body)-1] ^= 1
				}
				if condition == "cancel_after" {
					cancel()
				}
				return contract.ReadResult{Status: contract.ReadOK, Body: body}, true
			}
			work, ended, err := state.administrativeWorkClosure(marker.AttemptID)
			if err != nil {
				t.Fatal(err)
			}
			before := clonePublicationWork(work)
			images, views, err := state.rebindEndWorkPublication(ctx, &work, ended, endWorkIDs{operation: publicationRelationID(95), transition: publicationRelationID(96), snapshot: publicationRelationID(97), revision: publicationRelationID(98), receipts: publicationRelationID(99), receiptIndex: publicationRelationID(100)})
			got, typed := selectedReadResult(err)
			want := Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable}
			if condition == "missing" {
				want.Reason = MissingSelectedObject
			}
			if condition == "corrupt" || condition == "cached_corrupt" {
				want = Result{Outcome: IntegrityFailure, Reason: InvalidReference}
			}
			if !typed || got != want || len(images) != 0 || len(views) != 0 || !reflect.DeepEqual(work, before) {
				t.Fatal("rewrite read/cancel classification or staged state", got, typed, err)
			}
			if store.writes != 0 {
				t.Fatal("refused coordinate rewrite wrote to Store")
			}
			if (condition == "cancel_before" || condition == "cached_corrupt") && len(store.keys) != 0 || condition != "cancel_before" && condition != "cached_corrupt" && len(store.keys) != 1 {
				t.Fatal("failed rewrite GET count", len(store.keys))
			}
		})
	}
	for _, damage := range []string{"optional_coordinate", "wrong_summary", "wrong_owner"} {
		t.Run(damage, func(t *testing.T) {
			state, _, marker, ref, _ := publicationWholePageOwnerFixture(t, false, true)
			work, ended, err := state.administrativeWorkClosure(marker.AttemptID)
			if err != nil {
				t.Fatal(err)
			}
			p := slices.IndexFunc(work.Pages, func(p format.AdministrativePage) bool { return p.Ref == ref })
			switch damage {
			case "optional_coordinate":
				work.Pages[p].Spans[0].Mandatory = false
			case "wrong_summary":
				work.Pages[p].Rows[0].BodyLength++
			case "wrong_owner":
				g := work.Pages[p].Spans[0].GroupIndexes[0]
				work.Groups[g].OwnerID = contract.Hash([]byte("wrong coordinate owner"))
			}
			if _, _, err := state.endWorkPublicationRewriteAllowance(work, ended); !errors.Is(err, contract.ErrRecord) {
				t.Fatal("allowance accepted invalid coordinate shape", err)
			}
			if images, views, err := state.rebindEndWorkPublication(t.Context(), &work, ended, endWorkIDs{operation: publicationRelationID(95), transition: publicationRelationID(96), snapshot: publicationRelationID(97), revision: publicationRelationID(98), receipts: publicationRelationID(99), receiptIndex: publicationRelationID(100)}); !errors.Is(err, contract.ErrRecord) || len(images) != 0 || len(views) != 0 {
				t.Fatal("writer accepted same invalid shape", err)
			}
			if len(state.store.(*publicationWholePageStore).keys) != 0 {
				t.Fatal("shape refusal read a physical page")
			}
		})
	}
}

// full_only: false
func TestPublicationEndWorkBodyBackedCompletionChecksFreshOrdinals(t *testing.T) {
	for _, sparse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sparse=%t", sparse), func(t *testing.T) {
			state, _, marker, _, bodies := publicationWholePageOwnerFixture(t, false, sparse)
			// This is the explicit legacy complete-body construction mode. Recover
			// exact bodies before clearing facts; do not give it a false root proof.
			for i, ref := range state.root.RequiredSupport {
				key, _ := format.Key(state.admission.store.Prefix, ref)
				page, err := format.InspectRequiredSupportPage(bodies[key])
				if err != nil {
					t.Fatal(err)
				}
				var selected []contract.SupportRecordView
				for _, span := range state.adminIndex.Pages[i].Spans {
					for ordinal := span.First; uint32(ordinal) < uint32(span.First)+uint32(span.Count); ordinal++ {
						selected = append(selected, page.Records[ordinal])
					}
				}
				state.support[i].Records = selected
			}
			state.supportFacts, state.fragmentFacts = nil, nil
			state.outputConfigurationRoot = contract.ID{}
			candidate, next, err := state.deriveEndWorkCandidate(t.Context(), marker.AttemptID, endWorkIDs{operation: publicationRelationID(180), transition: publicationRelationID(181), snapshot: publicationRelationID(182), revision: publicationRelationID(183), receipts: publicationRelationID(184), receiptIndex: publicationRelationID(185)})
			if state.store.(*publicationWholePageStore).writes != 0 {
				t.Fatal("nil-mode derivation wrote to Store")
			}
			if sparse {
				if !errors.Is(err, contract.ErrRecord) || !strings.Contains(err.Error(), "sparse unbound support") || candidate != nil || next != nil {
					t.Fatal("nil-facts fresh sparse copy did not stop at its owning guard", err)
				}
				return
			}
			if err != nil || candidate == nil || next == nil {
				t.Fatal("legacy complete compact path refused", err)
			}
			facts, err := next.selectedOutputFactsByRecord()
			if err != nil || len(facts) != 1 {
				t.Fatal("legacy completion stamped a root without output facts", err)
			}
		})
	}
}
