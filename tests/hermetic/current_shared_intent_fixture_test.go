package core

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Reproduce the release-only obsolete Intent relation on a separately produced
// current state. The historical Store is never converted or used as a template.
func currentSharedIntentRetirementCapture(t *testing.T) (sharedIntentHistoricalCapture, *StateSession, fixtureEnvironment) {
	t.Helper()
	f := actualSharedIntentRetirementPredecessor(t)
	selected := endSharedIntentWork(t, f.selected, f.dutyA, f.env.Trust)
	positive, result := Open(t.Context(), OpenContext{admission: &selected.admission}, f.env.Store)
	if positive == nil || result.Outcome != ObservedCurrent {
		t.Fatal("current shared Intent complete positive baseline", result)
	}
	selected = positive
	assertSharedIntentRetirement(t, f, selected, false)
	if _, changed, err := selected.administrativeDispositionPages(); err != nil || changed {
		t.Fatal("current shared Intent baseline changed ownership", err)
	}
	if proved, err := selected.publicationExitNeedsNoIntentCompaction(t.Context()); err != nil || !proved {
		t.Fatal("current shared Intent baseline lost the safe shortcut", err)
	}
	before := *f.selected
	before.support = slices.Clone(before.support)
	for i := range before.support {
		before.support[i].Records = slices.Clone(before.support[i].Records)
	}
	generatedMaterializeFixtureSupport(t, &before)
	bad := *selected
	bad.support = slices.Clone(bad.support)
	for i := range bad.support {
		bad.support[i].Records = slices.Clone(bad.support[i].Records)
	}
	generatedMaterializeFixtureSupport(t, &bad)
	rows := bad.supportRecords()
	locations, err := bad.resolveSelectedGeneratedSlices()
	if err != nil || slices.ContainsFunc(locations, func(row contract.GeneratorSliceLocation) bool {
		return row.ContentKind == contract.GeneratorContentIntent && row.ContentID == f.a.Generated.IntentDigest
	}) {
		t.Fatal("current positive baseline still has obsolete A Intent", err)
	}
	locations = slices.Clone(locations)
	originalLocations, err := before.resolveSelectedGeneratedSlices()
	if err != nil {
		t.Fatal(err)
	}
	// The old release-only A carrier shared its physical blob with a current
	// Intent. Keep that actual co-residency too: it is the no-drop predecessor
	// condition which made the historical publication shortcut unsafe.
	replacedBlobs := make(map[contract.ID]bool)
	for _, original := range originalLocations {
		if original.ContentKind != contract.GeneratorContentIntent || original.BlobID != f.locationA.BlobID {
			continue
		}
		for i := range locations {
			if locations[i].ContentKind == original.ContentKind && locations[i].ContentID == original.ContentID {
				if locations[i].Logical() != original.Logical() {
					t.Fatal("current fixture changed original Intent bytes")
				}
				replacedBlobs[locations[i].BlobID] = true
				locations[i] = original
			}
		}
	}
	locations = append(locations, f.locationA)
	rows = slices.DeleteFunc(rows, func(row contract.SupportRecord) bool {
		if row.Kind != contract.GeneratedFragmentSupportKind {
			return false
		}
		fragment, err := contract.InspectGeneratedFragment(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		return replacedBlobs[fragment.BlobID] && !slices.ContainsFunc(locations, func(location contract.GeneratorSliceLocation) bool {
			return location.BlobID == fragment.BlobID
		})
	})
	slices.SortFunc(locations, func(a, b contract.GeneratorSliceLocation) int {
		if a.ContentKind != b.ContentKind {
			return int(a.ContentKind) - int(b.ContentKind)
		}
		return bytes.Compare(a.ContentID[:], b.ContentID[:])
	})
	var encoded [][]byte
	for _, location := range locations {
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, body)
	}
	descriptor, carriers, err := generatedCarrierRows(bad.root.Domain, contract.GeneratorSnapshotOwner, bad.root.Snapshot, contract.GeneratorVectorSlices, encoded)
	if err != nil {
		t.Fatal(err)
	}
	rows = slices.DeleteFunc(rows, func(row contract.SupportRecord) bool {
		if row.Kind != contract.GeneratorVectorSupportKind {
			return false
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		return carrier.OwnerKind == contract.GeneratorSnapshotOwner && carrier.VectorKind == contract.GeneratorVectorSlices
	})
	rows = append(rows, carriers...)
	fragments := 0
	for _, row := range before.supportRecords() {
		if row.Kind != contract.GeneratedFragmentSupportKind {
			continue
		}
		fragment, err := contract.InspectGeneratedFragment(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		if fragment.BlobID == f.locationA.BlobID {
			fragments++
			if !slices.ContainsFunc(rows, func(existing contract.SupportRecord) bool {
				return existing.Kind == row.Kind && existing.RecordID == row.RecordID
			}) {
				rows = append(rows, row)
			}
		}
	}
	if fragments == 0 {
		t.Fatal("actual current predecessor omitted original A fragment backing")
	}
	bad.root.Generated.Slices = descriptor
	packCurrentSharedIntentLegacyOwnership(t, f, &before, selected, &bad, rows, locations)
	store := recommitSharedIntentRetirement(t, f, selected, &bad)
	// A release cannot claim an obsolete logical Intent for complete reading.
	// The exact legacy regression belongs to the authenticated administrative
	// path, which must still support restoration and disposal of that work.
	if complete, result := Open(t.Context(), OpenContext{admission: &selected.admission}, store); complete != nil || result != failure(IntegrityFailure, InvalidRelation) {
		t.Fatal("controlled shared Intent complete admission boundary", result)
	}
	selected, result = openAdministrative(t.Context(), OpenContext{admission: &selected.admission}, store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("controlled shared Intent authenticated administrative admission", result)
	}
	assertSharedIntentRetirement(t, f, selected, true)
	// This administrative regression needs exact passive receipts and output
	// bindings. It cannot issue the complete generated-work facts refused above.
	input := processFixture{Objects: store.objects, Generation: store.generation, GeneratedOutputBindings: f.output}
	windows, err := selected.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		t.Fatal("controlled shared Intent administrative receipt facts", err)
	}
	for _, receipt := range append(windows.Successes, windows.Failures...) {
		body, err := contract.EncodeCompactMutationReceipt(receipt)
		if err != nil {
			t.Fatal(err)
		}
		input.Receipts = append(input.Receipts, receiptExpectation{OperationID: receipt.OperationID, Body: body})
	}
	capture := sharedIntentHistoricalCapture{Checkpoint: input, Current: f.current, A: f.a, B: f.b,
		DutyA: f.dutyA, DutyB: f.dutyB, Release: f.release, Marker: f.marker,
		LocationA: f.locationA, LocationB: f.locationB, Evidence: f.evidence, BeforeA: f.groups}
	env := f.env
	env.Store = store
	return capture, selected, env
}

// The current index writer correctly removes release ownership of Intents.
// This controlled regression instead preserves real row owners, then gives
// only the obsolete A logical carrier the old release owner. All framing,
// current mandatory classification and group commitments use existing owners.
func packCurrentSharedIntentLegacyOwnership(t *testing.T, f sharedIntentRetirementFixture, before, selected, bad *StateSession,
	rows []contract.SupportRecord, locations []contract.GeneratorSliceLocation) {
	t.Helper()
	rowOwners := make(map[generatedRecordKey][]contract.ID)
	sliceOwners := make(map[generatedContentKey][]contract.ID)
	for _, source := range []*StateSession{before, selected} {
		if len(source.adminIndex.Pages) != len(source.support) {
			t.Fatal("current shared Intent ownership source page count")
		}
		for i, page := range source.adminIndex.Pages {
			logical := 0
			for _, span := range page.Spans {
				var owners []contract.ID
				for _, index := range span.GroupIndexes {
					if int(index) >= len(source.adminIndex.Groups) {
						t.Fatal("current shared Intent ownership source group")
					}
					owners = append(owners, source.adminIndex.Groups[index].GroupID)
				}
				for range span.Count {
					if logical >= len(source.support[i].Records) {
						t.Fatal("current shared Intent ownership source span")
					}
					row := contract.SupportRecord(source.support[i].Records[logical])
					logical++
					rowOwners[generatedRecordKey{row.Kind, row.RecordID}] = slices.Clone(owners)
					if !page.ReadRequired {
						continue
					}
					carrier, match, err := snapshotSliceRecord(row, source.root.Domain, source.adminIndex.SliceSnapshot)
					if err != nil || !match {
						t.Fatal("current shared Intent ownership source Slice", err)
					}
					location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
					if err != nil {
						t.Fatal(err)
					}
					sliceOwners[generatedContentKey{location.ContentKind, location.ContentID}] = slices.Clone(owners)
				}
			}
			if logical != len(source.support[i].Records) {
				t.Fatal("current shared Intent ownership source coverage")
			}
		}
	}
	sliceOwners[generatedContentKey{contract.GeneratorContentIntent, f.a.Generated.IntentDigest}] = []contract.ID{f.release}
	bundles := generatedFixtureBundles(t, selected)
	groups, err := generatedReservationGroupsForState(bad, rows, locations, bundles)
	if err != nil {
		t.Fatal("current shared Intent legacy support groups", err)
	}
	packed, err := format.PackRequiredSupportRows(bad.root.Domain, groups, 1)
	if err != nil {
		t.Fatal("current shared Intent legacy support packing", err)
	}
	mandatory, err := newAdministrativeMandatorySupport(bad, locations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mandatory.selectedPublication(bad.root.Domain, rows, selected.adminIndex.PublicationOrder); err != nil {
		t.Fatal("current shared Intent legacy publication", err)
	}
	index := selected.adminIndex
	index.Groups = slices.Clone(index.Groups)
	index.Pages = nil
	index.SliceSnapshot = bad.root.Snapshot
	groupIndexes := make(map[contract.ID]uint16, len(index.Groups))
	for i, group := range index.Groups {
		groupIndexes[group.GroupID] = uint16(i)
	}
	if _, ok := groupIndexes[f.release]; !ok {
		t.Fatal("current shared Intent legacy release owner absent")
	}
	bad.support, bad.root.RequiredSupport = nil, nil
	bad.root.RequiredSupportRecordCount = 0
	var pages []format.RequiredSupportPage
	views := make(map[format.Ref]format.RequiredSupportPageView)
	for i, records := range packed {
		page := format.RequiredSupportPage{Domain: bad.root.Domain,
			Object: contract.Hash([]byte(fmt.Sprintf("current shared Intent legacy support/%x/%d", bad.root.Snapshot, i))),
			Index:  uint16(i), Records: records}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		indexed := format.AdministrativePage{Ref: ref}
		for ordinal, row := range records {
			owners, found := rowOwners[generatedRecordKey{row.Kind, row.RecordID}]
			if row.Kind == contract.GeneratorVectorSupportKind {
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if carrier.OwnerKind == contract.GeneratorSnapshotOwner && carrier.VectorKind == contract.GeneratorVectorSlices {
					location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
					if err != nil {
						t.Fatal(err)
					}
					owners, found = sliceOwners[generatedContentKey{location.ContentKind, location.ContentID}]
					indexed.ReadRequired = true
				}
			}
			if !found {
				t.Fatal("current shared Intent legacy row lacks genuine ownership")
			}
			keep, err := mandatory.row(row)
			if err != nil {
				t.Fatal(err)
			}
			span := format.AdministrativeSpan{First: uint16(ordinal), Count: 1, Mandatory: keep}
			for _, owner := range owners {
				if position, present := groupIndexes[owner]; present {
					span.GroupIndexes = append(span.GroupIndexes, position)
				}
			}
			slices.Sort(span.GroupIndexes)
			span.GroupIndexes = slices.Compact(span.GroupIndexes)
			if !span.Mandatory && len(span.GroupIndexes) == 0 {
				t.Fatal("current shared Intent legacy row has no surviving owner")
			}
			indexed.Spans = append(indexed.Spans, span)
		}
		if !indexed.ReadRequired {
			for _, row := range records {
				summary, err := format.AdministrativeSummary(row)
				if err != nil {
					t.Fatal(err)
				}
				indexed.Rows = append(indexed.Rows, summary)
			}
		}
		pages = append(pages, page)
		bad.support = append(bad.support, view)
		bad.root.RequiredSupport = append(bad.root.RequiredSupport, ref)
		bad.root.RequiredSupportRecordCount += uint32(len(records))
		index.Pages = append(index.Pages, indexed)
		views[ref] = view
	}
	bad.root.Generated.Fragments, err = generatedFragmentDirectory(pages)
	if err != nil {
		t.Fatal(err)
	}
	if err := rechargeEndWorkGroups(&index, views); err != nil {
		t.Fatal("current shared Intent legacy group charges", err)
	}
	evidence, err := administrativeSelectedEvidence(index, bad.support)
	if err != nil {
		t.Fatal("current shared Intent legacy evidence", err)
	}
	consumers, err := selectedAdministrativeConsumers(pages, nil, bundles)
	if err != nil {
		t.Fatal("current shared Intent legacy consumers", err)
	}
	deletes, creates, err := administrativeExposure(index, bad.support, consumers)
	if err != nil {
		t.Fatal("current shared Intent legacy exposure", err)
	}
	for i := range index.Groups {
		index.Groups[i].SelectedEvidenceSummary = evidence[i]
		index.Groups[i].DestructiveEffect, index.Groups[i].UncertainCreateProof = deletes[i], creates[i]
	}
	shards, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil || len(shards) == 0 {
		t.Fatal("current shared Intent legacy index encoding", err)
	}
	bad.adminIndex, bad.root.AdministrativeIndex = index, shards[0].Ref
	bad.root.AdministrativeIndexShards = nil
	for _, shard := range shards[1:] {
		bad.root.AdministrativeIndexShards = append(bad.root.AdministrativeIndexShards, shard.Ref)
	}
	bad.recountChildren()
	bad.clearSelectedSupportFacts()
	bad.generatedWork, bad.selectedReceiptRoot = nil, format.Ref{}
}

// Retain one current owner for the EndWork receipt and signature construction.
// All bytes use the existing public writers; only the controlled support image
// above differs from the actual modern successor.
func recommitSharedIntentRetirement(t *testing.T, f sharedIntentRetirementFixture, selected, bad *StateSession) *memoryStore {
	t.Helper()
	store := cloneCheckpointStore(requireAdmittedMemoryStore(t, f.env.Store))
	if selected.head.EndWork == nil {
		t.Fatal("current shared Intent baseline lacks actual EndWork authority")
	}
	q := *selected.head.EndWork
	q.AfterChildCount, q.AfterChildBytes = uint16(bad.root.ChildCount), bad.root.ChildEncodedBytes
	var err error
	q.RequestCoreDigest, err = contract.EndWorkRequestCoreDigest(q)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.selected.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		t.Fatal(err)
	}
	after, err := selected.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		t.Fatal(err)
	}
	after.Successes, after.Failures = slices.Clone(after.Successes), slices.Clone(after.Failures)
	index := slices.IndexFunc(after.Successes, func(row contract.CompactMutationReceipt) bool { return row.OperationID == q.OperationID })
	if index < 0 {
		t.Fatal("current shared Intent baseline omitted EndWork receipt")
	}
	receipt := after.Successes[index]
	receipt.RequestIdentityDigest, receipt.AdministrativeDisposition = q.RequestCoreDigest, q.RequestCoreDigest
	receipt.AdministrativePageDelta = int16(q.AfterChildCount) - int16(q.BeforeChildCount)
	receipt.AdministrativeByteDelta = int64(q.AfterChildBytes) - int64(q.BeforeChildBytes)
	projection := contract.CompactMutationReceiptPlan(receipt)
	projection.RequestIdentityDigest, projection.CompleteResult = contract.ID{}, contract.GeneratorDescriptor{}
	empty := contract.EmptyMutationResultDescriptors()
	receipt.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: projection,
		RequestCoreDigest: q.RequestCoreDigest, ChangedAccess: empty[0], Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
	if err != nil {
		t.Fatal(err)
	}
	after.Successes[index] = receipt
	q.ReceiptDeltaDigest, err = contract.MutationReceiptDeltaDigest(contract.MutationReceiptDelta{DomainID: bad.root.Domain,
		OperationKind: contract.OperationEndSelectedWork, AddedCount: 1, Before: before, After: after})
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeCompactMutationReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	rows := bad.supportRecords()
	for i := range rows {
		if rows[i].Kind == contract.MutationReceiptSupportKind && rows[i].RecordID == q.OperationID {
			rows[i].Body = body
		}
	}
	prior := *bad
	packCurrentSharedIntentLegacyOwnership(t, f, &prior, selected, bad, rows, generatedFixtureSliceLocations(t, rows))
	if uint16(bad.root.ChildCount) != q.AfterChildCount || bad.root.ChildEncodedBytes != q.AfterChildBytes {
		t.Fatal("fixed-size receipt replacement changed the controlled capacity")
	}
	for _, page := range bad.support {
		records := make([]contract.SupportRecord, len(page.Records))
		for i, row := range page.Records {
			records[i] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: records})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		store.put(mustKey(t, store.desc.Prefix, ref), body)
	}
	shards, err := format.EncodeAdministrativeIndexPages(bad.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range shards {
		store.put(mustKey(t, store.desc.Prefix, shard.Ref), shard.Body)
	}
	root, err := format.EncodeRoot(bad.root)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RootKind, bad.root.Domain, bad.root.Snapshot, 0, root)
	if err != nil {
		t.Fatal(err)
	}
	store.put(mustKey(t, store.desc.Prefix, ref), root)
	head := selected.head
	head.EndWork, head.Core.Root = &q, ref
	core, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := format.EncodeConditionalPlan(conditional(head.Core, core))
	if err != nil {
		t.Fatal(err)
	}
	q.HeadCoreDigest, q.HeadCoreLength, q.ConditionalPlanDigest = contract.Hash(core), uint32(len(core)), contract.Hash(condition)
	request, err := contract.NewEndWorkRequest(q)
	head.AuthorizationSignature = currentBasisSign(t, f.env.Trust, request, err)
	if !bad.verifyHeadProofs(head, currentControlOf(selected)) {
		t.Fatal("controlled current shared Intent signature failed")
	}
	body, err = format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	store.put(store.desc.HeadKey, body)
	return store
}
