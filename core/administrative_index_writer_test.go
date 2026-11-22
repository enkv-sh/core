package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func administrativeTestSpanAt(page format.AdministrativePage, ordinal int) (format.AdministrativeSpan, bool) {
	for _, span := range page.Spans {
		if ordinal >= int(span.First) && ordinal < int(span.First)+int(span.Count) {
			return span, true
		}
	}
	return format.AdministrativeSpan{}, false
}

// full_only: false
func TestAdministrativeIndexAssignsDetachedAttemptToExactDuty(t *testing.T) {
	selected := generatedReservationState(t)
	var rows []contract.SupportRecord
	var duty contract.ID
	for _, row := range selected.supportRecords() {
		if row.Kind == contract.GeneratedAttemptSupportKind || row.Kind == contract.GeneratedDutySupportKind {
			rows = append(rows, row)
			if row.Kind == contract.GeneratedDutySupportKind {
				duty = row.RecordID
			}
		}
	}
	if len(rows) != 2 || duty.IsZero() {
		t.Fatal("selected detached fixture has no attempt and duty")
	}
	page := format.RequiredSupportPage{Domain: selected.root.Domain, Object: generatedVectorID(201), Records: rows}
	body, err := format.EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	root := format.Root{Domain: page.Domain, Snapshot: generatedVectorID(202), RequiredSupport: []format.Ref{ref}}
	seed := &StateSession{admission: openAdmission{domain: page.Domain}, root: format.Root{Domain: page.Domain}}
	index, err := seed.buildAdministrativeIndex(context.Background(), root, []format.RequiredSupportPage{page}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Groups) != 1 || index.Groups[0].GroupID != duty || len(index.Pages) != 1 || len(index.Pages[0].Spans) != 1 || index.Pages[0].Spans[0].Count != 2 {
		t.Fatal("detached duty envelope missing")
	}
	attempt := index.Pages[0].Spans[0]
	if attempt.Mandatory || len(attempt.GroupIndexes) != 1 || index.Groups[attempt.GroupIndexes[0]].GroupID != duty {
		t.Fatal("detached attempt became mandatory or lost its exact duty", attempt)
	}
	wantBytes := uint64(0)
	for _, row := range rows {
		wantBytes += uint64(contract.SupportRecordOverhead + len(row.Body))
	}
	if index.Groups[0].ChargedBytes != wantBytes || index.Groups[0].Disposable.Count != 2 {
		t.Fatal("coalesced owner lost per-row charge or commitment", index.Groups[0])
	}
	seed.adminIndex, seed.root.RequiredSupport = index, root.RequiredSupport
	seed.root.AdministrativeIndex.Object = index.Object
	view, err := format.InspectRequiredSupportPage(body)
	if err != nil {
		t.Fatal(err)
	}
	seed.support = []format.RequiredSupportPageView{view}
	owned, err := seed.priorAdministrativeRows()
	if err != nil || len(owned) != 2 {
		t.Fatal("coalesced rows did not round trip through reader", err)
	}
	for _, row := range rows {
		got := seed.priorAdministrativeOwnership(owned[generatedRecordKey{row.Kind, row.RecordID}])
		if got.mandatory || len(got.groups) != 1 || got.groups[0] != duty {
			t.Fatal("coalesced row lost exact logical owner", row.Kind, got)
		}
	}
	remaining, err := seed.administrativeWorkDisposition(duty)
	if err != nil || len(remaining.Groups) != 0 || len(remaining.Pages) != 0 {
		t.Fatal("coalesced group was not disposable", err)
	}
}

// full_only: false
func TestAdministrativeIndexRetainsHistoricalAttemptMaterialsForCurrentDuty(t *testing.T) {
	s, attempts, duty := generatedRepeatedRetirementState(t, 1)
	group := -1
	for i, row := range s.adminIndex.Groups {
		if row.GroupID == duty.DutyID {
			group = i
		}
	}
	if group < 0 {
		t.Fatal("current duty envelope missing")
	}
	for _, attempt := range attempts {
		for _, wanted := range []struct {
			kind uint8
			id   contract.ID
		}{{contract.GeneratedAttemptSupportKind, attempt.record.AttemptID},
			{contract.OperationMaterialSupportKind, attempt.material.Core.OperationMaterialID}} {
			found := false
			for pageIndex, page := range s.support {
				for ordinal, row := range page.Records {
					if row.Kind != wanted.kind || row.RecordID != wanted.id {
						continue
					}
					span, ok := administrativeTestSpanAt(s.adminIndex.Pages[pageIndex], ordinal)
					if ok && !span.Mandatory && slices.Contains(span.GroupIndexes, uint16(group)) {
						found = true
					}
				}
			}
			if !found {
				t.Fatal("current duty lost a historical attempt or material", wanted.kind, wanted.id)
			}
		}
	}
}

// full_only: false
func TestAdministrativeIndexRejectsUnownedOldValue(t *testing.T) {
	entry, retained := generatedCanonicalSource(t)
	domain := generatedVectorID(245)
	page := format.RequiredSupportPage{Domain: domain, Object: generatedVectorID(246),
		Records: []contract.SupportRecord{{Kind: contract.RetainedCanonicalSupportKind, RecordID: retained.Entry.ValueState, Body: entry.Payload}}}
	body, err := format.EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, domain, page.Object, page.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	root := format.Root{Domain: domain, Snapshot: generatedVectorID(247), RequiredSupport: []format.Ref{ref}}
	seed := &StateSession{admission: openAdmission{domain: domain}, root: format.Root{Domain: domain}}
	if _, err := seed.buildAdministrativeIndex(context.Background(), root, []format.RequiredSupportPage{page}, nil, nil, nil); err == nil {
		t.Fatal("unowned noncurrent old value became mandatory support")
	}
}

// full_only: false
func TestAdministrativeReleaseRelatedOnlyToSelectedOriginalParent(t *testing.T) {
	selected, attempt, release := generatedInboxReleaseState(t, 0, contract.GeneratedReleaseUnknown)
	var rows []contract.SupportRecord
	for _, row := range selected.supportRecords() {
		if row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == attempt.record.AttemptID ||
			row.Kind == contract.PendingInboxReleaseSupportKind && row.RecordID == release.InboxID {
			rows = append(rows, row)
		}
	}
	if len(rows) != 2 {
		t.Fatal("release-only fixture lost selected mapping")
	}
	build := func(parent *contract.GeneratedParentPlan) format.AdministrativeIndex {
		t.Helper()
		selectedRows := slices.Clone(rows)
		if parent != nil {
			body, err := contract.EncodeGeneratedParentPlan(*parent)
			if err != nil {
				t.Fatal("parent plan:", err)
			}
			selectedRows = append(selectedRows, contract.SupportRecord{Kind: contract.GeneratedParentSupportKind, RecordID: parent.OperationID, Body: body})
		}
		slices.SortFunc(selectedRows, func(a, b contract.SupportRecord) int {
			if a.Kind != b.Kind {
				return int(a.Kind) - int(b.Kind)
			}
			return bytes.Compare(a.RecordID[:], b.RecordID[:])
		})
		page := format.RequiredSupportPage{Domain: selected.root.Domain, Object: generatedVectorID(205), Records: selectedRows}
		var body []byte
		var err error
		if parent == nil {
			body, err = format.EncodeRequiredSupportPage(page)
		} else {
			body, err = format.EncodeRequiredSupportParentPlan(page, *parent)
		}
		if err != nil {
			t.Fatal("support page:", err)
		}
		ref := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: page.Domain,
			Object: page.Object, Index: page.Index, Digest: contract.Hash(body), Length: uint32(len(body))}
		if parent == nil {
			ref, err = format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
			if err != nil {
				t.Fatal("support ref:", err)
			}
		}
		root := format.Root{Domain: page.Domain, Snapshot: generatedVectorID(206), RequiredSupport: []format.Ref{ref}}
		if parent != nil {
			root.Generated.ActiveOwner = parent.OperationID
		}
		seed := &StateSession{admission: openAdmission{domain: page.Domain}, root: format.Root{Domain: page.Domain}}
		index, err := seed.buildAdministrativeIndex(context.Background(), root, []format.RequiredSupportPage{page}, parent, nil, nil)
		if err != nil {
			t.Fatal("administrative index:", err)
		}
		return index
	}
	independent := build(nil)
	if len(independent.Groups) != 1 || independent.Groups[0].GroupID != release.InboxID || len(independent.Groups[0].RelatedGroupIndexes) != 0 {
		t.Fatal("release-only mapping acquired a parent dependency")
	}
	_, _, parentRecord := generatedEffectPlanFixture(t)
	parentRecord.DomainID = attempt.record.DomainID
	parentRecord.OperationID = attempt.record.OperationID
	parentRecord.RequestIdentityDigest = contract.ID{}
	plan := contract.GeneratedParentPlan(parentRecord)
	withParent := build(&plan)
	if len(withParent.Groups) != 2 {
		t.Fatal("selected parent or release envelope missing")
	}
	var releaseGroup *format.AdministrativeGroup
	for i := range withParent.Groups {
		if withParent.Groups[i].GroupID == release.InboxID {
			releaseGroup = &withParent.Groups[i]
		}
	}
	if releaseGroup == nil || len(releaseGroup.RelatedGroupIndexes) != 1 ||
		withParent.Groups[releaseGroup.RelatedGroupIndexes[0]].GroupID != plan.OperationID {
		t.Fatal("selected original parent did not own derived release")
	}
}

// full_only: false
func TestAdministrativePagePlanBindsProvisionalParentExactly(t *testing.T) {
	_, _, parentRecord := generatedEffectPlanFixture(t)
	parentRecord.RequestIdentityDigest = contract.ID{}
	plan := contract.GeneratedParentPlan(parentRecord)
	body, err := contract.EncodeGeneratedParentPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	page := format.RequiredSupportPage{Domain: plan.DomainID, Object: generatedVectorID(207),
		Records: []contract.SupportRecord{{Kind: contract.GeneratedParentSupportKind, RecordID: plan.OperationID, Body: body}}}
	encoded, err := format.EncodeRequiredSupportParentPlan(page, plan)
	if err != nil {
		t.Fatal(err)
	}
	ref := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: page.Domain,
		Object: page.Object, Index: page.Index, Digest: contract.Hash(encoded), Length: uint32(len(encoded))}
	root := format.Root{Domain: page.Domain, RequiredSupport: []format.Ref{ref}}
	seed := &StateSession{}
	if _, err := seed.administrativePagePlan(root, []format.RequiredSupportPage{page}, &plan); err != nil {
		t.Fatal("exact provisional parent", err)
	}
	mismatch := plan
	mismatch.ConditionDigest = generatedVectorID(208)
	if _, err := seed.administrativePagePlan(root, []format.RequiredSupportPage{page}, &mismatch); err == nil {
		t.Fatal("mismatched provisional parent was admitted")
	}
	if _, err := seed.administrativePagePlan(root, []format.RequiredSupportPage{page}, nil); err == nil {
		t.Fatal("provisional parent was accepted as a stored parent")
	}
}

// full_only: false
func TestAdministrativePagePlanBindsProvisionalReceiptExactly(t *testing.T) {
	seed, prior, _ := receiptStateFixture(t)
	plan := contract.CompactMutationReceiptPlan(prior)
	plan.RequestIdentityDigest = contract.ID{}
	body, err := contract.AppendCompactMutationReceiptPlan(nil, plan)
	if err != nil {
		t.Fatal(err)
	}
	page := format.RequiredSupportPage{Domain: plan.DomainID, Object: generatedVectorID(209),
		Records: []contract.SupportRecord{{Kind: contract.MutationReceiptSupportKind, RecordID: plan.OperationID, Body: body}}}
	encoded, err := format.EncodeRequiredSupportReceiptPlan(page, plan)
	if err != nil {
		t.Fatal(err)
	}
	ref := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: page.Domain,
		Object: page.Object, Index: page.Index, Digest: contract.Hash(encoded), Length: uint32(len(encoded))}
	root := format.Root{Domain: page.Domain, RequiredSupport: []format.Ref{ref}}
	if _, err := seed.administrativePagePlan(root, []format.RequiredSupportPage{page}, nil, &plan); err != nil {
		t.Fatal("exact provisional receipt", err)
	}
	mismatch := plan
	mismatch.DomainID = generatedVectorID(210)
	if _, err := seed.administrativePagePlan(root, []format.RequiredSupportPage{page}, nil, &mismatch); err == nil {
		t.Fatal("mismatched provisional receipt was admitted")
	}
	if _, err := seed.administrativePagePlan(root, []format.RequiredSupportPage{page}, nil); err == nil {
		t.Fatal("provisional receipt was accepted as a stored receipt")
	}
}

// full_only: false
func TestAdministrativeIndexKeepsSharedFragmentForIndependentOwner(t *testing.T) {
	_, _, first := generatedEffectPlanFixture(t)
	second := first
	second.OperationID = generatedVectorID(219)
	second.MaterialID = generatedVectorID(218)
	firstBody, err := contract.EncodeGeneratedParentRecord(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBody, err := contract.EncodeGeneratedParentRecord(second)
	if err != nil {
		t.Fatal(err)
	}
	blob := []byte("AB")
	blobID := contract.Hash(blob)
	locations := []contract.GeneratorSliceLocation{
		{Schema: 1, ContentKind: contract.GeneratorContentConfiguration, ContentID: first.MaterialID, BlobID: blobID, Length: 1, Digest: contract.Hash(blob[:1])},
		{Schema: 1, ContentKind: contract.GeneratorContentConfiguration, ContentID: second.MaterialID, BlobID: blobID, Offset: 1, Length: 1, Digest: contract.Hash(blob[1:])},
	}
	var sliceBodies [][]byte
	for _, location := range locations {
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal(err)
		}
		sliceBodies = append(sliceBodies, body)
	}
	snapshot := generatedVectorID(220)
	_, carriers, err := generatedCarrierRows(first.DomainID, contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, sliceBodies)
	if err != nil {
		t.Fatal(err)
	}
	fragments, err := generatedFragmentRows(blobID, blob)
	if err != nil || len(fragments) != 1 {
		t.Fatal("shared fragment:", err)
	}
	rows := []contract.SupportRecord{{Kind: contract.GeneratedParentSupportKind, RecordID: first.OperationID, Body: firstBody},
		{Kind: contract.GeneratedParentSupportKind, RecordID: second.OperationID, Body: secondBody}}
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	page := format.RequiredSupportPage{Domain: first.DomainID, Object: generatedVectorID(221), Records: rows}
	body, err := format.EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	slicePage := format.RequiredSupportPage{Domain: first.DomainID, Object: generatedVectorID(223), Index: 1, Records: carriers}
	sliceBody, err := format.EncodeRequiredSupportPage(slicePage)
	if err != nil {
		t.Fatal(err)
	}
	sliceRef, err := format.Reference(contract.RequiredSupportKind, slicePage.Domain, slicePage.Object, slicePage.Index, sliceBody)
	if err != nil {
		t.Fatal(err)
	}
	fragmentPage := format.RequiredSupportPage{Domain: first.DomainID, Object: generatedVectorID(222), Index: 2, Records: fragments}
	fragmentBody, err := format.EncodeRequiredSupportPage(fragmentPage)
	if err != nil {
		t.Fatal(err)
	}
	fragmentRef, err := format.Reference(contract.RequiredSupportKind, fragmentPage.Domain, fragmentPage.Object, fragmentPage.Index, fragmentBody)
	if err != nil {
		t.Fatal(err)
	}
	root := format.Root{Domain: page.Domain, Snapshot: snapshot, RequiredSupport: []format.Ref{ref, sliceRef, fragmentRef}}
	seed := &StateSession{admission: openAdmission{domain: page.Domain}, root: format.Root{Domain: page.Domain}}
	index, err := seed.buildAdministrativeIndex(context.Background(), root, []format.RequiredSupportPage{page, slicePage, fragmentPage}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Pages[2].Spans) != 1 || len(index.Pages[2].Spans[0].GroupIndexes) != 2 {
		t.Fatal("shared fragment lost one independent consumer")
	}
	root.AdministrativeIndex.Object = index.Object
	sliceView, err := format.InspectRequiredSupportPage(sliceBody)
	if err != nil {
		t.Fatal(err)
	}
	state := &StateSession{admission: openAdmission{domain: page.Domain}, root: root, adminIndex: index, support: []format.RequiredSupportPageView{sliceView}}
	afterFirst, err := state.administrativeWorkDisposition(first.OperationID)
	if err != nil || len(afterFirst.Pages) != 3 || len(afterFirst.Groups) != 1 || afterFirst.Groups[0].GroupID != second.OperationID ||
		len(afterFirst.Pages[2].Spans) != 1 || len(afterFirst.Pages[2].Spans[0].GroupIndexes) != 1 {
		t.Fatal("first exit removed the second owner's shared fragment", err)
	}
	state.adminIndex = afterFirst
	afterSecond, err := state.administrativeWorkDisposition(second.OperationID)
	if err != nil || len(afterSecond.Pages) != 0 {
		t.Fatal("last owner did not release shared fragment page", err)
	}
}

// full_only: false
func TestAdministrativeDeclarationBindsBothSourceIdentities(t *testing.T) {
	entry := generatedSealedSource(t, "alpha")
	envelope, err := contract.DecodeSealedInputEnvelope(entry.Payload)
	if err != nil {
		t.Fatal(err)
	}
	s := generatedReservationState(t, entry)
	pages := make([]format.RequiredSupportPage, len(s.support))
	for i, view := range s.support {
		pages[i] = format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index}
		for _, row := range view.Records {
			pages[i].Records = append(pages[i].Records, contract.SupportRecord(row))
		}
	}
	consumers, err := selectedAdministrativeConsumers(pages, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	operation := s.root.Generated.ActiveOwner
	entryID, err := contract.GeneratorDeclarationEntryID(s.root.Domain, operation, entry.Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []contract.ID{envelope.Core.SourceID, entryID} {
		if !slices.Equal(consumers.sourceOperation[id], []contract.ID{operation}) {
			t.Fatal("selected declaration did not bind source identity", id)
		}
	}
	wrong := consumers
	wrong.slices = make(map[contract.ID]contract.GeneratorSliceLocation, len(consumers.slices))
	otherEntryID, err := contract.GeneratorDeclarationEntryID(s.root.Domain, generatedVectorID(241), entry.Name)
	if err != nil {
		t.Fatal(err)
	}
	for id, location := range consumers.slices {
		if location.ContentKind == contract.GeneratorContentSource && location.ContentID == entryID {
			location.ContentID = otherEntryID
		}
		wrong.slices[id] = location
	}
	if err := wrong.bindDeclarationSources(pages, nil); err == nil {
		t.Fatal("declaration accepted a source ID from another operation")
	}
}

// full_only: false
func TestAdministrativeGraphBindsIntentAfterDeclarationLeavesSelection(t *testing.T) {
	s := generatedReservationState(t)
	selected, err := s.selectedGeneratedWork(context.Background())
	if err != nil || len(selected.bundles) != 1 {
		t.Fatal("selected graph fixture", err)
	}
	pages := make([]format.RequiredSupportPage, len(s.support))
	for i, view := range s.support {
		pages[i] = format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index}
		for _, row := range view.Records {
			pages[i].Records = append(pages[i].Records, contract.SupportRecord(row))
		}
	}
	consumers, err := selectedAdministrativeConsumers(pages, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	graphOnly := consumers
	graphOnly.slices = make(map[contract.ID]contract.GeneratorSliceLocation)
	graphOnly.intentOperation = make(map[contract.ID][]contract.ID)
	for id, location := range consumers.slices {
		if location.ContentKind == contract.GeneratorContentGraph {
			graphOnly.slices[id] = location
		}
	}
	if len(graphOnly.slices) != 1 {
		t.Fatal("fixture does not select one graph")
	}
	if err := graphOnly.bindDeclarationSources(pages, nil); err != nil {
		t.Fatal(err)
	}
	bundle := selected.bundles[0]
	intent := bundle.Lineages[0].Templates[0].IntentDigest
	if !slices.Equal(graphOnly.intentOperation[intent], []contract.ID{bundle.Header.OperationID}) {
		t.Fatal("retained graph did not bind its intent without declaration or bundle input")
	}
}

// full_only: false
func TestAdministrativeSelectedSliceHashesWholeBlobAndBoundsCopy(t *testing.T) {
	blob := []byte("ABCD")
	blobID, whole := generatedVectorID(242), contract.Hash(blob)
	parts := []contract.GeneratedFragment{
		{BlobID: blobID, Index: 1, Count: 2, TotalLength: 4, WholeDigest: whole, Offset: 2, Payload: blob[2:]},
		{BlobID: blobID, Index: 0, Count: 2, TotalLength: 4, WholeDigest: whole, Payload: blob[:2]},
	}
	location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentGraph,
		ContentID: generatedVectorID(243), BlobID: blobID, Offset: 1, Length: 2, Digest: contract.Hash([]byte("BC"))}
	got, err := selectedAdministrativeSlice(location, parts, 2)
	if err != nil || !bytes.Equal(got, []byte("BC")) || cap(got) != len(got) {
		t.Fatal("selected slice copy or whole-blob hash", err)
	}
	parts[1].WholeDigest = generatedVectorID(244)
	if _, err := selectedAdministrativeSlice(location, parts, 2); err == nil {
		t.Fatal("fragment changed its whole-blob commitment")
	}
	parts[1].WholeDigest = whole
	if _, err := selectedAdministrativeSlice(location, parts, 1); err == nil {
		t.Fatal("selected slice exceeded its content limit")
	}
}

// full_only: false
func TestAdministrativeMandatoryPartitionKeepsCurrentEvidenceAndSliceBlob(t *testing.T) {
	domain, value, intent, result, operation := generatedVectorID(230), generatedVectorID(231), generatedVectorID(232), generatedVectorID(233), generatedVectorID(234)
	current := &StateSession{root: format.Root{Domain: domain, Names: []format.NameEntry{{Name: "current", Slot: 0}}}}
	current.pages[0] = &format.ValueEntryPage{Domain: domain}
	current.pages[0].Slots[0] = &format.ValueEntry{Name: "current", ValueState: value, ValueSource: contract.Generated,
		Generated: contract.GeneratedEntryMetadata{IntentDigest: intent, CreateResultID: result, OriginOperationID: operation}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	blobID := contract.Hash([]byte("current intent and optional source"))
	locations := []contract.GeneratorSliceLocation{
		{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: intent, BlobID: blobID, Length: 1, Digest: contract.Hash([]byte("c"))},
		{Schema: 1, ContentKind: contract.GeneratorContentSource, ContentID: generatedVectorID(235), BlobID: blobID, Offset: 1, Length: 1, Digest: contract.Hash([]byte("s"))},
	}
	mandatory, err := newAdministrativeMandatorySupport(current, locations)
	if err != nil {
		t.Fatal(err)
	}
	old := []format.RequiredSupportGroup{
		{Class: format.OldValueSupport, Owner: result, Records: []contract.SupportRecord{{Kind: contract.GeneratedCreateEvidenceSupportKind, RecordID: result}}},
		{Class: format.OldValueSupport, Owner: value, Records: []contract.SupportRecord{{Kind: contract.RetainedCanonicalSupportKind, RecordID: value}}},
		{Class: format.OldValueSupport, Owner: generatedVectorID(236), Records: []contract.SupportRecord{{Kind: contract.RetainedCanonicalSupportKind, RecordID: generatedVectorID(236)}}},
	}
	partitioned, err := partitionAdministrativeSupportGroups(old, mandatory)
	if err != nil || len(partitioned) != 3 || !partitioned[0].Mandatory || partitioned[1].Mandatory || partitioned[2].Mandatory {
		t.Fatal("current generated evidence or optional retained copies have wrong partition", err)
	}
	var sliceBodies [][]byte
	for _, location := range locations {
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal(err)
		}
		sliceBodies = append(sliceBodies, body)
	}
	_, carriers, err := generatedCarrierRows(domain, contract.GeneratorSnapshotOwner, generatedVectorID(237), contract.GeneratorVectorSlices, sliceBodies)
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range carriers {
		keep, err := mandatory.row(row)
		if err != nil || keep != (i == 0) {
			t.Fatal("slice carrier mandatory classification", i, keep, err)
		}
	}
	fragments, err := generatedFragmentRows(blobID, []byte("current intent and optional source"))
	if err != nil {
		t.Fatal(err)
	}
	keep, err := mandatory.row(fragments[0])
	if err != nil || !keep {
		t.Fatal("shared blob lost current intent dependency", err)
	}
}

// full_only: false
func TestAdministrativeIndexRejectsMandatoryAndOptionalRowsOnOnePage(t *testing.T) {
	_, receipt, _ := receiptStateFixture(t)
	_, _, parent := generatedEffectPlanFixture(t)
	parent.DomainID = receipt.DomainID
	parentBody, err := contract.EncodeGeneratedParentRecord(parent)
	if err != nil {
		t.Fatal(err)
	}
	receiptBody, err := contract.EncodeCompactMutationReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	page := format.RequiredSupportPage{Domain: receipt.DomainID, Object: generatedVectorID(238), Records: []contract.SupportRecord{
		{Kind: contract.GeneratedParentSupportKind, RecordID: parent.OperationID, Body: parentBody},
		{Kind: contract.MutationReceiptSupportKind, RecordID: receipt.OperationID, Body: receiptBody},
	}}
	body, err := format.EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	root := format.Root{Domain: page.Domain, Snapshot: generatedVectorID(239), RequiredSupport: []format.Ref{ref}}
	seed := &StateSession{admission: openAdmission{domain: page.Domain}, root: format.Root{Domain: page.Domain}}
	if _, err := seed.buildAdministrativeIndex(context.Background(), root, []format.RequiredSupportPage{page}, nil, nil, nil); err == nil {
		t.Fatal("mandatory receipt shared a page with disposable parent")
	}
}

// full_only: false
func TestAdministrativeIndexKeepsMaterialButRejectsDetachedPhase(t *testing.T) {
	selected := generatedReservationState(t)
	var rows []contract.SupportRecord
	var duty contract.ID
	for _, row := range selected.supportRecords() {
		switch row.Kind {
		case contract.OperationMaterialSupportKind, contract.GeneratedPhaseSupportKind, contract.GeneratedAttemptSupportKind, contract.GeneratedDutySupportKind:
			rows = append(rows, row)
			if row.Kind == contract.GeneratedDutySupportKind {
				duty = row.RecordID
			}
		}
	}
	if duty.IsZero() || len(rows) != 4 {
		t.Fatalf("fixture has no detached material and phase: %d rows", len(rows))
	}
	var consumerRows int
	for _, row := range selected.supportRecords() {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		if carrier.OwnerKind == contract.GeneratedDutySupportKind && carrier.OwnerID == duty && carrier.VectorKind == contract.GeneratorVectorConsumers {
			rows = append(rows, row)
			consumerRows++
		}
	}
	if consumerRows != 2 {
		t.Fatalf("fixture has %d Duty consumer rows, want 2", consumerRows)
	}
	page := format.RequiredSupportPage{Domain: selected.root.Domain, Object: generatedVectorID(203), Records: rows}
	body, err := format.EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	root := format.Root{Domain: page.Domain, Snapshot: generatedVectorID(204), RequiredSupport: []format.Ref{ref}}
	seed := &StateSession{admission: openAdmission{domain: page.Domain}, root: format.Root{Domain: page.Domain}}
	if _, err := seed.buildAdministrativeIndex(context.Background(), root, []format.RequiredSupportPage{page}, nil, nil, nil); !errors.Is(err, contract.ErrRecord) {
		t.Fatal("detached Phase acquired a Duty consumer without an active parent", err)
	}
	rows = slices.DeleteFunc(rows, func(row contract.SupportRecord) bool { return row.Kind == contract.GeneratedPhaseSupportKind })
	page.Records = rows
	body, err = format.EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err = format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	root.RequiredSupport = []format.Ref{ref}
	index, err := seed.buildAdministrativeIndex(context.Background(), root, []format.RequiredSupportPage{page}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Groups) != 1 || index.Groups[0].GroupID != duty || len(index.Groups[0].RelatedGroupIndexes) != 0 {
		t.Fatal("detached material did not keep its exact independent Duty envelope")
	}
	for i, row := range rows {
		if row.Kind != contract.OperationMaterialSupportKind {
			continue
		}
		span, ok := administrativeTestSpanAt(index.Pages[0], i)
		if !ok || span.Mandatory || len(span.GroupIndexes) != 1 || index.Groups[span.GroupIndexes[0]].GroupID != duty {
			t.Fatalf("kind %d lost exact duty owner: %+v", row.Kind, span)
		}
	}
	page.Records = slices.DeleteFunc(slices.Clone(rows), func(row contract.SupportRecord) bool { return row.Kind == contract.GeneratorVectorSupportKind })
	body, err = format.EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err = format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	root.RequiredSupport = []format.Ref{ref}
	if _, err := seed.buildAdministrativeIndex(context.Background(), root, []format.RequiredSupportPage{page}, nil, nil, nil); !errors.Is(err, contract.ErrRecord) {
		t.Fatal("detached material acquired a Duty owner without a selected consumer", err)
	}
}

// full_only: false
func TestAdministrativeIndexLocalCreateHasNoRemoteAffectedSubjects(t *testing.T) {
	before := generatedEmptyPredecessor(t)
	input := generatedReservationInputFixture(t, before)
	x := input.graph.Lineages[0].Templates[0]
	x.Schema, x.LifecycleMode, x.ResultReaderID = contract.GeneratorAttemptTemplateSchema, contract.GeneratorLifecycleNone, contract.GeneratorResultReaderID()
	x.ResourceContractID, x.ResourceDigest, x.HazardID, x.TargetSourceID = contract.ID{}, contract.ID{}, contract.ID{}, contract.ID{}
	x.CompletionClass, x.NoEffectBudget, x.ResidueBudget, x.TargetKind = 0, 0, 0, 0
	var err error
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(x)
	if err != nil {
		t.Fatal(err)
	}
	a, d, err := generatedCreateRecords(contract.GeneratedParentRecord(input.parent), x, generatedVectorID(90), contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers))
	if err != nil {
		t.Fatal(err)
	}
	ab, err := contract.EncodeGeneratedAttemptRecord(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := contract.EncodeGeneratedDutyRecord(d)
	if err != nil {
		t.Fatal(err)
	}
	rows := []contract.SupportRecord{{Kind: contract.GeneratedAttemptSupportKind, RecordID: a.AttemptID, Body: ab}, {Kind: contract.GeneratedDutySupportKind, RecordID: d.DutyID, Body: db}}
	page := format.RequiredSupportPage{Domain: a.DomainID, Object: generatedVectorID(201), Records: rows}
	body, err := format.EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	root := format.Root{Domain: page.Domain, Snapshot: generatedVectorID(202), RequiredSupport: []format.Ref{ref}}
	seed := &StateSession{admission: openAdmission{domain: page.Domain}, root: format.Root{Domain: page.Domain}}
	index, err := seed.buildAdministrativeIndex(t.Context(), root, []format.RequiredSupportPage{page}, nil, nil, nil)
	if err != nil {
		t.Fatal("local create administrative owner refused", err)
	}
	expected, err := hex.DecodeString("f96e0e0879d453b297fbcd33d183a30241784079866ade552c3a3132d79cb7aa")
	if err != nil {
		t.Fatal(err)
	}
	want := contract.GeneratorDescriptor{Digest: contract.ID(expected), Length: 4}
	if len(index.Groups) != 1 || index.Groups[0].Affected != want || index.Groups[0].TargetID != d.ResourceID || index.Groups[0].EffectEntryCeiling != 1 || index.Groups[0].OwnerKind != format.AdministrativeGeneratedDuty || index.Groups[0].DutyKind != contract.GeneratedDutyCreate || !index.Groups[0].Affected.Valid() || index.Groups[0].Affected.Count != 0 || d.Target != want {
		t.Fatal("local owner invented remote affected subjects")
	}
	encoded, err := format.EncodeAdministrativeIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := format.DecodeAdministrativeIndex(encoded)
	if err != nil || len(decoded.Groups) != 1 || decoded.Groups[0].Affected != want {
		t.Fatal("local administrative projection changed on cold decode", err)
	}
	again, err := format.EncodeAdministrativeIndex(decoded)
	if err != nil || !bytes.Equal(encoded, again) {
		t.Fatal("local administrative index is not canonical", err)
	}
	for _, target := range []contract.GeneratorDescriptor{
		{},
		{Digest: generatedVectorID(203), Length: 8, Count: 1},
	} {
		bad := d
		bad.Target = target
		if _, err := contract.EncodeGeneratedDutyRecord(bad); err == nil {
			t.Fatal("local Duty accepted an absent or nonempty target descriptor", target)
		}
	}
	original := input.graph.Lineages[0].Templates[0]
	_, cf, err := generatedCreateRecords(contract.GeneratedParentRecord(input.parent), original, generatedVectorID(90), contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers))
	if err != nil {
		t.Fatal(err)
	}
	cfBody, err := contract.EncodeGeneratedDutyRecord(cf)
	if err != nil {
		t.Fatal(err)
	}
	cfGroup, present, err := administrativeGroupFromRow(contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: cf.DutyID, Body: cfBody}, nil)
	if err != nil || !present || cfGroup.Affected != cf.Target {
		t.Fatal("CF target projection changed", err)
	}

}

func administrativeOwnersWithoutProjectedBundle(t testing.TB, s *StateSession, prior *generatedSelection) administrativeConsumers {
	t.Helper()
	pages := make([]format.RequiredSupportPage, len(s.support))
	for i, page := range s.support {
		pages[i] = format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index}
		for _, view := range page.Records {
			row := contract.SupportRecord(view)
			if row.Kind == contract.GeneratedFragmentSupportKind && prior != nil {
				row.Body = nil
			}
			pages[i].Records = append(pages[i].Records, row)
		}
	}
	consumers, err := selectedAdministrativeConsumersWithValidated(pages, nil, nil, prior)
	if err != nil {
		t.Fatal(err)
	}
	if err := consumers.bindParentVectorOwners(s.root, pages); err != nil {
		t.Fatal(err)
	}
	return consumers
}

// full_only: false
func TestAdministrativeParentVectorsRecoverSourceUsesWithoutProjectedGraph(t *testing.T) {
	s := generatedReservationState(t, generatedSealedSource(t, "alpha"), generatedSealedSource(t, "omega"))
	generatedSealSelectedFixture(t, s)
	selected, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	operation := s.root.Generated.ActiveOwner
	uses := selected.bundles[0].SourceUses
	if len(uses) != 2 || uses[0].Consumers == uses[1].Consumers {
		t.Fatal("expected two distinct sealed-input consumers")
	}
	for _, prior := range []*generatedSelection{nil, selected} {
		consumers := administrativeOwnersWithoutProjectedBundle(t, s, prior)
		for _, use := range uses {
			key := generatedVectorKey{contract.GeneratedParentSupportKind, operation, contract.GeneratorVectorConsumers, use.Consumers}
			if !slices.Equal(consumers.parentVectors[key], []contract.ID{operation}) {
				t.Fatal("active source lost its exact group", key, consumers.parentVectors[key])
			}
		}
	}
}

// full_only: false
func TestAdministrativeDeleteHazardUsesTargetSupportWithoutProjectedGraph(t *testing.T) {
	s, _, hazard, target := generatedDeleteHazardState(t, 1)
	if target.OriginalOperationID == hazard.OriginalOperationID {
		t.Fatal("fixture requires distinct Create and Delete operations")
	}
	binding, err := contract.EncodeGeneratorSupportBinding(contract.GeneratorSupportBinding{Schema: contract.GeneratorSupportBindingSchema, Role: 3,
		ContractID: hazard.ConfigContractID, ImplementationID: hazard.ExecutorID, PublicBindingDigest: hazard.DescriptorID})
	if err != nil {
		t.Fatal(err)
	}
	support, carriers, err := generatedCarrierRows(s.root.Domain, contract.GeneratedParentSupportKind, target.OriginalOperationID, contract.GeneratorVectorSupport, [][]byte{binding})
	if err != nil {
		t.Fatal(err)
	}
	hazard.Support = support
	body, err := contract.EncodeGeneratedHazardRecord(hazard)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, contract.GeneratedHazardSupportKind, hazard.HazardID, body)
	page := &s.support[len(s.support)-1]
	for _, r := range carriers {
		page.Records = append(page.Records, contract.SupportRecordView(r))
	}
	generatedRefreshSupport(t, s)
	selected, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal("cold validation of Delete Hazard support", err)
	}
	for _, prior := range []*generatedSelection{nil, selected} {
		consumers := administrativeOwnersWithoutProjectedBundle(t, s, prior)
		key := generatedVectorKey{contract.GeneratedParentSupportKind, target.OriginalOperationID, contract.GeneratorVectorSupport, support}
		if !slices.Equal(consumers.parentVectors[key], []contract.ID{hazard.HazardID}) {
			t.Fatal("target support lost the Hazard that uses it", consumers.parentVectors[key])
		}
	}
}
