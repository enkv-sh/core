package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestNormalSupportPackingSelectsChangedOutputRows(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 1, false, 1)
	before := fixtureStateImage(t, f).entryInputs()
	selected := f.session
	oldRefs := slices.Clone(selected.root.RequiredSupport)
	if !selected.selectedOutputComplete() || len(oldRefs) == 0 {
		t.Fatal("fixture lacks complete selected output")
	}
	intent := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{{
		entryName: before[0].Name,
		target:    contract.OutputTarget{ServiceContractID: "controlled-provider", TargetContractID: "fixture/target/v1", CanonicalTarget: "app-secret", ConsumerLocator: "app-secret?stage=AWSCURRENT", TargetData: []byte("target:" + "app-secret"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{}},
	}}}}, groups: [][]string{{before[0].Name}}}
	installOutputFixtureSource(t, selected, intent)
	parent := admitSuppliedOutputComparison(t, selected, nil, before, intent)
	c, result := selected.compareWithOutput(ctx, before, intent, parent)
	if c == nil || result.Outcome != ObservedCurrent || parent == nil || parent.support == nil || c.support != parent.support || !c.outputChanged {
		t.Fatal("output-only comparison", result)
	}
	p, err := planTransition(ctx, c)
	if err != nil || c.outputAfter == nil {
		t.Fatal("output-only plan lacks complete canonical slices")
	}
	entry := selected.valueEntry(selected.root.Names[0].Slot)
	if entry == nil || p.outputBindings["app"].IsZero() {
		t.Fatal("output plan lacks selected entry or fresh binding identity")
	}
	wantTarget := intent.bindings[0].targets[0].target
	wantTarget.EntryIncarnationID = entry.Incarnation
	wantImage, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: 4, DomainID: selected.root.Domain,
		Bindings: []contract.OutputBinding{{DestinationID: "app", IncarnationID: p.outputBindings["app"],
			Destination: outputFixtureDestination("app", "controlled-provider", 63, contract.OutputPolicy{}),
			Targets:     []contract.OutputTarget{wantTarget}}}, Groups: [][]contract.ID{{entry.Incarnation}}, Routes: []contract.OutputRoute{{EntryIncarnationID: entry.Incarnation, Destinations: []string{"app"}}}})
	if err != nil {
		t.Fatal("independent expected output declaration", err)
	}
	wantDescriptor, wantSlices, err := contract.SplitOutputConfiguration(selected.root.Domain, wantImage)
	if err != nil || wantDescriptor != c.outputAfter.descriptor {
		t.Fatal("planned output descriptor differs from the independent declaration", err)
	}
	wantRows := make([]contract.SupportRecord, 0, len(wantSlices))
	for _, slice := range wantSlices {
		body, encodeErr := contract.EncodeOutputConfigurationSlice(slice)
		id, idErr := contract.OutputConfigurationSliceID(selected.root.Domain, wantDescriptor.ConfigurationDigest, slice.SliceIndex)
		if encodeErr != nil || idErr != nil {
			t.Fatal("independent expected output row", encodeErr, idErr)
		}
		wantRows = append(wantRows, contract.SupportRecord{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body})
	}
	if len(wantRows) == 0 {
		t.Fatal("independent output declaration has no selected slice")
	}
	slices.SortFunc(wantRows, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	equalRows := func(a, b []contract.SupportRecord) bool {
		return slices.EqualFunc(a, b, func(x, y contract.SupportRecord) bool {
			return x.Kind == y.Kind && x.RecordID == y.RecordID && slices.Equal(x.Body, y.Body)
		})
	}
	if !equalRows(c.outputAfter.records, wantRows) {
		t.Fatal("planned output rows differ from the independent declaration")
	}
	projection, err := generatedNormalSupportRows(c, p)
	descriptor, descriptorErr := contract.RequiredSupportDescriptorFromDigests(selected.root.Domain, projection.Facts)
	if err != nil || descriptorErr != nil || descriptor.Count != selected.root.RequiredSupportRecordCount-uint32(selected.root.OutputConfiguration.SliceCount)+uint32(len(c.outputAfter.records))+1 {
		t.Fatal("changed output support projection", err)
	}
	// The output changes, but the predecessor's complete receipt evidence does not.
	receiptIndex, err := contract.MutationReceiptIndexBlobID(selected.root.Domain,
		selected.root.Generated.SuccessWindow, selected.root.Generated.FailureWindow, selected.root.Generated.ReceiptOrder)
	if err != nil || receiptIndex.IsZero() {
		t.Fatal("fixture lacks its selected receipt index", err)
	}
	receiptFragments := make(map[contract.ID]bool)
	for _, location := range selected.root.Generated.Fragments {
		if location.BlobID == receiptIndex {
			id, err := contract.GeneratorFragmentID(receiptIndex, location.FragmentIndex)
			if err != nil {
				t.Fatal("selected receipt fragment identity", err)
			}
			receiptFragments[id] = true
		}
	}
	wantUnchangedPages := make(map[format.Ref]selectedSupportPageFacts)
	for _, page := range selected.supportFacts {
		unchanged := len(page.rows) != 0
		for _, row := range page.rows {
			if row.Kind() != contract.MutationReceiptSupportKind &&
				(row.Kind() != contract.GeneratedFragmentSupportKind || !receiptFragments[row.RecordID()]) {
				unchanged = false
			}
		}
		if !unchanged {
			continue
		}
		body, result := selected.readObject(ctx, page.ref)
		if result.Outcome != 0 || len(body) != int(page.ref.Length) || len(body) > contract.MaxRequiredSupportPageLength {
			t.Fatal("unchanged receipt page lacks bounded immutable backing", result)
		}
		wantUnchangedPages[page.ref] = page
	}
	if len(receiptFragments) == 0 || len(wantUnchangedPages) == 0 {
		t.Fatal("fixture lacks a separate unchanged receipt page")
	}
	packed, err := normalSupportPacking(ctx, c, p)
	if err != nil {
		t.Fatal("changed output canonical packing", err)
	}
	var packedOutput []contract.SupportRecord
	for _, page := range packed {
		if !page.retained.ref.Object.IsZero() {
			want, present := wantUnchangedPages[page.retained.ref]
			if !present || page.index != want.ref.Index || !slices.Equal(page.retained.rows, want.rows) ||
				!slices.Equal(page.retained.ordinals, want.ordinals) || !slices.Equal(page.facts, want.rows) || len(page.records) != len(want.rows) {
				t.Fatal("changed output retained a changed, duplicate, or displaced predecessor page")
			}
			for i, row := range page.records {
				if row.Kind != want.rows[i].Kind() || row.RecordID != want.rows[i].RecordID() {
					t.Fatal("retained receipt page changed its complete row set")
				}
			}
			delete(wantUnchangedPages, page.retained.ref)
			continue
		}
		body, encodeErr := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: selected.root.Domain,
			Object: contract.ID{byte(page.index + 1)}, Index: page.index, Records: page.records})
		if encodeErr != nil || len(body) > contract.MaxRequiredSupportPageLength {
			t.Fatal("changed output exceeds a physical page", encodeErr)
		}
		for _, row := range page.records {
			if row.Kind != contract.OutputConfigurationSliceSupportKind {
				continue
			}
			packedOutput = append(packedOutput, row)
		}
	}
	if len(wantUnchangedPages) != 0 {
		t.Fatal("changed output lost an unchanged receipt page")
	}
	slices.SortFunc(packedOutput, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	if !equalRows(packedOutput, wantRows) {
		t.Fatal("changed output packed an incomplete or duplicate row set")
	}
	groups := []format.RequiredSupportGroup{{Class: format.OutputConfigurationSupport, Owner: wantDescriptor.ConfigurationDigest,
		Mandatory: true, Records: wantRows}}
	if _, err := generatedSupportPages(selected.root.Domain, groups, contract.MaxChildPages, nil); err == nil {
		t.Fatal("changed output exceeded the joint child-page limit")
	}
	if boundary, err := generatedSupportPages(selected.root.Domain, groups, contract.MaxChildPages-1, nil); err != nil || len(boundary) != 1 {
		t.Fatal("changed output lost the final available child page", err)
	}
	bad := *c
	altered := *c.outputAfter
	altered.descriptor.ConfigurationDigest[0] ^= 1
	bad.outputAfter = &altered
	if _, err := normalSupportPacking(ctx, &bad, p); err == nil {
		t.Fatal("changed output accepted a descriptor that does not bind its slices")
	}
	badSelected := *selected
	badSelected.supportFacts = slices.Clone(selected.supportFacts)
	badSelected.supportFacts[0].ordinals = slices.Clone(selected.supportFacts[0].ordinals)
	badSelected.supportFacts[0].ordinals[0]++
	bad = *c
	bad.session = &badSelected
	if _, err := generatedNormalSupportRows(&bad, p); err == nil {
		t.Fatal("changed output accepted a displaced selected physical ordinal")
	}
	if next, err := selected.deriveSuccessor(ctx, c, p); next == nil || err != nil || next.root.OutputConfiguration != c.outputAfter.descriptor {
		t.Fatal("complete output packing did not derive exact selected configuration")
	}

	unchangedEntries := append(slices.Clone(before), ApplyEntryInput{Name: "extra", Recipients: slices.Clone(before[0].Recipients),
		ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte("extra"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	unchangedParent := admitSuppliedOutputComparison(t, selected, nil, unchangedEntries, nil)
	unchanged, result := selected.compareWithOutput(ctx, unchangedEntries, nil, unchangedParent)
	if unchanged == nil || result.Outcome != ObservedCurrent || unchangedParent == nil || unchangedParent.support == nil || unchanged.support != unchangedParent.support || unchanged.outputAfter != nil {
		t.Fatal("unchanged output comparison", result)
	}
	plainPlan, err := planTransition(ctx, unchanged)
	if err != nil {
		t.Fatal("unchanged output plan")
	}
	retained, err := normalSupportPacking(ctx, unchanged, plainPlan)
	if err != nil {
		t.Fatal("unchanged output packing", err)
	}
	wantRetained := selected.supportFacts
	wantRefs := make(map[format.Ref]selectedSupportPageFacts, len(wantRetained))
	for _, page := range wantRetained {
		wantRefs[page.ref] = page
	}
	var kept int
	for _, page := range retained {
		if len(page.retained.rows) == 0 {
			continue
		}
		want, present := wantRefs[page.retained.ref]
		if !present || !slices.Equal(page.retained.rows, want.rows) || !slices.Equal(page.retained.ordinals, want.ordinals) {
			t.Fatal("unchanged output changed an authenticated Ref, row fact, or physical ordinal")
		}
		delete(wantRefs, page.retained.ref)
		kept++
	}
	if kept != len(wantRetained) || len(wantRefs) != 0 {
		t.Fatal("unchanged output lost or duplicated an authenticated Ref")
	}
	t.Run("mixed_selected_page_keeps_physical_output_fact", func(t *testing.T) {
		mixed, _ := mixedReceiptOutputFixture(t)
		mixedPage := slices.IndexFunc(mixed.supportFacts, func(page selectedSupportPageFacts) bool {
			return slices.ContainsFunc(page.rows, func(row contract.SupportRecordDigest) bool {
				return row.Kind() == contract.OutputConfigurationSliceSupportKind
			})
		})
		if mixedPage < 0 || len(mixed.supportFacts[mixedPage].rows) != 3 || len(mixed.supportFacts[mixedPage].ordinals) != 3 ||
			mixed.supportFacts[mixedPage].rows[2].Kind() != contract.OutputConfigurationSliceSupportKind ||
			mixed.supportFacts[mixedPage].ordinals[2] != 2 || mixed.support[mixedPage].Records[2].Body != nil {
			t.Fatal("fixture lacks a bodyless output row after non-output rows")
		}
		mixedComparison := &Comparison{session: mixed}
		mixedProjection, err := generatedNormalSupportRows(mixedComparison, transitionPlan{})
		mixedDescriptor, descriptorErr := contract.RequiredSupportDescriptorFromDigests(mixed.root.Domain, mixedProjection.Facts)
		outputFacts := slices.DeleteFunc(slices.Clone(mixedProjection.Facts), func(fact contract.SupportRecordDigest) bool {
			return fact.Kind() != contract.OutputConfigurationSliceSupportKind
		})
		if err != nil || descriptorErr != nil || mixedDescriptor.Count != mixed.root.RequiredSupportRecordCount ||
			!equalRows(mixedProjection.Records, mixed.supportRecords()) ||
			len(outputFacts) != 1 || outputFacts[0] != mixed.supportFacts[mixedPage].rows[2] {
			t.Fatal("mixed page lost the selected receipt, material, or output fact", err)
		}
		wrong := *mixed
		wrong.supportFacts = slices.Clone(mixed.supportFacts)
		wrong.supportFacts[mixedPage].ordinals = slices.Clone(mixed.supportFacts[mixedPage].ordinals)
		wrong.supportFacts[mixedPage].ordinals[2]++
		mixedComparison.session = &wrong
		mixedComparison.outputChanged, mixedComparison.outputAfter = true, c.outputAfter
		if _, err := generatedNormalSupportRows(mixedComparison, transitionPlan{}); err == nil {
			t.Fatal("mixed page accepted a displaced output ordinal")
		}
	})
}

func mixedReceiptOutputFixture(t *testing.T) (*StateSession, contract.CompactMutationReceipt) {
	t.Helper()
	f := newFixture(t, 0, false, 1)
	s := f.session
	windows, err := s.receiptWindows(t.Context())
	if err != nil || len(windows.Successes) != 1 || len(windows.Failures) != 0 || len(windows.Order) != 1 ||
		windows.Order[0] != windows.Successes[0].OperationID {
		t.Fatal("mixed fixture lacks its exact initialization receipt", err)
	}
	receipt := windows.Successes[0]
	beforeRefs, beforeCount := slices.Clone(s.root.RequiredSupport), s.root.RequiredSupportRecordCount
	beforeFacts, beforePages := slices.Clone(s.supportFacts), slices.Clone(s.adminIndex.Pages)
	beforeGenerated := s.root.Generated
	position, outputs, receipts := -1, 0, 0
	for i, page := range s.support {
		for _, row := range page.Records {
			if row.Kind == contract.OutputConfigurationSliceSupportKind {
				position, outputs = i, outputs+1
			}
			if row.Kind == contract.MutationReceiptSupportKind {
				if row.RecordID != receipt.OperationID {
					t.Fatal("mixed fixture has an unindexed receipt")
				}
				receipts++
			}
		}
	}
	if outputs != 1 || receipts != 1 || position < 0 || len(s.support[position].Records) != 2 ||
		len(s.support) != len(beforeRefs) || len(s.support) != len(beforeFacts) || len(s.support) != len(beforePages) {
		t.Fatal("mixed fixture lacks its complete receipt/output page")
	}
	predecessor, result := s.readObject(t.Context(), beforeRefs[position])
	physicalBefore, err := format.InspectRequiredSupportPage(predecessor)
	if result.Outcome != 0 || err != nil || len(physicalBefore.Records) != 2 {
		t.Fatal("mixed fixture lacks its immutable selected page", result, err)
	}
	var receiptRow, outputRow contract.SupportRecord
	for _, row := range physicalBefore.Records {
		switch row.Kind {
		case contract.MutationReceiptSupportKind:
			actual, err := contract.InspectCompactMutationReceipt(row.Body)
			if err != nil || actual != receipt || row.RecordID != receipt.OperationID {
				t.Fatal("mixed fixture changed its indexed receipt", err)
			}
			receiptRow = contract.SupportRecord(row)
		case contract.OutputConfigurationSliceSupportKind:
			outputRow = contract.SupportRecord(row)
		default:
			t.Fatal("mixed fixture has an unexpected selected row")
		}
	}
	if receiptRow.Body == nil || outputRow.Body == nil {
		t.Fatal("mixed fixture lost its receipt or output bytes")
	}
	material := contract.OperationMaterialRecord{Core: contract.OperationMaterialCore{Schema: contract.CanonicalSchema,
		Profile: 2, DomainID: s.root.Domain, CompatibilityID: contract.ID{91}, CryptoSupportID: contract.ID{92},
		OperationID: contract.ID{93}, OperationMaterialID: contract.ID{94}, SeedEpoch: 1}, SeedCheck: contract.ID{95}}
	materialBody, err := contract.EncodeOperationMaterialRecord(material)
	if err != nil {
		t.Fatal(err)
	}
	rows := []contract.SupportRecord{receiptRow,
		{Kind: contract.OperationMaterialSupportKind, RecordID: material.Core.OperationMaterialID, Body: materialBody}, outputRow}
	physical := format.RequiredSupportPage{Domain: s.root.Domain, Object: fixtureID(s.root.Domain, "mixed output page"),
		Index: beforeRefs[position].Index, Records: rows}
	body, err := format.EncodeRequiredSupportPage(physical)
	if err != nil {
		t.Fatal(err)
	}
	view, err := format.InspectRequiredSupportPage(body)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, s.root.Domain, physical.Object, physical.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	s.root.RequiredSupport[position], s.support[position] = ref, view
	s.root.RequiredSupportRecordCount = beforeCount + 1
	s.supportFacts[position] = selectedSupportPageFacts{ref: ref}
	s.adminIndex.Pages[position] = format.AdministrativePage{Ref: ref,
		Spans: []format.AdministrativeSpan{{First: 0, Count: 3, Mandatory: true}}}
	for i, row := range rows {
		fact, err := contract.InspectSupportRecordDigest(s.root.Domain, row)
		if err != nil {
			t.Fatal(err)
		}
		s.supportFacts[position].rows = append(s.supportFacts[position].rows, fact)
		s.supportFacts[position].ordinals = append(s.supportFacts[position].ordinals, uint16(i))
		s.adminIndex.Pages[position].Rows = append(s.adminIndex.Pages[position].Rows,
			format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
	}
	indexPages, err := format.EncodeAdministrativeIndexPages(s.adminIndex)
	if err != nil || len(indexPages) == 0 {
		t.Fatal("mixed fixture administrative index", err)
	}
	s.root.AdministrativeIndex, s.root.AdministrativeIndexShards = indexPages[0].Ref, nil
	for _, page := range indexPages[1:] {
		s.root.AdministrativeIndexShards = append(s.root.AdministrativeIndexShards, page.Ref)
	}
	objects := []objectImage{{ref: ref, body: body}}
	for _, page := range indexPages {
		objects = append(objects, objectImage{ref: page.Ref, body: page.Body})
	}
	for _, object := range objects {
		key, err := format.Key(f.store.desc.Prefix, object.ref)
		if err != nil {
			t.Fatal(err)
		}
		f.store.put(key, object.body)
	}
	s.recountChildren()
	for i := range beforeRefs {
		if i != position && (s.root.RequiredSupport[i] != beforeRefs[i] || !reflect.DeepEqual(s.supportFacts[i], beforeFacts[i]) ||
			!reflect.DeepEqual(s.adminIndex.Pages[i], beforePages[i])) {
			t.Fatal("mixed fixture changed unrelated selected support")
		}
	}
	if !reflect.DeepEqual(s.root.Generated, beforeGenerated) {
		t.Fatal("mixed fixture changed receipt descriptors or fragment directory")
	}
	s.outputConfigurationRoot, s.generatedSlicesRoot = contract.ID{}, contract.ID{}
	s.selectedReceiptRoot, s.generatedSliceLocations = format.Ref{}, nil
	s.generatedWork = nil
	generatedVerifySelectedFixtureSlices(t, s)
	afterWindows, err := s.receiptWindowsFromSelectedSupport(t.Context())
	if err != nil || afterWindows.DomainID != windows.DomainID ||
		!slices.Equal(afterWindows.Successes, windows.Successes) || !slices.Equal(afterWindows.Failures, windows.Failures) ||
		!slices.Equal(afterWindows.Order, windows.Order) {
		t.Fatal("mixed fixture changed the complete selected receipt windows", err)
	}
	if !s.adminIndex.Valid() || !projectionSupportFactsBound(s.root, s.adminIndex, s.supportFacts) ||
		s.validateSelectedOutputConfiguration(t.Context()).Outcome != 0 || !s.selectedOutputComplete() {
		t.Fatal("mixed selected output fixture is invalid")
	}
	s.support[position].Records[2].Body = nil
	return s, receipt
}
