package core

import (
	"bytes"
	"maps"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedContentFixtureBlob struct {
	id   contract.ID
	body []byte
}

func generatedContentState(t testing.TB, blobs []generatedContentFixtureBlob, locations []contract.GeneratorSliceLocation) *StateSession {
	return generatedContentStateAtSnapshot(t, generatedVectorID(2), blobs, locations)
}

func generatedContentStateAtSnapshot(t testing.TB, snapshot contract.ID, blobs []generatedContentFixtureBlob, locations []contract.GeneratorSliceLocation) *StateSession {
	return generatedContentStateForDomainAtSnapshot(t, generatedVectorID(1), snapshot, blobs, locations)
}

func generatedContentStateForDomainAtSnapshot(t testing.TB, domain, snapshot contract.ID, blobs []generatedContentFixtureBlob,
	locations []contract.GeneratorSliceLocation) *StateSession {
	t.Helper()
	id := generatedVectorID
	s := &StateSession{admission: openAdmission{domain: domain}, root: format.Root{Domain: domain, Snapshot: snapshot, Generated: format.EmptyGeneratedClosure(), GCPlans: contract.EmptyGCOwnersDescriptor()},
		adminIndex: format.AdministrativeIndex{SliceSnapshot: snapshot}}
	for _, blob := range blobs {
		count := (len(blob.body) + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
		wholeDigest := contract.Hash(blob.body)
		for i := 0; i < count; i++ {
			start, end := i*contract.GeneratedFragmentMaxPayload, min((i+1)*contract.GeneratedFragmentMaxPayload, len(blob.body))
			f := contract.GeneratedFragment{Schema: 1, BlobID: blob.id, Index: uint16(i), Count: uint16(count), TotalLength: uint64(len(blob.body)),
				WholeDigest: wholeDigest, Offset: uint32(start), Payload: blob.body[start:end]}
			body, err := contract.EncodeGeneratedFragment(f)
			if err != nil {
				t.Fatal(err)
			}
			fid, err := contract.GeneratorFragmentID(blob.id, uint16(i))
			if err != nil {
				t.Fatal(err)
			}
			index := uint16(len(s.support))
			s.support = append(s.support, format.RequiredSupportPageView{Domain: domain, Object: contract.Hash(body), Index: index,
				Records: []contract.SupportRecordView{{Kind: 3, RecordID: fid, Body: body}}})
			s.root.Generated.Fragments = append(s.root.Generated.Fragments, format.FragmentLocation{BlobID: blob.id, FragmentIndex: uint16(i), SupportPageIndex: index})
		}
	}
	slices.SortFunc(s.root.Generated.Fragments, func(a, b format.FragmentLocation) int {
		if d := bytes.Compare(a.BlobID[:], b.BlobID[:]); d != 0 {
			return d
		}
		return int(a.FragmentIndex) - int(b.FragmentIndex)
	})
	slices.SortFunc(locations, func(a, b contract.GeneratorSliceLocation) int {
		if a.ContentKind != b.ContentKind {
			return int(a.ContentKind) - int(b.ContentKind)
		}
		return bytes.Compare(a.ContentID[:], b.ContentID[:])
	})
	var rows [][]byte
	for _, location := range locations {
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, body)
	}
	d, records := generatedVectorRowsForDomain(t, domain, contract.GeneratorSnapshotOwner, s.root.Snapshot, contract.GeneratorVectorSlices, rows)
	s.root.Generated.Slices = d
	if len(records) > 0 {
		page := format.RequiredSupportPageView{Domain: domain, Object: id(30), Index: uint16(len(s.support))}
		for _, row := range records {
			page.Records = append(page.Records, contract.SupportRecordView(row))
		}
		s.support = append(s.support, page)
	}
	return s
}

// full_only: false
func TestGeneratedContentSmallIntentRetainsWholeLargeBlob(t *testing.T) {
	const logicalLength = contract.GeneratorIntentMaxLength
	blobID, intentID := generatedVectorID(3), generatedVectorID(4)
	blob := bytes.Repeat([]byte{17}, 32<<20)
	offset := len(blob) - logicalLength
	location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentIntent,
		ContentID: intentID, BlobID: blobID, Offset: uint64(offset), Length: logicalLength,
		Digest: contract.Hash(blob[offset:])}
	s := generatedContentState(t, []generatedContentFixtureBlob{{blobID, blob}}, []contract.GeneratorSliceLocation{location})
	content, err := newGeneratedContentValidation(t.Context(), s)
	if err != nil {
		t.Fatal("complete old blob", err)
	}
	read, err := content.read(contract.GeneratorContentIntent, intentID, logicalLength)
	if err != nil || !bytes.Equal(read, blob[offset:]) || !content.complete(contract.ID{}) {
		t.Fatal("bounded intent slice did not retain and validate its whole blob", err)
	}
	if len(s.root.Generated.Fragments) != 33 {
		t.Fatal("32 MiB blob must retain all 33 fragments", len(s.root.Generated.Fragments))
	}
	rows := make([]contract.SupportRecord, 0, len(s.root.Generated.Fragments))
	for _, page := range s.support[:len(s.root.Generated.Fragments)] {
		rows = append(rows, contract.SupportRecord(page.Records[0]))
	}
	packed, err := format.PackRequiredSupportRows(s.root.Domain, []format.RequiredSupportGroup{{
		Class: format.IntentFragmentSupport, Owner: blobID, Mandatory: true, Records: rows,
	}}, 0)
	if err != nil || len(packed) != 17 {
		t.Fatal("one 384 KiB logical intent occupies 17 fragment pages", len(packed), err)
	}
	// A new operation charges the selected physical rows, not the 384 KiB
	// logical intent length. Its optional declaration needs a separate page.
	s.root.Names = []format.NameEntry{{Name: "current", Slot: 0}}
	s.pages[0] = &format.ValueEntryPage{}
	s.pages[0].Slots[0] = &format.ValueEntry{Name: "current", ValueState: generatedVectorID(5),
		ValueSource: contract.Generated, Generated: contract.GeneratedEntryMetadata{IntentDigest: intentID}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	facts, err := newGeneratedContent(s)
	if err != nil {
		t.Fatal("selected old intent facts", err)
	}
	selected := &generatedSelection{session: s, image: s.selectedImage(), content: facts, records: make(map[generatedRecordKey]contract.SupportRecord)}
	for _, page := range s.support {
		for _, view := range page.Records {
			row := contract.SupportRecord(view)
			selected.records[generatedRecordKey{kind: row.Kind, id: row.RecordID}] = row
		}
	}
	shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1,
		Secrets: 1, Memberships: 1, SecretMemberships: 1, Generated: 1, OldGenerated: 1,
		ValueEntryPlanCount: 1, DeclarationBytes: 512, OldIntentBytes: logicalLength}
	charged, err := generatedCapacityWithBacklog(shape, selected)
	if err != nil || charged[contract.GeneratorCapacityIntents].MaxCount != 34 ||
		charged[contract.GeneratorCapacityIntents].MaxPages != 18 {
		t.Fatal("physical old blob plus new declaration was not charged", charged[contract.GeneratorCapacityIntents], err)
	}
}

// full_only: false
func TestGeneratedContentReadsExactBoundedSlice(t *testing.T) {
	id := generatedVectorID
	body := bytes.Repeat([]byte{13}, contract.GeneratedFragmentMaxPayload+17)
	body[contract.GeneratedFragmentMaxPayload] = 14
	for _, offset := range []uint64{1, contract.GeneratedFragmentMaxPayload - 8} {
		location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentSource, ContentID: id(4), BlobID: id(3),
			Offset: offset, Length: 16, Digest: contract.Hash(body[offset : offset+16])}
		s := generatedContentState(t, []generatedContentFixtureBlob{{id(3), body}}, []contract.GeneratorSliceLocation{location})
		content, err := newGeneratedContentValidation(t.Context(), s)
		if err != nil {
			t.Fatal(err)
		}
		if content.complete(contract.ID{}) {
			t.Fatal("unclaimed slice accepted")
		}
		borrowed, err := content.facts.read(contract.GeneratorContentSource, id(4), 16)
		if err != nil || !bytes.Equal(borrowed, body[offset:offset+16]) || content.complete(contract.ID{}) {
			t.Fatal("pure read changed content coverage", err)
		}
		if cap(borrowed) != len(borrowed) {
			t.Fatal("bounded content span exposed extra capacity")
		}
		if offset == 1 && &borrowed[0] != &content.facts.fragments[id(3)][0].Payload[offset] {
			t.Fatal("contiguous content did not borrow authenticated bytes")
		}
		if offset != 1 {
			for _, fragment := range content.facts.fragments[id(3)] {
				start := uint64(fragment.Offset)
				if start <= offset && offset < start+uint64(len(fragment.Payload)) {
					before := fragment.Payload[offset-start]
					borrowed[0] ^= 1
					if fragment.Payload[offset-start] != before {
						t.Fatal("cross-fragment content changed authenticated fragment bytes")
					}
					borrowed[0] ^= 1
				}
			}
		}
		got, err := content.read(contract.GeneratorContentSource, id(4), 16)
		if err != nil || !bytes.Equal(got, body[offset:offset+16]) || !content.complete(contract.ID{}) {
			t.Fatal("exact slice resolution", err)
		}
		if _, err := content.read(contract.GeneratorContentSource, id(4), 15); err == nil {
			t.Fatal("slice crossed caller capacity")
		}
		if _, err := content.read(contract.GeneratorContentIntent, id(4), 16); err == nil {
			t.Fatal("slice changed family")
		}
		if _, err := content.read(contract.GeneratorContentSource, id(5), 16); err == nil {
			t.Fatal("slice changed identity")
		}
	}
}

// full_only: false
func TestGeneratedContentRejectsUnusedBlobAndWrongLogicalDescriptor(t *testing.T) {
	id := generatedVectorID
	body := []byte("content")
	location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: id(4), BlobID: id(3), Length: uint32(len(body)), Digest: contract.Hash(body)}
	s := generatedContentState(t, []generatedContentFixtureBlob{{id(3), body}, {id(5), []byte("unused")}}, []contract.GeneratorSliceLocation{location})
	content, err := newGeneratedContentValidation(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	d, err := contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{location.Logical()})
	if err != nil {
		t.Fatal(err)
	}
	bad := d
	bad.Digest = id(9)
	if _, err := content.readLogical(contract.GeneratorContentIntent, id(4), bad, 100); err == nil {
		t.Fatal("wrong immutable slice descriptor accepted")
	}
	if content.complete(id(5)) {
		t.Fatal("failed claim marked content used")
	}
	if _, err := content.readLogical(contract.GeneratorContentIntent, id(4), d, 100); err != nil {
		t.Fatal(err)
	}
	if content.complete(contract.ID{}) || content.complete(id(6)) {
		t.Fatal("unreferenced fragment retained")
	}
	if !content.complete(id(5)) {
		t.Fatal("separately checked receipt-index blob rejected")
	}
}

func generatedContentPlanFixture(t testing.TB) (contract.GeneratorPlanBundle, contract.GeneratorDeclaration, contract.GeneratedParentRecord) {
	t.Helper()
	id := generatedVectorID
	declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: id(1), OperationID: id(10), Entries: []contract.GeneratorDeclarationEntry{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain, Name: "plain", Recipients: []contract.ID{id(11)}, Payload: []byte("value")}}}
	declBytes, err := contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	view, err := contract.InspectGeneratorDeclaration(declBytes)
	if err != nil {
		t.Fatal(err)
	}
	declDescriptor, err := view.Descriptor()
	if err != nil {
		t.Fatal(err)
	}
	locations, err := view.Slices()
	if err != nil {
		t.Fatal(err)
	}
	var source contract.GeneratorDescriptor
	for _, row := range locations {
		if row.Logical.ContentKind == contract.GeneratorContentSource {
			source, err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{row.Logical})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	d := contract.GeneratorDescriptor{Digest: id(12), Length: 8, Count: 1}
	request := contract.GeneratorRequestCore{Schema: contract.GeneratorRequestCoreSchema, OperationKind: 2, DomainID: id(1), OperationID: id(10),
		PredecessorRevisionID: id(14), PredecessorHEADDigest: id(15), ConditionDigest: id(16), CallerNonce: id(17), Declaration: declDescriptor, Registry: d, CompatibilityID: contract.CompatibilityID(), RecoveryPolicyID: id(19)}
	requestDigest, err := contract.GeneratorRequestCoreDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	material, err := contract.GeneratorMaterialID(request.DomainID, request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	membership, err := contract.GeneratorIntendedMembershipDescriptor(declaration.Entries[0].Recipients)
	if err != nil {
		t.Fatal(err)
	}
	bundle := contract.GeneratorPlanBundle{Request: request, Header: contract.GeneratorGraphHeader{Schema: contract.GeneratorGraphHeaderSchema, DomainID: request.DomainID, OperationID: request.OperationID,
		MaterialID: material, RequestCoreDigest: requestDigest, RecoveryPolicyID: request.RecoveryPolicyID, ValueEntryPlanCount: 1},
		ValueEntryPlans: []contract.GeneratorValueEntryPlan{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, EntryIncarnationID: id(20), SourceSlice: source, IntendedMembership: membership, ChangeMask: 1}}}
	graph, err := contract.GeneratorGraphID(bundle.Header, bundle.ValueEntryPlans, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	uses, err := contract.GeneratorResultUsesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := contract.GeneratorSourceUsesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	bundle.UsePlan = contract.GeneratorUsePlanCore{DomainID: request.DomainID, OperationID: request.OperationID, MaterialID: material, PlanGraphID: graph, ResultUses: uses, SourceUses: sources, ValueDerivationID: contract.GeneratorValueDerivationID()}
	useDigest, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	graphDescriptor, err := contract.GeneratorPlanBundleDescriptor(bundle)
	if err != nil {
		t.Fatal(err)
	}
	intended, err := contract.GeneratorValueEntryPlansDescriptor(bundle.ValueEntryPlans)
	if err != nil {
		t.Fatal(err)
	}
	parent := contract.GeneratedParentRecord{Schema: contract.GeneratedParentSchema, DomainID: request.DomainID, OperationID: request.OperationID, RequestIdentityDigest: id(21), RequestCoreDigest: requestDigest,
		PlanGraphID: graph, UsePlanDigest: useDigest, MaterialID: material, RecoveryPolicyID: request.RecoveryPolicyID,
		ValueEntryPlanCount: 1, Declaration: declDescriptor, Registry: request.Registry, Graph: graphDescriptor, SourceUses: sources, IntendedEntryPlans: intended, Capacity: d,
		InitialPredecessorDigest: request.PredecessorHEADDigest, ConditionDigest: request.ConditionDigest}
	return bundle, declaration, parent
}

func generatedPlanContentState(t testing.TB, bundle contract.GeneratorPlanBundle, declaration contract.GeneratorDeclaration, configuration ...generatedContentFixtureBlob) *StateSession {
	t.Helper()
	id := generatedVectorID
	graph, err := contract.EncodeGeneratorPlanBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	decl, err := contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	view, err := contract.InspectGeneratorDeclaration(decl)
	if err != nil {
		t.Fatal(err)
	}
	logical, err := view.Slices()
	if err != nil {
		t.Fatal(err)
	}
	locations := []contract.GeneratorSliceLocation{{Schema: 1, ContentKind: contract.GeneratorContentGraph, ContentID: bundle.UsePlan.PlanGraphID,
		BlobID: id(31), Length: uint32(len(graph)), Digest: contract.Hash(graph)}}
	for _, row := range logical {
		locations = append(locations, contract.GeneratorSliceLocation{Schema: 1, ContentKind: row.Logical.ContentKind, ContentID: row.Logical.ContentID,
			BlobID: id(32), Offset: uint64(row.Offset), Length: row.Logical.Length, Digest: row.Logical.Digest})
	}
	blobs := []generatedContentFixtureBlob{{id(31), graph}, {id(32), decl}}
	for _, blob := range configuration {
		locations = append(locations, contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentConfiguration, ContentID: blob.id,
			BlobID: blob.id, Length: uint32(len(blob.body)), Digest: contract.Hash(blob.body)})
		blobs = append(blobs, blob)
	}
	return generatedContentState(t, blobs, locations)
}

// full_only: false
func TestGeneratedContentBindsCompleteParentGraphAndDeclaration(t *testing.T) {
	bundle, declaration, parent := generatedContentPlanFixture(t)
	s := generatedPlanContentState(t, bundle, declaration)
	content, err := newGeneratedContentValidation(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := content.parent(parent)
	if err != nil || resolved.UsePlan != bundle.UsePlan || !content.complete(contract.ID{}) {
		t.Fatal("parent content resolution", err)
	}
	for name, change := range map[string]func(*contract.GeneratedParentRecord){
		"domain":           func(v *contract.GeneratedParentRecord) { v.DomainID = generatedVectorID(99) },
		"request":          func(v *contract.GeneratedParentRecord) { v.RequestCoreDigest = generatedVectorID(99) },
		"graph":            func(v *contract.GeneratedParentRecord) { v.Graph.Digest = generatedVectorID(99) },
		"use plan":         func(v *contract.GeneratedParentRecord) { v.UsePlanDigest = generatedVectorID(99) },
		"source uses":      func(v *contract.GeneratedParentRecord) { v.SourceUses.Digest = generatedVectorID(99) },
		"intended members": func(v *contract.GeneratedParentRecord) { v.IntendedEntryPlans.Digest = generatedVectorID(99) },
		"member count":     func(v *contract.GeneratedParentRecord) { v.ValueEntryPlanCount++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := parent
			change(&bad)
			c, err := newGeneratedContentValidation(t.Context(), s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.parent(bad); err == nil {
				t.Fatal("independent parent assertion accepted")
			}
		})
	}
	declaration.Entries[0].Payload = []byte("changed")
	s = generatedPlanContentState(t, bundle, declaration)
	content, err = newGeneratedContentValidation(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := content.parent(parent); err == nil {
		t.Fatal("different declaration accepted under original graph")
	}
}

// full_only: false
func TestGeneratedGraphInventoryDoesNotRetainItsOwnContent(t *testing.T) {
	bundle, declaration, parent := generatedContentPlanFixture(t)
	s := generatedPlanContentState(t, bundle, declaration)
	content, err := newGeneratedContentValidation(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := content.facts.graph(parent.PlanGraphID); err == nil {
		t.Fatal("published graph lookup decoded unvalidated content")
	}
	if _, err := content.facts.graphForOperation(parent.OperationID); err == nil || len(content.facts.graphs) != 0 {
		t.Fatal("published graph inventory validated missing graph content")
	}
	graph, err := content.graphForOperation(parent.OperationID)
	if err != nil || graph.UsePlan != bundle.UsePlan {
		t.Fatal("graph inventory", err)
	}
	if len(content.claimed) != 0 || content.complete(contract.ID{}) {
		t.Fatal("graph inventory became a live root")
	}
	published := &generatedSelection{content: content.facts}
	if _, err := published.retainedGraph(parent.OperationID); err == nil || len(published.bundles) != 0 {
		t.Fatal("published retained graph lookup added an unselected bundle")
	}
	if _, err := content.graphForOperation(generatedVectorID(99)); err == nil {
		t.Fatal("foreign operation found a graph")
	}
	if _, err := content.parent(parent); err != nil || !content.complete(contract.ID{}) {
		t.Fatal("actual parent did not claim cached graph", err)
	}
}

// full_only: false
func TestGeneratedContentGraphCacheRequiresExactLogicalContent(t *testing.T) {
	bundle, declaration, parent := generatedContentPlanFixture(t)
	firstState := generatedPlanContentState(t, bundle, declaration)
	first, err := newGeneratedContentValidation(t.Context(), firstState)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.parent(parent); err != nil {
		t.Fatal("initial graph validation", err)
	}
	cached := maps.Clone(first.facts.graphs)
	validated := cached[parent.PlanGraphID]

	reusedState := generatedPlanContentState(t, bundle, declaration)
	reusedState.generatedGraphs = cached
	reused, err := newGeneratedContentValidation(t.Context(), reusedState)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reused.parent(parent)
	stored := reused.facts.graphs[parent.PlanGraphID]
	if err != nil || len(got.ValueEntryPlans) == 0 || len(stored.bundle.ValueEntryPlans) == 0 ||
		&stored.bundle.ValueEntryPlans[0] != &validated.bundle.ValueEntryPlans[0] || &got.ValueEntryPlans[0] == &stored.bundle.ValueEntryPlans[0] {
		t.Fatal("exact authenticated graph did not reuse validation", err)
	}
	got.ValueEntryPlans[0].Name = "changed"
	again, err := reused.parent(parent)
	if err != nil || again.ValueEntryPlans[0].Name == "changed" {
		t.Fatal("caller-owned graph container changed cached facts", err)
	}

	for name, change := range map[string]func(*validatedGeneratorGraph){
		"logical digest": func(v *validatedGeneratorGraph) { v.logical.Digest[0] ^= 1 },
		"domain":         func(v *validatedGeneratorGraph) { v.bundle.Header.DomainID[0] ^= 1 },
		"graph identity": func(v *validatedGeneratorGraph) { v.bundle.UsePlan.PlanGraphID[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changedCache := maps.Clone(cached)
			changed := changedCache[parent.PlanGraphID]
			change(&changed)
			changedCache[parent.PlanGraphID] = changed
			checkedState := generatedPlanContentState(t, bundle, declaration)
			checkedState.generatedGraphs = changedCache
			checked, err := newGeneratedContentValidation(t.Context(), checkedState)
			if err != nil {
				t.Fatal(err)
			}
			got, err := checked.parent(parent)
			stored := checked.facts.graphs[parent.PlanGraphID]
			if err != nil || len(got.ValueEntryPlans) == 0 || len(stored.bundle.ValueEntryPlans) == 0 ||
				&stored.bundle.ValueEntryPlans[0] == &changed.bundle.ValueEntryPlans[0] ||
				stored.logical != first.facts.graphs[parent.PlanGraphID].logical ||
				stored.bundle.Header.DomainID != bundle.Header.DomainID ||
				stored.bundle.UsePlan.PlanGraphID != parent.PlanGraphID {
				t.Fatal("changed graph identity reused cached validation", err)
			}
		})
	}
}
