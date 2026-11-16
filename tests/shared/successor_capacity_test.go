package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// The old intent remains owned by the real retained delete Hazard. Its blob
// also holds a current peer intent. Each exclusive current fragment shares a
// physical page with this mandatory peer, so compaction releases no page.
func successorWrappedCapacityState(t *testing.T, intentCount int) *StateSession {
	t.Helper()
	s, _, _, _ := generatedDeleteHazardForOperation(t, contract.Hash([]byte("capacity history operation")), 0)
	type relocation struct {
		blob   contract.ID
		offset uint64
	}
	relocated := make(map[generatedContentKey]relocation)
	physical := make(map[contract.ID][]byte)
	states := []*StateSession{s}
	exclusive, shared := generatedVectorID(120), generatedVectorID(121)
	var exclusiveBody []byte
	for i := 0; i < intentCount; i++ {
		settings := append([]byte{'"'}, bytes.Repeat([]byte{byte('a' + i)}, contract.GeneratorIntentMaxLength-73)...)
		settings = append(settings, '"')
		intent := generatedFixtureCanonicalIntent(t, settings, generatedFixtureProfile{LifecycleMode: contract.GeneratorLifecycleManaged, ConfigContractID: generatedVectorID(18), ResourceContractID: generatedVectorID(7)})
		if len(intent) != contract.GeneratorIntentMaxLength {
			t.Fatal("complete current Intent is not at its maximum", len(intent))
		}
		name := fmt.Sprintf("capacity-%02d", i)
		state := generatedSelectedEntryOriginWithIntent(t, contract.Hash([]byte("operation "+name)),
			contract.Hash([]byte("incarnation "+name)), 0, name, generatedVectorID(18), generatedVectorID(12),
			contract.Hash([]byte("token "+name)), contract.Hash([]byte("generation "+name)), exclusive, intent)
		states = append(states, state)
		id, err := contract.GeneratorIntentDigest(intent)
		if err != nil {
			t.Fatal(err)
		}
		relocated[generatedContentKey{contract.GeneratorContentIntent, id}] = relocation{exclusive, uint64(len(exclusiveBody))}
		exclusiveBody = append(exclusiveBody, intent...)
	}
	physical[exclusive] = exclusiveBody
	peerIntent := generatedFixtureCanonicalIntent(t, []byte(`"current peer"`), generatedFixtureProfile{LifecycleMode: contract.GeneratorLifecycleManaged, ConfigContractID: generatedVectorID(18), ResourceContractID: generatedVectorID(7)})
	oldIntent := generatedFixtureCanonicalIntent(t, []byte("{}"), generatedFixtureProfile{LifecycleMode: contract.GeneratorLifecycleManaged, ConfigContractID: generatedVectorID(9), ResourceContractID: generatedVectorID(7)})
	if len(oldIntent) != 73 || len(peerIntent) != 85 {
		t.Fatal("retained and peer canonical Intent lengths differ", len(oldIntent), len(peerIntent))
	}
	peer := generatedSelectedEntryOriginWithIntent(t, contract.Hash([]byte("peer operation")), contract.Hash([]byte("peer incarnation")),
		0, "capacity-peer", generatedVectorID(18), generatedVectorID(12), contract.Hash([]byte("peer token")),
		contract.Hash([]byte("peer generation")), shared, peerIntent)
	states = append(states, peer)
	// Retain the authority binding used by the Hazard's operation-seed wrap.
	s.recipients[0].Slots[1] = peer.recipientRecord(generatedVectorID(26))
	oldID, err := contract.GeneratorIntentDigest(oldIntent)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := contract.GeneratorIntentDigest(peerIntent)
	if err != nil {
		t.Fatal(err)
	}
	relocated[generatedContentKey{contract.GeneratorContentIntent, oldID}] = relocation{shared, 0}
	relocated[generatedContentKey{contract.GeneratorContentIntent, peerID}] = relocation{shared, uint64(len(oldIntent))}
	fragmentCount := (len(exclusiveBody) + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
	sharedBody := bytes.Repeat([]byte{99}, (fragmentCount-1)*contract.GeneratedFragmentMaxPayload+1)
	copy(sharedBody, oldIntent)
	copy(sharedBody[len(oldIntent):], peerIntent)
	physical[shared] = sharedBody
	var rows []contract.SupportRecord
	var locations []contract.GeneratorSliceLocation
	var bundles []contract.GeneratorPlanBundle
	var graphs []contract.ID
	var access []contract.AccessRecord
	seenContent := make(map[generatedContentKey]bool)
	seenRows := make(map[generatedRecordKey]bool)
	s.pages = [contract.MaxValueEntryPages]*format.ValueEntryPage{}
	s.root.Names = nil
	for _, state := range states {
		selected, err := state.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal("capacity source selection", err)
		}
		bundles = append(bundles, selected.bundles...)
		for key, location := range selected.content.locations {
			if seenContent[key] {
				continue
			}
			seenContent[key] = true
			body, err := selected.readSelectedSlice(t.Context(), key.kind, key.id, location.Length)
			if err != nil {
				t.Fatal("capacity selected content", err)
			}
			location.BlobID, location.Offset = contract.Hash(body), 0
			if moved, ok := relocated[key]; ok {
				location.BlobID, location.Offset = moved.blob, moved.offset
			} else {
				physical[location.BlobID] = body
			}
			locations = append(locations, location)
			if key.kind == contract.GeneratorContentGraph {
				graphs = append(graphs, key.id)
			}
		}
		for _, row := range state.supportRecords() {
			if row.Kind == contract.GeneratedFragmentSupportKind || row.Kind == contract.OutputConfigurationSliceSupportKind {
				continue
			}
			if row.Kind == contract.GeneratorVectorSupportKind {
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if carrier.OwnerKind == contract.GeneratorSnapshotOwner {
					continue
				}
			}
			key := generatedRecordKey{row.Kind, row.RecordID}
			if !seenRows[key] {
				rows = append(rows, row)
				seenRows[key] = true
			}
		}
		access = append(access, state.accessRecords()...)
		for _, name := range state.root.Names {
			entry := state.valueEntry(name.Slot)
			slot := len(s.root.Names)
			page := slot / format.PageSlots
			if s.pages[page] == nil {
				s.pages[page] = &format.ValueEntryPage{}
			}
			s.pages[page].Slots[slot%format.PageSlots] = entry
			s.root.Names = append(s.root.Names, format.NameEntry{Name: entry.Name, Slot: uint16(slot)})
		}
	}
	var blobs []generatedContentFixtureBlob
	for id, body := range physical {
		blobs = append(blobs, generatedContentFixtureBlob{id: id, body: body})
	}
	slices.SortFunc(blobs, func(a, b generatedContentFixtureBlob) int { return bytes.Compare(a.id[:], b.id[:]) })
	content := generatedContentStateAtSnapshot(t, s.root.Snapshot, blobs, locations)
	s.support = content.support
	s.root.Generated.Fragments, s.root.Generated.Slices = content.root.Generated.Fragments, content.root.Generated.Slices
	s.root.Generated.GeneratedCurrent = uint32(len(s.root.Names))
	s.root.ValueEntryCount = uint32(len(s.root.Names))
	generatedRefreshClosureCounts(&s.root.Generated, rows)
	slices.SortFunc(graphs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, graphs)
	if err != nil {
		t.Fatal(err)
	}
	s.access = [contract.MaxChildPages]*format.AccessPage{}
	s.access[0] = &format.AccessPage{Records: access}
	for _, row := range rows {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	t.Log("capacity fixture: merge selected support")
	generatedRepackSupportAtLocations(t, s, s.supportRecords(), bundles, locations)
	generatedSealSelectedFixture(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("capacity material index")
	}
	if _, err := s.selectedGeneratedWork(context.Background()); err != nil {
		t.Fatal("capacity complete selected ownership", err)
	}
	successorCapacityPairFragments(t, s, exclusive, shared, fragmentCount)
	return s
}

func successorCapacityPairFragments(t *testing.T, s *StateSession, exclusive, shared contract.ID, fragmentCount int) {
	t.Helper()
	var left, right []contract.SupportRecordView
	var kept []format.RequiredSupportPageView
	for _, page := range s.support {
		selected := 0
		for _, row := range page.Records {
			if row.Kind != contract.GeneratedFragmentSupportKind {
				continue
			}
			f, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if f.BlobID == exclusive {
				left = append(left, row)
				selected++
			}
			if f.BlobID == shared {
				right = append(right, row)
				selected++
			}
		}
		if selected == 0 {
			kept = append(kept, page)
		} else if selected != len(page.Records) {
			t.Fatal("paired reconstruction would remove an unrelated fragment")
		}
	}
	if len(left) != fragmentCount || len(right) != fragmentCount {
		t.Fatal("expected derived fragment count in each physical blob", len(left), len(right), fragmentCount)
	}
	sortFragments := func(rows []contract.SupportRecordView) {
		slices.SortFunc(rows, func(a, b contract.SupportRecordView) int {
			fa, _ := contract.InspectGeneratedFragment(a.Body)
			fb, _ := contract.InspectGeneratedFragment(b.Body)
			return int(fa.Index) - int(fb.Index)
		})
	}
	sortFragments(left)
	sortFragments(right)
	s.support = kept
	for i := range left {
		index := generatedFixtureFreeSupportIndex(t, s)
		s.support = append(s.support, format.RequiredSupportPageView{Domain: s.root.Domain,
			Object: contract.Hash([]byte(fmt.Sprintf("capacity paired fragment/%d", i))), Index: index,
			Records: []contract.SupportRecordView{left[i], right[i]}})
	}
	slices.SortFunc(s.support, func(a, b format.RequiredSupportPageView) int { return int(a.Index) - int(b.Index) })
	s.root.Generated.Fragments = nil
	for _, page := range s.support {
		for slot, row := range page.Records {
			if row.Kind != contract.GeneratedFragmentSupportKind {
				continue
			}
			f, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			s.root.Generated.Fragments = append(s.root.Generated.Fragments, format.FragmentLocation{BlobID: f.BlobID,
				FragmentIndex: f.Index, SupportPageIndex: page.Index, RowSlot: uint8(slot)})
		}
	}
	slices.SortFunc(s.root.Generated.Fragments, func(a, b format.FragmentLocation) int {
		if n := bytes.Compare(a.BlobID[:], b.BlobID[:]); n != 0 {
			return n
		}
		return int(a.FragmentIndex) - int(b.FragmentIndex)
	})
	t.Log("capacity fixture: seal paired physical fragments")
	generatedSealSelectedFixture(t, s)
	if _, err := s.selectedGeneratedWork(context.Background()); err != nil {
		t.Fatal("paired fragment selection", err)
	}
}

func successorCapacityPublicationRows(t *testing.T, s *StateSession) {
	t.Helper()
	_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, s.root.Domain)
	coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
	rows := publicationRelationRows(t, coordinate, marker)
	// The exact coordinate rewrite retains the configuration peer's page.
	configuration := -1
	for i, page := range s.support {
		if len(page.Records) == 1 && page.Records[0].Kind == contract.OutputConfigurationSliceSupportKind {
			configuration = i
			break
		}
	}
	if configuration < 0 {
		t.Fatal("isolated configuration peer missing")
	}
	s.support[configuration].Records = append(s.support[configuration].Records, contract.SupportRecordView(rows[0]))
	// A separate coordinate's marker keeps the selected marker page after exit.
	other := coordinate
	other.CanonicalTarget = "capacity/peer"
	var err error
	other.CoordinateID, err = contract.PublicationCoordinateID(s.root.Domain, other.ServiceContractID, other.CanonicalTarget)
	if err != nil {
		t.Fatal(err)
	}
	other.CurrentPublicationIncarnationID = contract.Hash([]byte("capacity peer publication incarnation"))
	other.LatestUnresolvedAttemptID = contract.Hash([]byte("capacity peer publication attempt"))
	peer := marker
	peer.AttemptID, peer.CoordinateID, peer.PublicationIncarnationID = other.LatestUnresolvedAttemptID, other.CoordinateID, other.CurrentPublicationIncarnationID
	peer.OperationID = contract.Hash([]byte("capacity peer publication operation"))
	peer.Projection.CoordinateID = other.CoordinateID
	peer.ProjectionCommitment, err = contract.PublicationProjectionCommitment(peer.Projection)
	if err != nil {
		t.Fatal(err)
	}
	otherRows := publicationRelationRows(t, other, peer)
	appendPage := func(records []contract.SupportRecordView, label string) {
		s.support = append(s.support, format.RequiredSupportPageView{Domain: s.root.Domain, Object: contract.Hash([]byte(label)),
			Index: generatedFixtureFreeSupportIndex(t, s), Records: records})
		slices.SortFunc(s.support, func(a, b format.RequiredSupportPageView) int { return int(a.Index) - int(b.Index) })
	}
	appendPage([]contract.SupportRecordView{contract.SupportRecordView(otherRows[0])}, "capacity peer coordinate page")
	appendPage([]contract.SupportRecordView{contract.SupportRecordView(rows[1]), contract.SupportRecordView(otherRows[1])}, "capacity shared marker page")
	t.Log("capacity fixture: refresh publication peers")
	generatedRefreshSupport(t, s)
	// Retired coordinates are complete typed rows. Recipient replacement keeps
	// their existing physical pages; ordinary preparation repacks these rows.
	// Empty history needs two new mandatory pages for the replacement receipt
	// and its ordered index. Keep the candidate at the ordinary maximum.
	const predecessorChildren = ordinaryChildPageLimit - 2
	paddingPages := int(predecessorChildren - s.root.ChildCount)
	for i := 0; i < paddingPages; i++ {
		padding := coordinate
		padding.CanonicalTarget = fmt.Sprintf("capacity/padding/%d", i)
		padding.CoordinateID, err = contract.PublicationCoordinateID(s.root.Domain, padding.ServiceContractID, padding.CanonicalTarget)
		if err != nil {
			t.Fatal(err)
		}
		padding.OwnerState, padding.LatestUnresolvedAttemptID = contract.PublicationOwnerNone, contract.ID{}
		padding.CurrentPublicationIncarnationID = contract.Hash([]byte(fmt.Sprintf("capacity padding incarnation/%d", i)))
		body, err := contract.EncodePublicationCoordinate(padding)
		if err != nil {
			t.Fatal(err)
		}
		appendPage([]contract.SupportRecordView{{Kind: contract.PublicationCoordinateSupportKind, RecordID: padding.CoordinateID, Body: body}}, fmt.Sprintf("capacity padding page/%d", i))
	}
	t.Log("capacity fixture: refresh exact child margin")
	generatedRefreshSupport(t, s)
	if s.root.ChildCount != predecessorChildren {
		t.Fatal("exact receipt-bearing ordinary child margin", s.root.ChildCount)
	}
}

func successorCapacityColdSelection(t *testing.T, s *StateSession) (*StateSession, *memoryStore, *fixtureTrust, *custody.Fixture) {
	t.Helper()
	basis := generatedEmptyPredecessorForFamily(t, contract.GCP)
	trust := &fixtureTrust{Signer: testtrust.New(t, contract.GCP, generatedVectorID(75))}
	keys := custody.New(t, contract.GCP, contract.Hash([]byte("capacity custody")), false, []contract.ID{basis.admission.recipient, generatedVectorID(26)})
	s.admission = basis.admission
	s.token, s.body = basis.token, bytes.Clone(basis.body)
	s.admission.composition = contract.Hash([]byte("capacity composition"))
	s.admission.expires = time.Now().Add(time.Hour)
	s.admission.store.HeadKey = s.admission.store.Prefix + "/HEAD"
	s.root.CurrentAccess.Core = basis.root.CurrentAccess.Core
	s.recipients = [contract.MaxRecipientPages]*format.RecipientPage{}
	page := &format.RecipientPage{}
	for i, row := range keys.Bindings() {
		binding := row.Binding
		page.Slots[i] = &contract.RecipientRecord{RecipientID: row.SubjectID, Status: contract.CurrentRecipient, CurrentBinding: &binding}
	}
	s.recipients[0] = page
	descriptor, err := contract.DecodeGenesisDescriptorCore(s.admission.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Recipients = nil
	for _, row := range page.Slots {
		if row != nil {
			descriptor.Recipients = append(descriptor.Recipients, *row)
		}
	}
	s.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	readers := []contract.ID{s.admission.recipient, generatedVectorID(26)}
	slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	var access []contract.AccessRecord
	makeWraps := func(readers []contract.ID) []contract.WrapRow {
		var wraps []contract.WrapRow
		for _, id := range readers {
			binding := s.recipientRecord(id).CurrentBinding
			digest, err := contract.PublicBindingDigest(*binding)
			if err != nil {
				t.Fatal(err)
			}
			wraps = append(wraps, contract.WrapRow{SubjectKind: 1, SubjectID: id, BindingID: binding.BindingID, BindingSerial: binding.BindingSerial,
				PublicBindingDigest: digest, RSACiphertext: bytes.Repeat([]byte{68}, 384)})
		}
		return wraps
	}
	for _, name := range s.root.Names {
		entry := s.valueEntry(name.Slot)
		entry.Recipients = slices.Clone(readers)
		payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
		if err != nil {
			t.Fatal(err)
		}
		payload.CryptoSupportID = contract.CryptoSupportID()
		entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		core, err := contract.ValueCoreForEntry(s.root.Domain, contract.CompatibilityID(), *entry)
		if err != nil {
			t.Fatal(err)
		}
		contextID, err := contract.ValueMaterialContextDigest(core)
		if err != nil {
			t.Fatal(err)
		}
		access = append(access, contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: entry.ValueState,
			MaterialContextDigest: contextID, PackageCheck: payload.PackageCheck, Wraps: makeWraps(readers)})
	}
	for i := range s.support {
		for j, row := range s.support[i].Records {
			if row.Kind != contract.OperationMaterialSupportKind {
				continue
			}
			material, err := contract.DecodeOperationMaterialRecord(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			material.Core.CompatibilityID, material.Core.CryptoSupportID = contract.CompatibilityID(), contract.CryptoSupportID()
			s.support[i].Records[j].Body, err = contract.EncodeOperationMaterialRecord(material)
			if err != nil {
				t.Fatal(err)
			}
			contextID, err := contract.OperationMaterialContextDigest(material.Core)
			if err != nil {
				t.Fatal(err)
			}
			access = append(access, contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.OperationSeedMaterialKind,
				MaterialID: material.Core.OperationMaterialID, MaterialContextDigest: contextID, PackageCheck: material.SeedCheck,
				Wraps: makeWraps([]contract.ID{s.admission.recipient})})
		}
	}
	s.access = [contract.MaxChildPages]*format.AccessPage{}
	s.access[0] = &format.AccessPage{Records: access}
	t.Log("capacity fixture: seal cold-selection metadata")
	generatedSealSelectedFixture(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("cold capacity material index")
	}
	successorCapacityPublicationRows(t, s)
	generatedSealSelectedFixture(t, s)
	store := &memoryStore{desc: s.admission.store, objects: make(map[string]stored)}
	put := func(ref format.Ref, body []byte) { store.put(mustKey(t, store.desc.Prefix, ref), body) }
	for i, page := range s.pages {
		if page != nil {
			body, err := format.EncodeValueEntryPage(*page)
			if err != nil {
				t.Fatal(err)
			}
			put(*s.root.ValueEntryPages[i], body)
		}
	}
	for i, page := range s.recipients {
		if page != nil {
			body, err := format.EncodeRecipientPage(*page)
			if err != nil {
				t.Fatal(err)
			}
			put(*s.root.Recipients[i], body)
		}
	}
	for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
		body, err := format.EncodeAccessPage(*s.access[ref.Index])
		if err != nil {
			t.Fatal(err)
		}
		put(ref, body)
	}
	for i, page := range s.support {
		var rows []contract.SupportRecord
		for _, row := range page.Records {
			rows = append(rows, contract.SupportRecord(row))
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		if err != nil {
			t.Fatal(err)
		}
		put(s.root.RequiredSupport[i], body)
	}
	shards, err := format.EncodeAdministrativeIndexPages(s.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range shards {
		put(shard.Ref, shard.Body)
	}
	body, err := format.EncodeRoot(s.root)
	if err != nil {
		t.Fatal(err)
	}
	put(s.head.Core.Root, body)
	s.head = basis.head
	s.head.Core.Root, err = format.Reference(contract.RootKind, s.root.Domain, s.root.Snapshot, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	p := transitionPlan{operation: contract.Hash([]byte("capacity selected operation")), revision: contract.Hash([]byte("capacity selected revision")), snapshot: s.root.Snapshot, transition: s.root.Transition}
	rows, _, err := buildEntryIntent(s.root.Domain, s.currentEntryInputs())
	if err != nil {
		t.Fatal("capacity selected ordinary intent", err)
	}
	desired, err := contract.CompleteApplyIntentDescriptor(s.root.Domain, rows, currentApplyRecipients(s.registry()))
	if err != nil {
		t.Fatal("capacity selected ordinary intent recipients", err)
	}
	if s.root.ValueEntryPages[0] == nil {
		t.Fatal("capacity selected value-page identity missing")
	}
	p.pages[0] = s.root.ValueEntryPages[0].Object
	c := &Comparison{session: s, desired: desired.Digest, desiredLength: desired.Length}
	authority, err := s.authorityFrom(s, c, p)
	if err != nil {
		t.Fatal(err)
	}
	rootRef := s.head.Core.Root
	s.head = format.Head{Core: s.successorCore(p), AuthKind: format.LifecycleAuth, Subject: authority.subject()}
	s.head.Core.Root = rootRef
	bindingRequest, err := contract.NewBindingRequest(s.root.CurrentAccess.Core.NormalSigning.Binding)
	if err != nil {
		t.Fatal(err)
	}
	k1 := trust.Sign(t.Context(), bindingRequest)
	if k1.Reason != contract.ReasonNone || len(k1.Signature) == 0 {
		t.Fatal("capacity K1 proof", k1.Reason)
	}
	s.head.K1 = k1.Signature
	storeHead(t, &fixture{store: store, trust: trust}, s.head, true)
	selected, result := Open(context.Background(), OpenContext{admission: &s.admission}, store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold public capacity predecessor", result)
	}
	return selected, store, trust, keys
}

// full_only: false
func TestRecipientReplacementPreservesWrappedEndWorkCapacityCause(t *testing.T) {
	for _, tc := range []struct {
		intents int
		fits    bool
	}{
		{21, true},
		{22, false},
	} {
		t.Run(fmt.Sprintf("maximum_intents_%d", tc.intents), func(t *testing.T) {
			s, store, trust, keys := successorCapacityColdSelection(t, successorWrappedCapacityState(t, tc.intents))
			if s.root.ChildCount != 250 || s.root.Generated.GeneratedCurrent != uint32(tc.intents+1) ||
				s.root.Generated.SuccessWindow.Count != 0 || s.root.Generated.FailureWindow.Count != 0 {
				t.Fatal("capacity predecessor child or current-entry boundary", s.root.ChildCount, s.root.Generated.GeneratedCurrent)
			}
			reader := generatedVectorID(26)
			successor := keys.RecipientSuccessor(t, reader)
			intent := contract.RecipientReplacementIntent{RecipientReplacementIntentFields: contract.RecipientReplacementIntentFields{
				Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(),
				DomainID: s.root.Domain, BeforeAccessRoot: s.root.CurrentAccess.AccessRoot, RecipientID: reader},
				Before: *s.recipientRecord(reader).CurrentBinding, Successor: successor}
			plan, ok := s.planRecipientReplacement(t.Context(), intent)
			if !ok {
				t.Fatal("recipient replacement public identity plan refused")
			}
			public, private := keys.Calls()
			creates, cas, signs := store.creates, store.cas, trust.signs
			before := generatedSuccessorPredecessorSnapshot(t, s)
			current := generatedContinuationContext(t, s, 220, 221)
			current.OperationClass = contract.CryptoAccessReplacementClass
			q, request, rows, err := s.replacementRequest(t.Context(), intent, plan, current)
			if err != nil {
				t.Fatal("public replacement request", err)
			}
			subjects, err := s.recipientReplacementSubjects(t.Context(), intent, rows)
			if err != nil {
				t.Fatal("complete changed material owners", err)
			}
			requestDigest, err := contract.RequestDigest(request)
			if err != nil || requestDigest != q.Context.IntentDescriptor.Digest {
				t.Fatal("exact replacement request descriptor", err)
			}
			// Every maximum-size current Intent plus the 85-byte canonical peer
			// must move to the compact mandatory blob. No paired old fragment,
			// Access page or administrative shard is released. The replacement's
			// two receipt/index pages are filtered before the first EndWork adds
			// its two pages: 252 + 2 - 2 + 4 = 256, then +5 = 257.
			intentBytes := uint64(tc.intents)*contract.GeneratorIntentMaxLength + 85
			fragments := (intentBytes + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
			compactPages := (fragments + 1) / 2
			firstExitChildren := uint64(252+2-2) + compactPages
			if tc.fits && firstExitChildren != 256 || !tc.fits && firstExitChildren != 257 {
				t.Fatal("independent first-exit child limit", firstExitChildren)
			}
			if tc.fits && (intentBytes != 8257621 || fragments != 8 || compactPages != 4) ||
				!tc.fits && (intentBytes != 8650837 || fragments != 9 || compactPages != 5) {
				t.Fatal("independent adjacent compact-Intent boundary", intentBytes, fragments, compactPages)
			}
			projected, err := s.projectedRecipientReplacementRoot(t.Context(), plan, subjects, requestDigest)
			if tc.fits {
				if err != nil || projected.ChildCount != 252 {
					t.Fatal("adjacent fitting first-EndWork image refused", projected.ChildCount, err)
				}
			} else {
				if !errors.Is(err, contract.ErrRecordCapacity) || err == contract.ErrRecordCapacity {
					t.Fatal("actual wrapped first-EndWork capacity producer", err)
				}
				permit := admitReaderReplacement(t, s, keys, reader, successor)
				candidate, result := s.PrepareRecipientReplacement(t.Context(), permit, trust)
				if candidate != nil || result != refused(CapacityExceeded) || permit.used {
					t.Fatal("wrapped capacity must keep its public result without consuming admission", result)
				}
			}
			afterPublic, afterPrivate := keys.Calls()
			if store.creates != creates || store.cas != cas || trust.signs != signs || afterPublic != public || afterPrivate != private || !bytes.Equal(before, generatedSuccessorPredecessorSnapshot(t, s)) {
				t.Fatal("capacity projection performed a private, Store or Trust effect, consumed permission, or changed its predecessor")
			}
		})
	}
}
