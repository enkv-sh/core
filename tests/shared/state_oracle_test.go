package core

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// stateImage is fixture evidence, copied before admission or successor construction.
// It is also the complete expected image passed to the cold-open child process.
type stateImage struct {
	Revision, Operation contract.ID
	RootRef             format.Ref
	Root                format.Root
	AdministrativeIndex format.AdministrativeIndex
	Support             []format.RequiredSupportPageView
	Pages               [contract.MaxValueEntryPages]*format.ValueEntryPage
	Recipient           format.RecipientPage
	Access              [contract.MaxChildPages]*format.AccessPage
}

func copyStateImage(t testing.TB, original stateImage) stateImage {
	t.Helper()
	body, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var copied stateImage
	if err := json.Unmarshal(body, &copied); err != nil {
		t.Fatal(err)
	}
	return copied
}

func fixtureStateImage(t *testing.T, f *fixture) stateImage {
	t.Helper()
	return sessionStateImage(t, f.session)
}

func sessionStateImage(t testing.TB, s *StateSession) stateImage {
	t.Helper()
	operation, ok := observedHeadOperation(s.head)
	if !ok {
		t.Fatal("selected HEAD has no operation identity")
	}
	var support []format.RequiredSupportPageView
	if s.head.AuthKind == format.GenesisAuth {
		support = s.support
	}
	return copyStateImage(t, stateImage{Revision: s.head.Core.Revision, Operation: operation, RootRef: s.head.Core.Root, Root: s.root, AdministrativeIndex: s.adminIndex, Support: support, Pages: s.pages, Recipient: s.recipient, Access: s.access})
}

func observedHeadOperation(head format.Head) (contract.ID, bool) {
	var operation contract.ID
	switch head.AuthKind {
	case format.LifecycleAuth:
		operation = head.Subject.Operation
	case format.GenesisAuth:
		if head.Genesis != nil {
			operation = head.Genesis.Subject.InitID
		}
	case format.SuccessionAuth:
		if head.Succession != nil {
			operation = head.Succession.Subject.OperationID
		}
	case format.GeneratorAuth:
		if head.Generator != nil {
			operation = head.Generator.OperationID
		}
	case format.OutputReserveAuth:
		if head.OutputReserve != nil {
			operation = head.OutputReserve.OperationID
		}
	case format.OutputCloseAuth:
		if head.OutputClose != nil {
			operation = head.OutputClose.OperationID
		}
	case format.AdministrativeAuth:
		if head.EndWork != nil {
			operation = head.EndWork.OperationID
		}
	case format.GCAuth:
		if head.GC != nil {
			operation = head.GC.OperationID
		}
	}
	return operation, !operation.IsZero()
}

func (s stateImage) entryInputs() []ApplyEntryInput {
	values := make([]ApplyEntryInput, len(s.Root.Names))
	for i, entry := range s.Root.Names {
		m := s.Pages[entry.Slot/format.PageSlots].Slots[entry.Slot%format.PageSlots]
		values[i] = ApplyEntryInput{Name: m.Name, Recipients: slices.Clone(m.Recipients), ValueSource: m.ValueSource, ConfidentialityClass: m.ConfidentialityClass, InputBytes: bytes.Clone(m.ValueBytes), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	}
	return values
}

// The oracle applies caller input to the original fixture, using admitted IDs.
// It never obtains expected records, identities or refs from buildSuccessor or a
// Candidate. Only the canonical encoders are shared when hashing expected refs.
func expectedSuccessorImage(t testing.TB, original stateImage, requested []ApplyEntryInput, inputs allocatedTransitionInputs) stateImage {
	t.Helper()
	want := copyStateImage(t, original)
	want.Revision, want.Operation = inputs.revision, inputs.operation
	want.Root.Snapshot, want.Root.Transition = inputs.snapshot, inputs.transition
	expectedOrdinarySupport(t, &want, inputs)
	indexIdentity := make([]byte, 0, len("ENKV/admin-index/v1\x00")+2*len(contract.ID{}))
	indexIdentity = append(indexIdentity, "ENKV/admin-index/v1\x00"...)
	indexIdentity = append(indexIdentity, want.Root.Domain[:]...)
	indexIdentity = append(indexIdentity, inputs.snapshot[:]...)
	index := want.AdministrativeIndex
	index.Domain, index.Object, index.SliceSnapshot = want.Root.Domain, contract.Hash(indexIdentity), inputs.snapshot
	indexPages, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil || len(indexPages) != 1 {
		t.Fatal("expected administrative index:", err)
	}
	want.Root.AdministrativeIndex = indexPages[0].Ref
	want.Root.AdministrativeIndexShards = make([]format.Ref, 0)
	want.AdministrativeIndex = index
	want.Root.RawBytes, want.Root.ValueEntryCount, want.Root.ChildCount = 0, uint32(len(requested)), 1+uint32((int(original.Root.RecipientCount)+7)/8)+uint32(len(want.Root.RequiredSupport))
	want.Root.MembershipCount = uint32(len(requested))
	want.Root.Names = make([]format.NameEntry, 0, len(requested))
	var occupied [contract.MaxValueEntryPages * format.PageSlots]bool
	before := make(map[string]format.NameEntry, len(original.Root.Names))
	for _, entry := range original.Root.Names {
		before[entry.Name] = entry
	}
	values := append([]ApplyEntryInput(nil), requested...)
	sort.Slice(values, func(i, j int) bool { return values[i].Name < values[j].Name })
	for i, value := range values {
		if i > 0 && values[i-1].Name == value.Name {
			t.Fatal("duplicate oracle request name")
		}
		if entry, retained := before[value.Name]; retained {
			occupied[entry.Slot] = true
		}
	}
	var nextPages [contract.MaxValueEntryPages]*format.ValueEntryPage
	changed, added := 0, 0
	for _, value := range values {
		entry, retained := before[value.Name]
		var valueEntry format.ValueEntry
		if retained {
			valueEntry = *original.Pages[entry.Slot/format.PageSlots].Slots[entry.Slot%format.PageSlots]
			if !slices.Equal(value.Recipients, valueEntry.Recipients) || value.ValueSource != valueEntry.ValueSource || value.ConfidentialityClass != valueEntry.ConfidentialityClass {
				t.Fatal("oracle request changed retained member tags or recipient")
			}
			if _, unexpected := inputs.incarnations[entry.Slot]; unexpected {
				t.Fatal("retained member received a new incarnation")
			}
		} else {
			slot := 0
			for slot < len(occupied) && occupied[slot] {
				slot++
			}
			if slot == len(occupied) {
				t.Fatal("oracle successor exceeds slot capacity")
			}
			entry = format.NameEntry{Name: value.Name, Slot: uint16(slot)}
			occupied[slot] = true
			incarnation, admitted := inputs.incarnations[entry.Slot]
			if !admitted || incarnation.IsZero() {
				t.Fatal("addition lacks an admitted incarnation")
			}
			valueEntry = format.ValueEntry{Name: value.Name, Incarnation: incarnation, Recipients: slices.Clone(value.Recipients), ValueSource: value.ValueSource, ConfidentialityClass: value.ConfidentialityClass, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
			added++
		}
		valueID, admitted := inputs.values[entry.Slot]
		if !retained || valueEntry.InputEncoding != value.InputEncoding || !bytes.Equal(valueEntry.ValueBytes, value.InputBytes) {
			if !admitted || valueID.IsZero() {
				t.Fatalf("missing admitted value ID at slot %d", entry.Slot)
			}
			valueEntry.ValueState, valueEntry.OriginSnapshot, valueEntry.OriginTransition = valueID, inputs.snapshot, inputs.transition
			changed++
		} else if admitted {
			t.Fatalf("admitted value ID for unchanged slot %d", entry.Slot)
		}
		valueEntry.ValueBytes = bytes.Clone(value.InputBytes)
		valueEntry.InputEncoding, valueEntry.OutputEncoding = value.InputEncoding, value.OutputEncoding
		valueEntry.ContentLength, valueEntry.RetainedLength = uint32(len(value.InputBytes)), uint32(len(value.InputBytes))
		switch value.InputEncoding {
		case contract.InputEncodingRaw:
		case contract.InputEncodingBase64:
			decoded, err := base64.StdEncoding.Strict().DecodeString(string(value.InputBytes))
			if err != nil {
				t.Fatal("oracle input representation:", err)
			}
			valueEntry.ContentLength = uint32(len(decoded))
			clear(decoded)
		default:
			t.Fatal("oracle input encoding refused")
		}
		pageIndex := entry.Slot / format.PageSlots
		if nextPages[pageIndex] == nil {
			nextPages[pageIndex] = &format.ValueEntryPage{Domain: want.Root.Domain, Index: pageIndex}
		}
		nextPages[pageIndex].Slots[entry.Slot%format.PageSlots] = &valueEntry
		want.Root.Names = append(want.Root.Names, entry)
		want.Root.RawBytes += uint64(valueEntry.ContentLength)
	}
	if changed != len(inputs.values) || added != len(inputs.incarnations) {
		t.Fatal("admitted member identities do not match the requested changes")
	}
	for i, page := range nextPages {
		if page == nil {
			if !inputs.valueEntryPages[i].IsZero() {
				t.Fatalf("admitted page ID for absent successor page %d", i)
			}
			want.Pages[i], want.Root.ValueEntryPages[i] = nil, nil
			continue
		}
		want.Root.ChildCount++
		unchanged := original.Pages[i] != nil
		for j, valueEntry := range page.Slots {
			if !unchanged {
				break
			}
			old := original.Pages[i].Slots[j]
			if valueEntry == nil || old == nil {
				unchanged = valueEntry == old
			} else {
				unchanged = entriesEqual(*valueEntry, *old)
			}
		}
		if unchanged {
			if !inputs.valueEntryPages[i].IsZero() {
				t.Fatalf("admitted page ID for unchanged page %d", i)
			}
			continue
		}
		if inputs.valueEntryPages[i].IsZero() {
			t.Fatalf("missing admitted page ID for changed page %d", i)
		}
		page.Object = inputs.valueEntryPages[i]
		body, err := format.EncodeValueEntryPage(*page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(format.ValueEntryPageKind, want.Root.Domain, page.Object, uint16(i), body)
		if err != nil {
			t.Fatal(err)
		}
		want.Pages[i], want.Root.ValueEntryPages[i] = page, &ref
	}
	want.Root.ChildEncodedBytes = uint64(want.Root.AdministrativeIndex.Length)
	for _, ref := range want.Root.RequiredSupport {
		want.Root.ChildEncodedBytes += uint64(ref.Length)
	}
	for _, table := range [][]*format.Ref{want.Root.ValueEntryPages[:], want.Root.Recipients[:]} {
		for _, ref := range table {
			if ref != nil {
				want.Root.ChildEncodedBytes += uint64(ref.Length)
			}
		}
	}
	body, err := format.EncodeRoot(want.Root)
	if err != nil {
		t.Fatal(err)
	}
	want.RootRef, err = format.Reference(format.RootKind, want.Root.Domain, inputs.snapshot, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	return want
}

// Genesis combines the empty output slice and initialization receipt. The first
// ordinary transition separates their storage classes and retains the exact
// receipt-index fragment. Later ordinary transitions reuse those three pages.
func expectedOrdinarySupport(t testing.TB, want *stateImage, inputs allocatedTransitionInputs) {
	t.Helper()
	var allocated []int
	for index, id := range inputs.supportPages {
		if !id.IsZero() {
			allocated = append(allocated, index)
		}
	}
	if len(allocated) == 0 {
		return
	}
	if !slices.Equal(allocated, []int{0, 2}) || len(want.Support) != 2 || len(want.Root.RequiredSupport) != 2 ||
		len(want.AdministrativeIndex.Pages) != 2 || want.Support[0].Index != 0 || want.Support[1].Index != 1 ||
		len(want.Support[0].Records) != 2 || len(want.Support[1].Records) != 1 ||
		want.Support[1].Records[0].Kind != contract.GeneratedFragmentSupportKind {
		t.Fatal("ordinary oracle support allocation differs from the first genesis transition")
	}
	var receipt, output contract.SupportRecord
	for _, row := range want.Support[0].Records {
		switch row.Kind {
		case contract.MutationReceiptSupportKind:
			receipt = contract.SupportRecord(row)
		case contract.OutputConfigurationSliceSupportKind:
			output = contract.SupportRecord(row)
		default:
			t.Fatal("ordinary oracle genesis support contains another row")
		}
	}
	if receipt.Body == nil || receipt.RecordID.IsZero() || output.RecordID.IsZero() {
		t.Fatal("ordinary oracle genesis support evidence is incomplete")
	}
	body, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: want.Root.Domain})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, outputSlices, err := contract.SplitOutputConfiguration(want.Root.Domain, body)
	if err != nil || descriptor != want.Root.OutputConfiguration || len(outputSlices) != 1 {
		t.Fatal("ordinary oracle first genesis output is not the empty configuration")
	}
	output.Body, err = contract.EncodeOutputConfigurationSlice(outputSlices[0])
	if err != nil {
		t.Fatal(err)
	}
	id, err := contract.OutputConfigurationSliceID(want.Root.Domain, descriptor.ConfigurationDigest, 0)
	if err != nil || output.RecordID != id {
		t.Fatal("ordinary oracle genesis output identity differs")
	}
	fragment, fragmentIndex, fragmentRef := want.Support[1], want.AdministrativeIndex.Pages[1], want.Root.RequiredSupport[1]
	want.Support = make([]format.RequiredSupportPageView, 3)
	want.Root.RequiredSupport = make([]format.Ref, 3)
	want.AdministrativeIndex.Pages = make([]format.AdministrativePage, 3)
	want.Support[1], want.Root.RequiredSupport[1], want.AdministrativeIndex.Pages[1] = fragment, fragmentRef, fragmentIndex
	for _, page := range []struct {
		index uint16
		row   contract.SupportRecord
	}{{0, receipt}, {2, output}} {
		object := inputs.supportPages[page.index]
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: want.Root.Domain, Object: object, Index: page.index, Records: []contract.SupportRecord{page.row}})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, want.Root.Domain, object, page.index, body)
		if err != nil {
			t.Fatal(err)
		}
		want.Root.RequiredSupport[page.index] = ref
		want.Support[page.index] = format.RequiredSupportPageView{Domain: want.Root.Domain, Object: object, Index: page.index,
			Records: []contract.SupportRecordView{contract.SupportRecordView(page.row)}}
		want.AdministrativeIndex.Pages[page.index] = format.AdministrativePage{Ref: ref,
			Spans: []format.AdministrativeSpan{{Count: 1, Mandatory: true}},
			Rows:  []format.AdministrativeRowSummary{{Kind: page.row.Kind, RecordID: page.row.RecordID, BodyLength: uint32(len(page.row.Body))}}}
	}
}

func receiptIndexFragmentCount(t testing.TB, root format.Root) uint64 {
	t.Helper()
	if root.Generated.SuccessWindow.Count == 0 && root.Generated.FailureWindow.Count == 0 {
		return 0
	}
	blob, err := contract.MutationReceiptIndexBlobID(root.Domain, root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder)
	if err != nil {
		t.Fatal("receipt index identity", err)
	}
	var count uint64
	for _, location := range root.Generated.Fragments {
		if location.BlobID == blob {
			count++
		}
	}
	return count
}

func assertStateImage(t testing.TB, got *StateSession, want stateImage) {
	t.Helper()
	if err := stateImageDifference(got, want); err != nil {
		t.Fatal(err)
	}
}

func stateImageDifference(got *StateSession, want stateImage) error {
	if got == nil {
		return fmt.Errorf("missing observed session")
	}
	operation, ok := observedHeadOperation(got.head)
	if !ok || got.head.Core.Revision != want.Revision || operation != want.Operation || got.head.Core.Root != want.RootRef {
		return fmt.Errorf("observed HEAD differs from the admitted identities or expected root reference")
	}
	gotRootBody, gotRootErr := format.EncodeRoot(got.root)
	wantRootBody, wantRootErr := format.EncodeRoot(want.Root)
	if gotRootErr != nil || wantRootErr != nil {
		return fmt.Errorf("root encoding differs: observed=%v expected=%v", gotRootErr, wantRootErr)
	}
	if !bytes.Equal(gotRootBody, wantRootBody) {
		// DecodeRoot gives a non-nil empty shard slice. The wire comparison
		// above treats that and nil as equal while checking every actual Ref.
		wantRoot := want.Root
		if len(got.root.AdministrativeIndexShards) == 0 && len(wantRoot.AdministrativeIndexShards) == 0 {
			wantRoot.AdministrativeIndexShards = got.root.AdministrativeIndexShards
		}
		typ := reflect.TypeOf(want.Root)
		actual, expected := reflect.ValueOf(got.root), reflect.ValueOf(wantRoot)
		for i := 0; i < typ.NumField(); i++ {
			if !reflect.DeepEqual(actual.Field(i).Interface(), expected.Field(i).Interface()) {
				return fmt.Errorf("observed root %s differs", typ.Field(i).Name)
			}
		}
		return fmt.Errorf("observed root differs: fields, name slots or child references")
	}
	gotIndex, gotErr := format.EncodeAdministrativeIndexPages(got.adminIndex)
	wantIndex, wantErr := format.EncodeAdministrativeIndexPages(want.AdministrativeIndex)
	if gotErr != nil || wantErr != nil || len(gotIndex) != len(wantIndex) {
		return fmt.Errorf("administrative index differs")
	}
	for i := range gotIndex {
		if gotIndex[i].Ref != wantIndex[i].Ref || !bytes.Equal(gotIndex[i].Body, wantIndex[i].Body) {
			return fmt.Errorf("administrative index shard %d differs", i)
		}
	}
	for i, page := range want.Pages {
		actual := got.pages[i]
		if page == nil || actual == nil {
			if page != actual {
				return fmt.Errorf("page %d presence differs", i)
			}
			continue
		}
		if actual.Domain != page.Domain || actual.Object != page.Object || actual.Index != page.Index {
			return fmt.Errorf("page %d identity differs", i)
		}
		for j, entry := range page.Slots {
			observed := actual.Slots[j]
			if entry == nil || observed == nil {
				if entry != observed {
					return fmt.Errorf("slot %d presence differs", i*format.PageSlots+j)
				}
				continue
			}
			if !entriesEqual(*observed, *entry) {
				return fmt.Errorf("slot %d (%s) differs: fixed fields, value ID, origins or value bytes", i*format.PageSlots+j, entry.Name)
			}
		}
	}
	if !reflect.DeepEqual(got.access, want.Access) {
		return fmt.Errorf("access records differ")
	}
	if !reflect.DeepEqual(got.recipient, want.Recipient) {
		return fmt.Errorf("untouched recipient page differs")
	}
	return nil
}

func removeUnselectedFixtureObjects(t *testing.T, f *fixture, original, selected stateImage) {
	t.Helper()
	if original.Root.Domain != selected.Root.Domain || selected.Root.Domain != f.session.admission.domain {
		t.Fatal("fixture cleanup crossed domain ownership")
	}
	keep := map[string]bool{f.store.desc.HeadKey: true, mustKey(t, f.store.desc.Prefix, selected.RootRef): true}
	keep[mustKey(t, f.store.desc.Prefix, selected.Root.AdministrativeIndex)] = true
	for _, ref := range selected.Root.AdministrativeIndexShards {
		keep[mustKey(t, f.store.desc.Prefix, ref)] = true
	}
	for _, table := range [][]*format.Ref{selected.Root.ValueEntryPages[:], selected.Root.Recipients[:]} {
		for _, ref := range table {
			if ref != nil {
				keep[mustKey(t, f.store.desc.Prefix, *ref)] = true
			}
		}
	}
	for _, ref := range selected.Root.CurrentAccess.Core.AccessPageRefs {
		keep[mustKey(t, f.store.desc.Prefix, ref)] = true
	}
	for _, ref := range selected.Root.RequiredSupport {
		keep[mustKey(t, f.store.desc.Prefix, ref)] = true
	}
	// Actual genesis and fixture construction can leave more than one prior
	// closure. Remove every unselected object in this fixture's owned store.
	for key := range f.store.objects {
		if !keep[key] {
			delete(f.store.objects, key)
		}
	}
}

func entriesEqual(a, b format.ValueEntry) bool {
	av, bv := a.ValueBytes, b.ValueBytes
	a.ValueBytes, b.ValueBytes = nil, nil
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb) && bytes.Equal(av, bv)
}
