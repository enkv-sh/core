package core

import (
	"bytes"
	"context"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedSnapshotRebindPreservesContentAndPredecessor(t *testing.T) {
	id := generatedVectorID
	body := []byte("accepted source")
	location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentSource,
		ContentID: id(4), BlobID: id(3), Length: uint32(len(body)), Digest: contract.Hash(body)}
	s := generatedContentState(t, []generatedContentFixtureBlob{{id(3), body}}, []contract.GeneratorSliceLocation{location})
	for i, page := range s.support {
		rows := make([]contract.SupportRecord, len(page.Records))
		for j, row := range page.Records {
			rows[j] = contract.SupportRecord(row)
		}
		encoded, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, encoded)
		if err != nil {
			t.Fatal(err)
		}
		s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
		s.root.RequiredSupportRecordCount += uint32(len(rows))
		view, err := format.InspectRequiredSupportPage(encoded)
		if err != nil {
			t.Fatal(err)
		}
		s.support[i] = view
	}
	s.recountChildren()
	before, err := s.preservedWorkSupportRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	p := transitionPlan{snapshot: id(40)}
	indexes, err := s.generatedSnapshotPageIndexes()
	if err != nil || len(indexes) != 1 {
		t.Fatalf("snapshot pages: %v, %v", indexes, err)
	}
	p.supportPages[indexes[0]] = id(41)
	next := *s
	next.root.Snapshot = p.snapshot
	objects, err := s.rebindGeneratedSnapshot(t.Context(), &next, p)
	if err != nil || len(objects) != 1 {
		t.Fatalf("snapshot rebind: %v", err)
	}
	resolved, err := newGeneratedContent(&next)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := resolved.read(location.ContentKind, location.ContentID, location.Length)
	if err != nil || !bytes.Equal(actual, body) {
		t.Fatal("accepted source changed", err)
	}
	if _, err := newGeneratedContent(s); err != nil {
		t.Fatal("predecessor changed", err)
	}
	if next.support[indexes[0]].Object != p.supportPages[indexes[0]] || s.support[indexes[0]].Object == p.supportPages[indexes[0]] {
		t.Fatal("page identity not changed independently")
	}
	after, err := next.preservedWorkSupportRecords(t.Context())
	if err != nil || len(before) != len(after) {
		t.Fatal("preserved work changed", err)
	}
	for i := range before {
		if before[i].Kind != after[i].Kind || before[i].RecordID != after[i].RecordID || !bytes.Equal(before[i].Body, after[i].Body) {
			t.Fatal("physical snapshot changed preserved content")
		}
	}
	for _, bad := range []transitionPlan{{snapshot: id(40)}, {snapshot: s.root.Snapshot, supportPages: p.supportPages}} {
		candidate := *s
		candidate.root.Snapshot = bad.snapshot
		if _, err := s.rebindGeneratedSnapshot(t.Context(), &candidate, bad); err == nil {
			t.Fatal("incomplete or reused identity accepted")
		}
	}
	wrong := next
	wrong.adminIndex.SliceSnapshot = id(50)
	if _, err := wrong.preservedWorkSupportRecords(t.Context()); err == nil {
		t.Fatal("wrong authenticated slice snapshot accepted")
	}
	_, receipt, _ := receiptStateFixture(t)
	receipt.DomainID = s.admission.domain
	receipt.RequestIdentityDigest = contract.ID{}
	delta := contract.MutationReceiptDeltaPlan{DomainID: s.admission.domain, OperationKind: receipt.OperationKind, AddedCount: 1,
		Before: contract.MutationReceiptWindows{DomainID: s.admission.domain}, NewReceipt: contract.CompactMutationReceiptPlan(receipt)}
	receiptIndexes, err := s.mutationReceiptPageIndexes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range receiptIndexes {
		p.supportPages[index] = contract.ID{70, byte(index)}
	}
	storage, err := s.encodeMutationReceiptSupport(t.Context(), p, delta, id(80))
	if err != nil {
		t.Fatal(err)
	}
	receipted := *s
	receipted.root.Snapshot = p.snapshot
	storage.install(&receipted)
	if _, err := newGeneratedContent(&receipted); err != nil {
		t.Fatal("receipt append lost snapshot ownership", err)
	}
	if _, err := receipted.receiptWindows(t.Context()); err != nil {
		t.Fatal("snapshot rebind damaged receipt index", err)
	}
}

func generatedSnapshotSelectedFixture(t *testing.T) (*StateSession, contract.GeneratorSliceLocation, []byte) {
	t.Helper()
	s := generatedEmptyPredecessorForFamily(t, contract.GCP)
	s.admission.store.Prefix = "snapshot-fixture"

	reader := *s.recipients[0].Slots[0].CurrentBinding
	reader.BindingID = generatedVectorID(95)
	s.recipients[0].Slots[1] = &contract.RecipientRecord{RecipientID: generatedVectorID(12), Status: contract.CurrentRecipient, CurrentBinding: &reader}
	recipientBody, err := format.EncodeRecipientPage(*s.recipients[0])
	if err != nil {
		t.Fatal(err)
	}
	recipientRef, err := format.Reference(format.RecipientKind, s.root.Domain, s.recipients[0].Object, 0, recipientBody)
	if err != nil {
		t.Fatal(err)
	}
	s.root.Recipients[0], s.root.RecipientCount = &recipientRef, 2
	s.root.CurrentAccess.Core.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: s.root.Domain, Refs: []contract.Ref{recipientRef}})
	if err != nil {
		t.Fatal(err)
	}
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := format.InspectRequiredSupportPage(s.cache[s.root.RequiredSupport[0]])
	if err != nil {
		t.Fatal("fixture configuration", err)
	}
	s.support[0] = configuration
	payload := []byte("accepted source")
	location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentSource,
		ContentID: generatedVectorID(4), BlobID: generatedVectorID(5), Length: uint32(len(payload)), Digest: contract.Hash(payload)}
	content := generatedContentStateAtSnapshot(t, s.root.Snapshot, []generatedContentFixtureBlob{{location.BlobID, payload}}, []contract.GeneratorSliceLocation{location})
	s.root.Generated = content.root.Generated
	for i := range s.root.Generated.Fragments {
		s.root.Generated.Fragments[i].SupportPageIndex++
	}
	for _, page := range content.support {
		page.Index++
		s.support = append(s.support, page)
	}
	s.root.RequiredSupport, s.root.RequiredSupportRecordCount = nil, 0
	s.supportFacts = nil
	s.fragmentFacts = make(map[format.FragmentLocation]selectedFragmentFact)
	objects := make(map[string][]byte)
	for i, page := range s.support {
		rows := make([]contract.SupportRecord, len(page.Records))
		for j, row := range page.Records {
			rows[j] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		key, err := format.Key(s.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		objects[key] = body
		s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
		s.root.RequiredSupportRecordCount += uint32(len(rows))
		s.support[i], err = format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		facts := selectedSupportPageFacts{ref: ref}
		for j, row := range rows {
			digest, err := contract.InspectSupportRecordDigest(s.root.Domain, row)
			if err != nil {
				t.Fatal(err)
			}
			facts.rows = append(facts.rows, digest)
			facts.ordinals = append(facts.ordinals, uint16(j))
			if row.Kind == contract.GeneratedFragmentSupportKind {
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				loc := format.FragmentLocation{BlobID: fragment.BlobID, FragmentIndex: fragment.Index, SupportPageIndex: ref.Index, RowSlot: uint8(j)}
				s.fragmentFacts[loc] = selectedFragmentFact{ref: ref, row: digest, physical: uint16(j), logical: uint8(j),
					blob: fragment.BlobID, index: fragment.Index, count: fragment.Count, total: fragment.TotalLength,
					whole: fragment.WholeDigest, offset: fragment.Offset, payloadLength: uint32(len(fragment.Payload))}
			}
		}
		s.supportFacts = append(s.supportFacts, facts)
	}
	store := &readFailureStore{}
	store.onReadCtx = func(context.Context) (contract.ReadResult, bool) {
		body, ok := objects[store.keys[len(store.keys)-1]]
		if !ok {
			return contract.ReadResult{Status: contract.ReadMissing}, true
		}
		return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(body)}, true
	}
	s.store = store
	s.recountChildren()
	image := s.selectedImage()
	if result := verifySelectedGeneratedSlices(t.Context(), image, s.selectedObjectReader()); result.Outcome != 0 {
		t.Fatal("selected slice fixture", result)
	}
	s.generatedSliceLocations = image.generatedSliceLocations
	var ok bool
	s.generatedSlicesRoot, ok = s.generatedSelectionRoot()
	if !ok {
		t.Fatal("selected fixture root")
	}
	return s, location, payload
}

// full_only: false
func TestGeneratedSnapshotRebindRecountsVariableWidthRecipientReplacement(t *testing.T) {
	for _, test := range []struct {
		name  string
		width int
	}{{"growth", 2}, {"shrink", -2}, {"unchanged", 0}} {
		t.Run(test.name, func(t *testing.T) {
			s, location, payload := generatedSnapshotSelectedFixture(t)
			before, err := format.EncodeRoot(s.root)
			if err != nil {
				t.Fatal(err)
			}
			refs := slices.Clone(s.root.RequiredSupport)
			facts := maps.Clone(s.fragmentFacts)
			support := slices.Clone(s.support)
			for i := range support {
				support[i].Records = slices.Clone(support[i].Records)
				for j := range support[i].Records {
					support[i].Records[j].Body = bytes.Clone(support[i].Records[j].Body)
				}
			}
			sliceRoot := s.generatedSlicesRoot
			successor := *s.recipients[0].Slots[1].CurrentBinding
			successor.BindingID, successor.BindingSerial = generatedVectorID(90), successor.BindingSerial+1
			prefix, version, ok := strings.Cut(successor.KeySelector, "/cryptoKeyVersions/")
			if !ok {
				t.Fatal("fixture selector")
			}
			switch {
			case test.width > 0:
				prefix += "xx"
			case test.width < 0:
				prefix = prefix[:len(prefix)+test.width]
			}
			successor.KeySelector = prefix + "/cryptoKeyVersions/" + version
			p := transitionPlan{snapshot: generatedVectorID(40), transition: generatedVectorID(42)}
			p.recipientPages[0] = generatedVectorID(43)
			indexes, err := s.generatedSnapshotPageIndexes()
			if err != nil || len(indexes) != 1 {
				t.Fatal("snapshot pages", indexes, err)
			}
			p.supportPages[indexes[0]] = generatedVectorID(41)
			next, ok := s.replacementSuccessor(contract.RecipientReplacementIntent{RecipientID: generatedVectorID(12), Successor: successor}, p, nil)
			if !ok {
				t.Fatal("recipient successor refused")
			}
			if int64(next.root.Recipients[0].Length)-int64(s.root.Recipients[0].Length) != int64(test.width) {
				t.Fatal("selector width did not reach child encoding")
			}
			if _, err := s.rebindGeneratedSnapshot(t.Context(), next, p); err != nil {
				t.Fatal("variable-width snapshot rebind", err)
			}
			if next.root.ChildCount != s.root.ChildCount || int64(next.root.ChildEncodedBytes)-int64(s.root.ChildEncodedBytes) != int64(test.width) {
				t.Fatal("successor child aggregate differs")
			}
			if _, err := format.EncodeRoot(next.root); err != nil {
				t.Fatal("successor framing", err)
			}
			root, ok := next.generatedSelectionRoot()
			if !ok || root != next.generatedSlicesRoot || !slices.Equal(s.generatedSliceLocations, next.generatedSliceLocations) {
				t.Fatal("successor slice facts not bound")
			}
			content, err := newGeneratedContentValidation(t.Context(), next)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := content.read(location.ContentKind, location.ContentID, location.Length)
			if err != nil || !bytes.Equal(actual, payload) {
				t.Fatal("generated content changed", err)
			}
			after, err := format.EncodeRoot(s.root)
			if err != nil || !bytes.Equal(before, after) || !slices.Equal(refs, s.root.RequiredSupport) || !maps.Equal(facts, s.fragmentFacts) || !reflect.DeepEqual(support, s.support) || sliceRoot != s.generatedSlicesRoot {
				t.Fatal("predecessor facts changed", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedSnapshotRebindRejectsMalformedSelectedFacts(t *testing.T) {
	for name, damage := range map[string]func(*StateSession, *StateSession){
		"predecessor-child-count": func(before, _ *StateSession) { before.root.ChildCount++ },
		"predecessor-child-bytes": func(before, _ *StateSession) { before.root.ChildEncodedBytes++ },
		"successor-ref-domain": func(_, next *StateSession) {
			ref := *next.root.Recipients[0]
			ref.Domain = generatedVectorID(99)
			next.root.Recipients[0] = &ref
		},
		"successor-ref-index": func(_, next *StateSession) {
			ref := *next.root.Recipients[0]
			ref.Index++
			next.root.Recipients[0] = &ref
		},
		"successor-duplicate-object": func(_, next *StateSession) {
			ref := *next.root.Recipients[0]
			ref.Object = next.root.AdministrativeIndex.Object
			next.root.Recipients[0] = &ref
		},
		"successor-ref-length": func(_, next *StateSession) {
			ref := *next.root.Recipients[0]
			ref.Length = 0
			next.root.Recipients[0] = &ref
		},
		"predecessor-support-ref": func(before, _ *StateSession) { before.supportFacts[2].ref.Digest = generatedVectorID(99) },
	} {
		t.Run(name, func(t *testing.T) {
			before, _, _ := generatedSnapshotSelectedFixture(t)
			next := *before
			p := transitionPlan{snapshot: generatedVectorID(40)}
			p.supportPages[2] = generatedVectorID(41)
			next.root.Snapshot = p.snapshot
			damage(before, &next)
			if _, err := before.rebindGeneratedSnapshot(t.Context(), &next, p); err == nil {
				t.Fatal("malformed selected facts accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedSnapshotDirectBindingRejectsMalformedSuccessor(t *testing.T) {
	for name, damage := range map[string]func(*StateSession){
		"child-count":      func(next *StateSession) { next.root.ChildCount++ },
		"child-bytes":      func(next *StateSession) { next.root.ChildEncodedBytes++ },
		"slice-descriptor": func(next *StateSession) { next.root.Generated.Slices.Digest = generatedVectorID(99) },
		"slice-owner":      func(next *StateSession) { next.adminIndex.SliceSnapshot = generatedVectorID(99) },
		"fragment-fact": func(next *StateSession) {
			for location, fact := range next.fragmentFacts {
				fact.physical++
				next.fragmentFacts[location] = fact
			}
		},
		"fragment-location": func(next *StateSession) {
			next.root.Generated.Fragments = slices.Clone(next.root.Generated.Fragments)
			next.root.Generated.Fragments[0].RowSlot++
		},
	} {
		t.Run(name, func(t *testing.T) {
			before, _, _ := generatedSnapshotSelectedFixture(t)
			next := *before
			p := transitionPlan{snapshot: generatedVectorID(40)}
			p.supportPages[2] = generatedVectorID(41)
			next.root.Snapshot = p.snapshot
			if _, err := before.rebindGeneratedSnapshot(t.Context(), &next, p); err != nil {
				t.Fatal("valid snapshot rebind", err)
			}
			damage(&next)
			if err := before.bindReboundGeneratedSlices(&next); err == nil {
				t.Fatal("malformed successor binding accepted")
			}
		})
	}
}

// full_only: false
func TestNormalReceiptSliceExpectationBindsOneSuccessor(t *testing.T) {
	for name, damage := range map[string]func(*StateSession){
		"exact":           func(*StateSession) {},
		"before-revision": func(next *StateSession) { next.normalReceiptSlices.beforeRevision = generatedVectorID(70) },
		"before-root":     func(next *StateSession) { next.normalReceiptSlices.beforeRoot = generatedVectorID(70) },
		"domain":          func(next *StateSession) { next.normalReceiptSlices.domain = generatedVectorID(70) },
		"snapshot":        func(next *StateSession) { next.normalReceiptSlices.snapshot = generatedVectorID(70) },
		"transition":      func(next *StateSession) { next.normalReceiptSlices.transition = generatedVectorID(70) },
		"unpermitted-subset": func(next *StateSession) {
			next.normalReceiptSlices.descriptor = contract.EmptyGeneratorVector(contract.GeneratorVectorSlices)
			next.normalReceiptSlices.locations = nil
		},
		"changed-location": func(next *StateSession) { next.normalReceiptSlices.locations[0].Offset++ },
		"changed-fragment-fact": func(next *StateSession) {
			next.fragmentFacts = maps.Clone(next.fragmentFacts)
			for location, fact := range next.fragmentFacts {
				fact.total++
				next.fragmentFacts[location] = fact
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			before, _, _ := generatedSnapshotSelectedFixture(t)
			next := *before
			p := transitionPlan{snapshot: generatedVectorID(40), transition: generatedVectorID(42)}
			p.supportPages[2] = generatedVectorID(41)
			next.root.Snapshot, next.root.Transition = p.snapshot, p.transition
			if _, err := before.rebindGeneratedSnapshot(t.Context(), &next, p); err != nil {
				t.Fatal("valid snapshot rebind", err)
			}
			// The binder receives only fixed coordinates and the exact directory.
			// Construction from the admitted normal transform is tested by Apply.
			next.normalReceiptSlices = &normalReceiptSlices{beforeRevision: before.head.Core.Revision, beforeRoot: before.head.Core.Root.Digest,
				domain: next.root.Domain, snapshot: p.snapshot, transition: p.transition,
				descriptor: before.root.Generated.Slices, locations: slices.Clone(before.generatedSliceLocations)}
			damage(&next)
			if err := before.bindReceiptSuccessorSlices(&next); (err == nil) != (name == "exact") {
				t.Fatal("receipt slice expectation scope was not enforced", err)
			}
			if name == "exact" {
				if err := before.bindNormalReceiptSlicePlan(&Comparison{session: before}, &next, p); err == nil {
					t.Fatal("an already scoped expectation was reused")
				}
				next.root.Transition = generatedVectorID(71)
				if err := before.bindReceiptSuccessorSlices(&next); err == nil {
					t.Fatal("a copied expectation authorized a later successor")
				}
			}
		})
	}
}
