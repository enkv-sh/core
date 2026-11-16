package core

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func maximumLifecycleNames(prefix string) []string {
	names := make([]string, 512)
	for i := range names {
		name := fmt.Sprintf("%s-%03d-", prefix, i)
		names[i] = name + strings.Repeat("x", 256-len(name))
	}
	return names
}

// Counts refer to one transition. Dropped pages are obsolete but are not created.
func successorObjectCounts(original, next stateImage) (created, obsolete uint64) {
	created, obsolete = 1, 1
	if original.Root.AdministrativeIndex != next.Root.AdministrativeIndex {
		if !original.Root.AdministrativeIndex.Object.IsZero() {
			obsolete++
		}
		if !next.Root.AdministrativeIndex.Object.IsZero() {
			created++
		}
	}
	for _, before := range original.Root.AdministrativeIndexShards {
		if !slices.Contains(next.Root.AdministrativeIndexShards, before) {
			obsolete++
		}
	}
	for _, after := range next.Root.AdministrativeIndexShards {
		if !slices.Contains(original.Root.AdministrativeIndexShards, after) {
			created++
		}
	}
	for _, before := range original.Root.RequiredSupport {
		if !slices.Contains(next.Root.RequiredSupport, before) {
			obsolete++
		}
	}
	for _, after := range next.Root.RequiredSupport {
		if !slices.Contains(original.Root.RequiredSupport, after) {
			created++
		}
	}
	for i, before := range original.Root.ValueEntryPages {
		after := next.Root.ValueEntryPages[i]
		if before != nil && after != nil && *before == *after {
			continue
		}
		if before != nil {
			obsolete++
		}
		if after != nil {
			created++
		}
	}
	return created, obsolete
}

// Cold fixture sessions retain opaque rows without bodies. New support pages
// are materialized during admission and cached by persistence before selection.
func successorSupportReadCounts(original, next stateImage) (configurationReads, materializationReads, retainedPageReads uint64) {
	for _, page := range next.AdministrativeIndex.Pages {
		retained := slices.Contains(original.Root.RequiredSupport, page.Ref)
		opaque := false
		for _, row := range page.Rows {
			switch row.Kind {
			case contract.OutputConfigurationSliceSupportKind:
				opaque = true
				if retained {
					// Any bodyless slice makes Prepare borrow the complete
					// predecessor configuration, not just that slice.
					configurationReads = uint64(original.Root.OutputConfiguration.SliceCount)
				} else {
					materializationReads++
				}
			case contract.GeneratedFragmentSupportKind:
				opaque = true
			}
		}
		if retained && opaque {
			retainedPageReads++
		}
	}
	return configurationReads, materializationReads, retainedPageReads
}

func (r *scenarioRun) pruneObsolete(original, next stateImage) {
	r.t.Helper()
	refs := []format.Ref{original.RootRef}
	if original.Root.AdministrativeIndex != next.Root.AdministrativeIndex && !original.Root.AdministrativeIndex.Object.IsZero() {
		refs = append(refs, original.Root.AdministrativeIndex)
	}
	for _, ref := range original.Root.AdministrativeIndexShards {
		if !slices.Contains(next.Root.AdministrativeIndexShards, ref) {
			refs = append(refs, ref)
		}
	}
	for _, ref := range original.Root.RequiredSupport {
		if !slices.Contains(next.Root.RequiredSupport, ref) {
			refs = append(refs, ref)
		}
	}
	for i, ref := range original.Root.ValueEntryPages {
		if ref != nil && (next.Root.ValueEntryPages[i] == nil || *ref != *next.Root.ValueEntryPages[i]) {
			refs = append(refs, *ref)
		}
	}
	_, obsolete := successorObjectCounts(original, next)
	if uint64(len(refs)) != obsolete {
		r.t.Fatal("obsolete fixture object count differs")
	}
	for _, ref := range refs {
		if err := r.env.Delete(r.ctx, mustKey(r.t, r.env.Store.Descriptor().Prefix, ref)); err != nil {
			r.t.Fatal("obsolete fixture object removal failed")
		}
	}
}

func (r *scenarioRun) lifecycleSelection(session *StateSession, original stateImage, requested []ApplyEntryInput, seen map[contract.ID]bool) stateImage {
	r.t.Helper()
	comparison, permit, next := r.compare(session, requested)
	assertFreshAllocatedIDs(r.t, seen, observeAllocatedTransitionInputs(permit))
	candidate, result := r.prepare(session, comparison, permit)
	if candidate == nil || result.Outcome != ObservedCurrent {
		r.t.Fatalf("lifecycle preparation: %+v", result)
	}
	beforeNames := make(map[string]bool, len(original.Root.Names))
	for _, entry := range original.Root.Names {
		beforeNames[entry.Name] = true
	}
	var additions uint32
	for _, entry := range next.Root.Names {
		if !beforeNames[entry.Name] {
			additions++
		}
	}
	union := uint32(len(original.Root.Names)) + additions
	removals := union - uint32(len(next.Root.Names))
	subject := candidate.head.Subject
	if subject.Normal.Union.Count != union || subject.Grant.Grants.Count != additions || subject.Exclusion.Exclusions.Count != removals || subject.Exclusion.Retirements.Count != 0 {
		r.t.Fatal("lifecycle signed counts differ from independent complete membership")
	}
	result = r.selectCandidate(session, candidate)
	if result.Outcome != ObservedCurrent || result.ObservedRevision != next.Revision || result.ObservedSnapshotID != next.Root.Snapshot || result.Evidence != AuthenticatedClosure || result.CommitMayHaveOccurred {
		r.t.Fatalf("lifecycle selection: %+v", result)
	}
	created, _ := successorObjectCounts(original, next)
	// Compare validates the configuration twice. Selection borrows every
	// selected slice and verifies each retained receipt fragment three times.
	configurationReads, materializationReads, retainedPageReads := successorSupportReadCounts(original, next)
	// Prepare validates the new root's retained receipt index before any
	// immutable write; only the predecessor has cached receipt windows.
	prospectiveReceiptReads := receiptIndexFragmentCount(r.t, next.Root)
	reads := r.spy.StoreCreate + 1 + 2*uint64(original.Root.OutputConfiguration.SliceCount) + configurationReads +
		retainedPageReads + uint64(next.Root.OutputConfiguration.SliceCount) +
		3*uint64(len(next.Root.Generated.Fragments)) + materializationReads + prospectiveReceiptReads
	if r.spy.StoreCreate < created || r.spy.StoreCreate > created+2*r.spy.StoreTransportCreate || r.spy.StoreRead != reads+r.spy.StoreTransportRead || r.spy.StoreCAS != 1 || r.spy.TrustSign != 1 {
		r.t.Fatalf("lifecycle effects differ: %+v, created objects %d, reads %d", r.spy.scenarioEffects, created, reads)
	}
	r.pruneObsolete(original, next)
	return next
}

func (r *scenarioRun) emptyLifecycle(f *environmentFixture, original stateImage) {
	r.t.Helper()
	seen := historyIDs(original)
	r.phase("transition", func() {
		for _, requested := range [][]ApplyEntryInput{nil, {}} {
			reads, transportReads := r.spy.StoreRead, r.spy.StoreTransportRead
			comparison, result := f.session.Compare(r.ctx, requested, admitSuppliedComparison(r.t, f.session, nil, requested))
			if comparison != nil || result.Outcome != Unchanged || r.spy.StoreRead-reads != 2*uint64(original.Root.OutputConfiguration.SliceCount)+r.spy.StoreTransportRead-transportReads || r.spy.StoreCreate+r.spy.StoreCAS+r.spy.TrustSign != 0 {
				r.t.Fatal("empty intent changed state or read outside its configuration")
			}
		}
	})
	input := make([]ApplyEntryInput, 17)
	for i := range input {
		input[i] = ApplyEntryInput{Name: fmt.Sprintf("member-%03d", i), Recipients: []contract.ID{original.Root.CurrentAccess.Core.AuthorityRecipientID}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte{byte(i)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	}
	input[0].Name, input[0].InputBytes = "", nil
	want := original
	session := f.session
	for step := range 3 {
		r.phase("transition", func() {
			requested := input
			if step == 1 {
				requested = nil
			}
			want = r.lifecycleSelection(session, want, requested, seen)
			// The recipient, receipt, receipt-index and configuration pages
			// remain selected; only the root and administrative index are new.
			if step == 1 && (want.Root.ValueEntryCount != 0 || want.Root.ChildCount != 5 || want.Root.RawBytes != 0 || r.spy.StoreCreate != 2) {
				r.t.Fatal("last removal did not preserve recipient and output configuration support")
			}
		})
		session = r.verify(f.admission, want)
	}
}

func (r *scenarioRun) mixedLifecycle(f *environmentFixture, original stateImage) {
	r.t.Helper()
	requested := original.entryInputs()
	requested[1].InputBytes = []byte("updated")
	requested = append(requested[1:15], requested[16:]...)
	requested = append(requested,
		ApplyEntryInput{Name: "new-b", Recipients: []contract.ID{original.Root.CurrentAccess.Core.AuthorityRecipientID}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte("added"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw},
		ApplyEntryInput{Name: "new-a", Recipients: []contract.ID{original.Root.CurrentAccess.Core.AuthorityRecipientID}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw},
	)
	var want stateImage
	r.phase("transition", func() {
		want = r.lifecycleSelection(f.session, original, requested, historyIDs(original))
	})
	r.verify(f.admission, want)
}

func (r *scenarioRun) maximumReplacement(f *environmentFixture, original stateImage) {
	r.t.Helper()
	requested := original.entryInputs()
	names := maximumLifecycleNames("after")
	for i := range requested {
		if len(requested[i].Name) != 256 || len(names[i]) != 256 {
			r.t.Fatal("maximum replacement fixture does not use maximum-length names")
		}
		valueSize := 0
		if i >= 384 {
			valueSize = 65536
		}
		if len(requested[i].InputBytes) != valueSize {
			r.t.Fatal("maximum replacement fixture has the wrong joint value shape")
		}
		requested[i].Name = names[i]
	}
	var want stateImage
	r.phase("transition", func() {
		want = r.lifecycleSelection(f.session, original, requested, historyIDs(original))
		if original.Root.RawBytes != 8<<20 || want.Root.RawBytes != 8<<20 || len(original.Root.Names) != 512 || len(want.Root.Names) != 512 {
			r.t.Fatal("maximum disjoint replacement did not reach both joint limits")
		}
		created, obsolete := successorObjectCounts(original, want)
		if created != 34 || obsolete != 34 {
			r.t.Fatal("maximum disjoint replacement did not replace every member page")
		}
	})
	r.verify(f.admission, want)
}

// full_only: false
func TestSuccessorObjectCountsDistinguishesDroppedAndCreatedPages(t *testing.T) {
	original, next := stateImage{}, stateImage{}
	retained := format.Ref{Object: testID("retained")}
	original.Root.ValueEntryPages[0], next.Root.ValueEntryPages[0] = &retained, &retained
	original.Root.ValueEntryPages[1] = &format.Ref{Object: testID("dropped")}
	next.Root.ValueEntryPages[2] = &format.Ref{Object: testID("created")}
	original.Root.ValueEntryPages[3] = &format.Ref{Object: testID("replaced")}
	next.Root.ValueEntryPages[3] = &format.Ref{Object: testID("replacement")}
	original.Root.RequiredSupport = []format.Ref{{Object: testID("retained support")}, {Object: testID("dropped support")}}
	next.Root.RequiredSupport = []format.Ref{original.Root.RequiredSupport[0], {Object: testID("created support")}}
	if created, obsolete := successorObjectCounts(original, next); created != 4 || obsolete != 4 {
		t.Fatalf("created/obsolete = %d/%d", created, obsolete)
	}
	if created, obsolete := successorObjectCounts(original, stateImage{}); created != 1 || obsolete != 6 {
		t.Fatalf("empty successor created/obsolete = %d/%d", created, obsolete)
	}
}
