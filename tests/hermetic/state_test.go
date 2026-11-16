package core

import (
	"bytes"
	"context"
	"sort"
	"strconv"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type reusedStateReadStore struct {
	*memoryStore
	source reusedProjectionReadSource
}

func (s *reusedStateReadStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	return s.source.Read(ctx, key, limit)
}

// full_only: false
func TestSelectedHeadOwnsStoreReadBuffer(t *testing.T) {
	for _, mode := range []string{"open", "administrative-open", "receipt", "administrative-receipt"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, 1, false, 8)
			want := fixtureStateImage(t, f)
			wantBody, wantToken := bytes.Clone(f.session.body), f.session.token
			store := &reusedStateReadStore{memoryStore: f.store, source: reusedProjectionReadSource{
				store: f.store, backing: make([]byte, 0, contract.MaxRootLength+contract.MaxHeadLength),
			}}
			var selected *StateSession
			var result Result
			switch mode {
			case "open":
				selected, result = Open(t.Context(), f.admission, store)
			case "administrative-open":
				selected, result = openAdministrative(t.Context(), f.admission, store)
			default:
				prior := *f.session
				prior.store = store
				prior.cache = nil
				prior.mutationReceipts = nil
				prior.administrativeReceiptRead = mode == "administrative-receipt"
				selected, result = prior.readCurrentForReceipt(t.Context())
			}
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("borrowed Store buffer prevented valid selected read", result)
			}
			if store.source.reuseCount < 2 {
				t.Fatal("selected read did not reuse the HEAD buffer for later objects")
			}
			if selected.token != wantToken || !bytes.Equal(selected.body, wantBody) {
				t.Fatal("later Store read changed retained HEAD bytes or token")
			}
			assertStateImage(t, selected, want)
			if read := store.Read(t.Context(), store.desc.HeadKey, contract.MaxHeadLength); read.Status != contract.ReadOK {
				t.Fatal("positive HEAD reread", read.Status)
			}
			if selected.token != wantToken || !bytes.Equal(selected.body, wantBody) {
				t.Fatal("later caller read changed retained HEAD bytes or token")
			}
		})
	}
}

// full_only: false
func TestFixturePublicAdmissionRefuses(t *testing.T) {
	f := newFixture(t, 1, false, 0)
	if s, r := Open(context.Background(), OpenContext{}, f.store); s != nil || r.Outcome != AdmissionRefused {
		t.Fatal(r)
	}
	c := changed(t, f.session, 0)
	if p, r := f.session.Prepare(context.Background(), c, &AdmittedParentTransition{}, f.trust); p != nil || r.Outcome != AdmissionRefused {
		t.Fatal(r)
	}
	if f.store.creates != 0 || f.trust.signs != 0 {
		t.Fatal("refusal had side effects")
	}
}

// full_only: false
func TestNoOpAndCompleteImage(t *testing.T) {
	for _, count := range []int{0, 1, 64} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			f := newFixture(t, count, false, 0)
			before := f.store.reads
			original := fixtureStateImage(t, f)
			if before != len(processPlainReadRequests(t, f.store.desc, original)) {
				t.Fatal("no-op did not authenticate the complete predecessor")
			}
			want := Result{Outcome: Unchanged, ObservedRevision: original.Revision, ObservedSnapshotID: original.Root.Snapshot, Evidence: AuthenticatedClosure}
			if c, r := f.session.Compare(context.Background(), f.session.currentEntryInputs(), admitSuppliedComparison(t, f.session, nil, f.session.currentEntryInputs())); c != nil || r != want {
				t.Fatal(r)
			}
			if f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 || f.store.reads-before != 2*int(original.Root.OutputConfiguration.SliceCount) || f.session.prepared {
				t.Fatal("no-op had side effects")
			}
			assertStateImage(t, f.session, original)
			if count > 0 {
				if c, r := f.session.Compare(context.Background(), f.session.currentEntryInputs()[1:], admitSuppliedComparison(t, f.session, nil, f.session.currentEntryInputs()[1:])); c == nil || r.Outcome != ObservedCurrent {
					t.Fatal(r)
				}
			}
		})
	}
}

// full_only: false
func TestPointTwoPagesAndSamePage(t *testing.T) {
	all := make([]int, 64)
	for i := range all {
		all[i] = i
	}
	for _, tc := range []struct {
		name       string
		indices    []int
		fragmented bool
	}{
		{"state.single-value-update-preserves-other-values/members_32", []int{0}, false},
		{"state.same-page-updates-preserve-other-pages/members_32_same_page", []int{0, 1}, false},
		{"state.cross-page-updates-preserve-other-values/members_32_cross_page", []int{0, 16}, false},
		{"multiple-pages", []int{0, 1, 16, 32, 48}, false},
		{"full", all, false},
		{"fragmented-point", []int{0}, true},
		{"fragmented-same-page", []int{0, 32}, true},
		{"fragmented-two-pages", []int{0, 1}, true},
		{"fragmented-full", all, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, 64, tc.fragmented, 4096)
			original := fixtureStateImage(t, f)
			requested := original.entryInputs()
			pages := map[int]bool{}
			for _, i := range tc.indices {
				requested[i].InputBytes = append(requested[i].InputBytes, byte(99))
				pages[int(original.Root.Names[i].Slot)/format.PageSlots] = true
			}
			c, r := f.session.Compare(context.Background(), requested, admitSuppliedComparison(t, f.session, nil, requested))
			if c == nil {
				t.Fatal(r)
			}
			permit := admit(t, f.session, c)
			want := expectedSuccessorImage(t, original, requested, observeAllocatedTransitionInputs(permit))
			candidate, r := f.session.Prepare(context.Background(), c, permit, f.trust)
			if candidate == nil {
				t.Fatal(r)
			}
			if f.store.creates != len(pages)+2 || f.trust.signs != 1 {
				t.Fatal("wrong preparation count")
			}
			res := f.session.Select(context.Background(), candidate)
			if res.Outcome != ObservedCurrent || res.ObservedRevision != candidate.head.Core.Revision {
				t.Fatal(res)
			}
			configurationReads := 4*int(original.Root.OutputConfiguration.SliceCount) + len(processPlainReceiptReadRequests(t, f.store.desc, original)) + len(processPlainObservationReadRequests(t, f.store.desc, original)) + len(processPlainReceiptIndexReadRequests(t, f.store.desc, want))
			if f.store.cas != 1 || f.store.reads+f.store.creates+f.store.cas != int(f.session.root.ChildCount)+2*len(pages)+8+configurationReads {
				t.Fatal("request accounting")
			}
			s, r := Open(context.Background(), f.admission, f.store)
			if r.Outcome != ObservedCurrent {
				t.Fatal(r)
			}
			assertStateImage(t, s, want)
			if r := f.session.Select(context.Background(), candidate); r.Outcome != AdmissionRefused || f.store.cas != 1 {
				t.Fatal("candidate reused")
			}
		})
	}
}

// full_only: false
func TestStaleAdmissionAndInputIsolation(t *testing.T) {
	f := newFixture(t, 2, false, 1)
	original := fixtureStateImage(t, f)
	input := f.session.currentEntryInputs()
	input[0].InputBytes[0] = 99
	requested := original.entryInputs()
	requested[0].InputBytes[0] = 99
	c, r := f.session.Compare(context.Background(), input, admitSuppliedComparison(t, f.session, nil, input))
	if c == nil {
		t.Fatal(r)
	}
	input[0].InputBytes[0] = 42
	input[0].Name = "changed after comparison"
	permit := admit(t, f.session, c)
	authorizedSubject := *permit.authority.normal
	s, res := Open(context.Background(), f.admission, f.store)
	if s == nil {
		t.Fatal(res)
	}
	if p, r := s.Prepare(context.Background(), c, permit, f.trust); p != nil || r.Outcome != AdmissionRefused {
		t.Fatal("cross-session permit")
	}
	permit.authority.normal.Section.Union.Digest = testID("tamper")
	if p, r := f.session.Prepare(context.Background(), c, permit, f.trust); p != nil || r.Outcome != AdmissionRefused {
		t.Fatal("changed authority subject")
	}
	if f.store.creates != 0 || f.trust.signs != 0 {
		t.Fatal("admission side effects")
	}
	if c.desiredEntries[0].InputBytes[0] != 99 || c.desiredEntries[0].Name != requested[0].Name {
		t.Fatal("input aliases comparison")
	}
	*permit.authority.normal = authorizedSubject
	want := expectedSuccessorImage(t, original, requested, observeAllocatedTransitionInputs(permit))
	candidate, r := f.session.Prepare(context.Background(), c, permit, f.trust)
	if candidate == nil {
		t.Fatal(r)
	}
	if r := f.session.Select(context.Background(), candidate); r.Outcome != ObservedCurrent {
		t.Fatal(r)
	}
	s, res = Open(context.Background(), f.admission, f.store)
	if s == nil {
		t.Fatal(res)
	}
	assertStateImage(t, s, want)
}

// full_only: false
func TestImmutableReadback(t *testing.T) {
	for _, mode := range []string{"lost-after", "lost-before", "delayed", "conflict", "equal"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, 1, false, 1)
			c := changed(t, f.session, 0)
			permit := admit(t, f.session, c)
			f.store.createMode = mode
			if mode == "equal" {
				planned, _ := f.session.buildSuccessor(t.Context(), c, permit.plan)
				for _, o := range planned.objects {
					k, _ := format.Key(f.store.desc.Prefix, o.ref)
					f.store.put(k, o.body)
				}
			}
			candidate, r := f.session.Prepare(context.Background(), c, permit, f.trust)
			if mode == "lost-after" || mode == "equal" {
				if candidate == nil {
					t.Fatal(r)
				}
				if r := f.session.Select(context.Background(), candidate); r.Outcome != ObservedCurrent {
					t.Fatal(r)
				}
			} else {
				if candidate != nil || f.store.cas != 0 || f.trust.signs != 0 {
					t.Fatal("unverified child selected")
				}
				if mode == "conflict" && r.Outcome != IntegrityFailure {
					t.Fatal(r)
				}
				if f.store.late != nil {
					if err := f.store.late(); err != nil {
						t.Fatal("delayed Store write", err)
					}
					if s, r := Open(context.Background(), f.admission, f.store); s == nil || r.ObservedRevision != f.session.head.Core.Revision {
						t.Fatal("late child selected")
					}
				}
			}
		})
	}
}

// full_only: false
func TestSelectionUncertainty(t *testing.T) {
	for _, mode := range []string{"lost-after", "lost-before", "delayed", "ack-before", "conflict", "read-corrupt", "read-unavailable", "read-missing"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, 1, false, 1)
			candidate := prepare(t, f, changed(t, f.session, 0))
			frozenBody := bytes.Clone(candidate.body)
			casStart := len(f.store.casBodies)
			f.store.casMode = mode
			if mode == "read-corrupt" || mode == "read-unavailable" || mode == "read-missing" {
				f.store.readHook = func(key string, r contract.ReadResult) contract.ReadResult {
					if key != f.store.desc.HeadKey {
						return r
					}
					switch mode {
					case "read-corrupt":
						r.Body[0] ^= 1
					case "read-unavailable":
						r.Status = contract.ReadUnavailable
					case "read-missing":
						r.Status = contract.ReadMissing
					}
					return r
				}
			}
			r := f.session.Select(context.Background(), candidate)
			if mode == "lost-after" {
				if r.Outcome != ObservedCurrent {
					t.Fatal(r)
				}
			} else if mode == "lost-before" {
				if r.Outcome != EvidenceUnavailable || r.Reason != WriteUncertain || r.CommitMayHaveOccurred || r.StoreReason != contract.ReasonTransport {
					t.Fatal(r)
				}
			} else if r.Outcome != UnresolvedCommit || !r.CommitMayHaveOccurred {
				t.Fatal(r)
			}
			wantCAS := 1
			if mode == "lost-before" || mode == "delayed" {
				wantCAS = 3
			}
			if f.store.cas != wantCAS {
				t.Fatalf("CAS sends = %d, want %d", f.store.cas, wantCAS)
			}
			for i := casStart; i < len(f.store.casBodies); i++ {
				if f.store.casConditions[i] != f.session.token || !bytes.Equal(f.store.casBodies[i], frozenBody) {
					t.Fatalf("CAS send %d changed its condition or body", i)
				}
			}
			if f.store.late != nil {
				if err := f.store.late(); err != nil {
					t.Fatal("delayed Store write", err)
				}
				s, r := Open(context.Background(), f.admission, f.store)
				if s == nil || r.ObservedRevision != candidate.head.Core.Revision {
					t.Fatal("delayed CAS witness")
				}
			}
		})
	}
}

// full_only: false
func TestTwoWritersNeverRebase(t *testing.T) {
	for _, equal := range []bool{false, true} {
		t.Run(strconv.FormatBool(equal), func(t *testing.T) {
			f := newFixture(t, 32, false, 1)
			other, r := Open(context.Background(), f.admission, f.store)
			if other == nil {
				t.Fatal(r)
			}
			one := prepare(t, f, changed(t, f.session, 0, 16))
			index := 1
			if equal {
				index = 0
			}
			c := changed(t, other, index, 16)
			two, r := other.Prepare(context.Background(), c, admit(t, other, c), f.trust)
			if two == nil {
				t.Fatal(r)
			}
			if one.head.Core.Revision == two.head.Core.Revision {
				t.Fatal("candidate identity reused")
			}
			start := make(chan struct{})
			results := make(chan Result, 2)
			go func() { <-start; results <- f.session.Select(context.Background(), one) }()
			go func() { <-start; results <- other.Select(context.Background(), two) }()
			close(start)
			a, b := <-results, <-results
			outcomes := []int{int(a.Outcome), int(b.Outcome)}
			sort.Ints(outcomes)
			if outcomes[0] != int(ObservedCurrent) || outcomes[1] != int(Contention) || f.store.cas != 2 {
				t.Fatalf("%+v %+v", a, b)
			}
		})
	}
}

// full_only: false
func TestFullClosureAndSignerLoss(t *testing.T) {
	for _, which := range []string{"unchanged-page", "recipient", "root", "HEAD", "recipient-access", "lost-signer"} {
		t.Run(which, func(t *testing.T) {
			f := newFixture(t, 32, false, 1)
			switch which {
			case "unchanged-page":
				k, _ := format.Key(f.store.desc.Prefix, *f.session.root.ValueEntryPages[1])
				v := f.store.objects[k]
				v.Body[len(v.Body)-1] ^= 1
				f.store.objects[k] = v
			case "recipient":
				k, _ := format.Key(f.store.desc.Prefix, *f.session.root.Recipients[0])
				delete(f.store.objects, k)
			case "root":
				k, _ := format.Key(f.store.desc.Prefix, f.session.head.Core.Root)
				delete(f.store.objects, k)
			case "HEAD":
				delete(f.store.objects, f.store.desc.HeadKey)
			case "recipient-access":
				f.admission.admission.recipient = testID("wrong recipient")
			case "lost-signer":
				f.trust.SetUnavailable(true)
			}
			s, r := Open(context.Background(), f.admission, f.store)
			if which == "lost-signer" {
				if s == nil || r.Outcome != ObservedCurrent || f.trust.signs != 0 {
					t.Fatal(r)
				}
			} else if s != nil || r.Outcome == ObservedCurrent {
				t.Fatal("invalid closure accepted")
			}
			if which == "HEAD" && r.Outcome != RootLossUnsupported {
				t.Fatal(r)
			}
			if f.store.creates != 0 || f.store.cas != 0 {
				t.Fatal("closure failure repaired data")
			}
			if which == "lost-signer" {
				original := sessionStateImage(t, s)
				comparison := changed(t, s, 0)
				candidate, result := s.Prepare(context.Background(), comparison, admit(t, s, comparison), f.trust)
				if candidate != nil || result != (Result{Outcome: EvidenceUnavailable, Reason: SigningUnavailable}) || f.store.cas != 0 {
					t.Fatalf("signer loss admitted new selection: %+v", result)
				}
				fresh, result := Open(context.Background(), f.admission, f.store)
				if fresh == nil {
					t.Fatal(result)
				}
				assertStateImage(t, fresh, original)
			}
		})
	}
}

// full_only: false
func TestCapacityBeforeWrites(t *testing.T) {
	f := newFixture(t, 512, false, 16<<10)
	if f.session.root.RawBytes != contract.CryptoMaxRawSet {
		t.Fatal("fixture capacity")
	}
	original := fixtureStateImage(t, f)
	for _, name := range []string{"raw-eight-mib-plus-one", "value-sixty-four-kib-plus-one", "member-513"} {
		t.Run(name, func(t *testing.T) {
			desiredEntries := original.entryInputs()
			want := Result{Outcome: AdmissionRefused, Reason: CapacityExceeded}
			switch name {
			case "raw-eight-mib-plus-one":
				desiredEntries[0].InputBytes = append(desiredEntries[0].InputBytes, 1)
			case "value-sixty-four-kib-plus-one":
				desiredEntries[0].InputBytes = make([]byte, contract.CryptoMaxRawValue+1)
			case "member-513":
				desiredEntries = append(desiredEntries, ApplyEntryInput{})
			}
			reads := f.store.reads
			if c, r := f.session.Compare(context.Background(), desiredEntries, nil); c != nil || r != want {
				t.Fatal(r)
			}
			if f.store.reads != reads || f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 || f.session.prepared {
				t.Fatal("over-limit input crossed a mutation boundary")
			}
			assertStateImage(t, f.session, original)
		})
	}
	desiredEntries := original.entryInputs()
	for i := range desiredEntries {
		desiredEntries[i].InputBytes[0] ^= 255
	}
	c, r := f.session.Compare(context.Background(), desiredEntries, admitSuppliedComparison(t, f.session, nil, desiredEntries))
	if c == nil {
		t.Fatal(r)
	}
	permit := admit(t, f.session, c)
	want := expectedSuccessorImage(t, original, desiredEntries, observeAllocatedTransitionInputs(permit))
	candidate, r := f.session.Prepare(context.Background(), c, permit, f.trust)
	if candidate == nil {
		t.Fatal(r)
	}
	if len(candidate.body) > contract.MaxHeadLength || f.store.creates != 34 {
		t.Fatal("maximum replacement encoding")
	}
	for _, object := range candidate.objects {
		max := format.MaxValueEntryPage
		if object.ref.Kind == format.RootKind {
			max = format.MaxRoot
		}
		if len(object.body) > max {
			t.Fatal("maximum replacement exceeded an encoded object ceiling")
		}
	}
	if r := f.session.Select(context.Background(), candidate); r.Outcome != ObservedCurrent {
		t.Fatal(r)
	}
	s, r := Open(context.Background(), f.admission, f.store)
	if r.Outcome != ObservedCurrent {
		t.Fatal(r)
	}
	assertStateImage(t, s, want)
	removeUnselectedFixtureObjects(t, f, original, want)
	if len(f.store.objects) != int(want.Root.ChildCount)+2 {
		t.Fatal("maximum cold-open fixture retains unselected objects")
	}
	checkFreshProcess(t, f, want)
}
