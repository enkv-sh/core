package core

import (
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Observe completed Store calls while the real writer is paused. The callback
// runs after the underlying Store releases its mutex. Only a fresh reader sees
// each stored snapshot; it receives no writer session, permit or candidate.
type boundaryStore struct {
	contract.Store
	after func(method, key string)
}

func (s boundaryStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s boundaryStore) Read(ctx context.Context, key string, max uint32) contract.ReadResult {
	r := s.Store.Read(ctx, key, max)
	s.after("GET", key)
	return r
}

func (s boundaryStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	r := s.Store.Create(ctx, key, body)
	s.after("CREATE", key)
	return r
}

func (s boundaryStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	r := s.Store.CompareAndSwap(ctx, key, token, body)
	s.after("CAS", key)
	return r
}

// full_only: false
func TestFreshProcessAtTransitionBoundaries(t *testing.T) {
	for _, mode := range []string{"acknowledged", "lost-after"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, 32, false, 1)
			old := fixtureStateImage(t, f)
			checkFreshProcess(t, f, old)
			requested := old.entryInputs()
			for _, i := range []int{0, 16} {
				requested[i].InputBytes = append(requested[i].InputBytes, byte(99))
			}
			c, r := f.session.Compare(context.Background(), requested, admitSuppliedComparison(t, f.session, nil, requested))
			if c == nil {
				t.Fatal(r)
			}
			permit := admit(t, f.session, c)
			want := expectedSuccessorImage(t, old, requested, observeAllocatedTransitionInputs(permit))
			if old.Root.OutputConfiguration.SliceCount != 1 ||
				!slices.Equal(old.Root.RequiredSupport, want.Root.RequiredSupport) {
				t.Fatal("boundary fixture selected configuration")
			}
			configurationKey := mustKey(t, f.store.desc.Prefix, singleConfigurationRef(t, f.store.desc, old))
			expectedTrace := []string{"GET " + configurationKey}
			for _, read := range processPlainReceiptIndexReadRequests(t, f.store.desc, want) {
				expectedTrace = append(expectedTrace, "GET "+read.Key)
			}
			for _, ref := range []format.Ref{*want.Root.ValueEntryPages[0], *want.Root.ValueEntryPages[1], want.Root.AdministrativeIndex, want.RootRef} {
				key, err := format.Key(f.store.desc.Prefix, ref)
				if err != nil {
					t.Fatal(err)
				}
				expectedTrace = append(expectedTrace, "CREATE "+key, "GET "+key)
			}
			expectedTrace = append(expectedTrace, "CAS "+f.store.desc.HeadKey, "GET "+f.store.desc.HeadKey)
			if mode == "lost-after" {
				expectedTrace = append(expectedTrace, "GET "+f.store.desc.HeadKey)
			}
			for _, read := range processPlainObservationReadRequests(t, f.store.desc, want) {
				expectedTrace = append(expectedTrace, "GET "+read.Key)
			}
			var trace []string
			selected := false
			f.session.store = boundaryStore{Store: f.store, after: func(method, key string) {
				trace = append(trace, method+" "+key)
				if method == "CAS" {
					selected = true
				}
				expected := old
				if selected {
					expected = want
				}
				checkFreshProcess(t, f, expected)
			}}
			candidate, r := f.session.Prepare(context.Background(), c, permit, f.trust)
			if candidate == nil || r.ObservedRevision != old.Revision || f.store.cas != 0 {
				t.Fatal(r)
			}
			// Preparation and signing completed; no HEAD write has occurred.
			checkFreshProcess(t, f, old)
			f.store.casMode = mode
			r = f.session.Select(context.Background(), candidate)
			if r.Outcome != ObservedCurrent || r.Evidence != AuthenticatedClosure || r.RequestedRevision != want.Revision || r.ObservedRevision != want.Revision || r.CommitMayHaveOccurred {
				t.Fatal(r)
			}
			if !slices.Equal(trace, expectedTrace) || f.store.cas != 1 || f.trust.signs != 1 {
				t.Fatalf("wrong transition order or counts: %v", trace)
			}
			checkFreshProcess(t, f, want)
			// Cold open cannot depend on old diffs or obsolete objects.
			removeUnselectedFixtureObjects(t, f, old, want)
			checkFreshProcess(t, f, want)
		})
	}
}
