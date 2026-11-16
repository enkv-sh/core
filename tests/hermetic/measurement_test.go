package core

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type capacityAccountingLayout struct {
	name         string
	count, large int
	fragmented   bool
	change       string
}

// full_only: false
func TestCoreTelemetryCapacityAccounting(t *testing.T) {
	testCoreTelemetryCapacityAccounting(t, []capacityAccountingLayout{
		{"64-compact-all-supplied-plain", 64, 6, false, ""},
		{"64-fragmented-all-supplied-plain", 64, 6, true, ""},
		{"fragmented-mixed-membership", 32, 0, true, "mixed-membership"},
		{"drop-page", 32, 0, false, "drop-page"},
		{"new-page", 16, 0, false, "new-page"},
		{"last-removal", 1, 0, false, "last-removal"},
	})
}

// full_only: true
func TestCoreTelemetryMaximumCapacityAccounting(t *testing.T) {
	testCoreTelemetryCapacityAccounting(t, []capacityAccountingLayout{
		{"512-all-supplied-plain", 512, 51, false, ""},
		{"maximum-disjoint-replacement", 512, 128, false, "disjoint-replacement"},
	})
}

func testCoreTelemetryCapacityAccounting(t *testing.T, layouts []capacityAccountingLayout) {
	t.Helper()
	for _, layout := range layouts {
		changes := []string{"state.single-value-update-preserves-other-values/members_32", "state.cross-page-updates-preserve-other-values/members_32_cross_page"}
		if layout.change != "" {
			changes = []string{layout.change}
		}
		for _, change := range changes {
			t.Run(layout.name+"/"+change, func(t *testing.T) {
				ctx, reader, _ := coreTelemetryReader(t)
				delta := func(after metricdata.ResourceMetrics, name, operation string) int64 {
					return coreMetricSum(after, name, operation, "")
				}
				sizes := make([]int, layout.count)
				for i := range sizes {
					sizes[i] = 4096
					if layout.change != "" {
						sizes[i] = 0
					}
					if i >= len(sizes)-layout.large {
						sizes[i] = 65536
					}
				}
				memory := startMemoryAccounting()
				var f *fixture
				if change == "disjoint-replacement" {
					env := memoryScenarioEnvironment(t)
					base := newNamedEnvironmentFixture(t, ctx, env, sizes, false, maximumLifecycleNames("before"))
					f = &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: base.admission, session: base.session}
					f.trust.signs = 0
				} else {
					f = newSizedFixture(t, sizes, layout.fragmented)
				}
				selected := fixtureStateImage(t, f)
				removeUnselectedFixtureObjects(t, f, selected, selected)
				trace := &capacityTrace{}
				store := capacityStore{Store: f.store, trace: trace}
				trust := capacityTrust{Trust: f.trust, trace: trace}
				_ = coreTelemetrySnapshot(t, reader)
				var result Result
				f.session, result = Open(ctx, f.admission, store)
				if f.session == nil {
					t.Fatal(result)
				}
				original := fixtureStateImage(t, f)
				oldObjects := make(map[string]int64, len(f.store.objects))
				for key, object := range f.store.objects {
					oldObjects[key] = int64(len(object.Body))
				}
				memory.sample("open", f.session, nil, nil, nil)
				var oldBytes int64
				for _, v := range f.store.objects {
					oldBytes += int64(len(v.Body))
				}
				indices := []int{0}
				if change == "state.cross-page-updates-preserve-other-values/members_32_cross_page" {
					second := 16
					if layout.fragmented {
						second = 1
					}
					indices = append(indices, second)
				}
				var c *Comparison
				if layout.change == "" {
					c = changed(t, f.session, indices...)
				} else {
					input := original.entryInputs()
					switch change {
					case "disjoint-replacement":
						names := maximumLifecycleNames("after")
						for i := range input {
							input[i].Name = names[i]
						}
					case "mixed-membership":
						input = mixedLifecycleInput(original)
					case "drop-page":
						input = input[:16]
					case "last-removal":
						input = nil
					case "new-page":
						addition := input[0]
						addition.Name = "new-page-member"
						input = append(input, addition)
					}
					c, result = f.session.Compare(ctx, input, admitSuppliedComparison(t, f.session, nil, input))
					if c == nil {
						t.Fatal(result)
					}
				}
				memory.sample("compare", f.session, c, nil, nil)
				permit := admit(t, f.session, c)
				want := expectedSuccessorImage(t, original, c.desiredEntries, observeAllocatedTransitionInputs(permit))
				candidate, result := f.session.Prepare(ctx, c, permit, trust)
				if candidate == nil {
					t.Fatal(result)
				}
				memory.sample("prepare", f.session, c, candidate, nil)
				var newBytes int64
				for _, o := range candidate.objects {
					newBytes += int64(len(o.body))
				}
				if r := f.session.Select(ctx, candidate); r.Outcome != ObservedCurrent {
					t.Fatal(r)
				}
				memory.sample("select-returned", f.session, c, candidate, nil)
				transitionTrace := slices.Clone(trace.events)
				afterSelect := coreTelemetrySnapshot(t, reader)
				created, obsolete := successorObjectCounts(original, want)
				newPages, oldChildren, newChildren := int64(created)-1, int64(original.Root.ChildCount), int64(want.Root.ChildCount)
				if change == "disjoint-replacement" && (original.Root.RawBytes != 8<<20 || want.Root.RawBytes != 8<<20 || candidate.head.Subject.Normal.Union.Count != 1024 || created != 34 || obsolete != 34) {
					t.Fatal("replacement did not reach both member/raw/name and union limits")
				}
				headBytes := int64(len(candidate.body))
				openConfiguration := append(processConfigurationReadRequests(t, f.store.desc, original, false), processPlainReceiptReadRequests(t, f.store.desc, original)...)
				compareConfiguration := processConfigurationReadRequests(t, f.store.desc, original, false)
				prepareConfiguration := append(processConfigurationReadRequests(t, f.store.desc, original, false), processPlainReceiptIndexReadRequests(t, f.store.desc, want)...)
				selectConfiguration := processPlainObservationReadRequests(t, f.store.desc, want)
				configurationReads := int64(len(openConfiguration) + len(prepareConfiguration) + len(selectConfiguration))
				var configurationBytes int64
				for _, reads := range [][]processStoreRequest{openConfiguration, prepareConfiguration, selectConfiguration} {
					for _, read := range reads {
						configurationBytes += int64(read.Maximum)
					}
				}
				// changed uses a background context; only explicit membership
				// comparisons carry this test's telemetry capability.
				if layout.change != "" {
					configurationReads += 2 * int64(len(compareConfiguration))
					for _, read := range compareConfiguration {
						configurationBytes += 2 * int64(read.Maximum)
					}
				}
				// Cold Open and Prepare each borrow logical slices. Select scans
				// their physical pages and borrows logical slices after its HEAD read.
				for operation, want := range map[string]int64{
					"core.store.read":             oldChildren + newPages + 4 + configurationReads,
					"core.store.create":           newPages + 1,
					"core.store.compare_and_swap": 1,
					"core.trust.sign":             1,
				} {
					for _, name := range []string{"enkv.operation.calls", "enkv.operation.results"} {
						if got := delta(afterSelect, name, operation); got != want {
							t.Errorf("Open through Select: %s %s = %d, want %d", name, operation, got, want)
						}
					}
				}
				readBytes := delta(afterSelect, "enkv.operation.output_bytes", "core.store.read")
				createBytes := delta(afterSelect, "enkv.operation.input_bytes", "core.store.create")
				casBytes := delta(afterSelect, "enkv.operation.input_bytes", "core.store.compare_and_swap")
				if readBytes != oldBytes+newBytes+headBytes+configurationBytes || createBytes != newBytes || casBytes != headBytes {
					t.Fatalf("Store boundary bytes: read/create/CAS = %d/%d/%d, want %d/%d/%d", readBytes, createBytes, casBytes, oldBytes+newBytes+headBytes+configurationBytes, newBytes, headBytes)
				}
				// These are disjoint Store body transfers. Core logical value
				// bytes are a different boundary and must not enter this total.
				if got, want := readBytes+createBytes+casBytes, oldBytes+2*newBytes+2*headBytes+configurationBytes; got != want {
					t.Fatalf("Store body transfer = %d, want %d", got, want)
				}

				// Select returns facts, not its decoded StateSession. Retain a
				// real decode in this separate accounting pass.
				observation, r := f.session.readCurrent(ctx)
				if observation == nil || r.ObservedRevision != candidate.head.Core.Revision {
					t.Fatal(r)
				}
				memory.sample("retained-observation-accounting", f.session, c, candidate, observation)
				afterObservation := coreTelemetrySnapshot(t, reader)
				// Selected streamed configuration pages have no retained body cache.
				// Other immutable objects are reused; these exact physical and
				// logical configuration reads follow the selected HEAD observation.
				observationTrace := []string{"read " + f.store.desc.HeadKey}
				var observationConfigurationBytes int64
				for _, request := range selectConfiguration {
					observationTrace = append(observationTrace, "read "+request.Key)
					observationConfigurationBytes += int64(request.Maximum)
				}
				if !slices.Equal(trace.events[len(transitionTrace):], observationTrace) {
					t.Fatal("cached observation read outside its exact HEAD and streamed configuration selection")
				}
				for _, sample := range memory.samples {
					if sample.ByteCapacity > 77987224 {
						t.Fatalf("retained component bytes exceed preparation ledger: %+v", sample)
					}
					if sample.GoHeapUpperBound < sample.ByteCapacity {
						t.Fatalf("heap bound below retained byte capacity: %+v", sample)
					}
				}
				for _, name := range []string{"enkv.operation.calls", "enkv.operation.results"} {
					if got, want := delta(afterObservation, name, "core.store.read"), int64(len(observationTrace)); got != want {
						t.Errorf("cached observation: %s reads = %d, want exact HEAD and configuration reads %d", name, got, want)
					}
				}
				if got := delta(afterObservation, "enkv.operation.output_bytes", "core.store.read"); got != headBytes+observationConfigurationBytes {
					t.Fatalf("cached observation read bytes = %d, want exact HEAD and configuration bytes %d", got, headBytes+observationConfigurationBytes)
				}

				s, r := Open(ctx, f.admission, f.store)
				if s == nil {
					t.Fatal(r)
				}
				afterReopen := coreTelemetrySnapshot(t, reader)
				currentBytes := int64(len(s.body) + len(f.store.objects[mustKey(t, s.admission.store.Prefix, s.head.Core.Root)].Body))
				currentBytes += int64(len(f.store.objects[mustKey(t, s.admission.store.Prefix, want.Root.AdministrativeIndex)].Body))
				for _, table := range [][]*format.Ref{s.root.ValueEntryPages[:], s.root.Recipients[:]} {
					for _, ref := range table {
						if ref != nil {
							key := mustKey(t, s.admission.store.Prefix, *ref)
							currentBytes += int64(len(f.store.objects[key].Body))
						}
					}
				}
				for _, table := range [][]format.Ref{s.root.RequiredSupport, s.root.AdministrativeIndexShards, s.root.CurrentAccess.Core.AccessPageRefs} {
					for _, ref := range table {
						currentBytes += int64(ref.Length)
					}
				}
				reopenConfiguration := append(processConfigurationReadRequests(t, f.store.desc, want, false), processPlainReceiptReadRequests(t, f.store.desc, want)...)
				var reopenConfigurationBytes int64
				for _, read := range reopenConfiguration {
					reopenConfigurationBytes += int64(read.Maximum)
				}
				for _, name := range []string{"enkv.operation.calls", "enkv.operation.results"} {
					if got, want := delta(afterReopen, name, "core.store.read"), newChildren+2+int64(len(reopenConfiguration)); got != want {
						t.Errorf("reopen: %s reads = %d, want complete selected closure %d", name, got, want)
					}
					for _, operation := range []string{"core.store.create", "core.store.compare_and_swap", "core.trust.sign"} {
						if got := delta(afterObservation, name, operation) + delta(afterReopen, name, operation); got != 0 {
							t.Errorf("observation and reopen: %s %s = %d, want 0", name, operation, got)
						}
					}
				}
				if got := delta(afterReopen, "enkv.operation.output_bytes", "core.store.read"); got != currentBytes+reopenConfigurationBytes {
					t.Fatalf("reopen read bytes = %d, want complete selected closure and logical slice borrows %d", got, currentBytes+reopenConfigurationBytes)
				}
				assertStateImage(t, s, want)
				selectedKeys := map[string]bool{s.admission.store.HeadKey: true, mustKey(t, s.admission.store.Prefix, want.RootRef): true,
					mustKey(t, s.admission.store.Prefix, want.Root.AdministrativeIndex): true}
				for _, table := range [][]*format.Ref{want.Root.ValueEntryPages[:], want.Root.Recipients[:]} {
					for _, ref := range table {
						if ref != nil {
							selectedKeys[mustKey(t, s.admission.store.Prefix, *ref)] = true
						}
					}
				}
				for _, table := range [][]format.Ref{want.Root.RequiredSupport, want.Root.AdministrativeIndexShards, want.Root.CurrentAccess.Core.AccessPageRefs} {
					for _, ref := range table {
						selectedKeys[mustKey(t, s.admission.store.Prefix, ref)] = true
					}
				}
				var createdCount, garbageCount int
				var createdBytes, garbageBytes, retainedBytes int64
				for key, object := range f.store.objects {
					size := int64(len(object.Body))
					retainedBytes += size
					if _, old := oldObjects[key]; !old {
						createdCount++
						createdBytes += size
					}
					if !selectedKeys[key] {
						garbageCount++
						garbageBytes += size
					}
				}
				if createdCount != int(created) || garbageCount != int(obsolete) || createdBytes != newBytes || len(selectedKeys) != int(newChildren)+2 || retainedBytes != currentBytes+garbageBytes {
					t.Fatal("created, current and noncurrent object partition differs")
				}
				var expectedGarbage int64
				expectedGarbage = oldObjects[mustKey(t, s.admission.store.Prefix, original.RootRef)]
				expectedGarbage += oldObjects[mustKey(t, s.admission.store.Prefix, original.Root.AdministrativeIndex)]
				for i, ref := range original.Root.ValueEntryPages {
					if ref != nil && (want.Root.ValueEntryPages[i] == nil || *ref != *want.Root.ValueEntryPages[i]) {
						expectedGarbage += oldObjects[mustKey(t, s.admission.store.Prefix, *ref)]
					}
				}
				if garbageBytes != expectedGarbage {
					t.Fatal("obsolete immutable bytes differ from replaced root/pages")
				}
				var expectedTrace []string
				for _, request := range processPlainReadRequests(t, f.store.desc, original) {
					expectedTrace = append(expectedTrace, "read "+request.Key)
				}
				for range 2 {
					for _, request := range compareConfiguration {
						expectedTrace = append(expectedTrace, "read "+request.Key)
					}
				}
				for _, request := range prepareConfiguration {
					expectedTrace = append(expectedTrace, "read "+request.Key)
				}
				for i, ref := range want.Root.ValueEntryPages {
					if ref != nil && (original.Root.ValueEntryPages[i] == nil || *ref != *original.Root.ValueEntryPages[i]) {
						key := mustKey(t, f.store.desc.Prefix, *ref)
						expectedTrace = append(expectedTrace, "create "+key, "read "+key)
					}
				}
				rootKey := mustKey(t, f.store.desc.Prefix, want.RootRef)
				indexKey := mustKey(t, f.store.desc.Prefix, want.Root.AdministrativeIndex)
				expectedTrace = append(expectedTrace, "create "+indexKey, "read "+indexKey)
				expectedTrace = append(expectedTrace, "create "+rootKey, "read "+rootKey, "sign", "cas "+f.store.desc.HeadKey, "read "+f.store.desc.HeadKey)
				for _, request := range selectConfiguration {
					expectedTrace = append(expectedTrace, "read "+request.Key)
				}
				if !slices.Equal(transitionTrace, expectedTrace) || trace.maximum != 1 || trace.active != 0 {
					t.Fatalf("request order/concurrency: %v, maximum %d", transitionTrace, trace.maximum)
				}
				var operations []string
				for _, event := range transitionTrace {
					for _, operation := range []string{"read", "create", "sign", "cas"} {
						if event == operation || len(event) > len(operation) && event[:len(operation)+1] == operation+" " {
							operations = append(operations, operation)
							break
						}
					}
				}
				evidence := struct {
					Fixture, Change                                                                           string
					CurrentBytes, NewImmutableBytes, GarbageBytes, LogicalBodyTransfer                        int64
					CurrentObjects, NewImmutableObjects, GarbageObjects, SerialStoreDepth, MaximumConcurrency int
					Trace                                                                                     []string
					Memory                                                                                    []memorySample
				}{layout.name, change, currentBytes, newBytes, garbageBytes, readBytes + createBytes + casBytes, len(selectedKeys), createdCount, garbageCount, len(transitionTrace) - 1, trace.maximum, operations, memory.samples}
				body, err := json.Marshal(evidence)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("capacity accounting: %s", body)
			})
		}
	}
}

type capacityTrace struct {
	mu              sync.Mutex
	events          []string
	active, maximum int
}

func (t *capacityTrace) enter(event string) func() {
	t.mu.Lock()
	t.active++
	t.maximum = max(t.maximum, t.active)
	t.events = append(t.events, event)
	t.mu.Unlock()
	return func() { t.mu.Lock(); t.active--; t.mu.Unlock() }
}

type capacityStore struct {
	contract.Store
	trace *capacityTrace
}

func (s capacityStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s capacityStore) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	done := s.trace.enter("read " + key)
	defer done()
	return s.Store.Read(ctx, key, maximum)
}
func (s capacityStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	done := s.trace.enter("create " + key)
	defer done()
	return s.Store.Create(ctx, key, body)
}
func (s capacityStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	done := s.trace.enter("cas " + key)
	defer done()
	return s.Store.CompareAndSwap(ctx, key, token, body)
}

type capacityTrust struct {
	contract.Trust
	trace *capacityTrace
}

func (s capacityTrust) Sign(ctx context.Context, request contract.SignRequest) contract.SignResult {
	done := s.trace.enter("sign")
	defer done()
	return s.Trust.Sign(ctx, request)
}

// full_only: false
func TestAggregateMaximaDoNotCompose(t *testing.T) {
	f := newFixture(t, 512, false, 0)
	original := fixtureStateImage(t, f)
	desiredEntries := f.session.currentEntryInputs()
	for i := range desiredEntries {
		desiredEntries[i].InputBytes = make([]byte, 65536)
	}
	reads := f.store.reads
	if c, r := f.session.Compare(context.Background(), desiredEntries, nil); c != nil || r != (Result{Outcome: AdmissionRefused, Reason: CapacityExceeded}) || f.store.reads != reads || f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 || f.session.prepared {
		t.Fatal(r)
	}
	assertStateImage(t, f.session, original)
	f = newFixture(t, 1, false, 65536)
	original = fixtureStateImage(t, f)
	desiredEntries = f.session.currentEntryInputs()
	desiredEntries[0].InputBytes[0] ^= 255
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
	if r := f.session.Select(context.Background(), candidate); r.Outcome != ObservedCurrent {
		t.Fatal(r)
	}
	s, r := Open(context.Background(), f.admission, f.store)
	if s == nil {
		t.Fatal(r)
	}
	assertStateImage(t, s, want)
}
