package core

import (
	"maps"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// Compare the complete Core call/result deltas in a shared provider collection.
// Other components have their own assertions. Every Core operation and attribute
// must still match; checking only a requested operation could hide extra calls.
func assertCoreTelemetryResults(t *testing.T, after metricdata.ResourceMetrics, want map[[2]string]int64) {
	t.Helper()
	counts := func(data metricdata.ResourceMetrics, name string) map[[2]string]int64 {
		got := make(map[[2]string]int64)
		for _, scope := range data.ScopeMetrics {
			for _, measurement := range scope.Metrics {
				if measurement.Name != name {
					continue
				}
				sum, ok := measurement.Data.(metricdata.Sum[int64])
				if !ok {
					t.Fatalf("%s is not an int64 sum", name)
				}
				for _, point := range sum.DataPoints {
					provider, hasProvider := point.Attributes.Value("provider")
					if hasProvider && provider.AsString() != "core" {
						continue
					}
					operation, hasOperation := point.Attributes.Value("operation")
					result, hasResult := point.Attributes.Value("result")
					attributes := 2
					if name == "enkv.operation.results" {
						attributes = 3
					}
					if !hasProvider || provider.AsString() != "core" || !hasOperation || hasResult != (attributes == 3) || point.Attributes.Len() != attributes {
						t.Fatalf("%s has unexpected attributes: %v", name, point.Attributes)
					}
					got[[2]string{operation.AsString(), result.AsString()}] += point.Value
				}
			}
		}
		return got
	}
	for _, name := range []string{"enkv.operation.calls", "enkv.operation.results"} {
		expected := want
		if name == "enkv.operation.calls" {
			expected = make(map[[2]string]int64)
			for labels, count := range want {
				expected[[2]string{labels[0], ""}] += count
			}
		}
		got := counts(after, name)
		if !maps.Equal(got, expected) {
			t.Errorf("%s deltas = %v, want %v", name, got, expected)
		}
	}
}

// full_only: false
func TestCoreTelemetryCompleteChain(t *testing.T) {
	ctx, reader, _ := coreTelemetryReader(t)
	f := newFixture(t, 1, false, 1)
	_ = coreTelemetrySnapshot(t, reader)
	input := f.session.currentEntryInputs()
	input[0].InputBytes = append(input[0].InputBytes, 99)
	want := Result{Outcome: ObservedCurrent, ObservedRevision: f.session.head.Core.Revision, ObservedSnapshotID: f.session.root.Snapshot, Evidence: AuthenticatedClosure}
	comparison, result := f.session.Compare(ctx, input, admitSuppliedComparison(t, f.session, nil, input))
	if comparison == nil || result != want {
		t.Fatalf("ComparePlain result = %+v, want %+v", result, want)
	}
	permit := admit(t, f.session, comparison)
	want.RequestedRevision = permit.plan.revision
	candidate, result := f.session.Prepare(ctx, comparison, permit, f.trust)
	if candidate == nil || result != want {
		t.Fatalf("Prepare result = %+v, want %+v", result, want)
	}
	want.ObservedRevision, want.ObservedSnapshotID = permit.plan.revision, permit.plan.snapshot
	if result := f.session.Select(ctx, candidate); result != want {
		t.Fatalf("Select result = %+v, want %+v", result, want)
	}
	want.RequestedRevision = contract.ID{}
	if session, result := Open(ctx, f.admission, f.store); session == nil || result != want {
		t.Fatalf("Open result = %+v, want %+v", result, want)
	}
	const creates, configurationReads, readbacks = 3, 3, 3
	image := fixtureStateImage(t, f)
	selectionReads := 1 + len(processPlainObservationReadRequests(t, f.store.desc, image))
	coldReads := len(processPlainReadRequests(t, f.store.desc, image))
	after := coreTelemetrySnapshot(t, reader)
	assertCoreTelemetryResults(t, after, map[[2]string]int64{
		{"core.open", "observed_current"}:                     1,
		{"core.compare", "observed_current"}:                  1,
		{"core.prepare", "observed_current"}:                  1,
		{"core.select", "observed_current"}:                   1,
		{"core.store.read", "read_ok"}:                        int64(configurationReads + readbacks + selectionReads + coldReads + len(processPlainReceiptIndexReadRequests(t, f.store.desc, image))),
		{"core.store.create", "write_acknowledged"}:           creates,
		{"core.store.compare_and_swap", "write_acknowledged"}: 1,
		{"core.trust.sign", "sign_ok"}:                        1,
	})
	if coreMetricSum(after, "enkv.operation.input_bytes", "core.store.create", "") == 0 || coreMetricSum(after, "enkv.operation.output_bytes", "core.store.read", "") == 0 {
		t.Error("actual Store boundary bytes are absent")
	}
}

// full_only: false
func TestCoreTelemetryUnchanged(t *testing.T) {
	ctx, reader, _ := coreTelemetryReader(t)
	f := newFixture(t, 1, false, 1)
	_ = coreTelemetrySnapshot(t, reader)
	comparison, result := f.session.Compare(ctx, f.session.currentEntryInputs(), admitSuppliedComparison(t, f.session, nil, f.session.currentEntryInputs()))
	want := Result{Outcome: Unchanged, ObservedRevision: f.session.head.Core.Revision, ObservedSnapshotID: f.session.root.Snapshot, Evidence: AuthenticatedClosure}
	if comparison != nil || result != want {
		t.Fatalf("unchanged ComparePlain result = %+v, want %+v", result, want)
	}
	assertCoreTelemetryResults(t, coreTelemetrySnapshot(t, reader), map[[2]string]int64{
		{"core.compare", "unchanged"}:  1,
		{"core.store.read", "read_ok"}: 2,
	})
}

// full_only: false
func TestCoreTelemetryContention(t *testing.T) {
	ctx, reader, _ := coreTelemetryReader(t)
	f := newFixture(t, 1, false, 1)
	other, result := Open(ctx, f.admission, f.store)
	if other == nil || result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	winner := prepare(t, f, changed(t, f.session, 0))
	comparison := changed(t, other, 0)
	permit := admit(t, other, comparison)
	loser, result := other.Prepare(ctx, comparison, permit, f.trust)
	if loser == nil || result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	if result := f.session.Select(ctx, winner); result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	_ = coreTelemetrySnapshot(t, reader)
	result = other.Select(ctx, loser)
	want := Result{Outcome: Contention, Reason: StalePrecondition, RequestedRevision: permit.plan.revision, ObservedRevision: other.head.Core.Revision, ObservedSnapshotID: other.root.Snapshot, Evidence: AuthenticatedClosure}
	if result != want {
		t.Fatalf("stale Select result = %+v, want %+v", result, want)
	}
	assertCoreTelemetryResults(t, coreTelemetrySnapshot(t, reader), map[[2]string]int64{
		{"core.select", "contention"}:                         1,
		{"core.store.compare_and_swap", "write_precondition"}: 1,
	})
}

// full_only: false
func TestCoreTelemetrySelectionUncertainty(t *testing.T) {
	// Each observation reads HEAD, both opaque support pages, the configuration
	// slice and the receipt index in three passes. Transport recovery also reads
	// preliminary HEAD, once for each send.
	for _, tc := range []struct {
		mode             string
		outcome          Outcome
		reason           Reason
		mayHaveCommitted bool
		selected         bool
		coreLabel        string
		writeLabel       string
		writes, reads    int64
	}{
		{"lost-before", EvidenceUnavailable, WriteUncertain, false, false, "evidence_unavailable", "write_unknown", 3, 24},
		{"lost-after", ObservedCurrent, NoReason, false, true, "observed_current", "write_unknown", 1, 8},
		{"conflict", UnresolvedCommit, WriteUncertain, true, false, "unresolved_commit", "write_conflict", 1, 7},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ctx, reader, _ := coreTelemetryReader(t)
			f := newFixture(t, 1, false, 1)
			candidate := prepare(t, f, changed(t, f.session, 0))
			f.store.casMode = tc.mode
			want := Result{Outcome: tc.outcome, Reason: tc.reason, RequestedRevision: candidate.head.Core.Revision, ObservedRevision: f.session.head.Core.Revision, ObservedSnapshotID: f.session.root.Snapshot, Evidence: AuthenticatedClosure, CommitMayHaveOccurred: tc.mayHaveCommitted}
			if tc.mode == "lost-before" {
				want.ObservedRevision, want.ObservedSnapshotID, want.Evidence = contract.ID{}, contract.ID{}, NoEvidence
				want.StoreReason = contract.ReasonTransport
			}
			if tc.selected {
				want.ObservedRevision, want.ObservedSnapshotID = candidate.head.Core.Revision, candidate.head.Core.Root.Object
			}
			_ = coreTelemetrySnapshot(t, reader)
			if result := f.session.Select(ctx, candidate); result != want {
				t.Fatalf("Select result = %+v, want %+v", result, want)
			}
			assertCoreTelemetryResults(t, coreTelemetrySnapshot(t, reader), map[[2]string]int64{
				{"core.select", tc.coreLabel}:                  1,
				{"core.store.compare_and_swap", tc.writeLabel}: tc.writes,
				{"core.store.read", "read_ok"}:                 tc.reads,
			})
		})
	}
}

// full_only: false
func TestCoreTelemetryImmutableReadback(t *testing.T) {
	// Prepare streams the selected configuration and receipt index before it
	// persists the value page, administrative index and root.
	const immutableObjects = 3
	for _, tc := range []struct {
		mode          string
		prepared      bool
		result        Result
		coreLabel     string
		writeLabel    string
		readLabel     string
		writes, reads int64
	}{
		{"lost-before", false, Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}, "evidence_unavailable", "write_unknown", "read_missing", 3, 3},
		{"conflict", false, Result{Outcome: IntegrityFailure, Reason: ImmutableConflict}, "integrity_failure", "write_precondition", "read_ok", 1, 1},
		{"lost-after", true, Result{Outcome: ObservedCurrent}, "observed_current", "write_unknown", "read_ok", immutableObjects, immutableObjects},
		{"equal", true, Result{Outcome: ObservedCurrent}, "observed_current", "write_precondition", "read_ok", immutableObjects, immutableObjects},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ctx, reader, _ := coreTelemetryReader(t)
			f := newFixture(t, 1, false, 1)
			comparison := changed(t, f.session, 0)
			permit := admit(t, f.session, comparison)
			f.store.createMode = tc.mode
			if tc.mode == "equal" {
				planned, result := f.session.buildSuccessor(t.Context(), comparison, permit.plan)
				if planned == nil {
					t.Fatal(result)
				}
				for _, object := range planned.objects {
					f.store.put(mustKey(t, f.store.desc.Prefix, object.ref), object.body)
				}
			}
			want := tc.result
			if tc.prepared {
				want.RequestedRevision, want.ObservedRevision = permit.plan.revision, f.session.head.Core.Revision
				want.ObservedSnapshotID, want.Evidence = f.session.root.Snapshot, AuthenticatedClosure
			}
			_ = coreTelemetrySnapshot(t, reader)
			candidate, result := f.session.Prepare(ctx, comparison, permit, f.trust)
			if (candidate != nil) != tc.prepared || result != want {
				t.Fatalf("Prepare candidate present = %t, result = %+v; want present = %t, result = %+v", candidate != nil, result, tc.prepared, want)
			}
			metrics := map[[2]string]int64{
				{"core.prepare", tc.coreLabel}:       1,
				{"core.store.create", tc.writeLabel}: tc.writes,
				{"core.store.read", tc.readLabel}:    tc.reads,
			}
			metrics[[2]string{"core.store.read", "read_ok"}] += 2
			if tc.prepared {
				metrics[[2]string{"core.trust.sign", "sign_ok"}] = 1
			}
			assertCoreTelemetryResults(t, coreTelemetrySnapshot(t, reader), metrics)
		})
	}
}

// full_only: false
func TestCoreTelemetryOpenFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		damage    func(*testing.T, *fixture)
		result    Result
		coreLabel string
		reads     map[string]int64
	}{
		{
			name: "corrupt-member",
			damage: func(t *testing.T, f *fixture) {
				key := mustKey(t, f.store.desc.Prefix, *f.session.root.ValueEntryPages[0])
				object := f.store.objects[key]
				object.Body[len(object.Body)-1] ^= 1
				f.store.objects[key] = object
			},
			result: Result{Outcome: IntegrityFailure, Reason: InvalidReference}, coreLabel: "integrity_failure", reads: map[string]int64{"read_ok": 3},
		},
		{
			name: "missing-root",
			damage: func(t *testing.T, f *fixture) {
				delete(f.store.objects, mustKey(t, f.store.desc.Prefix, f.session.head.Core.Root))
			},
			result: Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}, coreLabel: "evidence_unavailable", reads: map[string]int64{"read_ok": 1, "read_missing": 1},
		},
		{
			name: "missing-head",
			damage: func(_ *testing.T, f *fixture) {
				delete(f.store.objects, f.store.desc.HeadKey)
			},
			result: Result{Outcome: RootLossUnsupported, Reason: MissingSelectedObject}, coreLabel: "root_loss_unsupported", reads: map[string]int64{"read_missing": 1},
		},
		{
			name: "unavailable-root",
			damage: func(t *testing.T, f *fixture) {
				rootKey := mustKey(t, f.store.desc.Prefix, f.session.head.Core.Root)
				f.store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
					if key == rootKey {
						return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
					}
					return result
				}
			},
			result: Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}, coreLabel: "evidence_unavailable", reads: map[string]int64{"read_ok": 1, "read_unavailable": 3},
		},
		{
			name: "oversized-head",
			damage: func(_ *testing.T, f *fixture) {
				f.store.put(f.store.desc.HeadKey, make([]byte, contract.MaxHeadLength+1))
			},
			result: Result{Outcome: IntegrityFailure, Reason: InvalidFormat}, coreLabel: "integrity_failure", reads: map[string]int64{"read_invalid": 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, reader, _ := coreTelemetryReader(t)
			f := newFixture(t, 1, false, 1)
			tc.damage(t, f)
			_ = coreTelemetrySnapshot(t, reader)
			if session, result := Open(ctx, f.admission, f.store); session != nil || result != tc.result {
				t.Fatalf("Open result = %+v, want %+v", result, tc.result)
			}
			metrics := map[[2]string]int64{{"core.open", tc.coreLabel}: 1}
			for label, count := range tc.reads {
				metrics[[2]string{"core.store.read", label}] = count
			}
			assertCoreTelemetryResults(t, coreTelemetrySnapshot(t, reader), metrics)
		})
	}
}

// full_only: false
func TestCoreTelemetrySignerFailures(t *testing.T) {
	// The selected configuration and receipt index are streamed before the value
	// page, administrative index and root are written and read back before signing.
	const immutableObjects = 3
	for _, tc := range []struct {
		name       string
		proof      contract.SignResult
		result     Result
		coreLabel  string
		trustLabel string
	}{
		{"provider-proof-failure", contract.SignResult{Reason: contract.ReasonProof}, Result{Outcome: IntegrityFailure, Reason: InvalidProof}, "integrity_failure", "sign_invalid"},
		{"provider-access-failure", contract.SignResult{Reason: contract.ReasonAccess}, Result{Outcome: EvidenceUnavailable, Reason: SigningUnavailable}, "evidence_unavailable", "sign_unavailable"},
		{"provider-transport-failure", contract.SignResult{Reason: contract.ReasonTransport}, Result{Outcome: EvidenceUnavailable, Reason: SigningUnavailable}, "evidence_unavailable", "sign_unavailable"},
		{"empty-success", contract.SignResult{}, Result{Outcome: EvidenceUnavailable, Reason: SigningUnavailable}, "evidence_unavailable", "sign_unavailable"},
		{"malformed-empty-proof", contract.SignResult{Reason: contract.ReasonMalformed}, Result{Outcome: EvidenceUnavailable, Reason: SigningUnavailable}, "evidence_unavailable", "sign_invalid"},
		{"corrupt-signature", contract.SignResult{Signature: []byte("invalid signature")}, Result{Outcome: IntegrityFailure, Reason: InvalidProof}, "integrity_failure", "sign_ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, reader, _ := coreTelemetryReader(t)
			f := newFixture(t, 1, false, 1)
			comparison := changed(t, f.session, 0)
			permit := admit(t, f.session, comparison)
			trust := &signResultTrust{Trust: f.trust, result: tc.proof}
			_ = coreTelemetrySnapshot(t, reader)
			if candidate, result := f.session.Prepare(ctx, comparison, permit, trust); candidate != nil || result != tc.result {
				t.Fatalf("Prepare result = %+v, want %+v", result, tc.result)
			}
			if trust.calls != 1 || !trust.request.Valid() || trust.request.Purpose() != contract.LifecyclePurpose {
				t.Fatalf("sign calls = %d, request = %+v; want one valid lifecycle request", trust.calls, trust.request)
			}
			assertCoreTelemetryResults(t, coreTelemetrySnapshot(t, reader), map[[2]string]int64{
				{"core.prepare", tc.coreLabel}:              1,
				{"core.store.create", "write_acknowledged"}: immutableObjects,
				{"core.store.read", "read_ok"}:              2 + immutableObjects,
				{"core.trust.sign", tc.trustLabel}:          1,
			})
		})
	}
}

// full_only: false
func TestCoreTelemetryCollectorShutdownDoesNotChangeResult(t *testing.T) {
	ctx, reader, shutdown := coreTelemetryReader(t)
	shutdown()
	f := newFixture(t, 1, false, 1)
	candidate := prepare(t, f, changed(t, f.session, 0))
	if result := f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	var data metricdata.ResourceMetrics
	if err := reader.ManualReader().Collect(ctx, &data); err == nil || !strings.Contains(err.Error(), "shutdown") {
		t.Fatalf("collector shutdown must remain explicit: %v", err)
	}
}
