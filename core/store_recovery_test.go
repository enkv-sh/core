package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type readFailureStore struct {
	results   []contract.ReadResult
	keys      []string
	limits    []uint32
	onRead    func()
	onReadCtx func(context.Context) (contract.ReadResult, bool)
}

// full_only: false
func TestStoreEpisodeExtendsOnlyCurrentStage(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	episode := storeEpisode{deadline: deadline}
	if episode.beginStage(0) || !episode.beginStage(2) || !episode.readAllowed() || !episode.readAllowed() || episode.readAllowed() {
		t.Fatal("initial stage did not stop at its exact read limit")
	}
	if episode.extendStage(1) || episode.extendStage(0) || episode.extendStage(-1) ||
		episode.stages != 1 || episode.stageReads != 2 || episode.readLimit != 2 || episode.deadline != deadline {
		t.Fatal("rejected extension changed the active stage")
	}
	if !episode.extendStage(3) || !episode.readAllowed() || episode.readAllowed() ||
		episode.stages != 1 || episode.stageReads != 3 || episode.readLimit != 3 || episode.deadline != deadline {
		t.Fatal("extension reset a stage or missed its exact new limit")
	}
	if episode.extendStage(4) || episode.readLimit != 3 {
		t.Fatal("the same observed image extended its allowance twice")
	}
	// A caller may not turn an already exhausted stage into an unlimited one.
	episode.readLimit = 2
	if episode.readAllowed() {
		t.Fatal("reads beyond a lowered limit were permitted")
	}
	episode.readLimit = 3
	if !episode.beginStage(1) || episode.stages != 2 || episode.stageReads != 0 || episode.deadline != deadline {
		t.Fatal("next stage did not preserve the failure deadline")
	}
}

// full_only: false
func TestObservedReadStageAllowanceIsCheckedAndKeepsTheSameEpisode(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	episode := &storeEpisode{deadline: deadline}
	if !episode.beginStage(headObservationLimit()) {
		t.Fatal("observation stage did not start")
	}
	ctx := context.WithValue(context.Background(), storeEpisodeKey{}, episode)
	for range headObservationLimit() {
		if !episode.readAllowed() {
			t.Fatal("base observation limit refused an authorized read")
		}
	}
	if episode.readAllowed() || extendObservedReadStage(ctx, 0) || extendObservedReadStage(ctx, ^uint64(0)) ||
		episode.stageReads != headObservationLimit() || episode.stages != 1 || episode.deadline != deadline {
		t.Fatal("exhaustion or rejected extension changed the stage")
	}
	if !extendObservedReadStage(ctx, 1) || episode.readLimit != headObservationLimit()+3 || episode.stages != 1 || episode.deadline != deadline {
		t.Fatal("one additional logical read did not allow exactly three Store attempts")
	}
	for range 3 {
		if !episode.readAllowed() {
			t.Fatal("an allowed transport attempt was refused")
		}
	}
	if episode.readAllowed() || extendObservedReadStage(ctx, 1) || episode.stageReads != headObservationLimit()+3 {
		t.Fatal("the extra physical-attempt limit was exceeded")
	}
}

func (s *readFailureStore) Descriptor() contract.Descriptor { return contract.Descriptor{} }
func (s *readFailureStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	s.keys = append(s.keys, key)
	s.limits = append(s.limits, limit)
	if s.onRead != nil {
		s.onRead()
	}
	if s.onReadCtx != nil {
		if result, handled := s.onReadCtx(ctx); handled {
			return result
		}
	}
	result := s.results[0]
	if len(s.results) > 1 {
		s.results = s.results[1:]
	}
	return result
}

// full_only: false
func TestStoreRetryCallInheritsEpisodeDeadline(t *testing.T) {
	store := &readFailureStore{results: []contract.ReadResult{{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}}}
	store.onReadCtx = func(ctx context.Context) (contract.ReadResult, bool) {
		if len(store.keys) == 1 {
			return contract.ReadResult{}, false
		}
		<-ctx.Done()
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}, true
	}
	session := &StateSession{store: store, admission: openAdmission{expires: time.Now().Add(150 * time.Millisecond)}}
	started := time.Now()
	got := session.storeRead(context.Background(), "fixed-key", 23)
	if got.Status != contract.ReadUnavailable || len(store.keys) != 2 || time.Since(started) > time.Second {
		t.Fatal("retry Store call escaped episode deadline", got, len(store.keys))
	}
}

// full_only: false
func TestStoreReadStopsBeforeRetryWhenCancelledOrAdmissionExpires(t *testing.T) {
	transport := contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport, Body: []byte("partial")}
	for _, tc := range []struct {
		name   string
		cancel bool
		expiry time.Duration
	}{
		{name: "cancelled during first call", cancel: true, expiry: time.Minute},
		{name: "admission expires before first wait", expiry: 50 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store := &readFailureStore{results: []contract.ReadResult{transport}}
			if tc.cancel {
				store.onRead = cancel
			}
			session := &StateSession{store: store, admission: openAdmission{expires: time.Now().Add(tc.expiry)}}
			got := session.storeRead(ctx, "fixed-key", 23)
			if got.Status != contract.ReadUnavailable || got.Reason != contract.ReasonLimit || len(got.Body) != 0 || len(store.keys) != 1 {
				t.Fatalf("result=%+v calls=%d", got, len(store.keys))
			}
		})
	}
}
func (*readFailureStore) Create(context.Context, string, []byte) contract.WriteResult {
	return contract.WriteResult{}
}
func (*readFailureStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	return contract.WriteResult{}
}
func (*readFailureStore) CompareAndSwap(context.Context, string, contract.Token, []byte) contract.WriteResult {
	return contract.WriteResult{}
}

// full_only: false
func TestStoreReadRecoversOnlyTypedTransportFailure(t *testing.T) {
	transport := contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport, Body: []byte("partial")}
	for _, tc := range []struct {
		name    string
		results []contract.ReadResult
		calls   int
		status  contract.ReadStatus
		body    string
	}{
		{name: "transport then complete", results: []contract.ReadResult{transport, {Status: contract.ReadOK, Body: []byte("complete")}}, calls: 2, status: contract.ReadOK, body: "complete"},
		{name: "last permitted call", results: []contract.ReadResult{transport, transport, {Status: contract.ReadOK, Body: []byte("complete")}}, calls: 3, status: contract.ReadOK, body: "complete"},
		{name: "exhausted", results: []contract.ReadResult{transport}, calls: 3, status: contract.ReadUnavailable},
		{name: "access denial", results: []contract.ReadResult{{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}}, calls: 1, status: contract.ReadUnavailable},
		{name: "missing", results: []contract.ReadResult{{Status: contract.ReadMissing}}, calls: 1, status: contract.ReadMissing},
		{name: "invalid", results: []contract.ReadResult{{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}}, calls: 1, status: contract.ReadInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &readFailureStore{results: tc.results}
			session := &StateSession{store: store, admission: openAdmission{expires: time.Now().Add(time.Minute)}}
			got := session.storeRead(context.Background(), "fixed-key", 23)
			if got.Status != tc.status || string(got.Body) != tc.body || len(store.keys) != tc.calls {
				t.Fatalf("result=%+v calls=%d", got, len(store.keys))
			}
			for i := range store.keys {
				if store.keys[i] != "fixed-key" || store.limits[i] != 23 {
					t.Fatalf("call %d changed target or bound", i)
				}
			}
		})
	}
}

type immutableDiagnosticStore struct {
	contract.Store
	write          contract.WriteResult
	read           contract.ReadResult
	creates, reads int
	onRead         func()
}

func (s *immutableDiagnosticStore) Create(context.Context, string, []byte) contract.WriteResult {
	s.creates++
	return s.write
}

func (s *immutableDiagnosticStore) Read(context.Context, string, uint32) contract.ReadResult {
	s.reads++
	if s.onRead != nil {
		s.onRead()
	}
	return s.read
}

// full_only: false
func TestImmutablePersistenceReportsResolvedFactsWithoutReuseWarnings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write contract.WriteResult
		want  string
	}{
		{"created", contract.WriteResult{Status: contract.WriteAcknowledged}, "immutable_created"},
		{"reused", contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}, "immutable_reused"},
		{"unknown-then-present", contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}, "immutable_verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := observationTestSession(t)
			store := &immutableDiagnosticStore{Store: s.store, write: tc.write, read: contract.ReadResult{Status: contract.ReadOK, Body: []byte("fixed immutable bytes")}}
			s.store = store
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			ctx, preparation := beginApplyPreparation(ctx)
			if got := s.persistImmutable(ctx, "fixed-key", []byte("fixed immutable bytes"), 64); got != (Result{}) {
				t.Fatal("verified persistence changed Product success", got)
			}
			if store.creates != 1 || store.reads != 1 {
				t.Fatal("telemetry changed physical call counts", store.creates, store.reads)
			}
			wantFacts := ApplyPreparationFacts{VerifiedPreparations: 1, PossibleUnacknowledgedCreate: tc.name == "unknown-then-present"}
			if tc.name == "created" {
				wantFacts.AcknowledgedCreates = 1
			}
			if preparation.facts != wantFacts {
				t.Fatal("diagnostics changed preparation history", preparation.facts, wantFacts)
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32))
			resolved, pending, unknown := 0, 0, 0
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal("invalid persistence record", err, record)
				}
				if record.Event != telemetry.DiagnosticReturn {
					continue
				}
				if string(record.Operation) == "core.store.persist_immutable" {
					resolved++
					if string(record.Result) != tc.want || record.SeverityText != "INFO" || record.Reason != "" {
						t.Fatal("missing exact resolved persistence fact", record)
					}
				}
				if string(record.Result) == "verification_pending" {
					pending++
				}
				if record.Result == telemetry.ResultWriteUnknown {
					unknown++
				}
				if tc.name == "reused" && record.SeverityNumber >= telemetry.SeverityWarn {
					t.Fatal("verified reuse emitted an operator warning", record)
				}
			}
			if resolved != 1 || tc.name == "reused" && pending != 1 || tc.name == "unknown-then-present" && unknown != 1 {
				t.Fatal("persistence history or resolution missing", resolved, pending, unknown)
			}
			if recorder.Status().Rejected != 0 {
				t.Fatal("persistence facts were rejected")
			}
			store.creates, store.reads = 0, 0
			disabled, disabledPreparation := beginApplyPreparation(t.Context())
			if got := s.persistImmutable(disabled, "fixed-key", []byte("fixed immutable bytes"), 64); got != (Result{}) || disabledPreparation.facts != wantFacts || store.creates != 1 || store.reads != 1 {
				t.Fatal("disabled telemetry changed persistence or preparation", got, disabledPreparation.facts, store.creates, store.reads)
			}
		})
	}
}

// full_only: false
func TestImmutablePersistenceKeepsVerificationFailuresVisible(t *testing.T) {
	for _, tc := range []struct {
		name    string
		read    contract.ReadResult
		outcome Outcome
		reason  Reason
	}{
		{"mismatch", contract.ReadResult{Status: contract.ReadOK, Body: []byte("different")}, IntegrityFailure, ImmutableConflict},
		{"invalid", contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}, IntegrityFailure, ImmutableConflict},
		{"missing", contract.ReadResult{Status: contract.ReadMissing}, EvidenceUnavailable, ReadUnavailable},
		{"unavailable", contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}, EvidenceUnavailable, ReadUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := observationTestSession(t)
			store := &immutableDiagnosticStore{Store: s.store, write: contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}, read: tc.read}
			s.store = store
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			result := s.persistImmutable(ctx, "fixed-key", []byte("fixed immutable bytes"), 64)
			if result.Outcome != tc.outcome || result.Reason != tc.reason || store.creates != 1 || store.reads != 1 {
				t.Fatal("verification failure changed Product facts", result, store.creates, store.reads)
			}
			returns := 0
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
				if record.Event == telemetry.DiagnosticReturn && string(record.Operation) == "core.store.persist_immutable" {
					returns++
					if record.SeverityNumber != telemetry.SeverityError || record.Validate() != nil || record.Reason != coreDiagnosticReason(tc.reason) {
						t.Fatal("verification failure lacks exact visible cause", record)
					}
				}
			}
			if returns != 1 {
				t.Fatal("verification failure lacks semantic terminal", returns)
			}
		})
	}
}

// full_only: false
func TestImmutablePersistenceCancellationKeepsPossibleWriteHistory(t *testing.T) {
	s, _ := observationTestSession(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	recorder := telemetry.NewRecorder()
	ctx = telemetry.WithCapability(ctx, telemetry.NewCapability(nil, recorder))
	ctx, preparation := beginApplyPreparation(ctx)
	store := &immutableDiagnosticStore{Store: s.store, write: contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}, read: contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}, onRead: cancel}
	s.store = store
	result := s.persistImmutable(ctx, "fixed-key", []byte("fixed immutable bytes"), 64)
	if result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable || result.StoreReason != contract.ReasonLimit || !preparation.facts.PossibleUnacknowledgedCreate || preparation.facts.VerifiedPreparations != 0 || store.creates != 1 || store.reads != 1 {
		t.Fatal("cancellation changed unresolved write facts", result, preparation.facts, store.creates, store.reads)
	}
	terminals := 0
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
		if record.Event == telemetry.DiagnosticReturn && record.Operation == telemetry.OpCoreStorePersistImmutable {
			terminals++
			if record.Result != telemetry.ResultCancelled || record.Reason != telemetry.DiagnosticReasonCancelled || record.SeverityNumber != telemetry.SeverityWarn {
				t.Fatal("cancellation lost its distinct visible terminal", record)
			}
		}
	}
	if terminals != 1 {
		t.Fatal("cancellation has no terminal", terminals)
	}
}
