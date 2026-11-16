package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/telemetry"
)

func nativePublicationFixture(t *testing.T, secret bool, slots ...string) (*fixture, fixtureEnvironment, publicationInput, publicationPrivate, string) {
	t.Helper()
	env := memoryScenarioEnvironment(t)
	f := newEnvironmentFixture(t, t.Context(), env, nil, false)
	entries := []ApplyEntryInput{{Name: "plain", Recipients: []contract.ID{f.admission.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
		InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, InputBytes: []byte("private data")}}
	if secret {
		entries = append(entries, suppliedSecret(t, env, "secret", "publication source", custody.StandardValue))
	}
	if len(slots) == 0 {
		slots = []string{"plain-target", "secret-target"}
	}
	targets := make([]outputApplyTarget, len(entries))
	for i, entry := range entries {
		targets[i] = outputApplyTarget{entryName: entry.Name, target: hermeticNativeOutputTarget(slots[i], slots[i], contract.OutputEncodingRaw, hermeticNumberPolicy("test-policy", []uint64{1, 9}))}
		f.admission.admission.publicationNamespaces = append(f.admission.admission.publicationNamespaces, publicationNamespace{domain: env.Domain, service: "test-output/service/v1", physical: slots[i], premise: fixtureID(env.Domain, "independent namespace "+slots[i])})
	}
	f.session.admission.publicationNamespaces = f.admission.admission.publicationNamespaces
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "native", targets: targets}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"native"}}}}
	f.session = selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, env.Custody, entries, output)
	f.admission = OpenContext{admission: &f.session.admission}
	config := installedPublicationTestConfig(t)
	if err := env.Custody.InstallPublication(t.Context(), config, "native", publicationTestConfigContract); err != nil {
		t.Fatal("install exact publication child", err)
	}
	input := publicationInput{names: []string{"plain"}, acting: f.admission.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	if secret {
		input.names = append(input.names, "secret")
	}
	return &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: f.admission, session: f.session}, env, input, publicationCustodyPrivate(env.Custody), os.TempDir()
}

func nativePublicationPlan(t *testing.T, ctx context.Context, f *fixture, input publicationInput, private publicationPrivate, diagnostics *publicationDiagnosticCapture) *publicationPlan {
	t.Helper()
	plan, result := f.session.planPublication(ctx, input, private)
	diagnostics.collect()
	if plan == nil {
		t.Fatalf("native plan outcome=%d reason=%d", result.Outcome, result.Reason)
	}
	return plan
}

func assertNativePublicationACK(t *testing.T, got publicationOperationResult, count int, action uint8) {
	t.Helper()
	if got.summary != contract.PublicationSummaryComplete || len(got.output.Entries) != count {
		for _, entry := range got.output.Entries {
			for _, row := range entry.Actions {
				t.Logf("action fact coordinate=%x action=%d disposition=%d attempt=%x evidence_class=%d entry=%d status=%d", entry.CoordinateID, row.Action, row.Disposition, row.AttemptID, row.Evidence.Class, row.Evidence.Entry, row.Evidence.NormalizedStatus)
			}
		}
		t.Fatalf("native result summary=%d entries=%d state=%+v", got.summary, len(got.output.Entries), got.state)
	}
	attempts := map[contract.ID]bool{}
	for _, entry := range got.output.Entries {
		if len(entry.Actions) != 1 {
			t.Fatal("native action count", len(entry.Actions))
		}
		row := entry.Actions[0]
		if row.Action != action || row.Disposition != contract.PublicationOutcomeAcknowledged || row.AttemptID.IsZero() || attempts[row.AttemptID] || row.Evidence.Class != contract.PublicationRequestAcknowledged || row.Evidence.Entry != contract.PublicationMayHaveEnteredEntry {
			t.Fatalf("native action=%d disposition=%d attempt=%x evidence=%+v", row.Action, row.Disposition, row.AttemptID, row.Evidence)
		}
		attempts[row.AttemptID] = true
	}
}

func assertNativePublicationJoined(t *testing.T, recorder *publicationDiagnosticCapture, staging string, sends int) {
	t.Helper()
	assertNativePublicationRecordsJoined(t, drainNativePublicationDiagnostics(t, recorder), staging, sends)
}

// Test capture is drained only between synchronous calls or while other owners
// are held. Retaining each batch keeps the complete oracle without exceeding the
// recorder's bounded production capture.
type publicationDiagnosticCapture struct {
	recorder *telemetry.Recorder
	records  []telemetry.DiagnosticRecord
}

func newPublicationDiagnosticCapture() *publicationDiagnosticCapture {
	return &publicationDiagnosticCapture{recorder: telemetry.NewRecorder()}
}

func (capture *publicationDiagnosticCapture) collect() {
	for {
		batch := capture.recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 128))
		capture.records = append(capture.records, batch...)
		if len(batch) < 128 {
			return
		}
	}
}

func (capture *publicationDiagnosticCapture) current(current publicationCurrent) publicationCurrent {
	return func(ctx context.Context) (*StateSession, contract.Trust, Result) {
		capture.collect()
		session, trust, result := current(ctx)
		capture.collect()
		return session, trust, result
	}
}

func drainNativePublicationDiagnostics(t *testing.T, capture *publicationDiagnosticCapture) []telemetry.DiagnosticRecord {
	t.Helper()
	capture.collect()
	status := capture.recorder.Status()
	if status.DroppedContention != 0 || status.DroppedFull != 0 || status.DroppedClosed != 0 || status.Rejected != 0 {
		t.Fatalf("native diagnostic evidence incomplete: %+v", status)
	}
	records := capture.records
	capture.records = nil
	return records
}

func assertNativePublicationRecordsJoined(t *testing.T, records []telemetry.DiagnosticRecord, staging string, sends int) {
	t.Helper()
	starts, joins, dispatches := 0, 0, 0
	for _, row := range records {
		if row.Validate() != nil {
			t.Fatal("invalid host diagnostic")
		}
		if row.Provider != telemetry.ProviderOutputHost {
			continue
		}
		if row.Operation == telemetry.OpOutputHostDispatch && row.Event == telemetry.DiagnosticStart {
			dispatches++
		}
		if row.Operation == telemetry.OpOutputHostJoin {
			if row.Event == telemetry.DiagnosticStart {
				starts++
			}
			if row.Event == telemetry.DiagnosticReturn && (row.Result == telemetry.ResultSuccess || row.Result == telemetry.ResultCancelled || row.Result == telemetry.ResultExpired) {
				joins++
			}
		}
	}
	files, err := os.ReadDir(staging)
	if dispatches != sends || starts == 0 || starts != joins || err != nil || len(files) != 0 {
		t.Fatalf("native joins dispatches=%d starts=%d positive=%d staged=%d err=%v", dispatches, starts, joins, len(files), err)
	}
}

// full_only: false
func TestPublicationNativeSelectedCreate(t *testing.T) {
	f, _, input, private, staging := nativePublicationFixture(t, false)
	recorder := newPublicationDiagnosticCapture()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder))
	got := nativePublicationPlan(t, ctx, f, input, private, recorder).execute(ctx, private, recorder.current(publicationEngineCurrent(f)))
	assertNativePublicationACK(t, got, 1, contract.PublicationCreateWithValue)
	row := got.output.Entries[0].Actions[0]
	want := "test-instance/plain-target/" + hex.EncodeToString(row.AttemptID[:])
	if row.Evidence.SafeResourceID != want || row.Evidence.NormalizedStatus != 201 {
		t.Fatal("qualified create resource", row.Evidence)
	}
	assertNativePublicationJoined(t, recorder, staging, 1)
}

// full_only: false
func TestPublicationNativeSeparateValuesAndNoOp(t *testing.T) {
	f, env, input, private, staging := nativePublicationFixture(t, true)
	recorder := newPublicationDiagnosticCapture()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder))
	got := nativePublicationPlan(t, ctx, f, input, private, recorder).execute(ctx, private, recorder.current(publicationEngineCurrent(f)))
	assertNativePublicationACK(t, got, 2, contract.PublicationCreateWithValue)
	if got.output.Entries[0].CoordinateID == got.output.Entries[1].CoordinateID || !slices.IsSortedFunc(got.output.Entries, func(a, b contract.PublicationTargetOutcome) int {
		return slices.Compare(a.CoordinateID[:], b.CoordinateID[:])
	}) {
		t.Fatal("separate coordinate order")
	}
	assertNativePublicationJoined(t, recorder, staging, 2)
	var state Result
	f.session, state = Open(ctx, f.admission, f.store)
	if f.session == nil || state.Outcome != ObservedCurrent {
		t.Fatal("native no-op Open", state)
	}
	actions, checks, owners := 0, 0, 0
	original := private
	private.Actions = func(ctx context.Context, target publicationExecutionInput) (publicationActionFacts, error) {
		actions++
		return original.Actions(ctx, target)
	}
	private.Check = func(ctx context.Context, in publicationActionCheckInput) (publicationActionCheckFacts, error) {
		checks++
		return original.Check(ctx, in)
	}
	private.NewOwner = func(ctx context.Context, in publicationOwnerInput) (publicationPrivateOwner, error) {
		owners++
		return original.NewOwner(ctx, in)
	}
	calls, privateCalls := env.Custody.Calls()
	got = nativePublicationPlan(t, ctx, f, input, private, recorder).execute(ctx, private, recorder.current(publicationEngineCurrent(f)))
	afterCalls, afterPrivate := env.Custody.Calls()
	if got.summary != contract.PublicationSummaryNoChange || actions != 0 || checks != 0 || owners != 0 || calls != afterCalls || privateCalls != afterPrivate {
		t.Fatalf("no-op summary=%d actions=%d checks=%d owners=%d public=%d/%d private=%d/%d", got.summary, actions, checks, owners, calls, afterCalls, privateCalls, afterPrivate)
	}
	for _, entry := range got.output.Entries {
		if len(entry.Actions) != 1 || entry.Actions[0].Disposition != contract.PublicationNoOp || !entry.Actions[0].AttemptID.IsZero() {
			t.Fatal("no-op added attempt")
		}
	}
	assertNativePublicationNoPrivateWork(t, recorder)
	env.FreshCurrent(t, f.admission, f.session)
}

func nativePublicationOutput(entries []ApplyEntryInput, subjects []uint64) *outputApplyInput {
	targets := make([]outputApplyTarget, len(entries))
	for i, entry := range entries {
		slot := entry.Name + "-target"
		targets[i] = outputApplyTarget{entryName: entry.Name, target: hermeticNativeOutputTarget(slot, slot, contract.OutputEncodingRaw, hermeticNumberPolicy("test-policy", slices.Clone(subjects)))}
	}
	return &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "native", targets: targets}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"native"}}}}
}

// full_only: false
func TestPublicationNativeValuePolicyAndDeletion(t *testing.T) {
	f, env, input, private, staging := nativePublicationFixture(t, true)
	recorder := newPublicationDiagnosticCapture()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder))
	create := nativePublicationPlan(t, ctx, f, input, private, recorder).execute(ctx, private, recorder.current(publicationEngineCurrent(f)))
	assertNativePublicationACK(t, create, 2, contract.PublicationCreateWithValue)
	instances := map[contract.ID]string{}
	for _, entry := range create.output.Entries {
		instances[entry.CoordinateID] = entry.Actions[0].Evidence.SafeResourceID
	}
	assertNativePublicationJoined(t, recorder, staging, 2)
	publicationEngineReopen(t, f)
	entries := f.session.currentEntryInputs()
	entries[0].InputBytes = []byte("updated plain data")
	entries[1] = suppliedSecret(t, env, "secret", "publication updated source", custody.AlternateStandardValue)
	beforeConfiguration, state := f.session.currentOutputConfigurationForApply(ctx)
	if state.Outcome != 0 {
		t.Fatal("before value output configuration", state)
	}
	parent := admitSuppliedComparison(t, f.session, env.Custody, entries)
	comparison, state := f.session.Compare(ctx, entries, parent)
	recorder.collect()
	if comparison == nil {
		t.Fatal("native value comparison", state)
	}
	candidate, state := f.session.Prepare(ctx, comparison, admit(t, f.session, comparison), env.Trust)
	recorder.collect()
	if candidate == nil {
		t.Fatal("native value preparation", state)
	}
	env.Custody.RetireApply()
	state = f.session.Select(ctx, candidate)
	recorder.collect()
	if state.Outcome != ObservedCurrent {
		t.Fatal("native value selection", state)
	}
	publicationEngineReopen(t, f)
	afterConfiguration, state := f.session.currentOutputConfigurationForApply(ctx)
	if state.Outcome != 0 || !reflect.DeepEqual(beforeConfiguration, afterConfiguration) {
		t.Fatal("ordinary value change did not preserve output configuration", state)
	}
	input.deadline = time.Now().Add(30 * time.Second)
	value := nativePublicationPlan(t, ctx, f, input, private, recorder).execute(ctx, private, recorder.current(publicationEngineCurrent(f)))
	assertNativePublicationACK(t, value, 2, contract.PublicationWriteValue)
	assertNativePublicationJoined(t, recorder, staging, 2)
	publicationEngineReopen(t, f)
	// Retain the admitted supplied envelopes; canonical secret bytes are not producer input.
	f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, nativePublicationOutput(entries, []uint64{1}))
	input.deadline = time.Now().Add(30 * time.Second)
	policy := nativePublicationPlan(t, ctx, f, input, private, recorder).execute(ctx, private, recorder.current(publicationEngineCurrent(f)))
	assertNativePublicationACK(t, policy, 2, contract.PublicationUpdatePolicy)
	assertNativePublicationJoined(t, recorder, staging, 2)
	before := publicationEngineReopen(t, f)
	env.FreshCurrent(t, f.admission, f.session)
	f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, &outputApplyInput{})
	input.names = nil
	for _, entry := range create.output.Entries {
		input.deletes = append(input.deletes, entry.CoordinateID)
	}
	input.deadline = time.Now().Add(30 * time.Second)
	deletion := nativePublicationPlan(t, ctx, f, input, private, recorder).execute(ctx, private, recorder.current(publicationEngineCurrent(f)))
	assertNativePublicationACK(t, deletion, 2, contract.PublicationDeleteOwned)
	assertNativePublicationJoined(t, recorder, staging, 2)
	after := publicationEngineReopen(t, f)
	for _, result := range []publicationOperationResult{value, policy, deletion} {
		for _, entry := range result.output.Entries {
			row := entry.Actions[0]
			if row.Evidence.NormalizedStatus != 204 || row.Evidence.SafeResourceID != instances[entry.CoordinateID] {
				t.Fatal("action changed exact owned instance", row.Action, row.Evidence)
			}
		}
	}
	for _, entry := range deletion.output.Entries {
		row := after.coordinates[entry.CoordinateID]
		old := before.coordinates[entry.CoordinateID]
		if row.BindingState != contract.PublicationBindingRetired || !row.ActiveBindingIncarnationID.IsZero() || row.DeletionTargetRowDigest != old.DeletionTargetRowDigest || row.LastDeleteAckAttemptID != entry.Actions[0].AttemptID || row.PossibleRemoteObject != 1 {
			t.Fatalf("retained deletion relation binding=%d deletion=%x ack=%x residue=%d", row.BindingState, row.DeletionTargetRowDigest, row.LastDeleteAckAttemptID, row.PossibleRemoteObject)
		}
	}
}

// full_only: false
func TestPublicationNativeLostProcessReopensWithoutSend(t *testing.T) {
	f, env, input, private, staging := nativePublicationFixture(t, false)
	recorder := newPublicationDiagnosticCapture()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder))
	plan := nativePublicationPlan(t, ctx, f, input, private, recorder)
	candidate, preparation, state := plan.reserveCandidate(ctx, f.session, plan.targets[0], contract.PublicationCreateWithValue, private)
	if candidate == nil {
		t.Fatal("native reserve candidate", state)
	}
	persisted, state := f.session.persistCandidate(ctx, candidate, f.trust)
	if persisted == nil {
		t.Fatal("native reserve persistence", state)
	}
	selected, state := f.session.selectCandidate(ctx, persisted)
	if selected == nil || !preparation.armed {
		t.Fatal("native direct ACK did not arm", state)
	}
	if err := preparation.retire(ctx); err != nil {
		t.Fatal("lost process private Close", err)
	}
	assertNativePublicationJoined(t, recorder, staging, 0)
	f.session = selected
	env.FreshCurrent(t, f.admission, f.session)
	relation := publicationEngineReopen(t, f)
	marker := relation.markers[preparation.original.marker.AttemptID]
	if marker.State != contract.PublicationMayHaveEntered || marker.Evidence.Class != contract.PublicationUnproved {
		t.Fatal("open reservation gained result", marker.State, marker.Evidence.Class)
	}
	original := private
	actions, checks, owners := 0, 0, 0
	private.Actions = func(ctx context.Context, target publicationExecutionInput) (publicationActionFacts, error) {
		actions++
		return original.Actions(ctx, target)
	}
	private.Check = func(ctx context.Context, in publicationActionCheckInput) (publicationActionCheckFacts, error) {
		checks++
		return original.Check(ctx, in)
	}
	private.NewOwner = func(ctx context.Context, in publicationOwnerInput) (publicationPrivateOwner, error) {
		owners++
		return original.NewOwner(ctx, in)
	}
	reopened := nativePublicationPlan(t, ctx, f, input, private, recorder).execute(ctx, private, recorder.current(publicationEngineCurrent(f)))
	row := reopened.output.Entries[0].Actions[0]
	if reopened.summary != contract.PublicationSummaryUnknown || row.Disposition != contract.PublicationOutcomeUnknown || row.AttemptID != marker.AttemptID || actions != 0 || checks != 0 || owners != 0 {
		t.Fatalf("cold read restored send summary=%d disposition=%d actions=%d checks=%d owners=%d", reopened.summary, row.Disposition, actions, checks, owners)
	}
	assertNativePublicationNoPrivateWork(t, recorder)
}

func assertNativePublicationNoPrivateWork(t *testing.T, recorder *publicationDiagnosticCapture) {
	t.Helper()
	operations := map[telemetry.Operation]int{}
	for _, record := range drainNativePublicationDiagnostics(t, recorder) {
		operations[record.Operation]++
		if err := record.Validate(); err != nil {
			t.Fatal("zero-work diagnostic invalid", err)
		}
		switch record.Operation {
		case telemetry.OpCryptoPublicationPrepare, telemetry.OpCryptoPublicationArm, telemetry.OpCryptoPublicationSend, telemetry.OpCryptoPublicationRetire:
			t.Fatal("zero-work plan made private publication work", record.Operation)
		}
		if record.Provider == telemetry.ProviderOutputHost {
			t.Fatal("zero-work plan made child work", record.Operation)
		}
	}
	t.Logf("zero-work observation operations: %v", operations)
}

// full_only: false
func TestPublicationNativeCancellationJoinsChild(t *testing.T) {
	f, env, input, private, staging := nativePublicationFixture(t, false, "sleep")
	recorder := newPublicationDiagnosticCapture()
	ctx, cancel := context.WithCancel(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)))
	defer cancel()
	plan := nativePublicationPlan(t, ctx, f, input, private, recorder)
	done := make(chan publicationOperationResult, 1)
	joined := false
	t.Cleanup(func() {
		cancel()
		if !joined {
			select {
			case <-done:
				joined = true
			case <-time.After(5 * time.Second):
				t.Error("native publication cleanup did not join")
			}
		}
	})
	go func() { done <- plan.execute(ctx, private, recorder.current(publicationEngineCurrent(f))) }()
	entered := false
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
waiting:
	for {
		select {
		case <-deadline.C:
			cancel()
			t.Fatal("native child did not enter Execute")
		case got := <-done:
			joined = true
			t.Fatalf("native child ended before cancellation summary=%d", got.summary)
		case <-ticker.C:
			var err error
			entered, err = publicationTestChildEntered(staging)
			if err != nil {
				cancel()
				t.Fatal("cancel barrier", err)
			}
			if entered {
				break waiting
			}
		}
	}
	cancel()
	select {
	case got := <-done:
		joined = true
		if !entered || got.summary != contract.PublicationSummaryUnknown || got.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeUnknown {
			t.Fatal("cancelled entered action lost unknown", got.summary)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled publication did not positively join")
	}
	assertNativePublicationJoined(t, recorder, staging, 1)
	publicationEngineReopen(t, f)
	env.FreshCurrent(t, f.admission, f.session)
}

// full_only: false
func TestPublicationNativeEncodingChangeChain(t *testing.T) {
	for _, source := range []string{"supplied", "generated"} {
		t.Run(source, func(t *testing.T) {
			var f *fixture
			var env fixtureEnvironment
			var input publicationInput
			var private publicationPrivate
			var staging string
			var entries []ApplyEntryInput
			var registry []contract.GeneratorImplementation
			var generatedEffects func() int32
			slots := []string{"plain-encoding-target", "secret-encoding-target"}
			if source == "supplied" {
				f, env, input, private, staging = nativePublicationFixture(t, true, slots...)
				entries = f.session.currentEntryInputs()
				// Keep producer envelopes outside the selected canonical value.
				entries[1] = suppliedSecret(t, env, "secret", "encoding chain source", custody.StandardValue)
			} else {
				generatedEnv, _, selected, implementation, effects, _ := normalHandoffGeneratedFixture(t, false, true)
				env = generatedEnv
				original := *selected.valueEntry(entrySlot(t, selected, "generated"))
				historyNames := []string{"history-alpha", "history-omega"}
				history := generatedPlanInputWithCurrentGenerated(t, selected, fixtureID(env.Domain, "encoding chain historical cleanup"), historyNames, defaultGeneratedFixtureProfile())
				selected, failed := selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, historyNames, history, nil)
				selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
				work := mustSelectedGeneratedWork(t, selected)
				var cleanupDuty contract.ID
				for _, row := range work.records {
					if row.Kind == contract.GeneratedDutySupportKind {
						duty, err := contract.InspectGeneratedDutyRecord(row.Body)
						if err != nil || duty.Kind != contract.GeneratedDutyUnselectedCleanup || duty.OriginalOperationID != history.graph.Request.OperationID {
							t.Fatal("encoding history lacks its exact unselected cleanup duty", err)
						}
						cleanupDuty = duty.DutyID
					}
				}
				if cleanupDuty.IsZero() || selected.root.Generated.Duties != 1 || work.parent != nil || !selected.root.Generated.ActiveOwner.IsZero() ||
					!work.hasRecord(generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: failed.expected.Template.HazardID}) ||
					!reflect.DeepEqual(*selected.valueEntry(entrySlot(t, selected, "generated")), original) || effects.Load() != 1 {
					t.Fatal("encoding history did not preserve the generated value and exact cleanup backlog")
				}
				generatedEffects = effects.Load
				registry = []contract.GeneratorImplementation{implementation}
				entries = selected.currentEntryInputs()
				slots = []string{"generated-encoding-target"}
				selected.admission.publicationNamespaces = []publicationNamespace{{domain: env.Domain, service: "test-output/service/v1", physical: slots[0], premise: fixtureID(env.Domain, "independent encoding namespace")}}
				f = &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: OpenContext{admission: &selected.admission}, session: selected}
				config := installedPublicationTestConfig(t)
				if err := env.Custody.InstallPublication(t.Context(), config, "native", publicationTestConfigContract); err != nil {
					t.Fatal("install generated publication child", err)
				}
				private = publicationCustodyPrivate(env.Custody)
				staging = os.TempDir()
				input = publicationInput{names: []string{"generated"}, acting: selected.admission.recipient}
			}
			output := func(encoding string) *outputApplyInput {
				out := nativePublicationOutput(entries, []uint64{1, 9})
				for i := range out.bindings[0].targets {
					hermeticRetargetOutput(&out.bindings[0].targets[i].target, slots[i], slots[i])
					out.bindings[0].targets[i].target.PayloadEncoding = hermeticOutputEncoding(encoding)
				}
				return out
			}
			priorReceipts, err := f.session.receiptWindows(t.Context())
			if err != nil {
				t.Fatal("encoding chain prior authenticated receipts", err)
			}
			priorReceipts.Successes = slices.Clone(priorReceipts.Successes)
			priorReceipts.Failures = slices.Clone(priorReceipts.Failures)
			if source == "generated" && (len(priorReceipts.Successes) == 0 || len(priorReceipts.Failures) == 0) {
				t.Fatal("generated encoding history lacks prior success and failure receipts")
			}
			checkPriorReceipts := func(s *StateSession) {
				got, err := s.receiptWindows(t.Context())
				if err != nil || got.DomainID != priorReceipts.DomainID {
					t.Fatal("encoding chain current authenticated receipts", err)
				}
				for _, window := range []struct {
					before, after []contract.CompactMutationReceipt
				}{{priorReceipts.Successes, got.Successes}, {priorReceipts.Failures, got.Failures}} {
					for _, receipt := range window.before {
						if !slices.Contains(window.after, receipt) {
							t.Fatal("encoding chain changed or lost a prior receipt in its original window")
						}
					}
				}
			}
			if source == "generated" {
				f.session = selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, env.Custody, entries, output("raw"), registry...)
				f.admission = OpenContext{admission: &f.session.admission}
			}
			checkPriorReceipts(f.session)
			canonical, access := f.session.currentEntryInputs(), f.session.root.CurrentAccess
			generatedRecords := func(s *StateSession) []contract.SupportRecord {
				rows, err := s.preservedWorkSupportRecords(t.Context())
				if err != nil {
					t.Fatal("authenticated generated support and receipts", err)
				}
				rows = slices.DeleteFunc(rows, func(row contract.SupportRecord) bool { return row.Kind >= contract.PublicationCoordinateSupportKind })
				for i := range rows {
					rows[i].Body = bytes.Clone(rows[i].Body)
				}
				return rows
			}
			beforeGenerated := generatedRecords(f.session)
			if source == "generated" && len(beforeGenerated) == 0 {
				t.Fatal("generated chain lacks authenticated historical cleanup records")
			}
			recorder := newPublicationDiagnosticCapture()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder))
			rawLengths := map[string]uint32{"plain-encoding-target": 12, "secret-encoding-target": 28, "generated-encoding-target": 42}
			encodedLengths := map[string]uint32{"plain-encoding-target": 16, "secret-encoding-target": 40, "generated-encoding-target": 56}
			births := map[contract.ID]contract.PublicationCoordinate{}
			instances := map[contract.ID]string{}
			rawBases := map[contract.ID]contract.ID{}
			coordinateSlots := map[contract.ID]string{}
			attempts := map[contract.ID]bool{}
			for phase, encoding := range []string{"raw", "base64", "raw"} {
				if phase != 0 {
					f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, output(encoding), registry...)
					f.admission = OpenContext{admission: &f.session.admission}
				}
				checkPriorReceipts(f.session)
				if !reflect.DeepEqual(f.session.currentEntryInputs(), canonical) || !reflect.DeepEqual(f.session.root.CurrentAccess, access) || !reflect.DeepEqual(generatedRecords(f.session), beforeGenerated) || generatedEffects != nil && generatedEffects() != 1 {
					t.Fatal("encoding selection changed canonical values, access, generated records or generation effects", phase)
				}
				// Configuration authentication is a separate completed stage without publication private work.
				assertNativePublicationNoPrivateWork(t, recorder)
				input.deadline = time.Now().Add(30 * time.Second)
				plan := nativePublicationPlan(t, ctx, f, input, private, recorder)
				planRecords := drainNativePublicationDiagnostics(t, recorder)
				for _, target := range plan.targets {
					want := rawLengths[target.target.CanonicalTarget]
					if target.valueBasis.ContentLength != want {
						t.Fatal("encoding replaced original raw length", target.valueBasis.ContentLength, want)
					}
					if encoding == "base64" {
						want = encodedLengths[target.target.CanonicalTarget]
					}
					if want == 0 || target.payloadLength != want {
						t.Fatal("planned length differs from independent byte literal", target.payloadLength, want)
					}
					if phase == 0 {
						rawBases[target.coordinate] = target.valueBasisDigest
						coordinateSlots[target.coordinate] = target.target.CanonicalTarget
					} else if (target.valueBasisDigest == rawBases[target.coordinate]) != (encoding == "raw") {
						t.Fatal("value equality did not bind encoding", phase)
					}
				}
				action := uint8(contract.PublicationWriteValue)
				if phase == 0 {
					action = contract.PublicationCreateWithValue
				}
				got := plan.execute(ctx, private, recorder.current(publicationEngineCurrent(f)))
				assertNativePublicationACK(t, got, len(entries), action)
				planRecords = append(planRecords, drainNativePublicationDiagnostics(t, recorder)...)
				assertNativePublicationRecordsJoined(t, planRecords, staging, len(entries))
				selected := publicationEngineReopen(t, f)
				for _, outcome := range got.output.Entries {
					row := outcome.Actions[0]
					coordinate := selected.coordinates[outcome.CoordinateID]
					if attempts[row.AttemptID] || coordinate.LastValueAckAttemptID != row.AttemptID {
						t.Fatal("encoding reused an attempt or failed to select the value ACK", phase)
					}
					attempts[row.AttemptID] = true
					if phase == 0 {
						wantInstance := "test-instance/" + coordinateSlots[outcome.CoordinateID] + "/" + hex.EncodeToString(row.AttemptID[:])
						if row.Evidence.SafeResourceID != wantInstance || row.Evidence.NormalizedStatus != 201 {
							t.Fatal("encoding create did not qualify the independently expected exact instance")
						}
						births[outcome.CoordinateID], instances[outcome.CoordinateID] = coordinate, row.Evidence.SafeResourceID
					} else {
						birth := births[outcome.CoordinateID]
						if coordinate.CoordinateID != birth.CoordinateID || coordinate.ActiveBindingIncarnationID != birth.ActiveBindingIncarnationID || coordinate.LastEntryIncarnationID != birth.LastEntryIncarnationID || coordinate.OwnedBirthAttemptID != birth.OwnedBirthAttemptID || coordinate.OwnedInstanceDigest != birth.OwnedInstanceDigest || coordinate.DeletionTargetRowDigest != birth.DeletionTargetRowDigest || coordinate.DeletionPayloadEncoding != contract.OutputEncodingRaw || row.Evidence.SafeResourceID != instances[outcome.CoordinateID] {
							t.Fatal("encoding changed ownership or the frozen deletion target", phase)
						}
					}
					if phase == 1 && selected.markers[row.AttemptID].Projection.ValueBasisDigest == rawBases[outcome.CoordinateID] {
						t.Fatal("selected Base64 ACK retained raw equality")
					}
				}
				checkPriorReceipts(f.session)
				if !reflect.DeepEqual(f.session.currentEntryInputs(), canonical) || !reflect.DeepEqual(f.session.root.CurrentAccess, access) || !reflect.DeepEqual(generatedRecords(f.session), beforeGenerated) || generatedEffects != nil && generatedEffects() != 1 {
					t.Fatal("publication changed canonical or generated state", phase)
				}
				actions, checks, owners := 0, 0, 0
				counted := private
				counted.Actions = func(ctx context.Context, target publicationExecutionInput) (publicationActionFacts, error) {
					actions++
					return private.Actions(ctx, target)
				}
				counted.Check = func(ctx context.Context, in publicationActionCheckInput) (publicationActionCheckFacts, error) {
					checks++
					return private.Check(ctx, in)
				}
				counted.NewOwner = func(ctx context.Context, in publicationOwnerInput) (publicationPrivateOwner, error) {
					owners++
					return private.NewOwner(ctx, in)
				}
				publicCalls, privateCalls := env.Custody.Calls()
				creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
				noOp := nativePublicationPlan(t, ctx, f, input, counted, recorder).execute(ctx, counted, recorder.current(publicationEngineCurrent(f)))
				afterPublic, afterPrivate := env.Custody.Calls()
				if noOp.summary != contract.PublicationSummaryNoChange || actions != 0 || checks != 0 || owners != 0 || publicCalls != afterPublic || privateCalls != afterPrivate || creates != f.store.creates || cas != f.store.cas || signs != f.trust.signs {
					t.Fatal("selected encoding ACK did not produce a zero-work no-op", phase)
				}
				for _, outcome := range noOp.output.Entries {
					if len(outcome.Actions) != 1 || outcome.Actions[0].Disposition != contract.PublicationNoOp || !outcome.Actions[0].AttemptID.IsZero() {
						t.Fatal("encoding no-op acquired an attempt", phase)
					}
				}
				assertNativePublicationNoPrivateWork(t, recorder)
				checkPriorReceipts(f.session)
			}
			f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, &outputApplyInput{}, registry...)
			f.admission = OpenContext{admission: &f.session.admission}
			input.names = nil
			for coordinate := range births {
				input.deletes = append(input.deletes, coordinate)
			}
			input.deadline = time.Now().Add(30 * time.Second)
			assertNativePublicationNoPrivateWork(t, recorder)
			deletionPlan := nativePublicationPlan(t, ctx, f, input, private, recorder)
			deletionRecords := drainNativePublicationDiagnostics(t, recorder)
			for _, target := range deletionPlan.targets {
				if target.target.PayloadEncoding != contract.OutputEncodingRaw || target.targetDigest != births[target.coordinate].DeletionTargetRowDigest {
					t.Fatal("retired deletion used the current encoding instead of original birth")
				}
			}
			deletion := deletionPlan.execute(ctx, private, recorder.current(publicationEngineCurrent(f)))
			assertNativePublicationACK(t, deletion, len(entries), contract.PublicationDeleteOwned)
			deletionRecords = append(deletionRecords, drainNativePublicationDiagnostics(t, recorder)...)
			assertNativePublicationRecordsJoined(t, deletionRecords, staging, len(entries))
			selected := publicationEngineReopen(t, f)
			for _, outcome := range deletion.output.Entries {
				coordinate, birth := selected.coordinates[outcome.CoordinateID], births[outcome.CoordinateID]
				if coordinate.BindingState != contract.PublicationBindingRetired || !coordinate.ActiveBindingIncarnationID.IsZero() || coordinate.OwnedBirthAttemptID != birth.OwnedBirthAttemptID || coordinate.DeletionTargetRowDigest != birth.DeletionTargetRowDigest || coordinate.LastDeleteAckAttemptID != outcome.Actions[0].AttemptID || outcome.Actions[0].Evidence.SafeResourceID != instances[outcome.CoordinateID] {
					t.Fatal("encoding chain deletion lost the exact original ownership relation")
				}
			}
			checkPriorReceipts(f.session)
			if !reflect.DeepEqual(f.session.currentEntryInputs(), canonical) || !reflect.DeepEqual(f.session.root.CurrentAccess, access) || !reflect.DeepEqual(generatedRecords(f.session), beforeGenerated) || generatedEffects != nil && generatedEffects() != 1 {
				t.Fatal("retired deletion changed canonical or generated state")
			}
		})
	}
}
