package core

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/telemetry"
)

// full_only: false
func TestConsumerSelectionCapturesRequestBasisActorAndOneDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	originalContext := ctx
	originalDeadline, _ := ctx.Deadline()
	f := newConsumerLoadingFixture(t, ctx, false)
	before := sessionStateImage(t, f.f.session)
	prefix := consumerLoadingPrefix(t, f.store, before)
	candidate, want := prepareConsumerLoadingSuccessor(t, ctx, f)
	basis := f.f.session.admission.publicBasis()
	names := []string{before.Root.Names[0].Name}
	acting := f.f.session.admission.recipient
	originalName, originalActor := names[0], acting
	entered, returned := 0, 0
	source := &consumerRestartReadStore{memoryStore: f.store}
	source.after = func(readContext context.Context, key string, _ contract.ReadResult) {
		if actual, finite := readContext.Deadline(); !finite || !actual.Equal(originalDeadline) {
			t.Fatal("public consumer changed its original deadline")
		}
		if !consumerLoadingImageCut(source, key, prefix[1].Key, 1) {
			return
		}
		entered++
		if entered != 1 {
			t.Fatal("consumer reloaded its discarded image")
		}
		selectConsumerLoadingSuccessor(t, originalContext, f, candidate, want)
		removeConsumerLoadingChild(t, f.store, prefix[2].Key)
		names[0], acting = "caller-changed-name", testID("caller changed consumer actor")
		clear(basis.Descriptor)
		clear(basis.Control)
		clear(basis.Selection)
		replacement, stop := context.WithTimeout(t.Context(), 2*time.Minute)
		t.Cleanup(stop)
		ctx = replacement
		returned++
	}
	creates, cas, signs := f.store.creates, f.store.cas, f.env.Trust.(*fixtureTrust).signs
	public, private := f.env.Custody.Calls()
	t.Cleanup(func() { logConsumerLoadingReads(t, source) })
	image, selected, result := loadPublicConsumerFixture(t, ctx, f.env, f.f.session, basis, source, names, acting)
	if !image.complete || selected == nil || result.Outcome != 0 || selected.Recipient.SubjectID != originalActor || len(selected.Entries) != 1 || selected.Entries[0].Slot != 0 || image.image.valueEntry(0).Name != originalName || names[0] == originalName || acting == originalActor || selected.ExpiresAt != originalDeadline {
		t.Fatal("public consumer refreshed captured request/basis/lifetime", result)
	}
	assertPublicConsumerImage(t, image, want)
	wantReads := append(append([]processStoreRequest(nil), consumerSelectedLoadingPrefix(t, f.store, before)...), publicConsumerReadRequests(t, f.store.desc, want)...)
	if !reflect.DeepEqual(source.reads, wantReads) || entered != 1 || returned != 1 || f.store.creates != creates || f.store.cas != cas+1 || f.env.Trust.(*fixtureTrust).signs != signs {
		t.Fatal("public capture lost exact reads or joined writer effects")
	}
	if gotPublic, gotPrivate := f.env.Custody.Calls(); gotPublic != public || gotPrivate != private {
		t.Fatal("public capture used private custody")
	}
	if actual, _ := originalContext.Deadline(); actual != originalDeadline {
		t.Fatal("consumer changed original caller lifetime")
	}
	if replacement, _ := ctx.Deadline(); !replacement.After(originalDeadline) {
		t.Fatal("caller Context variable was not replaced")
	}
}

// full_only: false
func TestConsumerSelectionCancellationAfterLossStopsBeforeHEADGate(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newConsumerLoadingFixture(t, ctx, false)
	before := sessionStateImage(t, f.f.session)
	prefix := consumerLoadingPrefix(t, f.store, before)
	candidate, want := prepareConsumerLoadingSuccessor(t, ctx, f)
	entered, returned, cancelled := 0, 0, 0
	source := &consumerRestartReadStore{memoryStore: f.store}
	source.after = func(_ context.Context, key string, read contract.ReadResult) {
		if consumerLoadingImageCut(source, key, prefix[1].Key, 1) {
			entered++
			if entered != 1 {
				t.Fatal("consumer read another image after cancellation")
			}
			selectConsumerLoadingSuccessor(t, ctx, f, candidate, want)
			removeConsumerLoadingChild(t, f.store, prefix[2].Key)
			returned++
		}
		if key == prefix[2].Key {
			if read.Status != contract.ReadMissing {
				t.Fatal("cancellation did not follow the exact missing child")
			}
			cancelled++
			cancel()
		}
	}
	creates, cas, signs := f.store.creates, f.store.cas, f.env.Trust.(*fixtureTrust).signs
	t.Cleanup(func() { logConsumerLoadingReads(t, source) })
	image, selected, result := loadPublicConsumerFixture(t, ctx, f.env, f.f.session, f.f.admission.admission.publicBasis(), source, []string{before.Root.Names[0].Name}, f.f.session.admission.recipient)
	wantResult := readerRefusal(contract.ReasonCancelled)
	if image.complete || selected != nil || result != wantResult || ctx.Err() != context.Canceled ||
		!reflect.DeepEqual(source.reads, consumerSelectedLoadingPrefix(t, f.store, before)) || entered != 1 || returned != 1 || cancelled != 1 ||
		f.store.creates != creates || f.store.cas != cas+1 || f.env.Trust.(*fixtureTrust).signs != signs {
		t.Fatal("consumer cancellation entered a HEAD gate or lost joined effects", result)
	}
}

// full_only: false
func TestLoadedConsumerCustodyFinishesAfterSuccessorAndOldChildRemoval(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env := memoryScenarioEnvironment(t)
	env.Context = ctx
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	input := []ApplyEntryInput{suppliedSecret(t, env, "secret", "loaded consumer original", custody.StandardValue)}
	run.suppliedSelection(f, input)
	before := sessionStateImage(t, f.session)
	store := env.Store.(*memoryStore)
	source := &consumerRestartReadStore{memoryStore: store, after: func(context.Context, string, contract.ReadResult) {}}
	t.Cleanup(func() { logConsumerLoadingReads(t, source) })
	public, private := env.Custody.Calls()
	image, selected, result := loadPublicConsumerFixture(t, ctx, env, f.session, f.admission.admission.publicBasis(), source, []string{"secret"}, f.session.admission.recipient)
	if !image.complete || selected == nil || result.Outcome != 0 {
		t.Fatal("complete consumer custody was not loaded", result)
	}
	owned := materializationConsumerRecord(t, selected, 0)
	if gotPublic, gotPrivate := env.Custody.Calls(); gotPublic != public || gotPrivate != private {
		t.Fatal("consumer loading entered private custody")
	}
	completeReads := publicConsumerReadRequests(t, store.desc, before)
	wantReads := append([]processStoreRequest{completeReads[0]}, completeReads[2:]...)
	if !reflect.DeepEqual(source.reads, wantReads) {
		t.Fatal("loaded consumer did not verify exactly one complete image")
	}
	input[0] = suppliedSecret(t, env, "secret", "loaded consumer successor", custody.EmptyValue)
	run.suppliedSelection(f, input)
	oldKey := mustKey(t, store.desc.Prefix, *before.Root.ValueEntryPages[0])
	newKey := mustKey(t, store.desc.Prefix, *f.session.root.ValueEntryPages[0])
	if oldKey == newKey || f.session.head.Core.Revision == owned.HEADRevision || f.session.root.Snapshot == owned.SnapshotID {
		t.Fatal("loaded consumer fixture did not advance its selected bytes")
	}
	store.mu.Lock()
	old, present := store.objects[oldKey]
	if present {
		delete(store.objects, oldKey)
		clear(old.Body)
	}
	store.mu.Unlock()
	if !present {
		t.Fatal("loaded consumer old child was absent before removal")
	}
	reads, creates, cas := store.reads, store.creates, store.cas
	signs := env.Trust.(*fixtureTrust).signs
	public, private = env.Custody.Calls()
	check := env.Custody.Consume(ctx, owned, custody.StandardValue)
	if check.Code != contract.CryptoSuccess || check.Delivery != 1 || check.SinkCalls != 1 || !check.ValueMatched {
		t.Fatal("loaded consumer did not finish its original owned value", check)
	}
	if store.reads != reads || store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).signs != signs {
		t.Fatal("loaded consumer required current Store bytes or a new lease")
	}
	if gotPublic, gotPrivate := env.Custody.Calls(); gotPublic != public || gotPrivate != private+1 {
		t.Fatal("loaded consumer did not join exactly one private material open")
	}
}

// full_only: false
func TestConsumerRestartKeepsDiagnosticEvidenceWithMetricsAndTracesOff(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newConsumerLoadingFixture(t, ctx, false)
	before := sessionStateImage(t, f.f.session)
	prefix := consumerLoadingPrefix(t, f.store, before)
	candidate, want := prepareConsumerLoadingSuccessor(t, ctx, f)
	source := &consumerRestartReadStore{memoryStore: f.store}
	entered, returned := 0, 0
	source.after = func(_ context.Context, key string, _ contract.ReadResult) {
		if !consumerLoadingImageCut(source, key, prefix[1].Key, 2) {
			return
		}
		entered++
		if entered != 1 {
			t.Fatal("diagnostic consumer retried its old image")
		}
		selectConsumerLoadingSuccessor(t, ctx, f, candidate, want)
		removeConsumerLoadingChild(t, f.store, prefix[2].Key)
		returned++
	}
	recorder := telemetry.NewRecorder()
	capability := telemetry.NewCapability(nil, recorder)
	defer capability.Deactivate()
	observed := telemetry.WithCapability(ctx, capability)
	t.Cleanup(func() { logConsumerLoadingReads(t, source) })
	f.env.Store = source
	admission, result := captureConsumerMaterialization(t, observed, f.env, f.f.admission.admission.publicBasis(), []string{before.Root.Names[0].Name}, f.f.session.admission.recipient)
	if admission == nil || result.Payload == nil || result.StateResult != contract.MaterializationRefused || result.Failure.Reason != contract.MaterializationInvalidAdmission || entered != 1 || returned != 1 || admission.Root != want.RootRef || !bytes.Equal(admission.Entries[0].Entry.ValueBytes, want.Pages[0].Slots[0].ValueBytes) {
		t.Fatal("diagnostic consumer did not admit its replacement image", result.StateResult, result.Failure)
	}

	starts, finished, checkpoints, counted := 0, 0, 0, 0
	readMissing := 0
	for _, status := range source.statuses {
		if status == contract.ReadMissing {
			readMissing++
		}
	}
	for {
		records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 4))
		if len(records) == 0 {
			break
		}
		for _, record := range records {
			counted++
			if record.Validate() != nil || record.TraceID != "" || record.SpanID != "" || record.TraceSampled || record.Path != "" || record.ErrorDetail != "" {
				t.Fatal("consumer diagnostic record is rejected, private or trace-enabled", record)
			}
			body, err := json.Marshal(record)
			if err != nil || bytes.Contains(body, []byte(prefix[1].Key)) || bytes.Contains(body, []byte(prefix[2].Key)) {
				t.Fatal("consumer diagnostic disclosed a raw Store key", err)
			}
			if record.Operation != telemetry.OpCoreMaterialize {
				continue
			}
			switch record.Event {
			case telemetry.DiagnosticStart:
				starts++
			case telemetry.DiagnosticCheckpoint:
				if record.Stage == telemetry.DiagnosticStateLoading && record.Reason == telemetry.DiagnosticReasonMissingSelectedObject {
					if readMissing != 1 {
						t.Fatal("consumer checkpoint preceded its exact failed read")
					}
					checkpoints++
				}
			case telemetry.DiagnosticReturn:
				finished++
				if record.Result != telemetry.ResultAdmissionRefused || record.Reason != telemetry.DiagnosticReasonAdmissionInvalid {
					t.Fatal("consumer final diagnostic did not retain the actual result", record)
				}
			}
		}
	}
	status := recorder.Status()
	if starts != 1 || finished != 1 || checkpoints != 1 || readMissing != 1 ||
		status.Accepted != uint64(counted) || status.Rejected != 0 || status.DroppedFull != 0 || status.DroppedContention != 0 || status.DroppedClosed != 0 ||
		capability.MetricsEnabled() || capability.LostMetrics() != 0 || capability.RejectedMetrics() != 0 || capability.LostTraces() != 0 {
		t.Fatal("consumer diagnostic evidence was dropped, rejected or dependent on metrics/traces", status)
	}
}
