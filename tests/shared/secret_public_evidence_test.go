package core

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"enkv.sh/compositions/observability"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/telemetry"
)

type publicCryptoReplies struct {
	inner     contract.Crypto
	mu        sync.Mutex
	responses [][]byte
	err       error
}

func (capture *publicCryptoReplies) InstanceID() contract.ID { return capture.inner.InstanceID() }

func (capture *publicCryptoReplies) Exchange(ctx context.Context, request contract.CryptoRequest) contract.CryptoResponse {
	reply := capture.inner.Exchange(ctx, request)
	encoded, err := json.Marshal(reply)
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if err != nil {
		capture.err = err
	} else {
		capture.responses = append(capture.responses, bytes.Join([][]byte{encoded, reply.Body}, []byte{'\n'}))
	}
	return reply
}

func (capture *publicCryptoReplies) publicBytes(t *testing.T) []byte {
	t.Helper()
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.err != nil || len(capture.responses) == 0 {
		t.Fatal("Core-visible Crypto replies were not captured", capture.err)
	}
	return bytes.Join(capture.responses, []byte{'\n'})
}

func storedPublicClosure(t *testing.T, store contract.Store) []byte {
	t.Helper()
	memory := requireAdmittedMemoryStore(t, store)
	memory.mu.Lock()
	defer memory.mu.Unlock()
	keys := make([]string, 0, len(memory.objects))
	for key := range memory.objects {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var out bytes.Buffer
	for _, key := range keys {
		object := memory.objects[key]
		out.WriteString(key)
		out.WriteByte('\n')
		out.WriteString(object.Token.Value)
		out.WriteByte('\n')
		out.Write(object.Body)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func localPublicEvidenceTelemetry(t *testing.T) (context.Context, *observability.Runtime, string) {
	t.Helper()
	settings, err := observability.Decode([]byte(`{"schema_version":1,"logs":{"level":"debug","exporters":["capture"]},"traces":{"exporters":["capture"]},"metrics":{"exporters":["capture"]},"exporters":{"capture":{"type":"otlp_file","directory":"telemetry"}}}`), observability.Options{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	runtime, err := observability.Start(settings, observability.SetupOptions{BaseDirectory: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(deadline); err != nil {
			t.Error("local telemetry close", err)
		}
	})
	ready, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.AwaitMetrics(ready); err != nil {
		t.Fatal("local metrics unavailable", err)
	}
	if err := runtime.AwaitTraces(ready); err != nil {
		t.Fatal("local traces unavailable", err)
	}
	return runtime.Context(context.Background()), runtime, root
}

func localPublicEvidenceFiles(t *testing.T, runtime *observability.Runtime, root string) []custody.PublicSurface {
	t.Helper()
	deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.Close(deadline); err != nil {
		t.Fatal("local telemetry close", err)
	}
	for name, status := range map[string]observability.DeliveryStatus{
		"logs": runtime.LogStatus("capture"), "traces": runtime.TraceStatus("capture"), "metrics": runtime.MetricStatus("capture"),
	} {
		if status.Incomplete || status.Dropped != 0 || status.Failed != 0 || status.Written == 0 || status.Accepted != status.Written {
			t.Fatalf("local %s delivery incomplete: %+v", name, status)
		}
	}
	var surfaces []custody.PublicSurface
	for _, name := range []string{"logs", "traces", "metrics"} {
		body, err := os.ReadFile(filepath.Join(root, "telemetry", name+".jsonl"))
		if err != nil {
			t.Fatal("local public telemetry file missing", name, err)
		}
		surfaces = append(surfaces, custody.PublicSurface{Name: "serialized_" + name, Body: body})
	}
	return surfaces
}

// full_only: false
func TestSecretPublicClosurePreservesOnlyPermittedEquality(t *testing.T) {
	// This detects the named low-entropy disclosures, not every side channel or
	// cryptographic indistinguishability.
	observer := custody.NewDictionaryObserver()
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	capture := &publicCryptoReplies{inner: env.Crypto}
	env.Crypto = capture
	run := newScenarioRun(t, ctx, env)
	fixture := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	input := append(fixture.session.currentEntryInputs(),
		suppliedSecret(t, env, "secret-a", "first public evidence seal", custody.StandardValue),
		suppliedSecret(t, env, "secret-b", "second public evidence seal", custody.StandardValue))
	run.suppliedSelection(fixture, input)
	first := sessionConsumerSelection(t, fixture.session, fixture.session.admission.recipient, "secret-a")
	second := sessionConsumerSelection(t, fixture.session, fixture.session.admission.recipient, "secret-b")
	if bytes.Equal(first.Entry.ValueBytes, second.Entry.ValueBytes) || bytes.Equal(first.Payload.Ciphertext, second.Payload.Ciphertext) || first.Payload.SemanticCommitment == second.Payload.SemanticCommitment {
		t.Fatal("fresh equal-value entries exposed equal protected material")
	}
	input = append(input, suppliedSecret(t, env, "secret-c", "later public evidence seal", custody.StandardValue))
	run.suppliedSelection(fixture, input)
	third := sessionConsumerSelection(t, fixture.session, fixture.session.admission.recipient, "secret-c")
	if bytes.Equal(first.Entry.ValueBytes, third.Entry.ValueBytes) || first.Payload.SemanticCommitment == third.Payload.SemanticCommitment {
		t.Fatal("later fresh equal value exposed equal protected material")
	}
	before := sessionConsumerSelection(t, fixture.session, fixture.session.admission.recipient, "secret-b")
	input[0].InputBytes = []byte("changed public plain value")
	run.suppliedSelection(fixture, input)
	after := sessionConsumerSelection(t, fixture.session, fixture.session.admission.recipient, "secret-b")
	if !bytes.Equal(before.Entry.ValueBytes, after.Entry.ValueBytes) || before.Payload.SemanticCommitment != after.Payload.SemanticCommitment || !bytes.Equal(before.Payload.Ciphertext, after.Payload.Ciphertext) {
		t.Fatal("unaffected secret ciphertext or semantic evidence changed")
	}
	if check := keys.Consume(ctx, after, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
		t.Fatal("selected private consumer failed")
	}
	reader := fixtureID(env.Domain, "reader")
	public, private := keys.Calls()
	if selected, result := fixture.session.admitConsumerSelection(ctx, []string{"secret-b"}, reader); selected != nil || result != refused(AdmissionInvalid) {
		t.Fatal("public-only reader selection was admitted", result)
	}
	denied := after
	for _, row := range env.Bindings {
		if row.SubjectID == reader {
			denied.Binding = row
			break
		}
	}
	if check := keys.Consume(ctx, denied, custody.StandardValue); check.Code != contract.CryptoInvalidAdmission || check.Delivery != 0 || check.SinkCalls != 0 || len(check.KeyUses) != 0 {
		t.Fatal("public-only denial used private custody or delivery")
	}
	if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
		t.Fatal("public-only denial used a key route")
	}
	shared := []contract.ID{fixture.session.admission.recipient, reader}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	input[2] = suppliedSecret(t, env, "secret-b", "public evidence grant seal", custody.StandardValue, shared...)
	run.suppliedSelection(fixture, input)
	granted := sessionConsumerSelection(t, fixture.session, fixture.session.admission.recipient, "secret-b")
	if !bytes.Equal(after.Entry.ValueBytes, granted.Entry.ValueBytes) || after.Core != granted.Core || !reflect.DeepEqual(after.Payload, granted.Payload) ||
		after.Access.MaterialContextDigest != granted.Access.MaterialContextDigest || after.Access.PackageCheck != granted.Access.PackageCheck || len(granted.Access.Wraps) != len(after.Access.Wraps)+1 {
		t.Fatal("access-only grant changed retained ciphertext or semantic evidence")
	}
	for _, previous := range after.Access.Wraps {
		index := slices.IndexFunc(granted.Access.Wraps, func(row contract.WrapRow) bool {
			return row.SubjectKind == previous.SubjectKind && row.SubjectID == previous.SubjectID
		})
		if index < 0 || !reflect.DeepEqual(previous, granted.Access.Wraps[index]) {
			t.Fatal("access-only grant replaced an existing wrap")
		}
	}
	readerSelection := sessionConsumerSelection(t, fixture.session, reader, "secret-b")
	if check := keys.Consume(ctx, readerSelection, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
		t.Fatal("granted reader cannot consume selected value")
	}
	diagnosticContext, runtime, root := localPublicEvidenceTelemetry(t)
	diagnosticEnv := env
	diagnosticEnv.Context = diagnosticContext
	sealed := suppliedSecret(t, diagnosticEnv, "secret-probe", "public evidence diagnostic seal", custody.StandardValue)
	if check := keys.Consume(diagnosticContext, granted, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
		t.Fatal("local diagnostic consumer failed")
	}
	recorder := telemetry.NewRecorder()
	recordContext := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	if check := keys.Consume(recordContext, granted, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
		t.Fatal("recorded private consumer failed")
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 8))
	status := recorder.Status()
	if status.Accepted != 3 || status.DroppedContention != 0 || status.DroppedFull != 0 || status.DroppedClosed != 0 || status.Rejected != 0 {
		t.Fatalf("successful-operation recorder incomplete: %+v", status)
	}
	if len(records) != 3 || records[0].Event != telemetry.DiagnosticStart || records[1].Event != telemetry.DiagnosticCheckpoint || records[2].Event != telemetry.DiagnosticReturn || records[2].Result != telemetry.ResultSuccess {
		t.Fatal("successful-operation diagnostics were not captured")
	}
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal("invalid public diagnostic", err)
		}
	}
	recordBytes, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	selectionBytes, err := json.Marshal(granted)
	if err != nil {
		t.Fatal(err)
	}
	surfaces := []custody.PublicSurface{
		{Name: "stored_public_closure", Body: storedPublicClosure(t, env.Store)},
		{Name: "core_visible_crypto_replies", Body: capture.publicBytes(t)},
		{Name: "selected_public_reply", Body: selectionBytes},
		{Name: "sealed_source_reply", Body: sealed.InputBytes},
		{Name: "successful_operation_recorder", Body: recordBytes},
	}
	surfaces = append(surfaces, localPublicEvidenceFiles(t, runtime, root)...)
	for _, surface := range surfaces {
		if err := observer.Check([]custody.PublicSurface{surface}); err != nil {
			t.Error(err)
		}
	}
}
