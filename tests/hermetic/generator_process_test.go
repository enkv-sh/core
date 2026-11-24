package core

import (
	"bytes"
	stdcontext "context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
)

func buildHermeticGenerator(t *testing.T, mode string) string {
	t.Helper()
	source, err := filepath.Abs("compositions/generatorhost/testdata/hermetic")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "generator")
	command := exec.Command("go", "build", "-trimpath", "-ldflags=-buildid= -X=main.mode="+mode, "-o", path, "./testdata/hermetic")
	command.Dir = filepath.Clean(filepath.Join(source, "..", ".."))
	command.Env = append(os.Environ(), "GOWORK=off")
	prepareNativeModule(t, filepath.Clean(filepath.Join(command.Dir, "..", "..")), command, path+".mod")
	before := captureHermeticGeneratorBuildInputs(t, command)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build hermetic generator: %v\n%s", err, output)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(filepath.Dir(path), ".enkv-generator-staging"), 0700); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	descriptorBytes, err := os.ReadFile(filepath.Join(source, "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := artifact.DecodeDescriptor(descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	metadata, dependency := hermeticGeneratorMetadata(t, command, path, descriptor, before)
	metadataBytes, err := artifact.EncodeMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for suffix, data := range map[string][]byte{".metadata.json": metadataBytes, ".dependencies.bin": dependency} {
		if err := os.WriteFile(path+suffix, data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	t.Logf("hermetic generator mode=%s sha256=%x length=%d tuple=%s/%s", mode, sha256.Sum256(body), len(body), runtime.GOOS, runtime.GOARCH)
	clear(body)
	return path
}

func hermeticGeneratorInstallation(t testing.TB, path string) *generatorhost.Installation {
	t.Helper()
	metadataBytes, err := os.ReadFile(path + ".metadata.json")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := artifact.DecodeMetadata(metadataBytes)
	if err != nil {
		t.Fatal(err)
	}
	dependency, err := os.ReadFile(path + ".dependencies.bin")
	if err != nil {
		t.Fatal(err)
	}
	installed, err := generatorhost.NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	return installed
}
func hermeticGeneratorConfig(t testing.TB, path string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
	t.Helper()
	row := hermeticGeneratorInstallation(t, path).Artifact()
	if row.ConfigContractID != expected.Template.ConfigContractID || row.DescriptorID != expected.Template.DescriptorID || row.ExecutorID != expected.Template.ExecutorID || row.CredentialRouteID != expected.Template.CredentialRouteID {
		t.Fatal("generated plan differs from exact implementation")
	}
	route, err := credentialroute.Decode(row.CredentialRoute)
	if err != nil {
		t.Fatal("fixture credential route unavailable", err)
	}
	for _, name := range route.Names {
		t.Setenv(name, "private ordinary token, no provider grammar")
	}
	metadata, err := os.ReadFile(path + ".metadata.json")
	if err != nil {
		t.Fatal(err)
	}
	dependency, err := os.ReadFile(path + ".dependencies.bin")
	if err != nil {
		t.Fatal(err)
	}
	return custody.GeneratedProcessConfig{ArtifactPath: path, Artifact: row, Metadata: metadata, Dependency: dependency}

}
func generatorProcessProfile(t *testing.T, path string) generatedFixtureProfile {
	t.Helper()
	return nativeGeneratedFixtureProfile(t, hermeticGeneratorInstallation(t, path).Artifact())
}

func preparePrivateGeneratedProcessProducer(t *testing.T, env fixtureEnvironment, s *StateSession, prior *generatedPreparation, artifact string, lifetime ...time.Duration) (*generatedPreparation, contract.GeneratorResultExpectation) {
	return preparePrivateGeneratedProcessProducerWithConfig(t, env, s, prior, artifact, hermeticGeneratorConfig, lifetime...)
}

// full_only: false
func TestNativeGeneratorCommandDeadlineBoundsChildJoin(t *testing.T) {
	artifact := buildHermeticGenerator(t, "hang")
	ctx := stdcontext.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, ctx, env)
	fixture := newEnvironmentFixture(t, ctx, run.env, nil, false)
	prior, _ := preparePrivateGeneratedReservation(t, env, fixture.session, generatedPlanInputForProfile(t, fixture.session, generatedVectorID(10), generatorProcessProfile(t, artifact)), nil)
	producer, expected := preparePrivateGeneratedProcessProducer(t, env, fixture.session, prior, artifact, 3*time.Second)
	var code contract.CryptoResultCode
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx stdcontext.Context, authority contract.ID) contract.CryptoResultCode {
		_, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("deadline process first-send handoff")
	}
	started := time.Now()
	selected, result := fixture.session.selectCandidate(ctx, producer.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent || result.Reason != CustodyUnavailable || code != contract.CryptoExpired {
		t.Fatal("command deadline did not close the stalled child", code, result)
	}
	if elapsed := time.Since(started); elapsed > 8*time.Second {
		t.Fatal("command deadline did not bound child join", elapsed)
	}
	work, err := selected.selectedGeneratedWork(stdcontext.Background())
	if err != nil || len(work.attempts[expected.Template.AttemptID].result) != 0 {
		t.Fatal("expired process became a frozen result", err)
	}
}

// full_only: false
func TestNativeGeneratorEnteredReturnSurvivesCallerCancellation(t *testing.T) {
	artifact := buildHermeticGenerator(t, "return-cancel-race")
	ctx, cancel := stdcontext.WithCancel(stdcontext.Background())
	defer cancel()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, stdcontext.Background(), env)
	fixture := newEnvironmentFixture(t, stdcontext.Background(), run.env, nil, false)
	prior, _ := preparePrivateGeneratedReservation(t, env, fixture.session,
		generatedPlanInputForProfile(t, fixture.session, generatedVectorID(10), generatorProcessProfile(t, artifact)), nil)
	producer, expected := preparePrivateGeneratedProcessProducer(t, env, fixture.session, prior, artifact, 5*time.Second)
	type producerResult struct {
		body []byte
		code contract.CryptoResultCode
	}
	result := make(chan producerResult, 1)
	go func() {
		body, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, producer.reservation.candidate.generated.authority)
		result <- producerResult{body: body, code: code}
	}()
	wait, stopWait := stdcontext.WithTimeout(stdcontext.Background(), 10*time.Second)
	defer stopWait()
	if !keys.WaitGeneratedProcessCommand(wait) {
		t.Fatal("generator command did not enter the real child")
	}
	ready := filepath.Join(filepath.Dir(artifact), ".enkv-hermetic-result-ready")
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		select {
		case <-wait.Done():
			t.Fatal("real child did not publish its result before cancellation")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	var got producerResult
	completed := false
	select {
	case got = <-result:
		completed = true
	case <-time.After(50 * time.Millisecond):
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(artifact), ".enkv-hermetic-release-result"), []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	if completed {
		t.Fatal("caller cancellation erased the entered return", got.code)
	}
	select {
	case got = <-result:
	case <-wait.Done():
		t.Fatal("entered real-child return did not join")
	}
	work, err := producer.reservation.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	record, err := contract.DecodeGeneratedResultRecord(got.body)
	if got.code != contract.CryptoSuccess || err != nil ||
		contract.ValidateGeneratedResult(expected, work.attempts[expected.Template.AttemptID].material, record) != nil {
		t.Fatal("qualified return was not sealed after caller cancellation", got.code, err)
	}
}

func requireNoGeneratorPlaintext(t *testing.T, store *memoryStore, bodies ...[]byte) {
	t.Helper()
	sentinels := [][]byte{[]byte("enkv_"), []byte("Hermetic_bearer_"), []byte("Generated_secret_"), []byte("Management_bearer_")}
	for _, body := range bodies {
		for _, sentinel := range sentinels {
			if bytes.Contains(body, sentinel) {
				t.Fatal("generator plaintext reached a parent-owned byte surface")
			}
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for key, object := range store.objects {
		for _, sentinel := range sentinels {
			if bytes.Contains(object.Body, sentinel) {
				t.Fatal("generator plaintext reached Store", key)
			}
		}
	}
}

type nativeGeneratedEntryFixture struct {
	request        contract.CryptoGeneratedCompareRequest
	phase          contract.GeneratorPhaseIdentity
	reference      contract.GeneratorResultReference
	input          custody.GeneratedFinalInput
	entryAdmission custody.GeneratedEntryAdmission
	plan           contract.CryptoGeneratedValueEntryPlan
}

func nativeGeneratedEntryPlan(t *testing.T, s *StateSession, attempt contract.ID, resultBody []byte, label string) nativeGeneratedEntryFixture {
	t.Helper()
	g, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil || g.parent == nil || g.phase == nil {
		t.Fatal("recorded generated work unavailable", err)
	}
	a, ok := g.attempts[attempt]
	if !ok || !bytes.Equal(a.result, resultBody) {
		t.Fatal("member preparation lost its exact recorded result")
	}
	result, err := contract.DecodeGeneratedResultRecord(resultBody)
	if err != nil {
		t.Fatal(err)
	}
	graph := g.bundles[0]
	planIndex := slices.IndexFunc(graph.ValueEntryPlans, func(row contract.GeneratorValueEntryPlan) bool {
		return row.ValueSource == contract.Generated && row.LineageID == a.expected.Template.LineageID
	})
	if planIndex < 0 {
		t.Fatal("generated member plan unavailable")
	}
	entryPlan := graph.ValueEntryPlans[planIndex]
	input := generatedFinalInput(t.Context(), t, s, g, attempt)
	input.ResultBodies = [][]byte{bytes.Clone(resultBody)}
	input.Plan.Canonical = generatedCanonicalInputs(t, s, g, input.Plan.Declaration)
	context := generatedContinuationContext(t, s, 81, 82)
	context.AdmissionID, context.SessionID = testID(label+" final admission"), testID(label+" final session")
	p := *g.parent
	q := contract.CryptoGeneratedCompareRequest{Context: context, Purpose: 3, Parent: p, PlanGraph: p.Graph, UsePlanDigest: p.UsePlanDigest,
		MaterialID: p.MaterialID, AcceptedSources: p.SourceUses, IntendedEntryPlans: p.IntendedEntryPlans}
	q.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(q)
	if err != nil {
		t.Fatal(err)
	}
	reference := contract.GeneratorResultReference{Schema: 1, ResultID: result.Core.ResultID, ResultBodyDigest: contract.Hash(resultBody), ResultLength: uint32(len(resultBody))}
	evidence := contract.GeneratorDescriptor{Digest: contract.Hash(resultBody), Length: uint64(len(resultBody)), Count: 1}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: p.RequestIdentityDigest, ObservedHEADDigest: q.Context.PredecessorHEADDigest,
		ConditionDigest: q.Context.OriginalConditionDigest, TransitionKind: contract.GeneratorAuthorityFinal,
		BeforePhase: g.phase.Phase, AfterPhase: g.phase.Phase + 1, Evidence: evidence}
	phaseID, err := contract.GeneratorPhaseID(phase)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := g.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, a.expected.Template.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	intentDescriptor, err := contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{{Schema: 1, ContentKind: contract.GeneratorContentIntent,
		ContentID: a.expected.Template.IntentDigest, Length: uint32(len(intent)), Digest: contract.Hash(intent)}})
	if err != nil {
		t.Fatal(err)
	}
	coreBody, err := contract.EncodeGeneratedResultCore(result.Core)
	if err != nil {
		t.Fatal(err)
	}
	factsBody, err := contract.EncodeGeneratorSafeFacts(result.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	createEvidence, err := contract.GeneratedCreateEvidenceDescriptor(contract.GeneratedCreateEvidence{Schema: contract.GeneratedCreateEvidenceSchema, OriginalResultID: result.Core.ResultID, CredentialRouteID: a.expected.Template.CredentialRouteID,
		ResultCore: coreBody, SafeFacts: factsBody, Intent: intentDescriptor, LifecycleMode: a.expected.Template.LifecycleMode, CompletionClass: a.expected.Template.CompletionClass})
	if err != nil {
		t.Fatal(err)
	}
	resourceDigest, err := contract.GeneratorResourceDigest(result.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	meta := contract.GeneratedEntryMetadata{Schema: contract.GeneratedEntryMetadataSchema, Epoch: entryPlan.Epoch, IntentDigest: a.expected.Template.IntentDigest, ResourceIncarnationID: a.expected.Template.ResourceIncarnationID, OriginOperationID: result.Core.OperationID, OriginAttemptID: result.Core.AttemptID, GenerationID: testID(label + " unresolved generation"), ResourceDigest: resourceDigest, CreateResultID: result.Core.ResultID, CreateEvidence: createEvidence, RequiredSupport: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), CompletionClass: a.expected.Template.CompletionClass, RetirementMode: entryPlan.RetirementMode, ConfigContractID: a.expected.Template.ConfigContractID, ResourceContractID: a.expected.Template.ResourceContractID, LifecycleMode: contract.GeneratorLifecycleManaged}
	binding, err := contract.GeneratedBindingDigest(meta)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := contract.DeriveGeneratedValueIdentity(a.expected.Template.PlannedValueSlotID, phaseID, result.Core.ResultID, binding)
	if err != nil {
		t.Fatal(err)
	}
	meta.GenerationID = identity.ValueStateID
	value := contract.ValueCore{Schema: contract.CanonicalSchema, Profile: 2, DomainID: q.Context.DomainID,
		CompatibilityID: q.Context.CompatibilityID, CryptoSupportID: result.Payload.CryptoSupportID, Name: entryPlan.Name,
		EntryIncarnationID: entryPlan.EntryIncarnationID, ValueStateID: identity.ValueStateID, OriginSnapshotID: identity.OriginSnapshotID,
		OriginTransitionID: identity.OriginTransitionID, DataKeyID: identity.DataKeyID, DataKeyEpoch: 1,
		CommitmentKeyID: identity.CommitmentKeyID, CommitmentKeyEpoch: 1, ContentLength: result.Payload.ContentLength,
		ValueSource: contract.Generated, GeneratedBindingDigest: binding, InputEncoding: result.Payload.InputEncoding, RetainedLength: result.Payload.RetainedLength}
	declaration, err := contract.InspectGeneratorDeclaration(input.Plan.Declaration)
	if err != nil {
		t.Fatal(err)
	}
	var recipients []contract.ID
	for i := 0; i < declaration.EntryCount(); i++ {
		entry, _, err := declaration.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		if string(entry.Name) != entryPlan.Name {
			continue
		}
		for offset := 0; offset < len(entry.RecipientIDs); offset += len(contract.ID{}) {
			recipients = append(recipients, contract.ID(entry.RecipientIDs[offset:offset+len(contract.ID{})]))
		}
	}
	if len(recipients) == 0 {
		t.Fatal("generated member recipients unavailable")
	}
	return nativeGeneratedEntryFixture{request: q, phase: phase, reference: reference, input: input,
		entryAdmission: custody.GeneratedEntryAdmission{Slot: entryPlan.Slot, Generated: meta},
		plan: contract.CryptoGeneratedValueEntryPlan{Slot: entryPlan.Slot, OutputEncoding: entryPlan.OutputEncoding, Result: bytes.Clone(resultBody), ValueCore: value,
			Generated: meta, Recipients: recipients}}
}

func cloneNativeGeneratedEntryPlan(v contract.CryptoGeneratedValueEntryPlan) contract.CryptoGeneratedValueEntryPlan {
	v.Result = bytes.Clone(v.Result)
	v.Recipients = slices.Clone(v.Recipients)
	return v
}

func prepareNativeGeneratedEntry(t *testing.T, keys *custody.Fixture, s *StateSession, f nativeGeneratedEntryFixture, plan contract.CryptoGeneratedValueEntryPlan, phaseID contract.ID, label string) (contract.CryptoResponse, error) {
	t.Helper()
	keys.RetireGenerated()
	q := f.request
	q.Context.AdmissionID, q.Context.SessionID, q.Context.IntentDescriptor = testID(label+" final admission"), testID(label+" final session"), contract.DescriptorVector{}
	var err error
	q.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(q)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Unix(0, int64(q.Context.Expiry))
	if err := keys.AdmitGeneratedValueEntries(q, currentControlOf(s), f.input, f.phase,
		[]contract.GeneratorResultReference{f.reference}, []custody.GeneratedEntryAdmission{f.entryAdmission}, deadline); err != nil {
		t.Fatal("member private admission", err)
	}
	crypto := keys.Crypto()
	body, err := contract.EncodeCryptoGeneratedCompareRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	compareID := testID(label + " member compare")
	compared := crypto.Exchange(stdcontext.Background(), contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoCompare,
		RequestID: compareID, CustodyInstanceID: crypto.InstanceID(), Body: body})
	if compared.ResultCode != contract.CryptoSuccess || compared.Schema != contract.CryptoSchema || compared.Kind != contract.CryptoCompare ||
		compared.RequestID != compareID || compared.CustodyInstanceID != crypto.InstanceID() || len(compared.KeyUseRows) == 0 {
		t.Fatal("member compare", compared.ResultCode)
	}
	opened, err := contract.InspectCryptoGeneratedCompareResult(compared.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, err = contract.EncodeCryptoGeneratedValueEntriesRequest(contract.CryptoGeneratedValueEntriesRequest{OperationRef: opened.OperationRef,
		Context: q.Context, PhaseID: phaseID, Final: 1, Rows: []contract.CryptoGeneratedValueEntryPlan{plan}})
	if err != nil {
		return contract.CryptoResponse{}, err
	}
	prepareID := testID(label + " member prepare")
	reply := crypto.Exchange(stdcontext.Background(), contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoPrepare,
		RequestID: prepareID, CustodyInstanceID: crypto.InstanceID(), Body: body})
	if reply.Schema != contract.CryptoSchema || reply.Kind != contract.CryptoPrepare || reply.RequestID != prepareID || reply.CustodyInstanceID != crypto.InstanceID() {
		t.Fatal("member prepare response framing")
	}
	return reply, nil
}

// full_only: false
func TestNativeGeneratorReturnUsesReservedFirstSendAndFreshRecovery(t *testing.T) {
	for _, mode := range []string{"success", "owned-unusable"} {
		artifact := buildHermeticGenerator(t, mode)
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovery%t", mode, recovery), func(t *testing.T) {
				ctx := stdcontext.Background()
				env, keys := genesisEnvironment(t, contract.GCP, recovery)
				run := newScenarioRun(t, ctx, env)
				fixture := newEnvironmentFixture(t, ctx, run.env, nil, false)
				input, canonical := generatedSourcePlanInputForProfile(t, run, fixture, 2, generatorProcessProfile(t, artifact))
				prior, _ := preparePrivateGeneratedReservation(t, env, fixture.session, input, canonical)
				producer, expected := preparePrivateGeneratedProcessProducer(t, env, fixture.session, prior, artifact)
				calls := 0
				var result []byte
				if !producer.reservation.candidate.bindFirstSend(producer, func(ctx stdcontext.Context, authority contract.ID) contract.CryptoResultCode {
					calls++
					var code contract.CryptoResultCode
					result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
					return code
				}) {
					t.Fatal("process first-send handoff")
				}
				selected, res := fixture.session.selectCandidate(ctx, producer.reservation.candidate)
				if selected == nil || res.Outcome != ObservedCurrent || res.Reason != NoReason || calls != 1 || len(result) == 0 {
					t.Fatal("process result did not follow the reserved first send", calls, res)
				}
				record, err := contract.DecodeGeneratedResultRecord(result)
				work, workErr := selected.selectedGeneratedWork(stdcontext.Background())
				wantDisposition := uint8(1)
				if mode == "owned-unusable" {
					wantDisposition = 2
				}
				if err != nil || workErr != nil || record.SafeFacts.Disposition != wantDisposition || contract.ValidateGeneratedResult(expected, work.attempts[expected.Template.AttemptID].material, record) != nil {
					t.Fatal("process result is not the expected frozen record", err, workErr)
				}
				if again, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, producer.reservation.candidate.generated.authority); code == contract.CryptoSuccess || len(again) != 0 || calls != 1 {
					t.Fatal("process return became reusable")
				}
				requireNoGeneratorPlaintext(t, env.Store.(*memoryStore), result)
				keys.RetireGenerated()
				recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), selected, expected.Template.AttemptID, result)
				current, err := recorded.selectedGeneratedWork(stdcontext.Background())
				if err != nil || !bytes.Equal(current.attempts[expected.Template.AttemptID].result, result) || current.phase.Phase != 2 {
					t.Fatal("fresh record changed the process result", err)
				}
				checkFreshGeneratedProcess(t, env.Store.(*memoryStore), recorded)
				requireNoGeneratorPlaintext(t, env.Store.(*memoryStore), result)
			})
		}
	}
}

// full_only: false
func TestNativeGeneratorRecordedResultPreparesOnlyItsCanonicalMember(t *testing.T) {
	artifact := buildHermeticGenerator(t, "success")
	ctx := stdcontext.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, ctx, env)
	fixture := newEnvironmentFixture(t, ctx, run.env, nil, false)
	input, canonical := generatedSourcePlanInputForProfile(t, run, fixture, 0, generatorProcessProfile(t, artifact))
	prior, _ := preparePrivateGeneratedReservation(t, env, fixture.session, input, canonical)
	producer, expected := preparePrivateGeneratedProcessProducer(t, env, fixture.session, prior, artifact)
	var result []byte
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx stdcontext.Context, authority contract.ID) contract.CryptoResultCode {
		var code contract.CryptoResultCode
		result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("member process first-send handoff")
	}
	selected, outcome := fixture.session.selectCandidate(ctx, producer.reservation.candidate)
	if selected == nil || outcome.Outcome != ObservedCurrent || outcome.Reason != NoReason || len(result) == 0 {
		t.Fatal("member process result selection", outcome)
	}
	recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), selected, expected.Template.AttemptID, result)
	checkFreshGeneratedProcess(t, env.Store.(*memoryStore), recorded)
	entryKeys := memoryCurrentAuthorityKeys(t, recorded)
	entryFixture := nativeGeneratedEntryPlan(t, recorded, expected.Template.AttemptID, result, "connected native")
	phaseID, err := contract.GeneratorPhaseID(entryFixture.phase)
	if err != nil {
		t.Fatal(err)
	}
	var first contract.CryptoGeneratedValueEntryResult
	for replay := 0; replay < 2; replay++ {
		reply, err := prepareNativeGeneratedEntry(t, entryKeys, recorded, entryFixture, cloneNativeGeneratedEntryPlan(entryFixture.plan), phaseID, fmt.Sprintf("exact replay %d", replay))
		if err != nil || reply.ResultCode != contract.CryptoSuccess || len(reply.KeyUseRows) == 0 {
			t.Fatal("exact canonical member preparation", replay, reply.ResultCode, err)
		}
		view, err := contract.InspectCryptoGeneratedValueEntriesResult(reply.Body)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := view.Own()
		if err != nil || len(owned.Rows) != 1 {
			t.Fatal("canonical member result", err)
		}
		if replay == 0 {
			first = owned.Rows[0]
		} else if first.ValueCore != owned.Rows[0].ValueCore || !bytes.Equal(first.Entry.ValueBytes, owned.Rows[0].Entry.ValueBytes) {
			t.Fatal("exact recorded result and phase changed canonical member output")
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*contract.CryptoGeneratedValueEntryPlan, *contract.ID)
	}{
		{"result ID", func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.ID) {
			p.Generated.CreateResultID = testID("changed result ID")
		}},
		{"result bytes", func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.ID) { p.Result[len(p.Result)-1] ^= 1 }},
		{"target", func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.ID) {
			p.Generated.ResourceDigest = testID("changed provider target")
		}},
		{"slot", func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.ID) { p.Slot++ }},
		{"phase", func(_ *contract.CryptoGeneratedValueEntryPlan, phase *contract.ID) { phase[0] ^= 1 }},
		{"generated binding", func(p *contract.CryptoGeneratedValueEntryPlan, _ *contract.ID) {
			p.ValueCore.GeneratedBindingDigest[0] ^= 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, changedPhase := cloneNativeGeneratedEntryPlan(entryFixture.plan), phaseID
			tc.change(&plan, &changedPhase)
			reply, err := prepareNativeGeneratedEntry(t, entryKeys, recorded, entryFixture, plan, changedPhase, "changed "+tc.name)
			if err == nil && (reply.ResultCode == contract.CryptoSuccess || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0) {
				t.Fatal("changed canonical member context prepared", reply.ResultCode)
			}
		})
	}
	requireNoGeneratorPlaintext(t, env.Store.(*memoryStore), result, first.Entry.ValueBytes)
}

// full_only: false
func TestNativeGeneratorProcessFailureCannotBecomeResult(t *testing.T) {
	// Caller cancellation does not end an entered return-only interval. A
	// stalled child must instead outlast its fixed command deadline.
	const commandLifetime = 3 * time.Second
	for _, mode := range []string{"bad-handshake", "exit-after-handshake", "wrong-command", "wrong-attempt", "wrong-result", "wrong-result-contract", "wrong-producer", "wrong-safe-facts", "duplicate-result", "truncated-result", "overlength-result", "exit-after-command", "exit-after-result", "failure-status", "duplicate-status", "hang", "stall-after-result"} {
		t.Run(mode, func(t *testing.T) {
			artifact := buildHermeticGenerator(t, mode)
			ctx := stdcontext.Background()
			env, keys := genesisEnvironment(t, contract.GCP, false)
			run := newScenarioRun(t, ctx, env)
			fixture := newEnvironmentFixture(t, ctx, run.env, nil, false)
			prior, _ := preparePrivateGeneratedReservation(t, env, fixture.session, generatedPlanInputForProfile(t, fixture.session, generatedVectorID(10), generatorProcessProfile(t, artifact)), nil)
			producer, expected := preparePrivateGeneratedProcessProducer(t, env, fixture.session, prior, artifact, commandLifetime)
			calls := 0
			var result []byte
			var producerCode contract.CryptoResultCode
			if !producer.reservation.candidate.bindFirstSend(producer, func(ctx stdcontext.Context, authority contract.ID) contract.CryptoResultCode {
				calls++
				result, _, producerCode = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return producerCode
			}) {
				t.Fatal("failed-process first-send handoff")
			}
			selectContext := ctx
			if mode == "hang" || mode == "stall-after-result" {
				var cancel stdcontext.CancelFunc
				selectContext, cancel = stdcontext.WithTimeout(ctx, time.Second)
				defer cancel()
			}
			selected, res := fixture.session.selectCandidate(selectContext, producer.reservation.candidate)
			if selected == nil || res.Outcome != ObservedCurrent || res.Reason != CustodyUnavailable || calls != 1 || len(result) != 0 {
				t.Fatal("failed process changed selected-effect evidence", calls, len(result), producerCode, res)
			}
			if (mode == "hang" || mode == "stall-after-result") && producerCode != contract.CryptoExpired {
				t.Fatal("stalled process did not end at its fixed command deadline", producerCode)
			}
			work, err := selected.selectedGeneratedWork(stdcontext.Background())
			if err != nil || len(work.attempts[expected.Template.AttemptID].result) != 0 {
				t.Fatal("failed process became a successful result", err)
			}
			if again, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, producer.reservation.candidate.generated.authority); code == contract.CryptoSuccess || len(again) != 0 {
				t.Fatal("failed process restored first-send authority")
			}
			cold, opened := Open(ctx, fixture.admission, env.Store)
			if cold == nil || opened.Outcome != ObservedCurrent {
				t.Fatal("selected effect did not survive process loss", opened)
			}
			checkFreshGeneratedProcess(t, env.Store.(*memoryStore), cold)
		})
	}
}

// full_only: false
func TestNativeGeneratorLateReturnSurvivesKeyReplacement(t *testing.T) {
	artifact := buildHermeticGenerator(t, "delay")
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery%t", recovery), func(t *testing.T) {
			ctx := stdcontext.Background()
			env, keys := genesisEnvironment(t, contract.GCP, recovery)
			replacementKeys := custody.New(t, contract.GCP, fixtureID(env.Domain, "custody"), recovery,
				[]contract.ID{fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")})
			if !reflect.DeepEqual(keys.Bindings(), replacementKeys.Bindings()) {
				t.Fatal("replacement process needs the same configured keys")
			}
			replacementEnv := env
			replacementEnv.Custody = replacementKeys
			replacementEnv = syntheticAuthorityScenarioEnvironment(t, replacementEnv)
			run := newScenarioRun(t, ctx, env)
			fixture := newEnvironmentFixture(t, ctx, run.env, nil, false)
			prior, _ := preparePrivateGeneratedReservation(t, env, fixture.session, generatedPlanInputForProfile(t, fixture.session, generatedVectorID(10), generatorProcessProfile(t, artifact)), nil)
			producer, expected := preparePrivateGeneratedProcessProducer(t, env, fixture.session, prior, artifact)
			var result []byte
			calls := 0
			if !producer.reservation.candidate.bindFirstSend(producer, func(ctx stdcontext.Context, authority contract.ID) contract.CryptoResultCode {
				calls++
				var code contract.CryptoResultCode
				result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("late process handoff")
			}
			type selectedResult struct {
				session *StateSession
				result  Result
			}
			selectedChannel := make(chan selectedResult, 1)
			go func() {
				selected, observed := fixture.session.selectCandidate(ctx, producer.reservation.candidate)
				selectedChannel <- selectedResult{session: selected, result: observed}
			}()
			started, cancel := stdcontext.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if !keys.WaitGeneratedProcessCommand(started) {
				t.Fatal("generator command did not enter the child")
			}
			selected, observed := Open(ctx, fixture.admission, env.Store)
			if selected == nil || observed.Outcome != ObservedCurrent {
				t.Fatal("reservation was not selected before process return", observed)
			}
			original, err := selected.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal(err)
			}
			approval := uint8(contract.NormalSigningRole)
			if recovery {
				approval = contract.RecoverySigningRole
			}
			actors := replacementEnv.ReplacementActors(t, ctx, selected, 1, 3, approval)
			permit := admitAuthorityReplacement(t, selected, replacementKeys, actors.After, 1, approval, 3, actors.Source)
			candidate, prepared := selected.PrepareSuccession(ctx, permit, actors.Signers)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("replacement during generator run", prepared)
			}
			admission := deliverSuccessionBasis(t, candidate)
			if res := selected.Select(ctx, candidate); res.Outcome != ObservedCurrent {
				t.Fatal("replacement selection during generator run", res)
			}
			replacementKeys.RetireAccess()
			successor, reopened := Open(ctx, admission, env.Store)
			if successor == nil || reopened.Outcome != ObservedCurrent {
				t.Fatal("replacement cold selection", reopened)
			}
			actors.Activate(t, successor)
			late := <-selectedChannel
			if late.session == nil || late.result.Outcome != ObservedCurrent || late.result.Reason != NoReason || calls != 1 || len(result) == 0 {
				t.Fatal("late process return did not finish under original custody", calls, late.result)
			}
			after, err := successor.selectedGeneratedWork(stdcontext.Background())
			if err != nil || *after.parent != *original.parent || *after.phase != *original.phase || !bytes.Equal(after.protected[after.parent.MaterialID], original.protected[original.parent.MaterialID]) {
				t.Fatal("replacement changed accepted generator work", err)
			}
			keys.RetireGenerated()
			recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), successor, expected.Template.AttemptID, result)
			current, err := recorded.selectedGeneratedWork(stdcontext.Background())
			if err != nil || !bytes.Equal(current.attempts[expected.Template.AttemptID].result, result) {
				t.Fatal("current keys lost the late original result", err)
			}
			checkFreshGeneratedProcess(t, env.Store.(*memoryStore), recorded)
			requireNoGeneratorPlaintext(t, env.Store.(*memoryStore), result)
		})
	}
}
