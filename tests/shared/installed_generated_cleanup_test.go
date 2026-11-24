package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	protocol "enkv.sh/sdk/protocols/generator"
)

func installedGeneratedCleanupTestEngine(t testing.TB, env fixtureEnvironment, selected *StateSession, generated *GeneratedApplyInstallation) *InstalledApply {
	t.Helper()
	validator := NewPublicConfigurationValidator(selected.admission.outputInterpreter)
	engine, err := NewInstalledApply(ApplyInstallation{
		ExpectedDomain: selected.root.Domain, ExpectedStore: env.Store.Descriptor(), PublicBasis: selected.admission.publicBasis(),
		ExpectedControl: currentControlOf(selected), DesiredRecipients: currentApplyRecipients(selected.registry()),
		ConfigurationValidator: validator, Generated: generated, Store: env.Store, Trust: env.Trust,
		CompositionID: selected.admission.composition, FileIdentity: generatedVectorID(250), CloseInstalled: func() {},
		AdmitCustody: func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*InstalledApplyCustody, error) {
			t.Fatal("cleanup opened supplied Apply custody")
			return nil, contract.ErrRecord
		},
	})
	if err != nil {
		t.Fatal("installed cleanup construction", err)
	}
	t.Cleanup(engine.Close)
	return engine
}

func installedGeneratedVerificationTestCallbacks(t testing.TB, env fixtureEnvironment) *GeneratedApplyInstallation {
	t.Helper()
	return &GeneratedApplyInstallation{AdmitVerification: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedVerificationInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
		owner, err := env.Custody.NewInstalledGeneratedVerification(q, control, input, deadline)
		if err != nil {
			return nil, err
		}
		return &InstalledGeneratedCustody{Crypto: owner, BindCandidate: owner.BindCandidate, Close: owner.Close}, nil
	}}
}

func installedGeneratedLateCreateProcess(t *testing.T, choice uint8) (*generatedProcessFixture, func() (int, []string)) {
	t.Helper()
	return installedGeneratedLateCreateProcessWithRemovalFailure(t, choice, false)
}

func installedGeneratedLateCreateProcessWithRemovalFailure(t *testing.T, choice uint8, removalFailure bool) (*generatedProcessFixture, func() (int, []string)) {
	t.Helper()
	var mu sync.Mutex
	creates := 0
	var deletes []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodPost:
			creates++
			value := ""
			if creates == 1 && choice == custody.StandardValue {
				value = `,"value":"` + hermeticCloudflareSecret + `"`
			}
			if _, err := fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%032x"%s,"status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`, creates, value, hermeticCloudflarePermission, hermeticCloudflareAccount); err != nil {
				t.Error("controlled late-create response failed")
			}
		case http.MethodDelete:
			token := path.Base(request.URL.Path)
			deletes = append(deletes, token)
			if _, err := fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, token); err != nil {
				t.Error("controlled following-cleanup response failed")
			}
		default:
			t.Error("unexpected late-create provider request")
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	origin := server.URL + "/client/v4"
	var artifact string
	var implementation contract.GeneratorImplementation
	if removalFailure {
		artifact, implementation = buildHermeticCloudflareGeneratorWithRemovalFailure(t, origin)
	} else {
		artifact, implementation = buildHermeticCloudflareGenerator(t, origin)
	}
	intent, request := hermeticCloudflareIntent()
	process := &generatedProcessFixture{Artifact: artifact, Implementation: implementation, Intent: intent,
		RequestDigest: hermeticCloudflareHTTPRequestDigest(request), Configure: func(tb testing.TB, artifact string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
			return hermeticCloudflareConfig(tb, artifact, origin, implementation, expected)
		}}
	return process, func() (int, []string) {
		mu.Lock()
		defer mu.Unlock()
		return creates, slices.Clone(deletes)
	}
}

// full_only: false
func TestInstalledManagedGeneratorKeepsOriginalCleanupFactsAfterExecutableRemovalFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	root := generatorRemovalFixtureRoot(t)
	process, effects := installedGeneratedLateCreateProcessWithRemovalFailure(t, custody.StandardValue, true)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	declaration := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema,
		LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual,
		ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
		CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
	healthy := ApplyEntryInput{Name: "healthy", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
		Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("unchanged healthy sibling"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	input := []ApplyEntryInput{{Name: "generated", ValueSource: contract.Generated, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Secret,
		Recipients: []contract.ID{f.selected.admission.recipient}, Generated: &declaration}, healthy}
	engine := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
	created := engine.Apply(ctx, fixtureID(f.env.Domain, "managed result despite executable removal"), input)
	engine.Close()
	creates, deletes := effects()
	t.Logf("managed_result_returned=true outcome=%d reason=%d creates=%d deletes=%d", created.Result.Outcome, created.Result.Reason, creates, len(deletes))
	assertGeneratorRemovalFixture(t, root)
	if created.Result.Outcome != ObservedCurrent || created.Generated == nil || created.Generated.StateResult != "success" || creates != 1 || len(deletes) != 0 {
		t.Fatalf("sole executable removal discarded the managed result: outcome=%d reason=%d generated=%t creates=%d deletes=%d", created.Result.Outcome, created.Result.Reason, created.Generated != nil, creates, len(deletes))
	}
	if len(created.Diagnostics) != 1 || !generatorCleanupDiagnostic(created.Diagnostics[0]) {
		t.Fatal("completed managed result did not retain one separate safe cleanup diagnostic")
	}
	cold := f.open(t, ctx)
	_, original := observeCurrentValueEntry(t, cold, "generated")
	if cold.root.Generated.GeneratedCurrent != 1 || !cold.root.Generated.ActiveOwner.IsZero() || original.Generated.ResourceDigest != hermeticCloudflareResourceDigest("00000000000000000000000000000001") {
		t.Fatal("cold generated result lost its original acknowledged resource")
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("managed private sink parent unavailable")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal("managed private sink parent mode unavailable")
	}
	valuePath := filepath.Join(directory, "managed-value.private")
	selection := sessionConsumerSelection(t, cold, cold.admission.recipient, "generated")
	read := f.keys.CaptureSelected(ctx, selection, valuePath)
	if read.Code != contract.CryptoSuccess || read.Delivery != 1 || read.SinkCalls != 1 || !read.ValueMatched {
		t.Fatalf("cold managed Reader capture refused: code=%d delivery=%d sink_calls=%d value_matched=%t", read.Code, read.Delivery, read.SinkCalls, read.ValueMatched)
	}
	value, err := os.ReadFile(valuePath)
	if err != nil {
		t.Fatal("cold managed value unavailable")
	}
	defer clear(value[:cap(value)])
	if !bytes.Equal(value, []byte(hermeticCloudflareSecret)) {
		t.Fatal("cold managed Reader did not retain the exact returned value")
	}
	removeInput := []ApplyEntryInput{healthy}
	remover := installedGeneratedTestEngine(t, ctx, f, cold, removeInput, currentApplyRecipients(cold.registry()), installedGeneratedRetirementCallbacks(t, f, process))
	removed := remover.Apply(ctx, fixtureID(f.env.Domain, "remove retained managed value"), removeInput)
	remover.Close()
	if removed.Result.Outcome != ObservedCurrent {
		t.Fatalf("ordinary removal of the retained value refused: outcome=%d reason=%d", removed.Result.Outcome, removed.Result.Reason)
	}
	cold = f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, cold)
	var duty contract.GeneratedDutyRecord
	for _, record := range cold.supportRecords() {
		if record.Kind != contract.GeneratedDutySupportKind {
			continue
		}
		candidate, err := contract.InspectGeneratedDutyRecord(record.Body)
		if err != nil {
			t.Fatal("retained generated Duty invalid")
		}
		if candidate.Kind == contract.GeneratedDutyRetirement {
			if !duty.DutyID.IsZero() {
				t.Fatal("ordinary removal invented another retirement Duty")
			}
			duty = candidate
		}
	}
	if duty.DutyID.IsZero() || duty.OriginalOperationID != original.Generated.OriginOperationID || duty.OriginalAttemptID != original.Generated.OriginAttemptID || duty.ResourceID != original.Generated.ResourceIncarnationID {
		t.Fatal("ordinary removal lost the original create identity")
	}
	target, err := work.retirementTarget(ctx, duty)
	if err != nil || target.ResourceDigest != original.Generated.ResourceDigest || target.OriginalAttemptID != original.Generated.OriginAttemptID {
		t.Fatal("ordinary retirement target changed the retained original")
	}
	facts, err := work.createTargetEvidence(ctx, target)
	if err != nil || !bytes.Equal(facts.Target, []byte(hermeticCloudflareAccount)) || !bytes.Equal(facts.ResourceData, []byte("00000000000000000000000000000001")) {
		t.Fatal("ordinary retirement lost the exact returned resource facts")
	}
	retirer := installedGeneratedRetirementEngine(t, ctx, f, cold, installedGeneratedRetirementCallbacks(t, f, process))
	retired := retirer.RetireGenerated(ctx, fixtureID(f.env.Domain, "retire original after executable removal"), GeneratedRetirementRequest{DutyID: duty.DutyID})
	retirer.Close()
	creates, deletes = effects()
	if retired.Result.Outcome != ObservedCurrent || retired.Generated == nil || retired.Generated.StateResult != "success" || creates != 1 || !slices.Equal(deletes, []string{"00000000000000000000000000000001"}) {
		t.Fatalf("ordinary retirement repeated create or changed its original target: outcome=%d reason=%d creates=%d deletes=%d", retired.Result.Outcome, retired.Result.Reason, creates, len(deletes))
	}
	closed := f.open(t, ctx)
	if closed.root.Generated.Retiring != 0 || closed.root.Generated.Hazards != 0 || !closed.root.Generated.ActiveOwner.IsZero() || closed.root.Generated.GeneratedCurrent != 0 {
		t.Fatal("acknowledged ordinary retirement retained work or resurrected a value")
	}
}

// full_only: false
func TestGeneratedNativePreStartFailureKeepsExactNoSendEvidence(t *testing.T) {
	for _, earlierUnknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "earlier-unknown-retained"}[earlierUnknown], func(t *testing.T) { testGeneratedNativePreStartFailure(t, earlierUnknown) })
	}
}

func testGeneratedNativePreStartFailure(t *testing.T, earlierUnknown bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	root := generatorRemovalFixtureRoot(t)
	process, effects := installedGeneratedLateCreateProcess(t, custody.StandardValue)
	var env fixtureEnvironment
	var before *StateSession
	var older generatedAttempt
	if earlierUnknown {
		env, before, older, _ = installedGeneratedLateCreateFixture(t, ctx, custody.StandardValue)
	} else {
		env, _ = genesisEnvironment(t, contract.GCP, true)
		env = syntheticAuthorityScenarioEnvironment(t, env)
		before = newEnvironmentFixture(t, ctx, env, nil, false).session
	}
	profile := liveGeneratedProfile(t, process.Implementation, contract.GeneratedRetirementManual)
	sources, canonical := generatedCurrentDeclaration(t, before)
	input := generatedPlanInputForGenerationsIntent(t, before, generatedVectorID(233), []string{"not-started"}, process.Intent, profile, sources...)
	input.requestBindings[0].Digest = process.RequestDigest
	prior, _ := preparePrivateGeneratedReservation(t, env, before, input, canonical)
	producer, expected := preparePrivateGeneratedProcessProducerWithConfig(t, env, before, prior, process.Artifact, process.Configure)
	t.Cleanup(env.Custody.RetireGenerated)
	body, err := os.ReadFile(process.Artifact)
	if err != nil || len(body) == 0 {
		t.Fatal("preadmitted native artifact unavailable")
	}
	info, err := os.Stat(process.Artifact)
	if err != nil {
		t.Fatal("preadmitted native artifact identity unavailable")
	}
	t.Cleanup(func() {
		env.Custody.RetireGenerated()
		if err := os.WriteFile(process.Artifact, body, info.Mode().Perm()); err != nil {
			t.Error("joined native artifact restoration failed")
		}
		clear(body)
	})
	damaged := bytes.Clone(body)
	defer clear(damaged)
	damaged[len(damaged)-1] ^= 1
	if err := os.WriteFile(process.Artifact, damaged, info.Mode().Perm()); err != nil {
		t.Fatal("controlled native artifact change failed")
	}
	candidate := producer.reservation.candidate
	wantRevision, wantSnapshot := candidate.head.Core.Revision, candidate.head.Core.Root.Object
	var packet []byte
	var facts contract.GeneratorSafeFacts
	var observed custody.GeneratedProducerOutcome
	var authority contract.ID
	calls := 0
	if !candidate.bindFirstSend(producer, func(callctx context.Context, accepted contract.ID) contract.CryptoResultCode {
		calls++
		authority = accepted
		packet, facts, observed = env.Custody.InvokeGeneratedProducerOutcome(callctx, producer.operation.context.AdmissionID, producer.producerLocator, accepted)
		return observed.Code
	}) {
		t.Fatal("preadmitted native producer handoff refused")
	}
	selected, result := before.selectCandidate(ctx, candidate)
	env.Custody.RetireGenerated()
	if selected == nil || result.Outcome != ObservedCurrent || result.Reason != CustodyUnavailable || result.RequestedRevision != wantRevision ||
		result.ObservedRevision != wantRevision || result.ObservedSnapshotID != wantSnapshot || result.Evidence != AuthenticatedClosure || result.CommitMayHaveOccurred ||
		selected.head.Core.Revision != wantRevision || selected.root.Snapshot != wantSnapshot {
		t.Fatalf("pre-start refusal changed authenticated selection facts: selected=%t outcome=%d reason=%d evidence=%d", selected != nil, result.Outcome, result.Reason, result.Evidence)
	}
	creates, deletes := effects()
	launches, err := filepath.Glob(filepath.Join(root, "enkv-generator-*", ".launch-*"))
	parents, parentErr := filepath.Glob(filepath.Join(root, "enkv-generator-*"))
	if err != nil || parentErr != nil || len(parents) != 0 || len(launches) != 0 || creates != 0 || len(deletes) != 0 {
		t.Fatalf("pre-start refusal retained staging or reached provider: launches=%d creates=%d deletes=%d inventory_error=%t", len(launches), creates, len(deletes), err != nil)
	}
	if calls != 1 || observed.ID != producer.operation.context.AdmissionID || observed.Locator != producer.producerLocator || authority.IsZero() || observed.Authority != authority ||
		observed.Code != contract.CryptoCustodyUnavailable || observed.Stage != "launch" || observed.Category != "unavailable" || observed.Qualified ||
		len(packet) != 0 || !reflect.DeepEqual(facts, contract.GeneratorSafeFacts{}) {
		t.Fatalf("pre-start refusal lost its closed invocation observation: calls=%d code=%d stage=%q category=%q qualified=%t packet=%d", calls, observed.Code, observed.Stage, observed.Category, observed.Qualified, len(packet))
	}
	work := mustSelectedGeneratedWork(t, selected)
	attempt, present := work.attempts[expected.Template.AttemptID]
	if !present || attempt.record.State != contract.GeneratedEffectTransmitted || len(attempt.result) != 0 {
		t.Fatal("private pre-start observation removed or rewrote the selected original Attempt")
	}
	if earlierUnknown {
		retained, present := work.attempts[older.record.AttemptID]
		if !present || !reflect.DeepEqual(retained.record, older.record) || !bytes.Equal(retained.result, older.result) || retained.record.State != contract.GeneratedEffectClosedWithResidue {
			t.Fatal("exact no-send evidence erased an earlier unresolved remote effect")
		}
	}
	if observed.Effect != "no_send" {
		t.Fatalf("proved pre-start refusal remained uncertain: effect=%q", observed.Effect)
	}
}

func installedGeneratedNativeLateCreateFixture(t *testing.T, ctx context.Context, process *generatedProcessFixture, encoding uint8) (fixtureEnvironment, *StateSession, generatedAttempt, []byte) {
	t.Helper()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
	f.env.GeneratedProcess = process
	plain := ApplyEntryInput{Name: "plain", Recipients: []contract.ID{f.selected.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("unrelated current value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	initial := f.engine(t, f.selected, []ApplyEntryInput{plain}, nil)
	if result := initial.Apply(ctx, testID("late create current predecessor"), []ApplyEntryInput{plain}); result.Result.Outcome != ObservedCurrent {
		t.Fatal("late create current predecessor did not select", result.Result)
	}
	initial.Close()
	before := f.open(t, ctx)
	input := []ApplyEntryInput{plain, {Name: "late", InputEncoding: encoding, OutputEncoding: contract.OutputEncodingRaw, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret,
		Recipients: []contract.ID{before.admission.recipient}, Generated: &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema,
			LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual,
			ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
			CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}}}
	callbacks := installedGeneratedRetirementCallbacks(t, f, process)
	admit := callbacks.AdmitProducer
	var originalID contract.ID
	var packet []byte
	callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
		owner, err := admit(ctx, q, control, in, implementation, deadline)
		if err != nil || in.Expected.Template.Branch != contract.GeneratorBranchInitial {
			return owner, err
		}
		if in.Expected.Template.Action != contract.GeneratorActionCreate || !originalID.IsZero() {
			t.Fatal("late create fixture entered a different original")
		}
		originalID = in.Expected.Template.AttemptID
		invoke := owner.InvokeProducer
		owner.InvokeProducer = func(ctx context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
			returned := invoke(ctx, locator, authority)
			body, facts, code := returned.Record, returned.Facts, returned.Code
			if code != contract.CryptoSuccess || len(body) == 0 || len(packet) != 0 {
				t.Fatal("late create native original did not return one sealed packet", code)
			}
			packet = bytes.Clone(body)
			clear(body)
			unknown := contract.GeneratorSafeFacts{Schema: facts.Schema, Action: facts.Action, LifecycleMode: facts.LifecycleMode,
				ResourceContractID: facts.ResourceContractID, Disposition: contract.GeneratorDispositionUnknown, Reason: contract.GeneratorReasonTransport,
				RequestDigest: facts.RequestDigest, IntentDigest: facts.IntentDigest}
			returned.Record, returned.Facts = nil, unknown
			return returned
		}
		return owner, nil
	}
	engine := installedGeneratedTestEngine(t, ctx, f, before, input, currentApplyRecipients(before.registry()), callbacks)
	result := engine.Apply(ctx, testID("late create lost original observation"), input)
	engine.Close()
	if result.Result.Outcome != ObservedCurrent || len(result.Receipt) == 0 || originalID.IsZero() || len(packet) == 0 {
		t.Fatal("late create native failed aggregate did not finish", result.Result)
	}
	closed := f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, closed)
	original := work.attempts[originalID]
	if work.parent != nil || work.phase != nil || len(work.attempts) != 1 || original.record.State != contract.GeneratedEffectClosedWithResidue || len(original.result) != 0 ||
		!reflect.DeepEqual(before.pages, closed.pages) || !reflect.DeepEqual(before.registry(), closed.registry()) {
		t.Fatal("native lost observation did not retain exact uncertainty and current state")
	}
	if persisted := closed.persistGeneratedResult(ctx, generatedResultWrite{attempt: originalID, body: packet}); persisted.Outcome != 0 {
		t.Fatal("late native original did not arrive at its retained inbox", persisted)
	}
	return f.env, closed, original, packet
}

func installedGeneratedLateCreateFixture(t *testing.T, ctx context.Context, choice uint8) (fixtureEnvironment, *StateSession, generatedAttempt, []byte) {
	t.Helper()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	profile, intent := defaultGeneratedFixtureProfile(), []byte(`{"name":"generated"}`)
	before := newEnvironmentFixture(t, ctx, env, []int{32}, false).session
	sources, canonical := generatedCurrentDeclaration(t, before)
	input := generatedPlanInputForGenerationsIntent(t, before, generatedVectorID(230), []string{"late"}, intent, profile, sources...)
	prior, _ := preparePrivateGeneratedReservation(t, env, before, input, canonical)
	sends := 0
	enter := func(s *StateSession, prior *generatedPreparation, value uint8) (*StateSession, contract.GeneratorResultExpectation, []byte) {
		t.Helper()
		producer, expected := preparePrivateGeneratedProducerValue(t, env, s, prior, value, nil)
		var packet []byte
		if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
			sends++
			var code contract.CryptoResultCode
			packet, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
			return code
		}) {
			t.Fatal("late create original handoff")
		}
		entered, result := s.selectCandidate(ctx, producer.reservation.candidate)
		if entered == nil || result.Outcome != ObservedCurrent || len(packet) == 0 {
			t.Fatal("late create original was not entered", result, sends)
		}
		keys.RetireGenerated()
		return entered, expected, packet
	}
	entered, expected, packet := enter(before, prior, choice)
	fenced := selectGeneratedResiduePlan(t, ctx, env, entered, expected.Template.AttemptID)
	prior = preparePrivateGeneratedSuccessorReservation(t, env, fenced)
	entered, successor, successorPacket := enter(fenced, prior, custody.GeneratedTerminalFailure)
	recordPlan, err := entered.generatedRecordRequest(ctx, successor.Template.AttemptID, successorPacket, generatedPlanInputFixture(t, entered).context)
	if err != nil {
		t.Fatal("following owned-unusable result could not be recorded", err)
	}
	record := preparePrivateGeneratedRecord(t, env, entered, recordPlan)
	recorded, result := entered.selectCandidate(ctx, record.reservation.candidate)
	if recorded == nil || result.Outcome != ObservedCurrent || sends != 2 {
		t.Fatal("following owned-unusable result was not selected exactly once", result, sends)
	}
	keys.RetireGenerated()
	admitted := generatedPlanInputFixture(t, recorded).context
	admitted.AdmissionID, admitted.SessionID = testID("late create closed Final admission"), testID("late create closed Final session")
	plan, err := recorded.generatedFinalRequest(ctx, admitted)
	if err != nil || plan.selecting {
		t.Fatal("late create failed aggregate did not derive Final", err)
	}
	recorded, final := preparePrivateGeneratedFinal(t, env, recorded, plan)
	closed, result := recorded.selectCandidate(ctx, final.reservation.candidate)
	if closed == nil || result.Outcome != ObservedCurrent {
		t.Fatal("late create failed aggregate did not select Final", result)
	}
	keys.RetireGenerated()
	closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
	work := mustSelectedGeneratedWork(t, closed)
	original := work.attempts[expected.Template.AttemptID]
	if work.parent != nil || work.phase != nil || len(work.attempts) != 2 || original.record.State != contract.GeneratedEffectClosedWithResidue || len(original.result) != 0 || len(closed.root.Names) != 1 {
		t.Fatal("late create fixture lost exact uncertainty or unrelated current value")
	}
	if persisted := closed.persistGeneratedResult(ctx, generatedResultWrite{attempt: original.record.AttemptID, body: packet}); persisted.Outcome != 0 {
		t.Fatal("late create original packet did not arrive at its fixed inbox", persisted)
	}
	return env, closed, original, packet
}

// full_only: false
func TestContinuationCapacityKeepsDetachedOriginalAcrossAnotherParent(t *testing.T) {
	ctx := t.Context()
	env, before, original, reply := installedGeneratedLateCreateFixture(t, ctx, custody.StandardValue)
	entries, canonical := generatedCurrentDeclaration(t, before)
	input := generatedPlanInputForGenerationsIntent(t, before, generatedVectorID(233), []string{"other"}, []byte(`{"name":"other"}`), defaultGeneratedFixtureProfile(), entries...)
	prior, _ := preparePrivateGeneratedReservation(t, env, before, input, canonical)
	active, _, _, _ := selectActualGeneratedPacketRecord(t, env, before, prior, custody.GeneratedTerminalFailure, true, nil)
	bound := continuationTestBound(t, active).Remaining
	if active.root.Generated.ActiveOwner == original.record.OperationID || active.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("fixture needs an independent live parent")
	}
	if _, _, err := active.readGeneratedCleanup(ctx); err == nil {
		t.Fatal("live parent admitted early reflection")
	}
	admitted := generatedPlanInputFixture(t, active).context
	admitted.AdmissionID, admitted.SessionID = testID("independent Final admission"), testID("independent Final session")
	plan, err := active.generatedFinalRequest(ctx, admitted)
	if err != nil || plan.selecting {
		t.Fatal("independent failed Final", err)
	}
	active, final := preparePrivateGeneratedFinal(t, env, active, plan)
	closed, selected := active.selectCandidate(ctx, final.reservation.candidate)
	if closed == nil || selected.Outcome != ObservedCurrent {
		t.Fatal("independent parent remained active", selected)
	}
	env.Custody.RetireGenerated()
	closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
	late, err := closed.generatedReflectionPlan(ctx, original.record.ResultID, reply, generatedPlanInputFixture(t, closed).context)
	if err != nil {
		t.Fatal("original reply after independent Final", err)
	}
	next, err := closed.deriveGeneratedReflection(ctx, late)
	if err != nil {
		t.Fatal("record detached original", err)
	}
	continuationTestCandidateWithin(t, next.state, bound)
}

// full_only: false
func TestInstalledGeneratedCleanupLateCreateReflectionAllowsFollowingCleanup(t *testing.T) {
	for _, test := range []struct {
		name, state      string
		choice, encoding uint8
		closed           bool
	}{
		{"complete", "effect-terminal-failure", custody.StandardValue, contract.InputEncodingRaw, false},
		{"invalid-encoding", "effect-terminal-failure", custody.StandardValue, contract.InputEncodingBase64, false},
		{"owned-unusable", "effect-terminal-failure", custody.GeneratedTerminalFailure, contract.InputEncodingRaw, false},
		{"no-effect", "success", custody.GeneratedConfirmedNoEffect, contract.InputEncodingRaw, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			var process *generatedProcessFixture
			var providerEffects func() (int, []string)
			if !test.closed {
				process, providerEffects = installedGeneratedLateCreateProcess(t, test.choice)
			}
			var env fixtureEnvironment
			var before *StateSession
			var original generatedAttempt
			var packet []byte
			if process == nil {
				env, before, original, packet = installedGeneratedLateCreateFixture(t, ctx, test.choice)
			} else {
				env, before, original, packet = installedGeneratedNativeLateCreateFixture(t, ctx, process, test.encoding)
			}
			work := mustSelectedGeneratedWork(t, before)
			hazardKey := generatedRecordKey{contract.GeneratedHazardSupportKind, original.expected.Template.HazardID}
			remaining := continuationTestBound(t, before).Remaining
			other := make(map[generatedRecordKey][]byte)
			for key, row := range work.records {
				if key.kind == contract.GeneratedHazardSupportKind && key != hazardKey {
					other[key] = bytes.Clone(row.Body)
				}
			}
			callbacks := installedGeneratedVerificationTestCallbacks(t, env)
			verify := callbacks.AdmitVerification
			verified := 0
			callbacks.AdmitVerification = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedVerificationInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
				owner, err := verify(ctx, q, control, input, deadline)
				if err == nil {
					verified++
				}
				return owner, err
			}
			callbacks.AdmitProducer = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedProducerInput, contract.GeneratorImplementation, time.Time) (*InstalledGeneratedProducerCustody, error) {
				t.Fatal("reflection entered a provider producer")
				return nil, contract.ErrRecord
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			store.creates, store.cas, trust.signs = 0, 0, 0
			engine := installedGeneratedCleanupTestEngine(t, env, before, callbacks)
			got := engine.CleanupGenerated(ctx, testID("installed late create reflection "+test.name))
			engine.Close()
			if got.Result.Outcome != ObservedCurrent || got.Generated == nil || got.Generated.StateResult != test.state ||
				got.Cleanup == nil || got.Cleanup.Basis.Kind != GeneratedCleanupReflection || len(got.Receipt) != 0 || got.Payload != nil ||
				got.OperationID.IsZero() || got.OperationID == original.record.OperationID || store.cas != 1 || trust.signs != 1 {
				deadline, _ := ctx.Deadline()
				admitted, contextErr := installedGeneratedContext(before, deadline)
				if contextErr == nil {
					plan, planErr := before.generatedReflectionPlan(ctx, original.record.ResultID, packet, admitted)
					if planErr == nil {
						proposal, deriveErr := before.deriveGeneratedLifecycle(ctx, plan, nil)
						if deriveErr == nil {
							capture, captureErr := captureInstalledGeneratedCleanupResult(ctx, before, work, plan, proposal, nil)
							if captureErr == nil {
								observed := PublicApplyResult{DomainID: before.root.Domain, OperationID: plan.identity.operation, RequestIdentity: plan.requestIdentity, RequestID: got.RequestID}
								t.Log("late create refusal boundary: result prevalidation", capture.prevalidate(observed, engine.installation), "private verifier admissions", verified)
							} else {
								t.Log("late create refusal boundary: result capture", captureErr)
							}
						} else {
							t.Log("late create refusal boundary: successor derivation", deriveErr)
						}
					} else {
						t.Log("late create refusal boundary: reflection selection", planErr)
					}
				}
				t.Fatal("installed late create reflection did not pass prevalidation and one effect-free selection", got.Result, store.cas, trust.signs)
			}
			if len(got.Generated.Effects) != 1 || got.Generated.Effects[0].Record.AttemptID != original.record.AttemptID ||
				got.Generated.Effects[0].Record.OperationID != original.record.OperationID || got.Cleanup.Basis.OriginalResult == nil ||
				got.Cleanup.Basis.OriginalResult.ResultBodyDigest != contract.Hash(packet) || got.Generated.ReceiptObservation {
				t.Fatal("reflection replaced original effect identity or omitted exact packet evidence")
			}
			if test.encoding == contract.InputEncodingBase64 && got.Generated.Effects[0].Reason != GeneratedReasonValueEncoding {
				t.Fatal("reflected result lost the host's encoding rejection", got.Generated.Effects[0].Reason)
			}
			cold := generatedLifecycleReopen(t, ctx, before, env.Store)
			after := mustSelectedGeneratedWork(t, cold)
			if !reflect.DeepEqual(before.pages, cold.pages) || !reflect.DeepEqual(before.registry(), cold.registry()) ||
				!cold.root.Generated.ActiveOwner.IsZero() || cold.root.Generated.Attempts > before.root.Generated.Attempts {
				t.Fatal("reflection changed current data, recipients or active ownership")
			}
			checkGeneratedReceiptRowsUnchanged(t, before, cold)
			for key, body := range other {
				if row, present := after.records[key]; !present || !bytes.Equal(row.Body, body) {
					t.Fatal("reflection changed an independent retained Hazard")
				}
			}
			_, remains := after.records[hazardKey]
			if remains == test.closed {
				t.Fatal("reflection changed the wrong exact obligation")
			}
			if !test.closed {
				retained := after.attempts[original.record.AttemptID]
				hazard, err := contract.InspectGeneratedHazardRecord(after.records[hazardKey].Body)
				if err != nil || retained.record.Facts.Count != 1 || hazard.Target.Count != 1 || hazard.OriginalResults.Count != 1 ||
					!bytes.Equal(retained.result, packet) || retained.record.State != contract.GeneratedEffectClosedWithResidue ||
					hazard.Exposure != contract.GeneratedExposureLateEffect || hazard.Eligibility != contract.GeneratedExposureLateEffect || hazard.Fenced != 1 {
					t.Fatal("cold reflection lost authenticated target or exact historical uncertainty", err)
				}
			} else if !after.hasRecord(generatedRecordKey{contract.PendingInboxReleaseSupportKind, original.record.InboxID}) {
				t.Fatal("no-effect closure lost the exact original release mapping")
			}
			next, present, err := cold.readGeneratedCleanup(ctx)
			if err != nil || !present || next.kind == generatedCleanupReflection {
				t.Fatal("cold reflection blocked the following eligible cleanup", err)
			}
			var closed *StateSession
			if process != nil {
				creates, deletes := providerEffects()
				const wantToken = "00000000000000000000000000000001"
				if creates != 1 || len(deletes) != 0 || next.target.OriginalAttemptID != original.record.AttemptID || next.target.ResourceDigest != hermeticCloudflareResourceDigest(wantToken) {
					t.Fatal("reflection lost the exact original target or sent another request", creates, deletes)
				}
				fixture := installedApplyTestFixture{env: env, keys: env.Custody}
				callbacks := installedGeneratedRetirementCallbacks(t, fixture, process)
				cleaner := installedGeneratedCleanupTestEngine(t, env, cold, callbacks)
				cleaned := cleaner.CleanupGenerated(ctx, testID("installed cleanup following late create "+test.name))
				cleaner.Close()
				creates, deletes = providerEffects()
				if cleaned.Result.Outcome != ObservedCurrent || cleaned.Generated == nil || cleaned.Generated.StateResult != "success" || cleaned.Cleanup == nil || cleaned.Cleanup.Basis.Kind != GeneratedCleanupOwnedTarget ||
					len(cleaned.Generated.Effects) != 1 || cleaned.Generated.Effects[0].Record.OperationID != cleaned.OperationID || cleaned.OperationID == got.OperationID ||
					cleaned.Generated.Effects[0].Action != contract.GeneratorActionDelete || cleaned.Generated.Effects[0].Target == nil || *cleaned.Generated.Effects[0].Target != next.target ||
					cleaned.Generated.AcknowledgedCount != 1 || cleaned.Generated.ConfirmedCount != 0 || len(cleaned.Receipt) != 0 ||
					creates != 1 || !slices.Equal(deletes, []string{wantToken}) {
					t.Fatal("following installed cleanup did not complete its own exact effect", cleaned.Result, creates, deletes)
				}
				closed = generatedLifecycleReopen(t, ctx, cold, env.Store)
			} else {
				row := after.records[next.sourceKey()]
				input, canonical := generatedDeletePlanInputForSource(t, cold, testID("cleanup following late create "+test.name), row, next.target)
				prior, _ := preparePrivateGeneratedReservation(t, env, cold, input, canonical)
				recorded, _, expected, _ := selectActualGeneratedPacketRecord(t, env, cold, prior, custody.StandardValue, true, nil)
				cleanup := mustSelectedGeneratedWork(t, recorded).attempts[expected.Template.AttemptID]
				if cleanup.record.OperationID == got.OperationID || cleanup.expected.Template.Action != contract.GeneratorActionDelete || cleanup.expected.TargetResourceDigest != next.target.ResourceDigest || cleanup.record.State != contract.GeneratedEffectSucceeded {
					t.Fatal("following cleanup did not enter its own exact selected target")
				}
				closed = selectOrdinaryGeneratedCleanupClose(t, ctx, env, recorded, cleanup.record.AttemptID)
				env.Custody.RetireGenerated()
				closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
			}
			if !closed.root.Generated.ActiveOwner.IsZero() || mustSelectedGeneratedWork(t, closed).hasRecord(next.sourceKey()) || !reflect.DeepEqual(before.pages, closed.pages) {
				t.Fatal("following cleanup did not close its own obligation and preserve current data")
			}
			checkGeneratedReceiptRowsUnchanged(t, cold, closed)
			t.Run("reported-capacity", func(t *testing.T) {
				continuationTestCandidateWithin(t, cold, remaining)
			})
		})
	}
}

// full_only: false
func TestInstalledGeneratedCleanupReflectsActualOriginalWithoutProducer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, selected, original, packet := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	t.Setenv("CLOUDFLARE_API_TOKEN", "invalid-credential-must-not-be-read-for-reflection")
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	key, err := format.GeneratedResultKey(store.desc.Prefix, original.record.DomainID, original.record.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	store.objects[key] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: store.desc.Family, Value: "42"}}
	store.creates, store.cas, trust.signs = 0, 0, 0
	before, recipients := selected.pages, selected.registry()
	engine := installedGeneratedCleanupTestEngine(t, env, selected, installedGeneratedVerificationTestCallbacks(t, env))
	got := engine.CleanupGenerated(ctx, generatedVectorID(248))
	engine.Close()
	if got.Result.Outcome != ObservedCurrent || got.Generated == nil || got.Generated.StateResult != "success" || len(got.Receipt) != 0 ||
		got.OperationID.IsZero() || got.OperationID == original.record.OperationID || got.RequestIdentity.IsZero() || store.cas != 1 || trust.signs != 1 || store.creates == 0 {
		t.Fatal("installed cleanup did not authenticate and close exact original once", got.Result, got.Generated, store.cas, trust.signs)
	}
	if len(got.Generated.Effects) != 1 || got.Generated.Effects[0].Record.AttemptID != original.record.AttemptID ||
		got.Generated.Effects[0].Record.OperationID != original.record.OperationID || !got.Generated.Warnings.InvalidationNotConfirmed ||
		got.Generated.AcknowledgedCount != 1 || got.Generated.ConfirmedCount != 0 || got.Generated.ReceiptObservation {
		t.Fatal("reflection changed original identity or exceeded acknowledgement", got.Generated)
	}
	if got.Payload != nil {
		t.Error("selected cleanup reflection emitted TransitionPayload instead of CleanupPayload")
	}
	closed := generatedLifecycleReopen(t, ctx, selected, env.Store)
	if !reflect.DeepEqual(before, closed.pages) || !reflect.DeepEqual(recipients, closed.registry()) {
		t.Fatal("cleanup changed current application values or recipient identities")
	}
	// Fresh zero work is a new observation, with no private key use or CAS.
	public, private := env.Custody.Calls()
	creates, cas, signs := store.creates, store.cas, trust.signs
	noWork := installedGeneratedCleanupTestEngine(t, env, closed, nil).CleanupGenerated(ctx, generatedVectorID(249))
	publicAfter, privateAfter := env.Custody.Calls()
	if noWork.Result.Outcome != Unchanged || noWork.Generated == nil || noWork.Generated.StateResult != "no-op" ||
		noWork.OperationID.IsZero() || noWork.RequestIdentity.IsZero() || noWork.OperationID == got.OperationID || len(noWork.Receipt) != 0 ||
		store.creates != creates || store.cas != cas || trust.signs != signs || publicAfter != public || privateAfter != private {
		t.Fatal("zero-work cleanup mutated, replayed or used private custody", noWork)
	}
	if noWork.Payload != nil {
		t.Error("zero-work cleanup emitted TransitionPayload")
	}
}

type installedCleanupReleaseStore struct {
	*generatedCleanupDeleteStore
	mode    string
	inbox   string
	swapped bool
}

func (s *installedCleanupReleaseStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if key == s.inbox && s.mode == "replacement" && s.cas != 0 && !s.swapped {
		s.objects[key] = stored{Body: []byte("replacement"), Token: contract.Token{Family: s.desc.Family, Value: "99"}}
		s.swapped = true
	}
	return s.generatedCleanupDeleteStore.Read(ctx, key, limit)
}

func (s *installedCleanupReleaseStore) DeleteIfToken(ctx context.Context, key string, token contract.Token) contract.WriteResult {
	if key == s.inbox {
		switch s.mode {
		case "refused":
			s.deletes++
			return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
		case "token-change":
			s.objects[key] = stored{Body: []byte("replacement"), Token: contract.Token{Family: s.desc.Family, Value: "99"}}
		}
	}
	return s.generatedCleanupDeleteStore.DeleteIfToken(ctx, key, token)
}

// full_only: false
func TestInstalledCleanupReleasesOriginalAtSelectedHandoff(t *testing.T) {
	for _, mode := range []string{"acknowledged", "lost", "refused", "token-change", "replacement", "no-capability"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, before, original, packet := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
			base := env.Store.(*memoryStore)
			key, err := format.GeneratedResultKey(base.desc.Prefix, original.record.DomainID, original.record.InboxID)
			if err != nil {
				t.Fatal(err)
			}
			base.objects[key] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: base.desc.Family, Value: "42"}}
			base.cas = 0
			store := &installedCleanupReleaseStore{generatedCleanupDeleteStore: &generatedCleanupDeleteStore{memoryStore: base, lost: mode == "lost"}, inbox: key, mode: mode}
			if mode != "no-capability" {
				env.Store = store
			}
			engine := installedGeneratedCleanupTestEngine(t, env, before, installedGeneratedVerificationTestCallbacks(t, env))
			out := engine.CleanupGenerated(ctx, testID("release reflected original"))
			engine.Close()
			if out.Generated == nil || out.Generated.StateResult != "success" || len(out.Receipt) != 0 ||
				out.Cleanup == nil || !slices.Contains(out.Cleanup.RemainingInboxIDs, original.record.InboxID) ||
				out.Cleanup.RemainingWorkBasis.HeadRevisionID != out.Result.ObservedRevision {
				t.Fatal("lost cleanup result at its selected handoff", out.Result)
			}
			cold := generatedLifecycleReopen(t, ctx, before, store)
			work := mustSelectedGeneratedWork(t, cold)
			release, mapped := work.releases[original.record.AttemptID]
			object, present := store.objects[key]
			state := uint8(0)
			if mapped {
				state = release.release.State
			}
			wantState := uint8(contract.GeneratedReleaseUnknown)
			switch mode {
			case "acknowledged":
				wantState = 0
			case "token-change", "replacement", "no-capability":
				wantState = contract.GeneratedReleasePending
			}
			wantPresent := mode != "acknowledged" && mode != "lost"
			wantDeletes := 1
			if mode == "replacement" || mode == "no-capability" {
				wantDeletes = 0
			}
			if state != wantState || present != wantPresent || store.deletes != wantDeletes || mapped && release.release.SelectedHandoffDigest != contract.Hash(packet) {
				t.Fatalf("release state=%d want=%d physical=%t want=%t conditional calls=%d want=%d", state, wantState, present, wantPresent, store.deletes, wantDeletes)
			}
			if (mode == "token-change" || mode == "replacement") && !bytes.Equal(object.Body, []byte("replacement")) {
				t.Fatal("replacement object changed")
			}
			marks, err := gcMarkSelected(work.image, work, store.Descriptor())
			if err != nil {
				t.Fatal(err)
			}
			_, protected := marks.objects[contract.StoreObjectIdentity{Namespace: contract.StoreResultObject, ObjectID: original.record.InboxID}]
			if protected != mapped {
				t.Fatal("release mapping and exact GC protection differ")
			}
			checkGeneratedReceiptRowsUnchanged(t, before, cold)
			writes := store.cas
			observe := installedGeneratedCleanupTestEngine(t, env, cold, nil)
			empty := observe.CleanupGenerated(ctx, testID("fresh cleanup following release"))
			observe.Close()
			if empty.Result.Outcome != Unchanged || store.cas != writes || store.deletes != wantDeletes || empty.Cleanup == nil ||
				slices.Contains(empty.Cleanup.RemainingInboxIDs, original.record.InboxID) != mapped {
				t.Fatal("fresh zero-work cleanup changed selected release or lost its observation", empty.Result)
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedCleanupRejectsUnauthenticatedFirstOriginalBeforeSigning(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, selected, original, packet := generatedAuthenticatedDeleteHazardFixture(t, false, 1)
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	key, err := format.GeneratedResultKey(store.desc.Prefix, original.record.DomainID, original.record.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	packet = bytes.Clone(packet)
	packet[len(packet)-1] ^= 1
	store.objects[key] = stored{Body: packet, Token: contract.Token{Family: store.desc.Family, Value: `"damaged-original"`}}
	store.creates, store.cas, trust.signs = 0, 0, 0
	before := bytes.Clone(store.objects[store.desc.HeadKey].Body)
	got := installedGeneratedCleanupTestEngine(t, env, selected, installedGeneratedVerificationTestCallbacks(t, env)).CleanupGenerated(ctx, generatedVectorID(247))
	if got.Result.Outcome == ObservedCurrent || store.creates != 0 || store.cas != 0 || trust.signs != 0 ||
		len(got.Receipt) != 0 || !bytes.Equal(before, store.objects[store.desc.HeadKey].Body) {
		t.Fatal("invalid first original authorized signing, mutation or later cleanup", got.Result, store.creates, store.cas, trust.signs)
	}
}

// full_only: false
func TestInstalledGeneratedCleanupUsesOneFencedDeleteTargetAndContinuationCannotExpand(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "unknown")
	retirer := installedGeneratedRetirementEngine(t, ctx, f, selected, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
	parked := retirer.RetireGenerated(ctx, generatedVectorID(241), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
	retirer.Close()
	selected = f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, selected)
	if parked.Generated == nil || parked.Generated.StateResult != "effect-unknown" || len(work.attempts) != 1 {
		t.Fatal("controlled retirement did not produce exact qualified uncertainty", parked)
	}
	var original contract.ID
	for id := range work.attempts {
		original = id
	}
	acceptor := installedGeneratedRetirementEngine(t, ctx, f, selected, nil)
	accepted := acceptor.AcceptGeneratedRetirementRisk(ctx, generatedVectorID(242), GeneratedRetirementRiskRequest{DutyID: current.Generated.RetiringDutyID, AttemptID: original})
	acceptor.Close()
	assertPositiveApplyPreparation(t, accepted)
	if accepted.Result.Outcome != ObservedCurrent {
		t.Fatal("exact qualified risk acceptance", accepted.Result)
	}
	selected = f.open(t, ctx)
	checkInstalledDeleteRequiresAdoption(t, ctx, f, selected, effects, func(engine *InstalledApply) PublicApplyResult {
		return engine.CleanupGenerated(ctx, testID("cleanup without result adoption"))
	})
	callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
	cleaner := installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
	got := cleaner.CleanupGenerated(ctx, generatedVectorID(243))
	cleaner.Close()
	assertPositiveApplyPreparation(t, got)
	creates, deletes := effects()
	if got.Result.Outcome != ObservedCurrent || got.Generated == nil || got.Generated.StateResult != "effect-unknown" || len(got.Receipt) != 0 ||
		len(got.Generated.Effects) != 1 || got.Generated.Effects[0].Record.OperationID != got.OperationID ||
		got.Generated.Effects[0].Target == nil || got.Generated.Effects[0].Target.ResourceDigest != hermeticCloudflareResourceDigest("00000000000000000000000000000001") ||
		creates != 2 || !reflect.DeepEqual(deletes, []string{"00000000000000000000000000000001", "00000000000000000000000000000001"}) {
		t.Fatal("cleanup expanded its one exact owned target or claimed completion", got.Result, got.Generated, creates, deletes)
	}
	if got.Payload != nil {
		t.Error("selected one-target cleanup cleanup emitted TransitionPayload instead of CleanupPayload")
	}
	cold := f.open(t, ctx)
	// A terminal receipt-free operation can only be observed. A new fresh
	// cleanup invocation is required to admit any later provider attempt.
	callbacks.AdmitProducer = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedProducerInput, contract.GeneratorImplementation, time.Time) (*InstalledGeneratedProducerCustody, error) {
		t.Fatal("continuation restored a producer")
		return nil, contract.ErrRecord
	}
	continuation := installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
	continued := continuation.ContinueGeneratedCleanup(ctx, generatedVectorID(244), GeneratedCleanupContinuationRequest{OperationID: got.OperationID})
	continuation.Close()
	ack, verified, possible, present := readApplyPreparation(t, continued)
	if !present || ack != 0 || verified != 0 || possible {
		t.Fatal("observation-only cleanup continuation restored historical preparation", ack, verified, possible, present)
	}
	afterCreates, afterDeletes := effects()
	if continued.Result.Outcome != ObservedCurrent || continued.OperationID != got.OperationID || continued.RequestIdentity != got.RequestIdentity ||
		continued.Generated == nil || continued.Generated.StateResult != "effect-unknown" || len(continued.Receipt) != 0 ||
		afterCreates != creates || !reflect.DeepEqual(afterDeletes, deletes) {
		t.Fatal("continuation changed fixed operation or sent another request", continued.Result, continued.Generated, afterCreates, afterDeletes)
	}
	if continued.Payload != nil {
		t.Error("exact cleanup continuation emitted TransitionPayload")
	}
}

// full_only: false
func TestInstalledGeneratedCleanupRecordsProviderIdentityConflict(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, cold, current, effects := installedGeneratedRetirementFixture(t, ctx, "cleanup-identity-conflict")
	callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
	engine := installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
	parked := engine.RetireGenerated(ctx, testID("first uncertain retirement"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
	engine.Close()
	if parked.Generated == nil || len(parked.Generated.Effects) != 1 {
		t.Fatal("missing retirement attempt", parked.Result)
	}
	engine = installedGeneratedRetirementEngine(t, ctx, f, f.open(t, ctx), nil)
	accepted := engine.AcceptGeneratedRetirementRisk(ctx, testID("transfer exact retirement"), GeneratedRetirementRiskRequest{DutyID: current.Generated.RetiringDutyID, AttemptID: parked.Generated.Effects[0].Record.AttemptID})
	engine.Close()
	if accepted.Result.Outcome != ObservedCurrent {
		t.Fatal("transfer exact retirement", accepted.Result)
	}
	before := f.open(t, ctx)
	_, beforeHealthy := observeCurrentValueEntry(t, before, "healthy")
	selected, present, err := before.readGeneratedCleanup(ctx)
	if err != nil || !present || selected.kind != generatedCleanupHazard {
		t.Fatal("missing eligible owner", err)
	}
	var returnedFacts []byte
	admit := callbacks.AdmitProducer
	callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedProducerInput, impl contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
		owner, err := admit(ctx, q, control, input, impl, deadline)
		if err != nil {
			return nil, err
		}
		invoke := owner.InvokeProducer
		owner.InvokeProducer = func(ctx context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
			result := invoke(ctx, locator, authority)
			if len(returnedFacts) != 0 || len(result.Facts.ProviderFacts) == 0 || len(result.Record) != 0 {
				t.Fatal("expected one native provider reply with safe facts only")
			}
			returnedFacts, err = contract.EncodeGeneratorSafeFacts(result.Facts)
			if err != nil {
				t.Fatal(err)
			}
			return result
		}
		return owner, nil
	}
	engine = installedGeneratedRetirementEngine(t, ctx, f, before, callbacks)
	got := engine.CleanupGenerated(ctx, testID("record native cleanup conflict"))
	engine.Close()
	if got.Result.Outcome != ObservedCurrent || got.Generated == nil || len(got.Generated.Effects) != 1 ||
		got.Generated.Effects[0].Reason != contract.GeneratorReasonIdentityConflict || got.Cleanup == nil ||
		got.Generated.StateResult != "effect-unknown" || len(got.Receipt) != 0 {
		t.Fatal("selected cleanup did not report the provider conflict", got.Result.Outcome, got.Result.Reason)
	}
	original := got.Generated.Effects[0]
	cold = f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, cold)
	if work.parent != nil || work.phase != nil || !work.hasRecord(selected.sourceKey()) || original.Target == nil || *original.Target != selected.target {
		t.Fatal("cold selection lost conflict owner or retained active cleanup")
	}
	if _, present, result := cold.ReadGeneratedResult(ctx, original.Record.AttemptID); present || result.Outcome != 0 {
		t.Fatal("unexpected protected result", result)
	}
	rows, err := work.vectors.resolve(contract.GeneratedAttemptSupportKind, original.Record.AttemptID, contract.GeneratorVectorFacts, original.Record.Facts)
	if err != nil || len(rows) != 1 {
		t.Fatal("missing selected provider reply", err)
	}
	fact, err := contract.InspectGeneratorFactsRow(rows[0])
	if err != nil || fact.ResultID != original.Record.ResultID || !bytes.Equal(fact.Facts, returnedFacts) {
		t.Fatal("the reopened reply differs from the native provider facts", err)
	}
	checkGeneratedReceiptRowsUnchanged(t, before, cold)
	engine = installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
	observed := engine.ContinueGeneratedCleanup(ctx, testID("observe conflict"), GeneratedCleanupContinuationRequest{OperationID: got.OperationID})
	engine.Close()
	if observed.Generated == nil || len(observed.Generated.Effects) != 1 || observed.Generated.Effects[0].Reason != contract.GeneratorReasonIdentityConflict ||
		observed.Generated.Effects[0].Record.AttemptID != original.Record.AttemptID || observed.Generated.StateResult != "effect-unknown" {
		t.Fatal("continuation lost the recorded reason", observed.Result)
	}
	engine = installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
	fresh := engine.CleanupGenerated(ctx, testID("fresh cleanup after conflict"))
	engine.Close()
	if fresh.Result.Outcome != IntegrityFailure || fresh.Result.Reason != InvalidRelation || !bytes.Equal(f.open(t, ctx).body, cold.body) {
		t.Fatal("fresh cleanup changed state", fresh.Result)
	}
	input := installedGeneratedRetirementEntries(f.env.GeneratedProcess, cold.admission.recipient, 1, "updated healthy sibling")
	engine = installedGeneratedTestEngine(t, ctx, f, cold, input, currentApplyRecipients(cold.registry()), callbacks)
	changed := engine.Apply(ctx, testID("edit healthy sibling after cleanup conflict"), input)
	engine.Close()
	if changed.Result.Outcome != ObservedCurrent {
		t.Fatal("unrelated supplied update remained blocked", changed.Result)
	}
	after := f.open(t, ctx)
	surviving := mustSelectedGeneratedWork(t, after)
	_, afterHealthy := observeCurrentValueEntry(t, after, "healthy")
	if reflect.DeepEqual(beforeHealthy, afterHealthy) || cold.head.Core.Revision == after.head.Core.Revision {
		t.Fatal("unrelated change did not select a new healthy entry")
	}
	if !bytes.Equal(work.records[selected.sourceKey()].Body, surviving.records[selected.sourceKey()].Body) || surviving.attempts[original.Record.AttemptID].record != original.Record {
		t.Fatal("unrelated update lost the hazard")
	}
	creates, deletes := effects()
	t.Logf("predecessor=%x recorded=%x independent_update=%x retained_hazard=%x creates=%d deletes=%d", before.head.Core.Revision, cold.head.Core.Revision, after.head.Core.Revision, selected.sourceKey().id, creates, len(deletes))
	if creates != 2 || !slices.Equal(deletes, []string{"00000000000000000000000000000001", "00000000000000000000000000000001"}) {
		t.Fatal("unexpected native requests", creates, deletes)
	}
}

// full_only: false
func TestInstalledManagedCreateKeepsCleanupTargetAfterValueEncodingRefusal(t *testing.T) {
	t.Run("successful sibling stays unselected", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		process, counts := installedGeneratedRetirementProcess(t, "acknowledged")
		f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
		f.env.GeneratedProcess = process
		entries := installedGeneratedRetirementEntries(process, f.selected.admission.recipient, 0, "proposed sibling")
		sibling := entries[0]
		sibling.Name = "sibling"
		entries[0].InputEncoding = contract.InputEncodingBase64
		entries = append(entries, sibling)
		callbacks := installedGeneratedRetirementCallbacks(t, f, process)
		engine := installedGeneratedTestEngine(t, ctx, f, f.selected, entries, currentApplyRecipients(f.selected.registry()), callbacks)
		got := engine.Apply(ctx, testID("mixed encoding results"), entries)
		engine.Close()
		cold := f.open(t, ctx)
		creates, deletes := counts()
		if creates != 2 || len(deletes) != 0 || got.Generated == nil || got.Generated.StateResult != "effect-terminal-failure" || len(got.Generated.Duties) != 1 || len(got.Generated.Hazards) != 1 ||
			!cold.root.Generated.ActiveOwner.IsZero() || cold.root.Generated.GeneratedCurrent != 0 || !reflect.DeepEqual(cold.root.Names, f.selected.root.Names) {
			t.Fatal("mixed result changed the predecessor or lost a cleanup obligation", got.Result, creates, deletes)
		}
		success, failure := got.Generated.Duties[0].Target, got.Generated.Hazards[0].Target
		if success == nil || failure == nil || success.Name != sibling.Name || failure.Name != entries[0].Name || success.ResourceDigest == failure.ResourceDigest ||
			got.Generated.Duties[0].Record.Kind != contract.GeneratedDutyUnselectedCleanup {
			t.Fatal("mixed result lost the distinct cleanup targets")
		}
	})
	for _, tc := range []struct {
		name                                       string
		encoding                                   uint8
		pauseBeforeFinal, replacement, validBase64 bool
	}{
		{name: "raw", encoding: contract.InputEncodingRaw},
		{name: "valid-base64", encoding: contract.InputEncodingBase64, validBase64: true},
		{name: "strict-base64", encoding: contract.InputEncodingBase64},
		{name: "restart-before-final", encoding: contract.InputEncodingBase64, pauseBeforeFinal: true},
		{name: "rejection-after-explicit-replacement", encoding: contract.InputEncodingBase64, replacement: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			mode, wantCreates := "acknowledged", 1
			if tc.validBase64 {
				mode = "valid-base64"
			}
			if tc.replacement {
				mode, wantCreates = "first-create-unknown", 2
			}
			token := fmt.Sprintf("%032x", wantCreates)
			process, counts := installedGeneratedRetirementProcess(t, mode)
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
			f.env.GeneratedProcess = process
			entries := installedGeneratedRetirementEntries(process, f.selected.admission.recipient, 0, "healthy")
			entries[0].InputEncoding = tc.encoding
			callbacks := installedGeneratedRetirementCallbacks(t, f, process)
			admitFinal := callbacks.AdmitFinal
			if tc.pauseBeforeFinal {
				callbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
					return nil, contract.ErrRecord
				}
			}
			engine := installedGeneratedTestEngine(t, ctx, f, f.selected, entries, currentApplyRecipients(f.selected.registry()), callbacks)
			result := engine.Apply(ctx, testID("create with declared "+tc.name), entries)
			engine.Close()
			cold := f.open(t, ctx)
			if tc.replacement {
				creates, deletes := counts()
				if result.Generated == nil || result.Generated.StateResult != "effect-unknown" || creates != 1 || len(deletes) != 0 || !cold.root.Generated.ActiveOwner.IsZero() {
					t.Fatal("uncertain first CREATE did not finish without replacement", result.Result, creates, deletes)
				}
				firstID := result.OperationID
				engine = installedGeneratedTestEngine(t, ctx, f, cold, entries, currentApplyRecipients(cold.registry()), callbacks)
				result = engine.Apply(ctx, testID("explicit replacement after uncertain CREATE"), entries)
				engine.Close()
				cold = f.open(t, ctx)
				if firstID == result.OperationID {
					t.Fatal("replacement reused the original operation")
				}
			}
			if tc.encoding == contract.InputEncodingRaw || tc.validBase64 {
				creates, deletes := counts()
				if result.Result.Outcome != ObservedCurrent || creates != 1 || len(deletes) != 0 || cold.root.Generated.GeneratedCurrent != 1 {
					t.Fatalf("raw adoption: outcome=%v creates=%d deletes=%d current=%d", result.Result.Outcome, creates, len(deletes), cold.root.Generated.GeneratedCurrent)
				}
				_, entry := observeCurrentValueEntry(t, cold, "generated")
				if generatedEntryProviderToken(t, cold, entry) != token {
					t.Fatal("wrong adopted resource")
				}
				work := mustSelectedGeneratedWork(t, cold)
				row := work.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID}]
				evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				facts, err := contract.DecodeGeneratorSafeFacts(evidence.SafeFacts)
				if err != nil || facts.Disposition != contract.GeneratorDispositionCompleteCreate {
					t.Fatal("missing original complete-create evidence")
				}
				_, body, err := callbacks.CheckRetirementCompatibility(ctx, process.Implementation, process.Intent, facts, contract.GeneratedCompletionAcknowledged)
				if err != nil {
					t.Fatal("original compatibility exchange", err)
				}
				checked, err := protocol.DecodeValidationResponse(body)
				if err != nil || !checked.Accepted {
					t.Fatal("original provider facts did not qualify for cleanup", err)
				}
				facts.Disposition, facts.Reason = contract.GeneratorDispositionOwnedUnusableCreate, contract.GeneratorReasonInvalidValue
				_, _, err = callbacks.CheckRetirementCompatibility(ctx, process.Implementation, process.Intent, facts, contract.GeneratedCompletionAcknowledged)
				if !errors.Is(err, generatorhost.ErrPassiveRefused) {
					t.Fatal("expected a correlated native refusal for changed original facts", err)
				}
				return
			}
			afterApply, _ := counts()
			if tc.pauseBeforeFinal {
				work := mustSelectedGeneratedWork(t, cold)
				if cold.root.Generated.ActiveOwner.IsZero() || len(work.attempts) != 1 || afterApply != 1 {
					t.Fatal("expected a recorded rejection before Final")
				}
				for _, a := range work.attempts {
					packet, err := contract.InspectGeneratedResultRecord(a.result)
					if err != nil || a.record.State != contract.GeneratedEffectFailedTerminal || packet.Core.Schema != contract.GeneratedResultEncodingFailureSchema {
						t.Fatal("cold checkpoint lost the original rejection", err)
					}
				}
				callbacks.AdmitFinal = admitFinal
			}
			// The fixture bearer is valid for the provider and contains an underscore,
			// which is outside the declared standard Base64 alphabet.
			if !cold.root.Generated.ActiveOwner.IsZero() {
				engine = installedGeneratedTestEngine(t, ctx, f, cold, entries, currentApplyRecipients(cold.registry()), callbacks)
				result = engine.Continue(ctx, testID("continue the recorded create"), result.OperationID)
				engine.Close()
				cold = f.open(t, ctx)
			}
			selected, present, err := cold.readGeneratedCleanup(ctx)
			creates, deletes := counts()
			if err != nil || !present || selected.kind != generatedCleanupHazard || selected.target.ResourceDigest != hermeticCloudflareResourceDigest(token) ||
				!cold.root.Generated.ActiveOwner.IsZero() || cold.root.Generated.GeneratedCurrent != 0 || creates != wantCreates || len(deletes) != 0 {
				t.Fatalf("expected one created resource and its exact cleanup target after reopen: predecessor=%x selected=%x creates_after_apply=%d creates_total=%d deletes=%d active=%t hazards=%d target_available=%t cleanup_read_error=%t current=%d",
					f.selected.head.Core.Revision, cold.head.Core.Revision, afterApply, creates, len(deletes), !cold.root.Generated.ActiveOwner.IsZero(), cold.root.Generated.Hazards, present, err != nil, cold.root.Generated.GeneratedCurrent)
			}
			if result.Generated == nil || result.Generated.StateResult != "effect-terminal-failure" || !slices.ContainsFunc(result.Generated.Effects, func(f GeneratedEffectFact) bool {
				return f.Reason == GeneratedReasonValueEncoding && f.Record.AttemptID == selected.hazard.OriginalAttemptID && f.Record.State == contract.GeneratedEffectFailedTerminal
			}) {
				t.Fatal("encoding refusal did not preserve the original failed attempt")
			}
			var checkConflict func(PublicApplyResult)
			if tc.pauseBeforeFinal {
				checkConflict = conflictInstalledDeleteReadback(t, &f, callbacks)
			}
			cleaner := installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
			cleaned := cleaner.CleanupGenerated(ctx, testID("clean the unusable generated value"))
			cleaner.Close()
			if checkConflict != nil {
				checkConflict(cleaned)
				cold = f.open(t, ctx)
				if cold.root.Generated.ActiveOwner != cleaned.OperationID {
					t.Fatal("conflict lost selected cleanup")
				}
				resumed := installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
				cleaned = resumed.ContinueGeneratedCleanup(ctx, testID("resume cleanup after Store conflict"), GeneratedCleanupContinuationRequest{OperationID: cleaned.OperationID})
				resumed.Close()
			}
			creates, deletes = counts()
			if cleaned.Generated == nil || cleaned.Generated.StateResult != "success" || creates != wantCreates || !slices.Equal(deletes, []string{token}) || int(f.open(t, ctx).root.Generated.Hazards) != wantCreates-1 {
				t.Fatalf("cleanup did not complete for the exact created resource: creates=%d deletes=%d outcome=%v", creates, len(deletes), cleaned.Result.Outcome)
			}
		})
	}
}

// full_only: false
func TestInstalledCleanupKeepsSealedReturnAfterCallerCancellation(t *testing.T) {
	for _, mode := range []string{"saved", "expired", "offline", "no-issued-deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
			f.env.GeneratedProcess = process
			entries := installedGeneratedRetirementEntries(process, f.selected.admission.recipient, 0, "healthy")
			entries[0].InputEncoding = contract.InputEncodingBase64
			callbacks := installedGeneratedRetirementCallbacks(t, f, process)
			engine := installedGeneratedTestEngine(t, ctx, f, f.selected, entries, currentApplyRecipients(f.selected.registry()), callbacks)
			applied := engine.Apply(ctx, testID("create cleanup hazard"), entries)
			engine.Close()
			if applied.Generated == nil || applied.Generated.StateResult != "effect-terminal-failure" {
				t.Fatal("missing selected cleanup target", applied.Result)
			}
			selected := f.open(t, ctx)
			cleanCtx, stop := context.WithCancel(ctx)
			defer stop()
			var packet []byte
			var attempt contract.ID
			var inbox string
			var writes int
			var issued uint64
			base := requireAdmittedMemoryStore(t, f.env.Store)
			proxy := &applyPreparationTestStore{Store: base, memory: base, read: base.Read}
			proxy.create = func(c context.Context, key string, b []byte) contract.WriteResult {
				if key == inbox {
					writes++
					if mode == "offline" {
						limit, ok := c.Deadline()
						if !ok || limit.UnixMilli() != int64(issued) {
							t.Fatal("Store did not retain issued deadline")
						}
						<-c.Done()
						return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
					}
				}
				return base.Create(c, key, b)
			}
			f.env.Store = proxy
			admit := callbacks.AdmitProducer
			callbacks.AdmitProducer = func(c context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, impl contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				owner, err := admit(c, q, control, in, impl, deadline)
				if err != nil {
					return nil, err
				}
				if in.Expected.Template.Action != contract.GeneratorActionDelete {
					t.Fatal("unexpected producer")
				}
				attempt = in.Expected.Template.AttemptID
				inbox, err = format.GeneratedResultKey(base.desc.Prefix, f.env.Domain, in.Expected.Template.InboxID)
				if err != nil {
					t.Fatal(err)
				}
				invoke := owner.InvokeProducer
				owner.InvokeProducer = func(c context.Context, loc, authority contract.ID) contract.GeneratedProducerResult {
					r := invoke(c, loc, authority)
					if r.Code != contract.CryptoSuccess || len(r.Record) == 0 {
						t.Fatal("missing sealed delete reply")
					}
					packet = bytes.Clone(r.Record)
					if r.ResultDeadlineUnixMillis == 0 {
						t.Fatal("managed return lacks issued deadline")
					}
					switch mode {
					case "expired":
						r.ResultDeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
					case "offline":
						r.ResultDeadlineUnixMillis = uint64(time.Now().Add(300 * time.Millisecond).UnixMilli())
					case "no-issued-deadline":
						r.ResultDeadlineUnixMillis = 0
					}
					issued = r.ResultDeadlineUnixMillis
					if mode != "expired" {
						stop()
					}
					return r
				}
				return owner, nil
			}
			cleaner := installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
			ended, end := context.WithCancel(ctx)
			end()
			before := cleaner.CleanupGenerated(ended, testID("cancel before cleanup launch"))
			_, deletes := effects()
			if len(deletes) != 0 || before.Result.Outcome != AdmissionRefused || !bytes.Equal(f.open(t, ctx).body, selected.body) {
				t.Fatal("early cancellation admitted cleanup")
			}
			out := cleaner.CleanupGenerated(cleanCtx, testID("cancel after sealed delete"))
			cleaner.Close()
			cold := f.open(t, ctx)
			if len(packet) == 0 || out.OperationID.IsZero() || cold.root.Generated.ActiveOwner != out.OperationID {
				t.Fatal("lost selected cleanup or its exact return")
			}
			stored, found, failure := cold.readGeneratedResult(ctx, attempt)
			wantSaved := mode == "saved"
			wantWrites := 0
			if wantSaved || mode == "offline" {
				wantWrites = 1
			}
			if writes != wantWrites || failure.Outcome != 0 || found != wantSaved || (found && !bytes.Equal(stored, packet)) {
				t.Fatalf("sealed inbox writes=%d want=%d present=%t want=%t read=%v", writes, wantWrites, found, wantSaved, failure.Outcome)
			}
			callbacks = installedGeneratedRetirementCallbacks(t, f, process)
			callbacks.AdmitProducer = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedProducerInput, contract.GeneratorImplementation, time.Time) (*InstalledGeneratedProducerCustody, error) {
				t.Fatal("cold cleanup attempted to dispatch again")
				return nil, contract.ErrRecord
			}
			next := installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
			done := next.ContinueGeneratedCleanup(ctx, testID("continue original cancelled cleanup"), GeneratedCleanupContinuationRequest{OperationID: out.OperationID})
			next.Close()
			creates, deletes := effects()
			if done.OperationID != out.OperationID || creates != 1 || len(deletes) != 1 || done.Generated == nil {
				t.Fatal("lost original cleanup identity", creates, len(deletes))
			}
			if !wantSaved {
				after := f.open(t, ctx)
				original := mustSelectedGeneratedWork(t, after).attempts[attempt]
				if done.Generated.StateResult == "success" || !bytes.Equal(after.body, cold.body) ||
					original.record.AttemptID != attempt || original.record.State != contract.GeneratedEffectTransmitted || len(original.result) != 0 {
					t.Fatal("missing inbox changed the exact transmitted cleanup attempt")
				}
				return
			}
			if done.Generated.StateResult != "success" || !f.open(t, ctx).root.Generated.ActiveOwner.IsZero() {
				t.Fatal("cold cleanup failed to close exact original result", done.Result, creates, len(deletes))
			}
		})
	}
}
