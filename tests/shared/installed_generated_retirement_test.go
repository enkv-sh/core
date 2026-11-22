package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"reflect"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func installedGeneratedRetirementProcess(t testing.TB, mode string) (*generatedProcessFixture, func() (int, []string)) {
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
			if creates == 1 && mode == "first-create-unknown" || creates == 2 && (mode == "create-hazard-acknowledged" || mode == "create-hazard-unknown") {
				if _, err := w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{}}`)); err != nil {
					t.Error("controlled ambiguous generated create response failed")
				}
				return
			}
			value := hermeticCloudflareSecret
			if mode == "valid-base64" {
				value = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
			}
			_, err := fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%032x","value":"%s","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`, creates, value, hermeticCloudflarePermission, hermeticCloudflareAccount)
			if err != nil {
				t.Error("controlled generated create response failed")
			}
		case http.MethodDelete:
			token := path.Base(request.URL.Path)
			deletes = append(deletes, token)
			if mode == "cleanup-identity-conflict" && len(deletes) == 1 || mode == "unknown" || mode == "create-hazard-unknown" || mode == "repeated-unknown" || mode == "earlier-identity-conflict" && len(deletes) > 1 {
				_, err := w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{}}`))
				if err != nil {
					t.Error("controlled ambiguous retirement response failed")
				}
				return
			}
			if mode == "identity-conflict" || mode == "earlier-identity-conflict" || mode == "cleanup-identity-conflict" {
				token = "ffffffffffffffffffffffffffffffff"
			}
			if _, err := fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, token); err != nil {
				t.Error("controlled retirement acknowledgement failed")
			}
		default:
			t.Error("unexpected controlled generated request method")
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	origin := server.URL + "/client/v4"
	artifact, implementation := buildHermeticCloudflareGenerator(t, origin)
	intent, request := hermeticCloudflareIntent()
	process := &generatedProcessFixture{Artifact: artifact, Implementation: implementation, Intent: intent,
		RequestDigest: hermeticCloudflareHTTPRequestDigest(request), Configure: func(tb testing.TB, artifact string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
			return hermeticCloudflareConfig(tb, artifact, origin, implementation, expected)
		}}
	return process, func() (int, []string) {
		mu.Lock()
		defer mu.Unlock()
		return creates, append([]string(nil), deletes...)
	}
}

func installedGeneratedRetirementCallbacks(t testing.TB, f installedApplyTestFixture, process *generatedProcessFixture) *GeneratedApplyInstallation {
	t.Helper()
	callbacks := installedGeneratedTestCallbacks(t, f, process)
	create := callbacks.RequestDigest
	callbacks.RequestDigest = func(ctx context.Context, row contract.GeneratorImplementation, action uint8, intent []byte, target *contract.GeneratorTarget) (contract.ID, error) {
		if action == contract.GeneratorActionCreate {
			return create(ctx, row, action, intent, target)
		}
		if ctx.Err() != nil || !reflect.DeepEqual(row, process.Implementation) || target == nil || action != contract.GeneratorActionDelete ||
			target.ResourceContractID != hermeticCloudflareResourceContractID() || !bytes.Equal(intent, process.Intent) {
			return contract.ID{}, contract.ErrRecord
		}
		return generatedRetirementRequestDigest(*target), nil
	}
	return callbacks
}

func installedGeneratedRetirementEntries(process *generatedProcessFixture, recipient contract.ID, epoch uint64, healthy string) []ApplyEntryInput {
	meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: epoch, RetirementMode: contract.GeneratedRetirementManual,
		ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
	return []ApplyEntryInput{{Name: "generated", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret,
		Recipients: []contract.ID{recipient}, Generated: &meta},
		{Name: "healthy", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
			Recipients: []contract.ID{recipient}, InputBytes: []byte(healthy)}}
}

func installedGeneratedRetirementFixture(t testing.TB, ctx context.Context, mode string) (installedApplyTestFixture, *StateSession, contract.ValueEntry, func() (int, []string)) {
	t.Helper()
	process, effects := installedGeneratedRetirementProcess(t, mode)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
	f.env.GeneratedProcess = process
	selected := f.selected
	for epoch := uint64(0); epoch < 2; epoch++ {
		input := installedGeneratedRetirementEntries(process, selected.admission.recipient, epoch, "retained healthy sibling")
		engine := installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
		result := engine.Apply(ctx, testID(fmt.Sprintf("installed retirement generation %d", epoch)), input)
		engine.Close()
		if result.Result.Outcome != ObservedCurrent {
			t.Fatal("public generated retirement fixture failed", epoch, result.Result)
		}
		selected = f.open(t, ctx)
	}
	_, current := observeCurrentValueEntry(t, selected, "generated")
	creates, deletes := effects()
	if creates != 2 || len(deletes) != 0 || current.Generated.RetiringDutyPresent != 1 {
		t.Fatal("public rotation did not retain one exact manual old Duty", creates, deletes)
	}
	return f, selected, current, effects
}

func installedGeneratedRetirementEngine(t testing.TB, ctx context.Context, f installedApplyTestFixture, selected *StateSession, callbacks *GeneratedApplyInstallation) *InstalledApply {
	t.Helper()
	// This unrelated local proposal must never replace accepted retirement work.
	input := []ApplyEntryInput{{Name: "local-edit", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
		Recipients: []contract.ID{selected.admission.recipient}, InputBytes: []byte("unapplied local edit")}}
	return installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), callbacks)
}

func checkInstalledDeleteRequiresAdoption(t *testing.T, ctx context.Context, f installedApplyTestFixture, selected *StateSession, effects func() (int, []string), run func(*InstalledApply) PublicApplyResult) {
	t.Helper()
	callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
	callbacks.AdmitAdoption = nil
	reservations := 0
	callbacks.AdmitReservation = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedReservationInput, time.Time) (*InstalledGeneratedCustody, error) {
		reservations++
		return nil, contract.ErrRecord
	}
	store := requireAdmittedMemoryStore(t, f.env.Store)
	trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
	if !ok {
		t.Fatal("missing admitted trust observer")
	}
	beforeHEAD := bytes.Clone(store.objects[store.desc.HeadKey].Body)
	beforeCreates, beforeCAS, beforeSigns := store.creates, store.cas, trust.signs
	beforeCalls, beforeDeletes := effects()
	engine := installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
	out := run(engine)
	engine.Close()
	afterCalls, afterDeletes := effects()
	if out.Result != refused(AdmissionInvalid) || out.Generated != nil || out.Cleanup != nil || len(out.Receipt) != 0 ||
		reservations != 0 || store.creates != beforeCreates || store.cas != beforeCAS || trust.signs != beforeSigns ||
		beforeCalls != afterCalls || !reflect.DeepEqual(beforeDeletes, afterDeletes) || !bytes.Equal(store.objects[store.desc.HeadKey].Body, beforeHEAD) {
		t.Fatal("missing adoption reached deletion admission or changed selected state", out.Result, reservations, store.creates-beforeCreates, store.cas-beforeCAS)
	}
}

// full_only: false
func TestInstalledGeneratedRetirementAcknowledgesOnlyExactOldTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "acknowledged")
	checkInstalledDeleteRequiresAdoption(t, ctx, f, selected, effects, func(engine *InstalledApply) PublicApplyResult {
		return engine.RetireGenerated(ctx, testID("retirement without result adoption"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
	})
	callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
	engine := installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
	result := engine.RetireGenerated(ctx, testID("exact old generated retirement"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
	engine.Close()
	creates, deletes := effects()
	if result.Result.Outcome != ObservedCurrent || result.Generated == nil || result.Generated.OperationKind != contract.OperationRetireGeneratedGeneration ||
		result.Generated.StateResult != "success" || result.Generated.EvidenceCeiling != contract.ReceiptEvidenceAcknowledged ||
		!result.Generated.Warnings.InvalidationNotConfirmed || len(result.Generated.Effects) != 1 || len(result.Generated.RelatedDutyIDs) != 0 ||
		creates != 2 || !reflect.DeepEqual(deletes, []string{"00000000000000000000000000000001"}) {
		t.Fatal("retirement changed target, class or result", result, creates, deletes)
	}
	closed := f.open(t, ctx)
	_, after := observeCurrentValueEntry(t, closed, "generated")
	expected := current
	expected.Generated.RetiringDutyPresent, expected.Generated.RetiringDutyID = 0, contract.ID{}
	if !reflect.DeepEqual(after, expected) || closed.root.Generated.Retiring != 0 || closed.root.Generated.GeneratedCurrent != 1 {
		t.Fatal("retirement replaced or removed its current successor")
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.OperationKind != contract.OperationRetireGeneratedGeneration || receipt.OperationID != result.OperationID ||
		receipt.EvidenceCeiling != contract.ReceiptEvidenceAcknowledged || receipt.WarningBits&contract.ReceiptWarningInvalidationNotConfirmed == 0 {
		t.Fatal("retirement receipt lost its acknowledgement ceiling", err, receipt)
	}
	wrongKind := installedGeneratedRetirementEngine(t, ctx, f, closed, nil)
	wrong := wrongKind.ContinueGeneratedRetirement(ctx, testID("wrong-kind retirement continuation"), GeneratedRetirementContinuationRequest{OperationID: current.Generated.OriginOperationID})
	wrongKind.Close()
	if wrong.Result.Outcome != AdmissionRefused || len(wrong.Receipt) != 0 {
		t.Fatal("an apply receipt became retirement continuation", wrong)
	}
	f.keys.SetDenied(closed.admission.recipient, true)
	public, private := f.keys.Calls()
	observer := installedGeneratedRetirementEngine(t, ctx, f, closed, nil)
	observed := observer.ContinueGeneratedRetirement(ctx, testID("exact old terminal retirement receipt"), GeneratedRetirementContinuationRequest{OperationID: result.OperationID})
	observer.Close()
	if observed.Result.Outcome != ObservedCurrent || observed.Generated == nil || !observed.Generated.ReceiptObservation ||
		observed.Generated.StateResult != "success" || !bytes.Equal(observed.Receipt, result.Receipt) {
		t.Fatal("terminal continuation did not return the original exact receipt", observed)
	}
	if p, q := f.keys.Calls(); p != public || q != private {
		t.Fatal("terminal receipt observation used a KMS route")
	}
	_, laterDeletes := effects()
	if !reflect.DeepEqual(laterDeletes, deletes) {
		t.Fatal("terminal continuation sent another delete", laterDeletes)
	}
}

// full_only: false
func TestInstalledGeneratedRetirementContinuesLateOriginalWithoutAnotherSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "acknowledged")
	callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
	callbacks.AdmitAdoption = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedAdoptionInput, time.Time) (*InstalledGeneratedCustody, error) {
		return nil, contract.ErrRecord
	}
	first := installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
	stopped := first.RetireGenerated(ctx, testID("retirement stop before original adoption"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
	first.Close()
	assertPositiveApplyPreparation(t, stopped)
	if stopped.Payload != nil || stopped.Generated == nil || len(stopped.Generated.Effects) != 1 ||
		stopped.Generated.Effects[0].Record.State != contract.GeneratedEffectTransmitted ||
		stopped.Generated.Effects[0].DutyID != current.Generated.RetiringDutyID {
		t.Fatal("nonterminal retirement published a transition or lost its actual Attempt", stopped)
	}
	cold := f.open(t, ctx)
	if stopped.OperationID.IsZero() || cold.root.Generated.ActiveOwner != stopped.OperationID {
		t.Fatal("interrupted retirement lost exact accepted operation", stopped.Result)
	}
	work := mustSelectedGeneratedWork(t, cold)
	refuser := installedGeneratedRetirementEngine(t, ctx, f, cold, nil)
	risk := refuser.AcceptGeneratedRetirementRisk(ctx, testID("active retirement without qualified ambiguity"), GeneratedRetirementRiskRequest{
		DutyID: current.Generated.RetiringDutyID, AttemptID: work.phase.FrontierAttemptID})
	refuser.Close()
	if risk.Result.Outcome != AdmissionRefused || len(risk.Receipt) != 0 {
		t.Fatal("transmitted state alone became qualified retirement ambiguity", risk)
	}
	callbacks = installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
	callbacks.AdmitProducer = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedProducerInput, contract.GeneratorImplementation, time.Time) (*InstalledGeneratedProducerCustody, error) {
		t.Fatal("cold retirement restored a producer")
		return nil, contract.ErrRecord
	}
	resumed := installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
	result := resumed.ContinueGeneratedRetirement(ctx, testID("cold retirement exact original"), GeneratedRetirementContinuationRequest{OperationID: stopped.OperationID})
	resumed.Close()
	assertPositiveApplyPreparation(t, result)
	creates, deletes := effects()
	if result.Result.Outcome != ObservedCurrent || result.Generated == nil || result.Generated.StateResult != "success" || result.OperationID != stopped.OperationID ||
		creates != 2 || !reflect.DeepEqual(deletes, []string{"00000000000000000000000000000001"}) {
		t.Fatal("cold retirement did not close only its original target", result, creates, deletes)
	}
}

// full_only: false
func TestInstalledGeneratedRetirementRiskRequiresExactQualifiedAmbiguity(t *testing.T) {
	for _, mode := range []string{"unknown", "identity-conflict", "repeated-unknown", "earlier-identity-conflict"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, mode)
			engine := installedGeneratedRetirementEngine(t, ctx, f, selected, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
			parked := engine.RetireGenerated(ctx, testID(mode+" ambiguous retirement"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
			engine.Close()
			cold := f.open(t, ctx)
			work := mustSelectedGeneratedWork(t, cold)
			if parked.Generated == nil || parked.Generated.StateResult != "effect-unknown" || work.parent != nil || len(work.attempts) != 1 || cold.root.Generated.Retiring != 1 {
				t.Fatal("unknown retirement did not retain its exact obligation", parked)
			}
			var attempt contract.ID
			for id := range work.attempts {
				attempt = id
			}
			firstAttempt := attempt
			if mode == "repeated-unknown" || mode == "earlier-identity-conflict" {
				retry := installedGeneratedRetirementEngine(t, ctx, f, cold, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
				second := retry.RetireGenerated(ctx, testID(mode+" explicit fresh retirement"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
				retry.Close()
				if mode == "earlier-identity-conflict" {
					_, deletes := effects()
					if second.Result.Outcome != AdmissionRefused || second.Payload != nil || len(second.Receipt) != 0 || len(deletes) != 1 {
						t.Fatal("fresh retirement ignored an earlier identity conflict", second.Result, deletes)
					}
				} else {
					if second.Generated == nil || second.Generated.StateResult != "effect-unknown" {
						t.Fatal("fresh explicit retirement did not preserve its second unknown", second)
					}
					cold = f.open(t, ctx)
					work = mustSelectedGeneratedWork(t, cold)
					if len(work.attempts) != 2 {
						t.Fatal("fresh retirement erased its prior invocation")
					}
					for id := range work.attempts {
						if id != firstAttempt {
							attempt = id
						}
					}
				}
			}
			duty, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{contract.GeneratedDutySupportKind, current.Generated.RetiringDutyID}].Body)
			if err != nil {
				t.Fatal(err)
			}
			history, err := work.vectors.resolve(contract.GeneratedDutySupportKind, duty.DutyID, contract.GeneratorVectorHistory, duty.History)
			if err != nil || len(history) != len(work.attempts) {
				t.Fatal("retirement history does not retain every invocation", err)
			}
			_, healthy := observeCurrentValueEntry(t, cold, "healthy")
			creates, deletes := effects()
			f.keys.SetDenied(cold.admission.recipient, true)
			public, private := f.keys.Calls()
			request := GeneratedRetirementRiskRequest{DutyID: current.Generated.RetiringDutyID, AttemptID: attempt}
			for _, damage := range []string{"wrong-duty", "wrong-attempt", "stale-attempt"} {
				if damage == "stale-attempt" && firstAttempt == attempt {
					continue
				}
				wrong := request
				switch damage {
				case "wrong-duty":
					wrong.DutyID = testID("unrelated retirement Duty")
				case "stale-attempt":
					wrong.AttemptID = firstAttempt
				default:
					wrong.AttemptID = testID("unrelated retirement Attempt")
				}
				refuser := installedGeneratedRetirementEngine(t, ctx, f, cold, nil)
				out := refuser.AcceptGeneratedRetirementRisk(ctx, testID(damage), wrong)
				refuser.Close()
				if out.Result.Outcome != AdmissionRefused || len(out.Receipt) != 0 {
					t.Fatal("mismatched risk selector was accepted", out)
				}
			}
			acceptor := installedGeneratedRetirementEngine(t, ctx, f, cold, nil)
			accepted := acceptor.AcceptGeneratedRetirementRisk(ctx, testID(mode+" exact risk acceptance"), request)
			acceptor.Close()
			if mode == "identity-conflict" || mode == "earlier-identity-conflict" {
				if accepted.Result.Outcome != AdmissionRefused || len(accepted.Receipt) != 0 {
					t.Fatal("identity conflict became accepted risk", accepted)
				}
			} else {
				if accepted.Result.Outcome != ObservedCurrent || accepted.Generated == nil || accepted.Generated.StateResult != "possible-live-residue-accepted" ||
					accepted.Generated.EffectSummary != contract.ReceiptEffectNotApplicable || len(accepted.Generated.Effects) != 0 ||
					!accepted.Generated.Warnings.PossibleLiveResidue || len(accepted.Generated.RelatedHazardIDs) != 1 || len(accepted.Receipt) == 0 {
					t.Fatal("exact risk acceptance lost its effect-free residue contract", accepted)
				}
				after := f.open(t, ctx)
				if after.root.Generated.Retiring != 0 || after.root.Generated.Hazards != 1 || after.root.Generated.GeneratedCurrent != 1 {
					t.Fatal("risk acceptance changed another generation or discarded residue")
				}
				_, actualCurrent := observeCurrentValueEntry(t, after, "generated")
				expectedCurrent := current
				expectedCurrent.Generated.RetiringDutyPresent, expectedCurrent.Generated.RetiringDutyID = 0, contract.ID{}
				_, actualHealthy := observeCurrentValueEntry(t, after, "healthy")
				if !reflect.DeepEqual(actualCurrent, expectedCurrent) || !reflect.DeepEqual(actualHealthy, healthy) {
					t.Fatal("risk acceptance replaced the current generation or healthy sibling")
				}
				retained := mustSelectedGeneratedWork(t, after)
				hazardID := accepted.Generated.RelatedHazardIDs[0]
				hazard, err := contract.InspectGeneratedHazardRecord(retained.records[generatedRecordKey{contract.GeneratedHazardSupportKind, hazardID}].Body)
				if err != nil || hazard.OwnerID != duty.DutyID || hazard.OriginalAttemptID != attempt || hazard.History.Count != uint32(len(history)) || hazard.Consumers.Count != duty.Consumers.Count {
					t.Fatal("risk acceptance lost the exact old obligation or original readers", err)
				}
				afterHistory, err := retained.vectors.resolve(contract.GeneratedHazardSupportKind, hazardID, contract.GeneratorVectorHistory, hazard.History)
				if err != nil || len(afterHistory) != len(history) || !reflect.DeepEqual(history[:len(history)-1], afterHistory[:len(afterHistory)-1]) ||
					firstAttempt != attempt && retained.attempts[firstAttempt].record != work.attempts[firstAttempt].record {
					t.Fatal("risk acceptance changed an earlier unknown invocation", err)
				}
				receipt, err := contract.InspectCompactMutationReceipt(accepted.Receipt)
				if err != nil || receipt.OperationKind != contract.OperationAcceptGeneratedRetirementResidue || receipt.OperationID != accepted.OperationID ||
					receipt.EffectSummary != contract.ReceiptEffectNotApplicable || receipt.OutputSummary != contract.ReceiptOutputNotApplicable ||
					receipt.SummaryCounts[contract.ReceiptEffectCount] != 0 || receipt.SummaryCounts[contract.ReceiptHazardCount] != 1 {
					t.Fatal("risk receipt changed its effect or output axis", receipt, err)
				}
				raw, read := after.MutationReceipt(ctx, accepted.OperationID)
				if read.Outcome != ObservedCurrent || !bytes.Equal(raw, accepted.Receipt) {
					t.Fatal("fresh receipt observation changed exact risk evidence", read)
				}
				observed := installedGeneratedReceiptObservation(PublicApplyResult{RequestID: testID("risk receipt-only observation")}, after, receipt, raw)
				if observed.Generated == nil || !observed.Generated.ReceiptObservation || observed.Generated.EffectsAvailable || observed.Generated.RelatedWorkAvailable ||
					observed.Generated.EffectSummary != contract.ReceiptEffectNotApplicable || observed.Generated.StateResult != "possible-live-residue-accepted" || !bytes.Equal(observed.Receipt, accepted.Receipt) {
					t.Fatal("risk receipt-only observation inferred effects or lost its axis", observed)
				}
			}
			if p, q := f.keys.Calls(); p != public || q != private {
				t.Fatal("risk acceptance used a private KMS route")
			}
			c, d := effects()
			if c != creates || !reflect.DeepEqual(d, deletes) {
				t.Fatal("risk acceptance sent a provider request", c, d)
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedRetirementRefusesChangedRetainedImplementation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "acknowledged")
	work := mustSelectedGeneratedWork(t, selected)
	duty, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{contract.GeneratedDutySupportKind, current.Generated.RetiringDutyID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	refuser := installedGeneratedRetirementEngine(t, ctx, f, selected, nil)
	absent := refuser.AcceptGeneratedRetirementRisk(ctx, testID("retirement has no ambiguity yet"), GeneratedRetirementRiskRequest{
		DutyID: duty.DutyID, AttemptID: duty.OriginalAttemptID})
	refuser.Close()
	if absent.Result.Outcome != AdmissionRefused || absent.Payload != nil || len(absent.Receipt) != 0 {
		t.Fatal("an unstarted retirement acquired qualified ambiguity", absent)
	}
	for _, field := range []string{"config-contract", "protocol", "artifact-contract", "executor", "credential-route", "descriptor", "dependency"} {
		t.Run(field, func(t *testing.T) {
			callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
			callbacks.ResolveImplementation = func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
				row := f.env.GeneratedProcess.Implementation
				changed := testID("changed retained " + field)
				switch field {
				case "config-contract":
					row.ConfigContractID = changed
				case "protocol":
					row.ProtocolID = changed
				case "artifact-contract":
					row.ArtifactContractID = changed
				case "executor":
					row.ExecutorID = changed
				case "credential-route":
					row.CredentialRouteID = changed
				case "descriptor":
					row.DescriptorID = changed
				case "dependency":
					row.DependencyManifestID = changed
				}
				return row, nil
			}
			callbacks.AdmitReservation = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedReservationInput, time.Time) (*InstalledGeneratedCustody, error) {
				t.Fatal("changed retained implementation reached reservation custody")
				return nil, contract.ErrRecord
			}
			engine := installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
			out := engine.RetireGenerated(ctx, testID("wrong retained implementation "+field), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
			engine.Close()
			if out.Result.Outcome != AdmissionRefused || out.Payload != nil || len(out.Receipt) != 0 {
				t.Fatal("changed implementation replaced the retained retirement tuple", out)
			}
			creates, deletes := effects()
			if creates != 2 || len(deletes) != 0 {
				t.Fatal("changed retained implementation sent a provider request", creates, deletes)
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedRetirementRefusesFreshDeleteAfterIdentityConflict(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "identity-conflict")
	callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
	engine := installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
	parked := engine.RetireGenerated(ctx, testID("retirement records conflicting identity"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
	engine.Close()
	if parked.Result.Outcome != ObservedCurrent || parked.Generated == nil || parked.Generated.StateResult != "effect-unknown" {
		t.Fatal("identity conflict did not park unfinished retirement", parked.Result)
	}
	receipt, err := contract.InspectCompactMutationReceipt(parked.Receipt)
	if err != nil || receipt.OperationID != parked.OperationID || receipt.OperationKind != contract.OperationRetireGeneratedGeneration ||
		receipt.SummaryCounts[contract.ReceiptSummaryUnknownCount] != 1 || receipt.AcknowledgedCount != 0 || receipt.ConfirmedCount != 0 || receipt.UnknownCount != 1 {
		t.Fatal("parked retirement receipt lost its unknown-effect ceiling", err)
	}
	cold := f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, cold)
	if work.parent != nil || len(work.attempts) != 1 || cold.root.Generated.Retiring != 1 {
		t.Fatal("parked conflict lost its exact retained owner")
	}
	for _, attempt := range work.attempts {
		rows, err := work.vectors.resolve(contract.GeneratedAttemptSupportKind, attempt.record.AttemptID, contract.GeneratorVectorFacts, attempt.record.Facts)
		if err != nil || len(rows) != 1 || attempt.record.State != contract.GeneratedEffectUnknown || len(attempt.result) != 0 {
			t.Fatal("cold conflict lost its original unknown facts", err)
		}
		row, err := contract.InspectGeneratorFactsRow(rows[0])
		if err != nil || row.ResultID != attempt.record.ResultID {
			t.Fatal("cold conflict changed its result coordinate", err)
		}
		facts, err := contract.InspectGeneratorSafeFacts(row.Facts)
		if err != nil || facts.Disposition != contract.GeneratorDispositionUnknown || facts.Reason != contract.GeneratorReasonIdentityConflict || facts.RequestDigest != attempt.record.RequestDigest {
			t.Fatal("cold conflict changed its qualified identity evidence", err)
		}
	}
	_, beforeCurrent := observeCurrentValueEntry(t, cold, "generated")
	_, beforeHealthy := observeCurrentValueEntry(t, cold, "healthy")
	beforeHead, beforeRows := bytes.Clone(cold.body), cold.supportRecords()
	reservations := 0
	reserve := callbacks.AdmitReservation
	callbacks.AdmitReservation = func(ctx context.Context, request contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedReservationInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
		reservations++
		return reserve(ctx, request, control, input, deadline)
	}
	for request := 0; request < 2; request++ {
		refuser := installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
		refused := refuser.RetireGenerated(ctx, testID(fmt.Sprintf("fresh retirement after conflict %d", request)), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
		refuser.Close()
		creates, deletes := effects()
		if refused.Result.Outcome != AdmissionRefused || refused.Payload != nil || len(refused.Receipt) != 0 || reservations != 0 || creates != 2 ||
			!reflect.DeepEqual(deletes, []string{"00000000000000000000000000000001"}) {
			t.Fatal("retained identity conflict admitted another destructive invocation", refused.Result, reservations, creates, deletes)
		}
		cold = f.open(t, ctx)
		_, afterCurrent := observeCurrentValueEntry(t, cold, "generated")
		_, afterHealthy := observeCurrentValueEntry(t, cold, "healthy")
		if !bytes.Equal(cold.body, beforeHead) || !reflect.DeepEqual(cold.supportRecords(), beforeRows) ||
			!reflect.DeepEqual(afterCurrent, beforeCurrent) || !reflect.DeepEqual(afterHealthy, beforeHealthy) {
			t.Fatal("refused fresh retirement changed selected state or retained evidence")
		}
	}
}
