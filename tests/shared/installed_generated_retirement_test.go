package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
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
func TestInstalledRetirementReleasesOnlyItsObsoleteInbox(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "acknowledged")
	store := &generatedCleanupDeleteStore{memoryStore: requireAdmittedMemoryStore(t, f.env.Store)}
	history := map[string]map[contract.ID]contract.ReadResult{}
	store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
		if read.Status == contract.ReadOK {
			if history[key] == nil {
				history[key] = map[contract.ID]contract.ReadResult{}
			}
			copied := read
			copied.Body = bytes.Clone(read.Body)
			history[key][contract.Hash(copied.Body)] = copied
		}
		return read
	}
	f.env.Store = store
	for epoch := uint64(1); epoch <= 2; epoch++ {
		if epoch == 2 {
			input := installedGeneratedRetirementEntries(f.env.GeneratedProcess, selected.admission.recipient, epoch, "retained healthy sibling")
			engine := installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
			rotated := engine.Apply(ctx, testID("rotate for next inbox release"), input)
			engine.Close()
			if rotated.Result.Outcome != ObservedCurrent {
				t.Fatal("next managed rotation", rotated.Result)
			}
			selected = f.open(t, ctx)
			_, current = observeCurrentValueEntry(t, selected, "generated")
		}
		prior, err := selected.receiptWindows(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if selected.root.Generated.PendingReleases != 0 {
			t.Fatal("unexpected baseline retirement inbox")
		}
		engine := installedGeneratedRetirementEngine(t, ctx, f, selected, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
		before := selected
		out := engine.RetireGenerated(ctx, testID(fmt.Sprintf("release retirement inbox %d", epoch)), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
		engine.Close()
		if out.Result.Outcome != ObservedCurrent || out.Generated == nil || len(out.Generated.Effects) != 1 || len(out.Receipt) == 0 {
			t.Fatal("retirement receipt", out.Result)
		}
		selected = f.open(t, ctx)
		effect := out.Generated.Effects[0].Record
		key, err := format.GeneratedResultKey(store.desc.Prefix, selected.root.Domain, effect.InboxID)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := contract.InspectCompactMutationReceipt(out.Receipt)
		if err != nil {
			t.Fatal(err)
		}
		original := func(_ context.Context, k string, digest contract.ID, length uint32) (contract.ReadResult, error) {
			read, ok := history[k][digest]
			if !ok || length != 0 && int(length) != len(read.Body) {
				return contract.ReadResult{}, contract.ErrRecord
			}
			read.Body = bytes.Clone(read.Body)
			return read, nil
		}
		stockHistoricalRetirement(t, ctx, before, selected, out.OperationID, receipt.ObservedRevisionID, current.Generated.RetiringDutyID, f.env.GeneratedProcess.Implementation.ExecutorID, original)
		if epoch == 1 {
			for _, damage := range []string{"different-body", "different-token", "missing", "different-root"} {
				t.Run(damage, func(t *testing.T) {
					image := *selected
					subject := *selected.head.Generator
					image.head.Generator = &subject
					if damage == "different-root" {
						subject.BeforeRootDigest = testID("unrelated root")
					}
					_, err := stockReleasePredecessor(ctx, before, &image, func(ctx context.Context, key string, digest contract.ID, n uint32) (contract.ReadResult, error) {
						read, err := original(ctx, key, digest, n)
						switch damage {
						case "different-body":
							read.Body = []byte("different HEAD")
						case "different-token":
							read.Token = contract.Token{Family: contract.AWS, Value: `"other"`}
						case "missing":
							return contract.ReadResult{Status: contract.ReadMissing}, nil
						}
						return read, err
					})
					if err == nil {
						t.Fatal("changed historical predecessor accepted")
					}
				})
			}
		}
		_, physical := store.objects[key]
		_, retained := mustSelectedGeneratedWork(t, selected).releases[effect.AttemptID]
		if physical || retained || selected.root.Generated.PendingReleases != 0 || store.deleteKey != key || store.deletes != int(epoch) {
			t.Fatalf("retirement %d inbox present=%t mapping=%t pending=%d conditional deletes=%d", epoch, physical, retained, selected.root.Generated.PendingReleases, store.deletes)
		}
		if selected.head.Generator == nil || selected.head.Generator.Purpose != contract.GeneratorAuthorityInboxRelease || selected.head.Generator.PreviousRevisionID != out.Result.ObservedRevision {
			t.Fatal("cold release does not follow the exact signed retirement close")
		}
		for _, group := range selected.adminIndex.Groups {
			if group.OwnerKind == format.AdministrativeInboxRelease {
				t.Fatal("released inbox still charges selected bytes or pages", group.ChargedBytes, group.ChargedPages)
			}
		}
		after, err := selected.receiptWindows(ctx)
		if err != nil || len(after.Successes) != len(prior.Successes)+1 || len(after.Failures) != len(prior.Failures) {
			t.Fatal("receipt-window growth per retirement", err)
		}
		check := installedGeneratedRetirementEngine(t, ctx, f, selected, nil)
		replay := check.ContinueGeneratedRetirement(ctx, testID(fmt.Sprintf("observe retirement %d", epoch)), GeneratedRetirementContinuationRequest{OperationID: out.OperationID})
		check.Close()
		creates, deletes := effects()
		if replay.Generated == nil || !replay.Generated.ReceiptObservation || !bytes.Equal(replay.Receipt, out.Receipt) || creates != int(epoch+1) || len(deletes) != int(epoch) || store.deletes != int(epoch) || f.open(t, ctx).head.Core != selected.head.Core {
			t.Fatal("cold observation changed the receipt, HEAD or effects")
		}
	}
}

// Keep the actual acknowledgement in the Store. Only its first readback
// differs, so a second read in the same invocation would conceal the conflict.
func conflictInstalledDeleteReadback(t *testing.T, f *installedApplyTestFixture, callbacks *GeneratedApplyInstallation) func(PublicApplyResult) {
	t.Helper()
	base := requireAdmittedMemoryStore(t, f.env.Store)
	store := &applyPreparationTestStore{Store: base, memory: base, create: base.Create}
	f.env.Store = store
	var inbox string
	var observed bool
	admit := callbacks.AdmitProducer
	callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, row contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
		if in.Expected.Template.Action == contract.GeneratorActionDelete {
			var err error
			inbox, err = format.GeneratedResultKey(base.desc.Prefix, f.env.Domain, in.Expected.Template.InboxID)
			if err != nil {
				return nil, err
			}
		}
		return admit(ctx, q, control, in, row, deadline)
	}
	store.read = func(ctx context.Context, key string, limit uint32) contract.ReadResult {
		r := base.Read(ctx, key, limit)
		if key == inbox && !observed && r.Status == contract.ReadOK {
			observed = true
			r.Body = []byte("different readback")
		}
		return r
	}
	return func(out PublicApplyResult) {
		t.Helper()
		var reasons []contract.DiagnosticReason
		for _, d := range out.Diagnostics {
			if d.Subject.Kind == contract.SubjectStore {
				reasons = append(reasons, d.Reason)
			}
		}
		if !observed || !reflect.DeepEqual(reasons, []contract.DiagnosticReason{contract.ReasonImmutableConflict}) ||
			out.Result.Outcome != ObservedCurrent || out.Result.Reason == CustodyUnavailable || len(out.Receipt) != 0 {
			t.Fatal("confirmed selection lost the original acknowledgement persistence failure", observed, reasons, out.Result.Outcome)
		}
	}
}

// full_only: false
func TestInstalledGeneratedRetirementContinuesLateOriginalWithoutAnotherSend(t *testing.T) {
	for _, mode := range []string{"adoption", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "acknowledged")
			callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
			var checkConflict func(PublicApplyResult)
			if mode == "conflict" {
				checkConflict = conflictInstalledDeleteReadback(t, &f, callbacks)
			} else {
				callbacks.AdmitAdoption = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedAdoptionInput, time.Time) (*InstalledGeneratedCustody, error) {
					return nil, contract.ErrRecord
				}
			}
			first := installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
			stopped := first.RetireGenerated(ctx, testID("retirement stop before original adoption"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
			first.Close()
			if checkConflict != nil {
				checkConflict(stopped)
			}
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
		})
	}
}

// full_only: false
func TestInstalledActiveRetirementAcceptsSavedUnknownAfterParkingFailure(t *testing.T) {
	for _, cut := range []string{"parking-cas", "parking-sign", "parking-read", "signer-replaced", "journal-unavailable", "journal-and-parking-unavailable"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "unknown")
			base := requireAdmittedMemoryStore(t, f.env.Store)
			trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
			if !ok {
				t.Fatal("fixture trust")
			}
			var terminalKey, noteKey string
			store := &applyPreparationTestStore{Store: base, memory: base, read: base.Read, create: base.Create}
			f.env.Store = store
			callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
			admit := callbacks.AdmitProducer
			var original contract.ID
			callbacks.AdmitProducer = func(c context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, row contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				owner, err := admit(c, q, control, in, row, deadline)
				if err != nil {
					return nil, err
				}
				invoke := owner.InvokeProducer
				owner.InvokeProducer = func(c context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
					result := invoke(c, locator, authority)
					if result.Code != contract.CryptoSuccess || result.Facts.Disposition != contract.GeneratorDispositionUnknown || len(result.Record) != 0 {
						t.Fatal("fixture did not return qualified bodyless Unknown")
					}
					original = in.Expected.Template.AttemptID
					terminalKey, err = format.GeneratedResultKey(base.desc.Prefix, f.env.Domain, in.Expected.Template.InboxID)
					if err != nil {
						t.Fatal(err)
					}
					coordinate, err := contract.GeneratorRetirementAmbiguityID(in.Expected.Template.InboxID)
					if err != nil {
						t.Fatal(err)
					}
					noteKey, err = format.GeneratedResultKey(base.desc.Prefix, f.env.Domain, coordinate)
					if err != nil {
						t.Fatal(err)
					}
					switch cut {
					case "parking-sign":
						trust.corrupt = true
					case "parking-read":
						store.read = func(ctx context.Context, key string, limit uint32) contract.ReadResult {
							if key == terminalKey {
								return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
							}
							return base.Read(ctx, key, limit)
						}
					case "parking-cas", "signer-replaced":
						base.casMode = "lost-before"
					case "journal-unavailable", "journal-and-parking-unavailable":
						if cut == "journal-and-parking-unavailable" {
							base.casMode = "lost-before"
						}
						store.create = func(ctx context.Context, key string, body []byte) contract.WriteResult {
							if key == noteKey {
								return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess, NotSent: true}
							}
							return base.Create(ctx, key, body)
						}
					}
					return result
				}
				return owner, nil
			}
			first := installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
			duty := current.Generated.RetiringDutyID
			stopped := first.RetireGenerated(ctx, testID("retirement parking failed"), GeneratedRetirementRequest{DutyID: duty})
			first.Close()
			base.casMode = ""
			store.read, store.create = base.Read, base.Create
			trust.corrupt = false
			cold := f.open(t, ctx)
			if cut == "journal-unavailable" {
				if stopped.Generated == nil || stopped.Generated.StateResult != "effect-unknown" || !cold.root.Generated.ActiveOwner.IsZero() || len(stopped.Diagnostics) == 0 {
					t.Fatal("unavailable note blocked ordinary parking or hid Store failure", stopped.Result.Outcome)
				}
				_, del := effects()
				if len(del) != 1 {
					t.Fatal("parking sent another DELETE")
				}
				return
			}
			if original.IsZero() || stopped.OperationID.IsZero() || cold.root.Generated.ActiveOwner != stopped.OperationID {
				t.Fatal("fixture lost active retirement")
			}
			if _, found, failure := cold.readGeneratedResult(ctx, original); found || failure.Outcome != 0 {
				t.Fatal("Unknown occupied the terminal inbox")
			}
			if cut == "signer-replaced" {
				env := syntheticAuthorityScenarioEnvironment(t, f.env)
				actors := env.ReplacementActors(t, ctx, cold, 1, 1, contract.NormalSigningRole)
				permit := admitAuthorityReplacement(t, cold, actors.Keys, actors.After, 1, contract.NormalSigningRole, 1, actors.Source)
				candidate, prepared := cold.PrepareSuccession(ctx, permit, actors.Signers)
				if candidate == nil || prepared.Outcome != ObservedCurrent {
					t.Fatal("active retirement signer replacement", prepared)
				}
				f.admitted = deliverSuccessionBasis(t, candidate)
				if result := cold.Select(ctx, candidate); result.Outcome != ObservedCurrent {
					t.Fatal("select successor signer", result)
				}
				f.basis = f.admitted.admission.publicBasis()
				cold = f.open(t, ctx)
				actors.Activate(t, cold)
				f.env.Trust = actors.Signers.NormalSuccessor
			}
			work := mustSelectedGeneratedWork(t, cold)
			a := work.attempts[original]
			reader := retirementEvidenceReader{cold.admission.store.Prefix, cold.storeRead}
			if cut == "journal-and-parking-unavailable" {
				recoverer := installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
				done := recoverer.AcceptGeneratedRetirementRisk(ctx, testID("missing origin evidence"), GeneratedRetirementRiskRequest{DutyID: duty, AttemptID: original})
				recoverer.Close()
				_, del := effects()
				if done.Result.Outcome != AdmissionRefused || !bytes.Equal(f.open(t, ctx).body, cold.body) || len(del) != 1 {
					t.Fatal("missing original became eligible")
				}
				return
			}
			saved, err := reader.load(ctx, work, a)
			if err != nil || len(saved) == 0 {
				t.Fatal("original evidence missing after parking failed", len(saved), err, stopped.Result, stopped.Diagnostics)
			}
			eligible, err := reader.activeRiskFacts(ctx, work, a)
			if err != nil || !bytes.Equal(eligible, saved) {
				t.Fatal("original evidence is ineligible", len(eligible), err)
			}
			if cut == "parking-cas" {
				list, _ := installedGeneratedReaderFixture(t, f)
				listed := list.List(ctx, testID("list saved active retirement"))
				list.Close()
				want := GeneratedNextAction{Command: "generated accept-retirement-risk", DutyID: duty, AttemptID: original}
				if listed.View == nil || !slices.Contains(listed.View.NextActions, want) {
					t.Fatal("GET-only list lost supported active risk action", listed.Result)
				}
				terminal := generatedRetirementResultFixture(t, cold, a, contract.GeneratorDispositionRetirementAcknowledged)
				for _, packet := range [][]byte{terminal, {0}} {
					store.read = func(ctx context.Context, key string, limit uint32) contract.ReadResult {
						if key == terminalKey {
							return contract.ReadResult{Status: contract.ReadOK, Body: packet}
						}
						return base.Read(ctx, key, limit)
					}
					seen, err := reader.activeRiskFacts(ctx, work, a)
					if len(seen) != 0 || (err == nil) != bytes.Equal(packet, terminal) {
						t.Fatal("terminal inbox precedence", len(seen), err)
					}
				}
				store.read = func(ctx context.Context, key string, limit uint32) contract.ReadResult {
					r := base.Read(ctx, key, limit)
					if key == noteKey && r.Status == contract.ReadOK {
						r.Body = bytes.Clone(r.Body)
						r.Body[len(r.Body)-1] ^= 1
					}
					return r
				}
				invalid := installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
				refused := invalid.AcceptGeneratedRetirementRisk(ctx, testID("damaged retirement evidence"), GeneratedRetirementRiskRequest{DutyID: duty, AttemptID: original})
				invalid.Close()
				store.read = base.Read
				if refused.Result.Outcome != IntegrityFailure || !bytes.Equal(f.open(t, ctx).body, cold.body) {
					t.Fatal("damaged evidence released retirement")
				}
			}
			if cut == "parking-read" {
				cont := installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
				parked := cont.ContinueGeneratedRetirement(ctx, testID("continue saved retirement ambiguity"), GeneratedRetirementContinuationRequest{OperationID: stopped.OperationID})
				cont.Close()
				cold = f.open(t, ctx)
				if !cold.root.Generated.ActiveOwner.IsZero() || parked.Generated == nil || parked.Generated.StateResult != "effect-unknown" {
					t.Fatal("continue failed to park original Unknown", parked.Result.Outcome)
				}
			}
			recoverer := installedGeneratedRetirementEngine(t, ctx, f, cold, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
			wrong := recoverer.AcceptGeneratedRetirementRisk(ctx, testID("another retirement attempt"), GeneratedRetirementRiskRequest{DutyID: duty, AttemptID: testID("unrelated attempt")})
			if wrong.Result.Outcome != AdmissionRefused || !bytes.Equal(f.open(t, ctx).body, cold.body) {
				t.Fatal("unrelated attempt affected retirement")
			}
			recoverer.Close()
			recoverer = installedGeneratedRetirementEngine(t, ctx, f, cold, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
			done := recoverer.AcceptGeneratedRetirementRisk(ctx, testID("accept exact active retirement risk"), GeneratedRetirementRiskRequest{DutyID: duty, AttemptID: original})
			recoverer.Close()
			after := f.open(t, ctx)
			creates, deletes := effects()
			if done.Result.Outcome != ObservedCurrent || done.Generated == nil || done.Generated.StateResult != "possible-live-residue-accepted" || !done.Generated.Warnings.PossibleLiveResidue || len(done.Receipt) == 0 || !after.root.Generated.ActiveOwner.IsZero() || after.root.Generated.Hazards != 1 || creates != 2 || len(deletes) != 1 {
				t.Fatal("restart lost the qualified Unknown", done.Result.Outcome, done.Result.Reason, after.root.Generated.Hazards, creates, len(deletes))
			}
			if cut == "parking-cas" {
				closed := mustSelectedGeneratedWork(t, after)
				marks, err := gcMarkSelected(closed.image, closed, after.admission.store)
				id, coordErr := contract.GeneratorRetirementAmbiguityID(a.record.InboxID)
				object := contract.StoreObjectIdentity{Namespace: contract.StoreResultObject, ObjectID: id}
				note := base.Read(ctx, noteKey, contract.RetirementAmbiguityMaxLength)
				_, marked := marks.objects[object]
				if err != nil || coordErr != nil || marked || note.Status != contract.ReadOK || !gcObjectBytesValid(f.env.Domain, after.admission.store, object, note.Body) {
					t.Fatal("released evidence is not eligible for ordinary GC", marked, err, coordErr)
				}
				object.ObjectID = a.record.InboxID
				if gcObjectBytesValid(f.env.Domain, after.admission.store, object, note.Body) {
					t.Fatal("GC confused evidence with the terminal inbox")
				}
			}
		})
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
	for _, field := range []string{"missing", "config-contract", "protocol", "artifact-contract", "executor", "credential-route", "descriptor", "dependency"} {
		t.Run(field, func(t *testing.T) {
			callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
			callbacks.ResolveImplementation = func(request GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
				if request.Retained == nil || request.Retained.ExecutorID != duty.ExecutorID || request.Retained.CredentialRouteID != duty.CredentialRouteID {
					t.Fatal("retirement did not request its accepted installation")
				}
				if field == "missing" {
					return contract.GeneratorImplementation{}, contract.ErrRecord
				}
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
	cold := f.open(t, ctx)
	retained := mustSelectedGeneratedWork(t, cold)
	record, err := contract.InspectGeneratedDutyRecord(retained.records[generatedRecordKey{contract.GeneratedDutySupportKind, duty.DutyID}].Body)
	if err != nil || record != duty || !bytes.Equal(cold.body, selected.body) || cold.token != selected.token {
		t.Fatal("unavailable or changed installation altered the accepted retirement", err)
	}
	engine := installedGeneratedRetirementEngine(t, ctx, f, cold, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
	resumed := engine.RetireGenerated(ctx, testID("exact retirement installation restored"), GeneratedRetirementRequest{DutyID: duty.DutyID})
	engine.Close()
	closed := f.open(t, ctx)
	creates, deletes := effects()
	if resumed.Result.Outcome != ObservedCurrent || len(resumed.Receipt) == 0 || closed.root.Generated.Retiring != 0 ||
		closed.root.Generated.Duties != 0 || creates != 2 || !reflect.DeepEqual(deletes, []string{"00000000000000000000000000000001"}) {
		t.Fatal("restoring the accepted installation did not close the original retirement", resumed.Result, creates, deletes)
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

// The native intake tests establish which returns can produce this host record.
// Exercise its installed custody handoff using the original local DELETE count.
// full_only: false
func TestInstalledRetirementParksHostRejectedResource(t *testing.T) {
	for _, operation := range []string{"retire", "cleanup"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "unknown")
			callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
			run := func(s *StateSession) *InstalledApply {
				return installedGeneratedRetirementEngine(t, ctx, f, s, callbacks)
			}
			duty := current.Generated.RetiringDutyID
			if operation == "cleanup" {
				engine := run(selected)
				first := engine.RetireGenerated(ctx, testID("initial qualified Unknown"), GeneratedRetirementRequest{DutyID: duty})
				engine.Close()
				if first.Generated == nil || len(first.Generated.Effects) != 1 {
					t.Fatal("no retirement to transfer", first.Result)
				}
				engine = run(f.open(t, ctx))
				accepted := engine.AcceptGeneratedRetirementRisk(ctx, testID("transfer for cleanup"), GeneratedRetirementRiskRequest{DutyID: duty, AttemptID: first.Generated.Effects[0].Record.AttemptID})
				engine.Close()
				if accepted.Result.Outcome != ObservedCurrent {
					t.Fatal("risk transfer", accepted.Result)
				}
				selected = f.open(t, ctx)
			}
			_, previous := effects()
			var requested, claimed contract.GeneratorSafeFacts
			var id contract.ID
			admit := callbacks.AdmitProducer
			callbacks.AdmitProducer = func(c context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedProducerInput, row contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				owner, err := admit(c, q, control, input, row, deadline)
				if err != nil {
					return nil, err
				}
				invoke := owner.InvokeProducer
				owner.InvokeProducer = func(c context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
					r := invoke(c, locator, authority)
					if r.Code != contract.CryptoSuccess || r.Facts.Disposition != contract.GeneratorDispositionUnknown {
						t.Fatal("missing original DELETE")
					}
					id = input.Expected.Template.AttemptID
					requested, err = contract.DecodeGeneratorSafeFacts(input.OriginalFacts)
					if err != nil {
						t.Fatal(err)
					}
					claimed = r.Facts
					if operation == "cleanup" {
						claimed.Target = []byte("other public account")
					} else {
						claimed.ResourceData = []byte("other public token")
						claimed.Disposition, claimed.Reason = contract.GeneratorDispositionRetirementAcknowledged, contract.GeneratorReasonNone
					}
					b, err := contract.EncodeRejectedRetirement(claimed)
					if err != nil {
						t.Fatal(err)
					}
					return contract.GeneratedProducerResult{Code: contract.CryptoCustodyUnavailable, RejectedRetirement: b}
				}
				return owner, nil
			}
			engine := run(selected)
			var parked PublicApplyResult
			if operation == "retire" {
				parked = engine.RetireGenerated(ctx, testID("park host rejection"), GeneratedRetirementRequest{DutyID: duty})
			} else {
				parked = engine.CleanupGenerated(ctx, testID("park rejected cleanup"))
			}
			engine.Close()
			cold := f.open(t, ctx)
			work := mustSelectedGeneratedWork(t, cold)
			if work.parent != nil || !cold.root.Generated.ActiveOwner.IsZero() || parked.Generated == nil || parked.Generated.StateResult != "effect-unknown" {
				t.Fatal("rejection did not park", parked.Result.Outcome, parked.Result.Reason, parked.Diagnostics, cold.root.Generated.ActiveOwner)
			}
			if operation == "retire" {
				receipt, err := contract.InspectCompactMutationReceipt(parked.Receipt)
				if err != nil || receipt.EvidenceCeiling != contract.ReceiptEvidenceCanonical || receipt.UnknownCount != 1 || receipt.AcknowledgedCount != 0 {
					t.Fatal("rejected reply inflated the receipt ceiling", err)
				}
				windows, err := cold.receiptWindows(ctx)
				if err != nil || !slices.Contains(windows.Failures, receipt) {
					t.Fatal("cold receipt lost host rejection ceiling", err)
				}
			}
			a := work.attempts[id]
			digest, err := contract.GeneratorResourceDigest(requested)
			if err != nil || a.expected.TargetResourceDigest != digest || a.record.State != contract.GeneratedEffectUnknown || len(a.result) != 0 {
				t.Fatal("lost original resource or selected terminal result")
			}
			rows, err := work.vectors.resolve(contract.GeneratedAttemptSupportKind, id, contract.GeneratorVectorFacts, a.record.Facts)
			if err != nil || len(rows) != 1 {
				t.Fatal("selected rejection absent", err)
			}
			row, err := contract.InspectGeneratorFactsRow(rows[0])
			if err != nil {
				t.Fatal(err)
			}
			rejection, err := inspectRetirementAttemptFacts(row.Facts, a)
			if err != nil || !rejection.RetirementRejected || rejection.Disposition != claimed.Disposition || !bytes.Equal(rejection.Target, claimed.Target) || !bytes.Equal(rejection.ResourceData, claimed.ResourceData) {
				t.Fatal("cold rejection lost reported resource", err)
			}
			if len(parked.Generated.Effects) != 1 || parked.Generated.Effects[0].Reason != GeneratedReasonRetirementResourceMismatch || parked.Generated.Effects[0].Warnings.InvalidationNotConfirmed {
				t.Fatal("host rejection reported as a provider result")
			}
			if _, ok, res := cold.ReadGeneratedResult(ctx, id); ok || res.Outcome != 0 {
				t.Fatal("rejection occupied terminal inbox", res)
			}
			engine = run(cold)
			if operation == "retire" {
				r := engine.AcceptGeneratedRetirementRisk(ctx, testID("risk after rejected reply"), GeneratedRetirementRiskRequest{DutyID: duty, AttemptID: id})
				engine.Close()
				if r.Result.Outcome != AdmissionRefused {
					t.Fatal("accepted risk for host rejection", r.Result)
				}
				engine = run(cold)
				r = engine.RetireGenerated(ctx, testID("blocked repeated retirement"), GeneratedRetirementRequest{DutyID: duty})
				if r.Result.Outcome != AdmissionRefused {
					t.Fatal("opened another retirement", r.Result)
				}
			} else {
				r := engine.CleanupGenerated(ctx, testID("blocked repeated cleanup"))
				if r.Result.Outcome != IntegrityFailure {
					t.Fatal("opened another cleanup", r.Result)
				}
			}
			engine.Close()
			if !bytes.Equal(cold.body, f.open(t, ctx).body) {
				t.Fatal("rejection changed on retry")
			}
			callbacks.AdmitProducer = admit
			input := installedGeneratedRetirementEntries(f.env.GeneratedProcess, cold.admission.recipient, 1, "update healthy sibling")
			engine = installedGeneratedTestEngine(t, ctx, f, cold, input, currentApplyRecipients(cold.registry()), callbacks)
			changed := engine.Apply(ctx, testID("unrelated edit after rejection"), input)
			engine.Close()
			_, deletes := effects()
			if changed.Result.Outcome != ObservedCurrent || len(deletes) != len(previous)+1 {
				t.Fatal("domain did not resume independently", changed.Result, len(deletes))
			}
		})
	}
}
