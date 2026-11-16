package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/telemetry"
)

type generatedProcessDiagnostics struct {
	recorder                         *telemetry.Recorder
	returns                          int
	plan, successor, producer, final bool
}

func (d *generatedProcessDiagnostics) drain(t *testing.T) {
	t.Helper()
	var batch [64]telemetry.DiagnosticRecord
	for {
		records := d.recorder.Drain(batch[:0])
		for _, record := range records {
			if record.Event != telemetry.DiagnosticReturn {
				continue
			}
			switch record.Operation {
			case telemetry.OpCoreGeneratedPreparePlan:
				d.plan = true
			case telemetry.OpCoreGeneratedPrepareSuccessorReservation:
				d.successor = true
			case telemetry.OpCoreGeneratedPrepareProducer:
				d.producer = true
			case telemetry.OpCoreGeneratedPrepareFinal:
				d.final = true
			case telemetry.OpCryptoGeneratedProcess:
				if record.Result != telemetry.ResultSuccess {
					t.Fatalf("generated process diagnostic result = %q", record.Result)
				}
				d.returns++
			}
		}
		if len(records) < len(batch) {
			break
		}
	}
	if status := d.recorder.Status(); status.DroppedContention != 0 || status.DroppedFull != 0 || status.DroppedClosed != 0 || status.Rejected != 0 {
		t.Fatalf("generated diagnostic capture lost records: %+v", status)
	}
}

func checkGeneratedProcessDiagnostics(t *testing.T, d *generatedProcessDiagnostics, want int, required ...telemetry.Operation) {
	t.Helper()
	d.drain(t)
	if d.returns != want {
		t.Fatalf("generated process return diagnostics = %d, want %d; recorder status = %+v", d.returns, want, d.recorder.Status())
	}
	for _, operation := range required {
		seen := operation == telemetry.OpCoreGeneratedPreparePlan && d.plan || operation == telemetry.OpCoreGeneratedPrepareSuccessorReservation && d.successor || operation == telemetry.OpCoreGeneratedPrepareProducer && d.producer || operation == telemetry.OpCoreGeneratedPrepareFinal && d.final
		if !seen {
			t.Fatalf("generated operation diagnostic %q missing; recorder status = %+v", operation, d.recorder.Status())
		}
	}
	d.returns, d.plan, d.successor, d.producer, d.final = 0, false, false, false, false
}

// full_only: false
func TestGeneratedSelectedControlledProviderProcessPathUsesTwoProviderCreates(t *testing.T) {
	var creates atomic.Int32
	bothEntered := make(chan struct{})
	secondReplied := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/client/v4/accounts/"+hermeticCloudflareAccount+"/tokens" {
			t.Error("unexpected generated provider request")
			return
		}
		ordinal := creates.Add(1)
		if ordinal == 2 {
			close(bothEntered)
		}
		select {
		case <-bothEntered:
		case <-time.After(15 * time.Second):
			t.Error("generated provider requests did not overlap")
			return
		}
		if ordinal == 1 {
			select {
			case <-secondReplied:
			case <-time.After(15 * time.Second):
				t.Error("second generated response did not precede first")
				return
			}
		} else {
			defer close(secondReplied)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%032x","value":"%s","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`,
			ordinal, hermeticCloudflareSecret, hermeticCloudflarePermission, hermeticCloudflareAccount)
	}))
	defer server.Close()
	origin := server.URL + "/client/v4"
	artifact, implementation := buildHermeticCloudflareGenerator(t, origin)
	intent, request := hermeticCloudflareIntent()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	env.GeneratedProcess = &generatedProcessFixture{
		Artifact: artifact, Implementation: implementation, Intent: intent,
		RequestDigest: hermeticCloudflareHTTPRequestDigest(request),
		Configure: func(t testing.TB, path string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
			return hermeticCloudflareConfig(t, path, origin, implementation, expected)
		},
	}
	runStateScenario(t, context.Background(), env, "generated.mixed-apply-selects-complete-set/plain1_supplied1_generated2")
	if creates.Load() != 2 {
		t.Fatalf("generated controlled provider process path sent %d creates, want 2", creates.Load())
	}
}

// full_only: false
func TestGeneratedControlledProviderAliasRefusesRecordBeforeAnyDelete(t *testing.T) {
	var creates, deletes atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/client/v4/accounts/"+hermeticCloudflareAccount+"/tokens":
			creates.Add(1)
			_, _ = fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"00000000000000000000000000000001","value":"%s","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`,
				hermeticCloudflareSecret, hermeticCloudflarePermission, hermeticCloudflareAccount)
		case r.Method == http.MethodDelete:
			deletes.Add(1)
			t.Error("aliased generated resource reached provider DELETE")
		default:
			t.Error("unexpected generated provider request")
		}
	}))
	defer server.Close()
	origin := server.URL + "/client/v4"
	artifact, implementation := buildHermeticCloudflareGenerator(t, origin)
	intent, request := hermeticCloudflareIntent()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	f := newEnvironmentFixture(t, context.Background(), env, nil, false)
	profile := liveGeneratedProfile(t, implementation, contract.GeneratedRetirementManual)
	configure := func(t testing.TB, path string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
		return hermeticCloudflareConfig(t, path, origin, implementation, expected)
	}
	initial := generatedPlanInputForGenerationsIntent(t, f.session, generatedVectorID(230), []string{"first"}, intent, profile)
	initial.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(request)
	selected := selectHermeticGeneratedProcessOperation(t, t.Context(), env, f.session, initial, artifact, configure)
	input := generatedPlanInputWithCurrentGenerated(t, selected, generatedVectorID(231), []string{"second"}, profile, intent)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(request)
	prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, nil)
	producer, expected := preparePrivateGeneratedProcessProducerWithConfig(t, env, selected, prior, artifact, configure)
	var packet []byte
	var facts contract.GeneratorSafeFacts
	var code contract.CryptoResultCode
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		packet, facts, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("second independent create did not enter")
	}
	entered, outcome := selected.selectCandidate(context.Background(), producer.reservation.candidate)
	if entered == nil || outcome.Outcome != ObservedCurrent || len(packet) == 0 {
		t.Fatal("second independent create entry", outcome, code, facts.Disposition, facts.Reason, facts.ProviderFacts, len(packet))
	}
	env.Custody.RetireGenerated()
	if code != contract.CryptoSuccess || facts.Disposition != 1 || !bytes.Equal(facts.Target, []byte(hermeticCloudflareAccount)) ||
		generatedFactsResourceDigest(facts) != selected.valueEntry(0).Generated.ResourceDigest {
		t.Fatal("local responder did not return the selected account and token", code, facts)
	}
	recordContext := generatedPlanInputFixture(t, entered).context
	recordContext.AdmissionID, recordContext.SessionID = testID("alias record admission"), testID("alias record session")
	recordPlan, err := entered.generatedRecordRequest(context.Background(), expected.Template.AttemptID, packet, recordContext)
	if err != nil {
		t.Fatal("second independent create record request", err)
	}
	if candidate, err := entered.deriveGeneratedRecord(context.Background(), recordPlan); candidate != nil || !errors.Is(err, contract.ErrRecord) {
		t.Fatal("same provider account and token entered selected evidence", err)
	}
	if creates.Load() != 2 || deletes.Load() != 0 {
		t.Fatal("aliased result sent a provider DELETE", creates.Load(), deletes.Load())
	}
	if cold, outcome := Open(context.Background(), OpenContext{admission: &entered.admission}, env.Store); cold == nil ||
		outcome.Outcome != ObservedCurrent || cold.valueEntry(0).Generated.ResourceDigest != generatedFactsResourceDigest(facts) {
		t.Fatal("alias refusal lost the already selected resource", outcome)
	}
}

// full_only: false
func TestGeneratedSelectedControlledProviderRetirementUsesExactProviderDelete(t *testing.T) {
	for _, scenario := range []string{"generated.retirement-acknowledgement-closes/one_current_one_retiring_manual_ack", "generated.auto-retirement-acknowledgement-closes/one_current_one_retiring_auto_ack"} {
		t.Run(scenario, func(t *testing.T) {
			var creates, deletes atomic.Int32
			var outcomes []custody.GeneratedProducerOutcome
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/client/v4/accounts/"+hermeticCloudflareAccount+"/tokens":
					ordinal := creates.Add(1)
					_, _ = fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%032x","value":"%s","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`,
						ordinal, hermeticCloudflareSecret, hermeticCloudflarePermission, hermeticCloudflareAccount)
				case r.Method == http.MethodDelete && r.URL.Path == "/client/v4/accounts/"+hermeticCloudflareAccount+"/tokens/00000000000000000000000000000001":
					deletes.Add(1)
					_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"00000000000000000000000000000001"}}`))
				default:
					t.Error("unexpected generated provider request")
				}
			}))
			defer server.Close()
			origin := server.URL + "/client/v4"
			artifact, implementation := buildHermeticCloudflareGenerator(t, origin)
			intent, request := hermeticCloudflareIntent()
			env, _ := genesisEnvironment(t, contract.GCP, true)
			recorder := telemetry.NewRecorder()
			diagnostics := &generatedProcessDiagnostics{recorder: recorder}
			store := env.Store.(*memoryStore)
			priorReadHook := store.readHook
			// Reads are synchronous between preparation and process invocation.
			// Drain there so the fixed recorder does not retain whole transitions.
			store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
				if priorReadHook != nil {
					result = priorReadHook(key, result)
				}
				diagnostics.drain(t)
				return result
			}
			defer func() { store.readHook = priorReadHook }()
			ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			env.GeneratedProcess = &generatedProcessFixture{
				Artifact: artifact, Implementation: implementation, Intent: intent,
				RequestDigest: hermeticCloudflareHTTPRequestDigest(request),
				Configure: func(t testing.TB, path string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
					return hermeticCloudflareConfig(t, path, origin, implementation, expected)
				},
				ObserveOutcome: func(out custody.GeneratedProducerOutcome) {
					outcomes = append(outcomes, out)
				},
				AfterCreate: func(contract.ID, contract.GeneratorSafeFacts) error {
					required := []telemetry.Operation{telemetry.OpCoreGeneratedPreparePlan, telemetry.OpCoreGeneratedPrepareProducer}
					if creates.Load() == 2 {
						required = append(required, telemetry.OpCoreGeneratedPrepareFinal)
					}
					checkGeneratedProcessDiagnostics(t, diagnostics, 1, required...)
					return nil
				},
				AfterDelete: func(contract.ID, contract.ID, contract.GeneratorSafeFacts) error {
					reservation := telemetry.OpCoreGeneratedPreparePlan
					if scenario == "generated.auto-retirement-acknowledgement-closes/one_current_one_retiring_auto_ack" {
						reservation = telemetry.OpCoreGeneratedPrepareSuccessorReservation
					}
					checkGeneratedProcessDiagnostics(t, diagnostics, 1, reservation, telemetry.OpCoreGeneratedPrepareProducer)
					return nil
				},
			}
			runStateScenario(t, ctx, env, scenario)
			checkGeneratedProcessDiagnostics(t, diagnostics, 0)
			if creates.Load() != 2 || deletes.Load() != 1 {
				t.Fatalf("retirement provider calls: creates=%d deletes=%d", creates.Load(), deletes.Load())
			}
			if len(outcomes) != 3 {
				t.Fatalf("private outcome count = %d, want 3", len(outcomes))
			}
			for i, out := range outcomes {
				wantEffect, wantDisposition := "complete", uint8(contract.GeneratorDispositionCompleteCreate)
				if i == 2 {
					wantEffect, wantDisposition = "delete_acknowledged", contract.GeneratorDispositionRetirementAcknowledged
				}
				if out.ID.IsZero() || out.Locator.IsZero() || out.Authority.IsZero() || out.Code != contract.CryptoSuccess ||
					out.Stage != "" || out.Category != "" || !out.Qualified || out.Effect != wantEffect ||
					out.Disposition != wantDisposition || out.Reason != contract.GeneratorReasonNone {
					t.Fatalf("private outcome %d lost qualified return facts", i)
				}
			}
		})
	}
}
