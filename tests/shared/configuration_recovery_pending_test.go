package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func configurationRecoveryRetiring(t testing.TB, ctx context.Context, env fixtureEnvironment, selected *StateSession, uncertain bool) *StateSession {
	t.Helper()
	profile := defaultGeneratedFixtureProfile()
	initial := generatedPlanInputForGenerations(t, selected, generatedVectorID(230), []string{"generated-alpha"}, profile)
	selectOperation := func(current *StateSession, input generatedPlanInput, name string) *StateSession {
		return selectPrivateGeneratedOperationInProcess(t, env, current, input, name)
	}
	if live := env.GeneratedProcess; live != nil {
		profile = liveGeneratedProfile(t, live.Implementation, contract.GeneratedRetirementManual)
		initial = generatedPlanInputForGenerationsIntent(t, selected, generatedVectorID(230), []string{"generated-alpha"}, live.Intent, profile)
		initial.requestBindings[0].Digest = live.RequestDigest
		selectOperation = func(current *StateSession, input generatedPlanInput, _ string) *StateSession {
			return selectLiveGeneratedProcessOperation(t, ctx, env, current, input)
		}
	}
	selected = selectOperation(selected, initial, "complete-loss initial")
	old := *selected.valueEntry(0)
	rotation := generatedStatePlanInput(t, selected, generatedVectorID(231), []string{old.Name}, profile, old.Generated.Epoch+1,
		map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old})
	if live := env.GeneratedProcess; live != nil {
		reservation := generatedReservationInputForStateIntent(t, selected, generatedVectorID(231), []string{old.Name}, live.Intent, profile,
			old.Generated.Epoch+1, map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old})
		rotation.graph, rotation.declaration, rotation.registry, rotation.recoveryPolicy = reservation.graph, reservation.declaration, reservation.graph.Request.Registry, reservation.graph.Request.RecoveryPolicyID
		rotation.requestBindings = slices.Clone(reservation.requestBindings)
		rotation.requestBindings[0].Digest = live.RequestDigest
	}
	selected = selectOperation(selected, rotation, "complete-loss rotation")
	current := selected.valueEntry(0)
	if current == nil || current.Generated.RetiringDutyPresent != 1 || selected.root.Generated.Retiring != 1 {
		t.Fatal("complete-loss retirement duty absent")
	}
	if !uncertain {
		return selected
	}
	work := mustSelectedGeneratedWork(t, selected)
	duty, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{kind: 10, id: current.Generated.RetiringDutyID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	target, err := work.retirementTarget(ctx, duty)
	if err != nil {
		t.Fatal(err)
	}
	input, inputCanonical := generatedDeletePlanInput(t, selected, generatedVectorID(232), duty, target, 2)
	if live := env.GeneratedProcess; live != nil {
		input.requestBindings[0].Digest = generatedRetirementRequestDigest(target)
	}
	prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, inputCanonical)
	var producer *generatedPreparation
	var expected contract.GeneratorResultExpectation
	if live := env.GeneratedProcess; live != nil {
		producer, expected = preparePrivateGeneratedProcessProducerWithConfig(t, env, selected, prior, live.Artifact, live.Configure)
		if live.BeforeDelete != nil {
			if err := live.BeforeDelete(expected.Template.AttemptID, generatedTargetProviderTokenID(t, selected, target)); err != nil {
				t.Fatal("recovery retirement ledger refused")
			}
		}
	} else {
		producer, expected = preparePrivateGeneratedProducer(t, env, selected, prior, nil)
	}
	sends := 0
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		sends++
		packet, facts, outcome := env.Custody.InvokeGeneratedProducerOutcome(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		if live := env.GeneratedProcess; live != nil {
			if live.ObserveOutcome != nil {
				live.ObserveOutcome(outcome)
			}
			if facts.Disposition == contract.GeneratorDispositionRetirementAcknowledged && len(facts.ResourceData) > 0 && generatedFactsResourceDigest(facts) == target.ResourceDigest && live.AfterDelete != nil {
				if err := live.AfterDelete(expected.Template.AttemptID, generatedTargetProviderTokenID(t, selected, target), facts); err != nil {
					t.Fatal("recovery retirement acknowledgement ledger refused")
				}
			}
		}
		// The parent drops the reply before Record. Cleanup keeps its private
		// provider acknowledgement, while the selected Attempt remains unknown.
		clear(packet)
		return outcome.Code
	}) {
		t.Fatal("complete-loss retirement handoff refused")
	}
	entered, result := selected.selectCandidate(ctx, producer.reservation.candidate)
	if entered == nil || result.Outcome != ObservedCurrent || sends != 1 {
		t.Fatal("uncertain retirement entry refused", result)
	}
	env.Custody.RetireGenerated()
	facts, err := contract.EncodeGeneratorSafeFacts(generatedUnknownFixtureFacts(expected, generatedTargetEvidence(t, entered, target)))
	if err != nil {
		t.Fatal(err)
	}
	permit, err := entered.admitGeneratedRetirementUnknown(context.Background(), duty.DutyID, facts, generatedPlanInputFixture(t, entered).context)
	if err != nil {
		t.Fatal(err)
	}
	candidate, result := entered.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
	if candidate == nil {
		t.Fatal("uncertain retirement preparation", result)
	}
	selected, result = entered.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("uncertain retirement selection", result)
	}
	work = mustSelectedGeneratedWork(t, selected)
	if work.attempts[expected.Template.AttemptID].record.State != contract.GeneratedEffectUnknown || selected.root.Generated.Retiring != 1 || sends != 1 {
		t.Fatal("uncertain retirement changed effect disposition")
	}
	return selected
}

// full_only: false
func TestConfigurationRecoveryRetiringRealGeneratedProcess(t *testing.T) {
	process, counts := configurationRecoveryLocalGeneratedProcess(t)
	for _, uncertain := range []bool{false, true} {
		name := "retiring"
		if uncertain {
			name = "uncertain"
		}
		t.Run(name, func(t *testing.T) {
			beforeCreates, beforeDeletes := counts()
			env, _ := genesisEnvironment(t, contract.GCP, true, 3)
			env.GeneratedProcess = process
			fixture := newEnvironmentFixture(t, t.Context(), env, nil, false)
			selected := configurationRecoveryRetiring(t, t.Context(), env, fixture.session, uncertain)
			wantDeletes := int32(0)
			if uncertain {
				wantDeletes = 1
			}
			created, deleted := counts()
			if created-beforeCreates != 2 || deleted-beforeDeletes != wantDeletes || selected.root.SecretCount != 1 || selected.root.Generated.Retiring != 1 {
				t.Fatal("real generated pending state or operation inventory differs")
			}
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal("private capture directory refused")
			}
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal("private capture owner mode refused")
			}
			oracles := configurationRecoveryCapture(t, t.Context(), selected, env.Custody, directory)
			if len(oracles) != 1 || oracles[0].Name != "generated-alpha" || oracles[0].Length != uint32(len(hermeticCloudflareSecret)) {
				t.Fatal("actual current generated capture incomplete")
			}
		})
	}
}

func configurationRecoveryLocalGeneratedProcess(t testing.TB) (*generatedProcessFixture, func() (int32, int32)) {
	t.Helper()
	var creates, deletes atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodPost:
			id := creates.Add(1)
			_, err := fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%032x","value":"%s","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`, id, hermeticCloudflareSecret, hermeticCloudflarePermission, hermeticCloudflareAccount)
			if err != nil {
				t.Error("local generated response failed")
			}
		case http.MethodDelete:
			deletes.Add(1)
			if _, err := w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{}}`)); err != nil {
				t.Error("local retirement response failed")
			}
		default:
			t.Error("unexpected local generated operation")
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	origin := server.URL + "/client/v4"
	artifact, implementation := buildHermeticCloudflareGenerator(t, origin)
	intent, request := hermeticCloudflareIntent()
	return &generatedProcessFixture{Artifact: artifact, Implementation: implementation, Intent: intent, RequestDigest: hermeticCloudflareHTTPRequestDigest(request), Configure: func(tb testing.TB, path string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
		return hermeticCloudflareConfig(tb, path, origin, implementation, expected)
	}}, func() (int32, int32) { return creates.Load(), deletes.Load() }
}
