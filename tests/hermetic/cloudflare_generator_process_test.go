package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/sdk/artifact/credentialroute"
)

func hermeticCloudflareStateBodies(t *testing.T, status Result, s *StateSession, result []byte) [][]byte {
	t.Helper()
	bodies := [][]byte{result, s.body, []byte(fmt.Sprintf("%+v", status))}
	work, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range work.records {
		bodies = append(bodies, row.Body)
	}
	return bodies
}

// full_only: false
func TestCloudflareTaggedProcessSealsPersistsAndFreshlyAdopts(t *testing.T) {
	intent, requestBody := hermeticCloudflareIntent()
	responseBody := []byte(fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":{"id":"%s","value":"%s","status":"active","name":"generated","creator_email_at_creation":"Generated_secret_creator@example.invalid","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`,
		hermeticCloudflareToken, hermeticCloudflareSecret, hermeticCloudflarePermission, hermeticCloudflareAccount))
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		if err != nil || request.Method != http.MethodPost || request.URL.Path != "/client/v4/accounts/"+hermeticCloudflareAccount+"/tokens" ||
			request.ProtoMajor != 1 || !request.Close || request.Header.Get("Authorization") != "Bearer "+hermeticCloudflareBearer ||
			request.Header.Get("Accept-Encoding") != "identity" || !bytes.Equal(body, requestBody) {
			t.Errorf("unexpected tagged Cloudflare request: method=%s path=%s proto=%s close=%t body=%q err=%v",
				request.Method, request.URL.Path, request.Proto, request.Close, body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(responseBody)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	origin := server.URL + "/client/v4"
	artifact, implementation := buildHermeticCloudflareGenerator(t, origin)
	profile := nativeGeneratedFixtureProfile(t, implementation)

	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	run := newScenarioRun(t, ctx, env)
	fixture := newEnvironmentFixture(t, ctx, run.env, nil, false)
	run.suppliedSelection(fixture, []ApplyEntryInput{suppliedSecret(t, env, "secret", "tagged Cloudflare predecessor", custody.StandardValue)})
	input := generatedPlanInputForGenerationsIntent(t, fixture.session, generatedVectorID(10), []string{"generated"}, intent, profile)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
	prior, _ := preparePrivateGeneratedReservation(t, env, fixture.session, input, nil)
	var processConfig custody.GeneratedProcessConfig
	configure := func(t testing.TB, path string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
		processConfig = hermeticCloudflareConfig(t, path, origin, implementation, expected)
		return processConfig
	}
	producer, expected := preparePrivateGeneratedProcessProducerWithConfig(t, env, fixture.session, prior, artifact, configure)
	var result []byte
	var code contract.CryptoResultCode
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("tagged Cloudflare first-send handoff")
	}
	selected, status := fixture.session.selectCandidate(ctx, producer.reservation.candidate)
	if selected == nil || status.Outcome != ObservedCurrent || status.Reason != NoReason || code != contract.CryptoSuccess ||
		requests.Load() != 1 || len(result) == 0 {
		t.Fatal("tagged Cloudflare result did not cross the reserved first send", code, requests.Load(), status)
	}
	record, err := contract.DecodeGeneratedResultRecord(result)
	work, workErr := selected.selectedGeneratedWork(context.Background())
	if err != nil || workErr != nil || record.SafeFacts.Disposition != 1 || !bytes.Equal(record.SafeFacts.ResourceData, []byte(hermeticCloudflareToken)) ||
		record.SafeFacts.RequestDigest != input.requestBindings[0].Digest || record.SafeFacts.IntentDigest != expected.Template.IntentDigest ||
		contract.ValidateGeneratedResult(expected, work.attempts[expected.Template.AttemptID].material, record) != nil {
		t.Fatal("tagged Cloudflare sealed result differs from its frozen expectation", err, workErr)
	}
	facts, err := contract.EncodeGeneratorSafeFacts(record.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	bodies := append(hermeticCloudflareStateBodies(t, status, selected, result), facts)
	requireNoGeneratorPlaintext(t, env.Store.(*memoryStore), bodies...)
	keys.RetireGenerated()
	recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), selected, expected.Template.AttemptID, result)
	fresh, err := recorded.selectedGeneratedWork(context.Background())
	if err != nil || !bytes.Equal(fresh.attempts[expected.Template.AttemptID].result, result) || fresh.phase.Phase != 2 {
		t.Fatal("fresh Cloudflare adoption changed the sealed process result", err)
	}
	oldSecret := sessionConsumerSelection(t, recorded, recorded.admission.recipient, "secret")
	actors := env.ReplacementActors(t, ctx, recorded, 1, 3, contract.NormalSigningRole)
	permit := admitAuthorityReplacement(t, recorded, actors.Keys, actors.After, 1, contract.NormalSigningRole, 3, actors.Source)
	candidate, replaced := recorded.PrepareSuccession(ctx, permit, actors.Signers)
	if candidate == nil || replaced.Outcome != ObservedCurrent {
		t.Fatal("tagged Cloudflare replacement preparation", replaced)
	}
	admission := deliverSuccessionBasis(t, candidate)
	if replaced = recorded.Select(ctx, candidate); replaced.Outcome != ObservedCurrent {
		t.Fatal("tagged Cloudflare replacement selection", replaced)
	}
	keys.RetireAccess()
	successor, replaced := Open(ctx, admission, env.Store)
	if successor == nil || replaced.Outcome != ObservedCurrent {
		t.Fatal("tagged Cloudflare replacement reopen", replaced)
	}
	actors.Activate(t, successor)
	if actors.Signers.NormalSuccessor == nil {
		t.Fatal("tagged Cloudflare replacement omitted its normal signer")
	}
	env.Trust = actors.Signers.NormalSuccessor
	if check := keys.Consume(ctx, oldSecret, custody.StandardValue); check.Code == contract.CryptoSuccess || check.Delivery != 0 {
		t.Fatal("retired authority KEK still opened predecessor material", check.Code, check.Delivery)
	}
	route, err := credentialroute.Decode(processConfig.Artifact.CredentialRoute)
	if err != nil {
		t.Fatal("retired process credential route unavailable", err)
	}
	for _, name := range route.Names {
		if err := os.Unsetenv(name); err != nil {
			t.Fatal("remove retired process environment input", err)
		}
		if _, present := os.LookupEnv(name); present {
			t.Fatal("retired process environment input remains available")
		}
	}
	for _, path := range []string{processConfig.ArtifactPath, processConfig.ArtifactPath + ".metadata.json", processConfig.ArtifactPath + ".dependencies.bin"} {
		if path == "" {
			t.Fatal("tagged Cloudflare process path was not captured")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal("remove retired tagged Cloudflare process input", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("retired tagged Cloudflare process input remains available", path, err)
		}
	}
	checkFreshGeneratedProcess(t, env.Store.(*memoryStore), successor)
	current, err := successor.selectedGeneratedWork(context.Background())
	if err != nil || !bytes.Equal(current.attempts[expected.Template.AttemptID].result, result) || current.phase.Phase != 2 {
		t.Fatal("replacement changed the sealed Cloudflare result", err)
	}

	finalContext := generatedPlanInputFixture(t, successor).context
	finalContext.AdmissionID, finalContext.SessionID = testID("tagged Cloudflare final admission"), testID("tagged Cloudflare final session")
	finalPlan, err := successor.generatedFinalRequest(t.Context(), finalContext)
	if err != nil {
		t.Fatal("tagged Cloudflare final request", err)
	}
	successor, final := preparePrivateGeneratedFinal(t, env, successor, finalPlan)
	closed, adopted := successor.selectCandidate(ctx, final.reservation.candidate)
	if closed == nil || adopted.Outcome != ObservedCurrent || !closed.root.Generated.ActiveOwner.IsZero() ||
		closed.root.Generated.GeneratedCurrent != 1 {
		t.Fatal("tagged Cloudflare final selection after replacement", adopted)
	}
	checkFreshGeneratedProcess(t, env.Store.(*memoryStore), closed)
	requireNoGeneratorPlaintext(t, env.Store.(*memoryStore), hermeticCloudflareStateBodies(t, status, closed, result)...)
}
