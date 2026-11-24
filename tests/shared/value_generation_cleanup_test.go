package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

const hermeticCloudflareOwnedUnusableToken = "33333333333333333333333333333333"

type cloudflareCleanupScenario struct {
	sourceMode          uint8
	ambiguitiesPerOwner int
	replaceCurrent      bool
	detachHazard        bool
}

// signedDetachedHazardFixture assembles a selected detached Hazard from the
// actual failed original, then signs that test image with the fixture authority.
// It proves cleanup from the selected state; no normal writer handoff is claimed.
func signedDetachedHazardFixture(t testing.TB, ctx context.Context, env fixtureEnvironment, lifecycle, selected *StateSession,
	failed generatedAttempt) (*StateSession, fixtureEnvironment) {
	t.Helper()
	if lifecycle == nil || lifecycle.head.AuthKind != format.LifecycleAuth {
		t.Fatal("detached fixture needs an actual lifecycle signing basis")
	}
	before := generatedLifecycleReopen(t, ctx, selected, env.Store)
	work := mustSelectedGeneratedWork(t, before)
	original, present := work.attempts[failed.record.AttemptID]
	hazardRow, hazardPresent := work.records[generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: failed.expected.Template.HazardID}]
	hazard, hazardErr := contract.InspectGeneratedHazardRecord(hazardRow.Body)
	if !present || !hazardPresent || hazardErr != nil || !bytes.Equal(original.result, failed.result) || len(original.result) == 0 {
		t.Fatal("signed detached fixture lacks the exact failed original and Hazard", present, hazardPresent, hazardErr)
	}
	input := []ApplyEntryInput{{Name: "detached-fixture-marker", Recipients: []contract.ID{before.admission.recipient},
		ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: format.Plain, InputBytes: []byte("authenticated detached cleanup fixture")}}
	comparison, result := before.compareEntryInputs(input)
	if comparison == nil || result.Outcome == AdmissionRefused {
		t.Fatal("signed detached fixture marker comparison", result)
	}
	plan, err := planTransition(t.Context(), comparison)
	if err != nil {
		t.Fatal("signed detached fixture identity plan")
	}
	next, err := before.deriveSuccessor(t.Context(), comparison, plan)
	if err != nil {
		t.Fatal("signed detached fixture value image")
	}
	detached := generatedHazardEvidenceHandoffAtSnapshot(t, generatedLifecycleReopen(t, ctx, selected, env.Store), original, hazard, 0, plan.snapshot)
	next.root.Generated, next.support, next.adminIndex = detached.root.Generated, detached.support, detached.adminIndex
	next.root.RequiredSupport, next.root.RequiredSupportRecordCount = detached.root.RequiredSupport, detached.root.RequiredSupportRecordCount
	next.root.AdministrativeIndex, next.root.AdministrativeIndexShards = detached.root.AdministrativeIndex, detached.root.AdministrativeIndexShards
	next.clearSelectedSupportFacts()
	next.generatedWork, next.generatedGraphs = nil, nil
	next.access = [contract.MaxChildPages]*format.AccessPage{}
	next.root.CurrentAccess.Core.AccessPageRefs = nil
	next.root.AccessRecordCount = 0
	next.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(before.root.Domain, nil)
	if err != nil {
		t.Fatal("signed detached empty access descriptor", err)
	}
	if err := contract.AdvanceAccessGeneration(&next.root.CurrentAccess.Core, next.root.Transition); err != nil {
		t.Fatal("signed detached access generation", err)
	}
	next.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(next.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal("signed detached access root", err)
	}
	for i, id := range plan.pages {
		if id.IsZero() {
			continue
		}
		if next.pages[i] == nil || next.pages[i].Object != id {
			t.Fatal("signed detached value page identity", i)
		}
		body, err := format.EncodeValueEntryPage(*next.pages[i])
		if err != nil {
			t.Fatal("signed detached value page encoding", i, err)
		}
		ref, err := format.Reference(format.ValueEntryPageKind, before.root.Domain, id, uint16(i), body)
		if err != nil {
			t.Fatal("signed detached value page reference", i, err)
		}
		next.root.ValueEntryPages[i] = &ref
	}
	next.recountChildren()
	if _, err := next.selectedGeneratedWork(ctx); err != nil {
		t.Fatal("signed detached selected work before signing", err)
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		t.Fatal("signed detached complete relations before signing", err)
	}
	put := func(ref format.Ref, body []byte) {
		t.Helper()
		if err := format.CheckReference(ref, body); err != nil {
			t.Fatal("signed detached object reference", err)
		}
		key, err := format.Key(env.Store.Descriptor().Prefix, ref)
		if err != nil {
			t.Fatal("signed detached object key", err)
		}
		if err := env.Put(ctx, key, body); err != nil {
			t.Fatal("signed detached object write", err)
		}
	}
	for i, ref := range next.root.ValueEntryPages {
		if ref == nil {
			continue
		}
		body, err := format.EncodeValueEntryPage(*next.pages[i])
		if err != nil {
			t.Fatal("signed detached value page", err)
		}
		put(*ref, body)
	}
	for i, view := range next.support {
		page := format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index}
		for _, row := range view.Records {
			page.Records = append(page.Records, contract.SupportRecord(row))
		}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal("signed detached support page", i, err)
		}
		put(next.root.RequiredSupport[i], body)
	}
	shards, err := format.EncodeAdministrativeIndexPages(next.adminIndex)
	if err != nil || len(shards) != 1+len(next.root.AdministrativeIndexShards) {
		t.Fatal("signed detached administrative pages", err)
	}
	for i, shard := range shards {
		want := next.root.AdministrativeIndex
		if i != 0 {
			want = next.root.AdministrativeIndexShards[i-1]
		}
		if shard.Ref != want {
			t.Fatal("signed detached administrative reference", i)
		}
		put(shard.Ref, shard.Body)
	}
	rootBody, err := format.EncodeRoot(next.root)
	if err != nil {
		t.Fatal("signed detached root", err)
	}
	rootRef, err := format.Reference(format.RootKind, before.root.Domain, next.root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal("signed detached root reference", err)
	}
	put(rootRef, rootBody)
	identity, err := contract.IdentityPlanDescriptor(identityPlan(comparison, plan))
	if err != nil {
		t.Fatal("signed detached identity", err)
	}
	union, grants, exclusions, changed := before.lifecycleVectors(next)
	if union.Digest.IsZero() || changed != 1 {
		t.Fatal("signed detached fixture membership projection", changed)
	}
	head := lifecycle.head
	head.Core = before.head.Core
	head.Core.Root, head.Core.Revision = rootRef, plan.revision
	head.Core.PreviousRevision, head.Core.PreviousDigest, head.Core.PreviousToken = before.head.Core.Revision, contract.Hash(before.body), before.token
	head.Subject.Operation = plan.operation
	head.Subject.IdentityPlan = contract.DigestLength{Digest: identity.Digest, Length: identity.Length}
	head.Subject.BeforeValueEntryCount, head.Subject.AfterValueEntryCount = before.root.ValueEntryCount, next.root.ValueEntryCount
	head.Subject.BeforeSecretCount, head.Subject.AfterSecretCount = uint16(before.root.SecretCount), uint16(next.root.SecretCount)
	head.Subject.BeforeRawBytes, head.Subject.AfterRawBytes = before.root.RawBytes, next.root.RawBytes
	head.Subject.BeforeAccessRoot, head.Subject.AfterAccessRoot = before.root.CurrentAccess.AccessRoot, next.root.CurrentAccess.AccessRoot
	head.Subject.BeforeMembershipCount, head.Subject.AfterMembershipCount = before.root.MembershipCount, next.root.MembershipCount
	head.Subject.Normal.Intent = contract.DigestLength{Digest: comparison.desired, Length: comparison.desiredLength}
	head.Subject.Normal.PublicState = next.publicState()
	head.Subject.Normal.Union, head.Subject.Normal.Changed = union, changed
	head.Subject.Grant.Grants = grantCommitment(before.root.Domain, grants)
	head.Subject.Exclusion.Exclusions = exclusionCommitment(before.root.Domain, exclusions)
	head.Subject.Exclusion.Retirements = retirementCommitment(before.root.Domain)
	head.Subject.Request = requestCommitment(head.Core, head.Subject)
	coreBody, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal("signed detached HEAD core", err)
	}
	conditionalBody, err := format.EncodeConditionalPlan(conditional(head.Core, coreBody))
	if err != nil {
		t.Fatal("signed detached conditional plan", err)
	}
	head.Subject.HeadCore, head.Subject.HeadCoreLength, head.Subject.ConditionalPlan = contract.Hash(coreBody), uint32(len(coreBody)), contract.Hash(conditionalBody)
	request, err := contract.NewLifecycleRequest(head.Subject)
	if err != nil {
		t.Fatal("signed detached lifecycle request", err)
	}
	proof := env.Trust.Sign(ctx, request)
	if proof.Reason != contract.ReasonNone {
		t.Fatal("signed detached authority proof", proof.Reason)
	}
	head.AuthorizationSignature = proof.Signature
	headBody, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal("signed detached HEAD", err)
	}
	if err := env.Put(ctx, env.Store.Descriptor().HeadKey, headBody); err != nil {
		t.Fatal("signed detached HEAD write", err)
	}
	opened, outcome := Open(ctx, OpenContext{admission: &before.admission}, env.Store)
	if opened == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("signed detached ordinary cold Open", outcome)
	}
	selectedWork, err := opened.selectedGeneratedWork(ctx)
	if err != nil || len(selectedWork.attempts) != 0 || opened.root.Generated.Duties != 0 || opened.root.Generated.Hazards != 1 {
		t.Fatal("signed detached predecessor restored private work", err)
	}
	cleanup, found, err := selectedWork.selectGeneratedCleanup(ctx, nil)
	if err != nil || !found || cleanup.kind != generatedCleanupHazard || cleanup.hazard.HazardID != hazard.HazardID ||
		cleanup.target.OriginalAttemptID != failed.record.AttemptID || cleanup.target.OriginalOperationID != failed.record.OperationID {
		t.Fatal("signed detached predecessor lost exact Hazard target", err)
	}
	fresh := currentGeneratedEnvironment(t, env.Store, opened)
	fresh.FreshGeneratedRecord, fresh.FreshCurrent = env.FreshGeneratedRecord, env.FreshCurrent
	fresh.Put, fresh.Delete, fresh.FreshOpen = env.Put, env.Delete, env.FreshOpen
	fresh.Phase, fresh.EndPhase = env.Phase, env.EndPhase
	return opened, fresh
}

func runCloudflareTaggedCleanupScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, scenario cloudflareCleanupScenario) {
	t.Helper()
	baseEnv := env
	memory, ok := underlyingAdmittedMemoryStore(env.Store)
	if !ok {
		t.Fatal("native cleanup requires the admitted memory store")
	}
	intent, requestBody := hermeticCloudflareIntent()
	tokens := []string{hermeticCloudflareToken, hermeticCloudflareOwnedUnusableToken}
	var creates, deletes atomic.Int32
	var deleteMu sync.Mutex
	deleteAttempts := make(map[string]int)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		if err != nil || request.ProtoMajor != 1 || !request.Close || request.Header.Get("Authorization") != "Bearer "+hermeticCloudflareBearer ||
			request.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("unexpected native cleanup transport: method=%s path=%s proto=%s close=%t err=%v", request.Method, request.URL.Path, request.Proto, request.Close, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodPost:
			ordinal := int(creates.Add(1)) - 1
			if ordinal < 0 || ordinal >= len(tokens) || !bytes.Equal(body, requestBody) ||
				request.URL.Path != "/client/v4/accounts/"+hermeticCloudflareAccount+"/tokens" {
				t.Errorf("unexpected native cleanup create: ordinal=%d path=%s body=%q", ordinal, request.URL.Path, body)
				return
			}
			secret := hermeticCloudflareSecret
			if ordinal == 1 {
				secret = "short-secret"
			}
			_, _ = fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%s","value":"%s","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`,
				tokens[ordinal], secret, hermeticCloudflarePermission, hermeticCloudflareAccount)
		case http.MethodDelete:
			if len(body) != 0 {
				t.Error("native cleanup delete carried a body")
				return
			}
			prefix := "/client/v4/accounts/" + hermeticCloudflareAccount + "/tokens/"
			token := strings.TrimPrefix(request.URL.Path, prefix)
			if token == request.URL.Path || token != tokens[0] && token != tokens[1] {
				t.Errorf("native cleanup changed its exact target: %s", request.URL.Path)
				return
			}
			deletes.Add(1)
			deleteMu.Lock()
			deleteAttempts[token]++
			attempt := deleteAttempts[token]
			deleteMu.Unlock()
			if attempt <= scenario.ambiguitiesPerOwner {
				connection, buffer, hijackErr := w.(http.Hijacker).Hijack()
				if hijackErr != nil {
					t.Error(hijackErr)
					return
				}
				_, writeErr := buffer.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}")
				flushErr := buffer.Flush()
				closeErr := connection.Close()
				if writeErr != nil || flushErr != nil || closeErr != nil {
					t.Error("native cleanup ambiguity response", writeErr, flushErr, closeErr)
				}
				return
			}
			_, _ = fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, token)
		default:
			t.Errorf("unexpected native cleanup method: %s", request.Method)
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	origin := server.URL + "/client/v4"
	artifact, implementation := buildHermeticCloudflareGenerator(t, origin)
	profile := nativeGeneratedFixtureProfile(t, implementation)
	configure := func(t testing.TB, path string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
		return hermeticCloudflareConfig(t, path, origin, implementation, expected)
	}

	keys := env.Custody
	run := newScenarioRun(t, ctx, env)
	env = run.env
	deleteStore := &generatedCleanupDeleteStore{Store: env.Store, memoryStore: memory}
	if env.FreshGeneratedRecord == nil || env.FreshCurrent == nil {
		t.Fatal("cleanup scenario requires fresh record and current-state hooks")
	}
	var fixture *environmentFixture
	var selected *StateSession
	var canonicalEntry *contract.ValueEntry
	var failedAttempt contract.ID
	run.phase("setup", func() {
		if scenario.detachHazard {
			fixture = newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
			run.suppliedSelection(fixture, nil)
		} else {
			fixture = newEnvironmentFixture(t, ctx, run.env, nil, false)
		}
		var sources []contract.GeneratorDeclarationEntry
		var canonical []custody.GeneratedCanonicalSelection
		if scenario.sourceMode == 2 {
			run.suppliedSelection(fixture, []ApplyEntryInput{suppliedSecret(t, env, "source", "native cleanup retained source", custody.EmptyValue)})
			sources, canonical = generatedCurrentDeclaration(t, fixture.session)
			copy := canonical[0].Record.Entry
			canonicalEntry = &copy
		} else if scenario.sourceMode != 0 {
			t.Fatal("unknown native cleanup source mode")
		}
		input := generatedPlanInputForGenerationsIntent(t, fixture.session, generatedVectorID(241), []string{"alpha", "omega"}, intent, profile, sources...)
		requestDigest := hermeticCloudflareHTTPRequestDigest(requestBody)
		for i := range input.requestBindings {
			input.requestBindings[i].Digest = requestDigest
		}
		prior, _ := preparePrivateGeneratedReservation(t, env, fixture.session, input, canonical)
		current := fixture.session
		producerInputs := acquireGeneratedProducerFixtureFacts(t, env, current, prior)
		producerKeys := make([]*custody.Fixture, len(tokens))
		producers := make([]*generatedPreparation, len(tokens))
		expectedResults := make([]contract.GeneratorResultExpectation, len(tokens))
		packets := make([][]byte, len(tokens))
		facts := make([]contract.GeneratorSafeFacts, len(tokens))
		codes := make([]contract.CryptoResultCode, len(tokens))
		createCounts, deleteCounts := make([]int32, len(tokens)), make([]int32, len(tokens))
		if len(input.requestBindings) != len(tokens) {
			t.Fatal("native cleanup requires the complete original create set")
		}
		for i := range tokens {
			producerKeys[i] = keys
			if i != 0 {
				producerKeys[i] = keys.ForkGenerated(t)
			}
			t.Cleanup(producerKeys[i].RetireGenerated)
			producers[i], expectedResults[i] = preparePrivateGeneratedOriginalProcessProducerForAttempt(t, env, current, prior,
				producerKeys[i], input.requestBindings[i].AttemptID, producerInputs, artifact, configure)
		}
		if candidate, outcome := current.ClaimGeneratedOriginalSet(ctx, producers, env.Trust); candidate == nil || outcome.Outcome != ObservedCurrent {
			t.Fatal("native cleanup complete original set Claim", outcome)
		}
		if !producers[0].reservation.candidate.bindFirstSend(producers[0], func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
			for i, producer := range producers {
				packets[i], facts[i], codes[i] = producerKeys[i].InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				createCounts[i], deleteCounts[i] = creates.Load(), deletes.Load()
				if codes[i] != contract.CryptoSuccess {
					return codes[i]
				}
			}
			return contract.CryptoSuccess
		}) {
			t.Fatal("native cleanup complete original handoff")
		}
		var outcome Result
		current, outcome = current.selectCandidate(ctx, producers[0].reservation.candidate)
		if current == nil || outcome.Outcome != ObservedCurrent {
			t.Fatal("native cleanup complete original selection", outcome)
		}
		for _, producer := range producerKeys {
			producer.RetireGenerated()
		}
		for i := range tokens {
			expected, packet := expectedResults[i], packets[i]
			wantDisposition := uint8(1)
			if i == 1 {
				wantDisposition = 2
			}
			if codes[i] != contract.CryptoSuccess || len(packet) == 0 || facts[i].Disposition != wantDisposition ||
				generatedFactsResourceDigest(facts[i]) != hermeticCloudflareResourceDigest(tokens[i]) || createCounts[i] != int32(i+1) || deleteCounts[i] != 0 {
				t.Fatal("native failed aggregate create differs", i, codes[i], facts[i], createCounts[i], deleteCounts[i])
			}
			admitted := generatedPlanInputFixture(t, current).context
			label := fmt.Sprintf("native cleanup original %d Record", i)
			admitted.AdmissionID, admitted.SessionID = testID(label+" admission"), testID(label+" session")
			plan, err := current.generatedRecordRequest(ctx, expected.Template.AttemptID, packet, admitted)
			if err != nil {
				t.Fatal("native failed aggregate Record request", err)
			}
			prior = preparePrivateGeneratedRecord(t, env, current, plan)
			current, outcome = current.selectCandidate(ctx, prior.reservation.candidate)
			if current == nil || outcome.Outcome != ObservedCurrent {
				t.Fatal("native failed aggregate Record selection", outcome)
			}
			keys.RetireGenerated()
			if i == len(tokens)-1 {
				failedAttempt = expected.Template.AttemptID
			}
		}
		finalContext := generatedPlanInputFixture(t, current).context
		finalContext.AdmissionID, finalContext.SessionID = testID("native cleanup final admission"), testID("native cleanup final session")
		finalPlan, err := current.generatedFinalRequest(ctx, finalContext)
		if err != nil || finalPlan.selecting {
			t.Fatal("native failed aggregate final request", err)
		}
		current, final := preparePrivateGeneratedFinal(t, env, current, finalPlan)
		selected, _ = current.selectCandidate(ctx, final.reservation.candidate)
		if selected == nil || selected.root.Generated.Duties != 1 || selected.root.Generated.Hazards != 1 ||
			!selected.root.Generated.ActiveOwner.IsZero() || creates.Load() != 2 || deletes.Load() != 0 {
			t.Fatal("native failed aggregate did not select both exact cleanup owners before delete")
		}
		keys.RetireGenerated()
		selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
		if scenario.detachHazard {
			if scenario.sourceMode != 0 || scenario.ambiguitiesPerOwner != 0 || scenario.replaceCurrent {
				t.Fatal("detached cleanup has an invalid scenario shape")
			}
			work := mustSelectedGeneratedWork(t, selected)
			failed, present := work.attempts[failedAttempt]
			if !present {
				t.Fatal("detached cleanup lost the failed aggregate Attempt")
			}
			selected, env = signedDetachedHazardFixture(t, ctx, env, fixture.session, selected, failed)
			run.env, keys = env, env.Custody
		}
		if scenario.replaceCurrent {
			fixture.session = selected
			actual := &generatedActualOperation{env: baseEnv, fixture: fixture}
			fresh := selectActualGeneratedLoss(t, actual, generatedActualLoss{name: "native-cleanup-current-authority-kek", operation: 1, approval: contract.NormalSigningRole, mask: 2})
			selected = actual.fixture.session
			fresh.FreshGeneratedRecord, fresh.FreshCurrent = env.FreshGeneratedRecord, env.FreshCurrent
			fresh.Put, fresh.Delete, fresh.FreshOpen = env.Put, env.Delete, env.FreshOpen
			fresh.Phase, fresh.EndPhase = env.Phase, env.EndPhase
			fresh.Store = scenarioStore{Store: fresh.Store, spy: run.spy}
			fresh.Trust = scenarioTrust{Trust: fresh.Trust, spy: run.spy}
			env, run.env, keys = fresh, fresh, fresh.Custody
		}
	})

	run.phase("transition", func() {
		owners := 2
		if scenario.detachHazard {
			owners = 1
		}
		deleteInput := func(operation contract.ID, row contract.SupportRecord, cleanup generatedCleanupSelection) (generatedPlanInput, []custody.GeneratedCanonicalSelection) {
			t.Helper()
			if !cleanup.attempt.record.AttemptID.IsZero() {
				return generatedDeletePlanInputForSource(t, selected, operation, row, cleanup.target)
			}
			source, err := contract.InspectGeneratedDeleteSource(row)
			if err != nil || row.Kind != contract.GeneratedHazardSupportKind || source.OriginalAttemptID != cleanup.hazard.OriginalAttemptID {
				t.Fatal("detached cleanup source differs from its selected Hazard", err)
			}
			deleteContract, err := contract.GeneratedResultContractID(implementation, 2, source.CompletionClass, 0, 4096, contract.InputEncodingRaw)
			if err != nil || deleteContract == source.ResultContractID {
				t.Fatal("detached cleanup lacks an independent static delete contract", err)
			}
			return generatedDeletePlanInputForIdentity(t, selected, operation, cleanup.target, 3, source.OwnerID,
				source.ConfigContractID, source.ResourceContractID, source.ExecutorID, source.CredentialRouteID,
				source.DescriptorID, deleteContract, source.CompletionClass)
		}
		for ownerIndex := 0; ownerIndex < owners; ownerIndex++ {
			work := mustSelectedGeneratedWork(t, selected)
			cleanup, ok, err := work.selectGeneratedCleanup(ctx, nil)
			if err != nil || !ok || cleanup.kind != generatedCleanupDuty && cleanup.kind != generatedCleanupHazard ||
				cleanup.attempt.record.AttemptID.IsZero() != scenario.detachHazard {
				t.Fatal("native ordinary cleanup selection", ownerIndex, err, cleanup.kind)
			}
			sourceKind, sourceID := uint8(10), cleanup.duty.DutyID
			if cleanup.kind == generatedCleanupHazard {
				sourceKind, sourceID = contract.GeneratedHazardSupportKind, cleanup.hazard.HazardID
			}
			originalAttempt := cleanup.attempt.record.AttemptID
			for ambiguity := 0; ambiguity < scenario.ambiguitiesPerOwner; ambiguity++ {
				row := work.records[generatedRecordKey{kind: sourceKind, id: sourceID}]
				operation := testID(fmt.Sprintf("native ordinary cleanup ambiguity operation %d %d", ownerIndex, ambiguity))
				input, inputCanonical := deleteInput(operation, row, cleanup)
				input.requestBindings[0].Digest = generatedRetirementRequestDigest(cleanup.target)
				prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, inputCanonical)
				producer, expected := preparePrivateGeneratedProcessProducerWithConfig(t, env, selected, prior, artifact, configure)
				var packet []byte
				var facts contract.GeneratorSafeFacts
				var code contract.CryptoResultCode
				if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
					packet, facts, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
					return code
				}) {
					t.Fatal("native ambiguous cleanup handoff")
				}
				entered, outcome := selected.selectCandidate(ctx, producer.reservation.candidate)
				if entered == nil || outcome.Outcome != ObservedCurrent || code != contract.CryptoSuccess || len(packet) != 0 || facts.Disposition != contract.GeneratorDispositionUnknown || facts.Reason != 8 ||
					deletes.Load() != int32(ownerIndex*(scenario.ambiguitiesPerOwner+1)+ambiguity+1) {
					t.Fatal("native ambiguous cleanup invocation", outcome, code, facts, deletes.Load())
				}
				keys.RetireGenerated()
				entered = generatedLifecycleReopen(t, ctx, entered, env.Store)
				ambiguityBody, err := contract.EncodeGeneratorSafeFacts(facts)
				if err != nil {
					t.Fatal(err)
				}
				permit, err := entered.admitGeneratedOrdinaryCleanupUnknown(ctx, expected.Template.AttemptID, ambiguityBody, generatedPlanInputFixture(t, entered).context)
				if err != nil {
					t.Fatal("native ordinary cleanup ambiguity admission", err)
				}
				candidate, result := entered.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
				if candidate == nil || result.Outcome != ObservedCurrent {
					t.Fatal("native ordinary cleanup ambiguity preparation", result)
				}
				selected, result = entered.selectCandidate(ctx, candidate)
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal("native ordinary cleanup ambiguity selection", result)
				}
				selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
				work = mustSelectedGeneratedWork(t, selected)
				cleanup, ok, err = work.selectGeneratedCleanup(ctx, nil)
				if err != nil || !ok || cleanup.attempt.record.AttemptID != originalAttempt {
					t.Fatal("native ambiguity lost its exact cleanup source", err)
				}
				sourceKind, sourceID = 10, cleanup.duty.DutyID
				if cleanup.kind == generatedCleanupHazard {
					sourceKind, sourceID = contract.GeneratedHazardSupportKind, cleanup.hazard.HazardID
				}
			}

			work = mustSelectedGeneratedWork(t, selected)
			cleanup, ok, err = work.selectGeneratedCleanup(ctx, nil)
			if err != nil || !ok {
				t.Fatal("native cleanup source after ambiguity", err)
			}
			sourceKind, sourceID = 10, cleanup.duty.DutyID
			if cleanup.kind == generatedCleanupHazard {
				sourceKind, sourceID = contract.GeneratedHazardSupportKind, cleanup.hazard.HazardID
			}
			row := work.records[generatedRecordKey{kind: sourceKind, id: sourceID}]
			operation := testID(fmt.Sprintf("native ordinary cleanup acknowledgement operation %d", ownerIndex))
			input, inputCanonical := deleteInput(operation, row, cleanup)
			input.requestBindings[0].Digest = generatedRetirementRequestDigest(cleanup.target)
			prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, inputCanonical)
			producer, expected := preparePrivateGeneratedProcessProducerWithConfig(t, env, selected, prior, artifact, configure)
			var packet []byte
			var facts contract.GeneratorSafeFacts
			var code contract.CryptoResultCode
			if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
				packet, facts, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("native cleanup acknowledgement handoff")
			}
			entered, outcome := selected.selectCandidate(ctx, producer.reservation.candidate)
			if entered == nil || outcome.Outcome != ObservedCurrent || code != contract.CryptoSuccess || len(packet) == 0 || facts.Disposition != contract.GeneratorDispositionRetirementAcknowledged || generatedFactsResourceDigest(facts) != cleanup.target.ResourceDigest {
				t.Fatal("native cleanup acknowledgement", outcome, code, facts)
			}
			keys.RetireGenerated()
			recorded := env.FreshGeneratedRecord(t, entered, expected.Template.AttemptID, packet)
			selected = selectOrdinaryGeneratedCleanupClose(t, ctx, env, recorded, expected.Template.AttemptID)
			selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
			selected = selectActualGeneratedInboxRelease(t, ctx, env, selected, deleteStore, expected.Template.AttemptID, false)
			if !originalAttempt.IsZero() {
				selected = selectActualGeneratedInboxRelease(t, ctx, env, selected, deleteStore, originalAttempt, false)
			}
			selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
		}
		work := mustSelectedGeneratedWork(t, selected)
		unobserved := owners * scenario.ambiguitiesPerOwner
		if len(work.attempts) != 0 || len(work.releases) != unobserved || selected.root.Generated.Duties != 0 || selected.root.Generated.Hazards != 0 ||
			creates.Load() != 2 || deletes.Load() != int32(owners*(scenario.ambiguitiesPerOwner+1)) {
			t.Fatal("native cleanup left obligations or changed exact effect counts", len(work.attempts), len(work.releases), creates.Load(), deletes.Load())
		}
		for _, mapping := range work.releases {
			if mapping.release.State != contract.GeneratedReleaseUnobserved || mapping.release.ObjectLength != 0 {
				t.Fatal("native ambiguous cleanup fabricated an observed inbox release")
			}
		}
		if canonicalEntry != nil {
			current := selected.valueEntry(0)
			if current == nil || !sameRetainedEntryValue(*current, *canonicalEntry) || !mustMaterialPresent(selected, 1, canonicalEntry.ValueState) {
				t.Fatal("native source-2 cleanup changed its current canonical member or access")
			}
		}
	})

	want := sessionStateImage(t, selected)
	run.phase("verification", func() {
		cold := generatedLifecycleReopen(t, ctx, selected, env.Store)
		assertStateImage(t, cold, want)
		inspection, err := cold.inspectGeneratedWork(context.Background())
		owners := 2
		if scenario.detachHazard {
			owners = 1
		}
		unobserved := owners * scenario.ambiguitiesPerOwner
		if err != nil || len(inspection.duties) != 0 || len(inspection.hazards) != 0 || len(inspection.releases) != unobserved || inspection.possibleGarbage != (unobserved != 0) {
			t.Fatal("native cleanup cold inspection differs", err)
		}
	})
	run.phase("reopen", func() {
		env.FreshCurrent(t, fixture.admission, selected)
	})
}

func mustMaterialPresent(s *StateSession, kind uint16, id contract.ID) bool {
	_, ok := s.materialAccess(kind, id)
	return ok
}

// full_only: false
func TestCloudflareTaggedDetachedHazardCleanupCloses(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery-%t", recovery), func(t *testing.T) {
			env := memoryScenarioEnvironmentMode(t, recovery)
			runCloudflareTaggedCleanupScenario(t, t.Context(), env, cloudflareCleanupScenario{detachHazard: true})
		})
	}
}
