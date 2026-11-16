package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedWholeSetSelectsAfterEveryOriginalResult(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	runGeneratedWholeSetScenario(t, ctx, env, false, false, 0, nil)
}

// full_only: false
func TestGeneratedOriginalSetRejectsNilFirstProducer(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, true)
	fixture := newEnvironmentFixture(t, context.Background(), env, nil, false)
	if candidate, result := fixture.session.ClaimGeneratedOriginalSet(context.Background(), []*generatedPreparation{nil}, env.Trust); candidate != nil || result.Outcome != AdmissionRefused {
		t.Fatal("nil first original producer was accepted", result)
	}
}

// full_only: false
func TestGeneratedMixedSuppliedAndGeneratedWholeSetSelectsAtomically(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	runGeneratedWholeSetScenario(t, ctx, env, true, false, 0, nil)
}

// full_only: false
func TestGeneratedMixedRetainedSealedAndGeneratedWholeSetSelectsAtomically(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	runGeneratedWholeSetScenario(t, ctx, env, true, true, 0, nil)
}

// full_only: false
func TestGeneratedSixtyFiveMaximumSuppliedSecretsSelectInBoundedBatches(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	runGeneratedWholeSetScenario(t, ctx, env, false, false, 65, nil)
}

// full_only: false
func TestGeneratedEightMiBRawSetSelectsInBoundedSuppliedBatches(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	runGeneratedWholeSetScenario(t, ctx, env, false, false, 126, nil)
}

// full_only: false
func TestGeneratedEightMiBRawSetAnd4096MembershipsSelectInBoundedBatches(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true, 32)
	var recipients []contract.ID
	for _, binding := range env.Bindings {
		if binding.SubjectKind == 1 {
			recipients = append(recipients, binding.SubjectID)
		}
	}
	if len(recipients) != 32 {
		t.Fatal("joint fixture recipient count", len(recipients))
	}
	runGeneratedWholeSetScenario(t, ctx, env, false, false, 126, recipients)
}

func runParallelGeneratedCreates(t testing.TB, ctx context.Context, env fixtureEnvironment, before *StateSession,
	reservation *generatedPreparation, originalIDs [2]contract.ID, choice uint8) (*StateSession, contract.GeneratorResultExpectation, contract.GeneratorResultExpectation, []byte, []byte) {
	t.Helper()
	g, err := reservation.reservation.state.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstID, secondID := originalIDs[0], originalIDs[1]
	if firstID.IsZero() || secondID.IsZero() || firstID == secondID ||
		len(reservation.reservation.originalAttempts) != 2 || reservation.reservation.originalAttempts[0] != firstID ||
		reservation.reservation.originalAttempts[1] != secondID ||
		g.attempts[firstID].expected.Template.Action != contract.GeneratorActionCreate ||
		g.attempts[secondID].expected.Template.Action != contract.GeneratorActionCreate {
		t.Fatal("original producers differ from the exact request bindings")
	}
	firstKeys, secondKeys := env.Custody, env.Custody.ForkGenerated(t)
	facts := acquireGeneratedProducerFixtureFacts(t, env, before, reservation)
	var firstProducer, secondProducer *generatedPreparation
	var first, second contract.GeneratorResultExpectation
	if live := env.GeneratedProcess; live != nil {
		firstProducer, first = preparePrivateGeneratedOriginalProcessProducerForAttempt(t, env, before, reservation, firstKeys, firstID, facts, live.Artifact, live.Configure)
		secondProducer, second = preparePrivateGeneratedOriginalProcessProducerForAttempt(t, env, before, reservation, secondKeys, secondID, facts, live.Artifact, live.Configure)
		if live.BeforeCreate != nil {
			for _, id := range []contract.ID{firstID, secondID} {
				if err := live.BeforeCreate(id); err != nil {
					t.Fatal(err)
				}
			}
		}
	} else {
		firstProducer, first = preparePrivateGeneratedOriginalProducerForAttempt(t, env, before, reservation, firstKeys, firstID, facts, choice, nil, nil)
		secondProducer, second = preparePrivateGeneratedOriginalProducerForAttempt(t, env, before, reservation, secondKeys, secondID, facts, choice, nil, nil)
	}
	if firstProducer.reservation.candidate.bindFirstSend(firstProducer, func(context.Context, contract.ID) contract.CryptoResultCode { return contract.CryptoSuccess }) ||
		secondProducer.reservation.candidate.bindFirstSend(secondProducer, func(context.Context, contract.ID) contract.CryptoResultCode { return contract.CryptoSuccess }) {
		t.Fatal("detached original gained first-send permission before complete set claim")
	}
	if selected, _ := before.selectCandidate(ctx, reservation.reservation.candidate); selected != nil {
		t.Fatal("incomplete original set selected the candidate")
	}
	if candidate, result := before.ClaimGeneratedOriginalSet(ctx, []*generatedPreparation{firstProducer}, env.Trust); candidate != nil || result.Outcome != AdmissionRefused {
		t.Fatal("incomplete original set claim", result)
	}
	if candidate, result := before.ClaimGeneratedOriginalSet(ctx, []*generatedPreparation{firstProducer, firstProducer}, env.Trust); candidate != nil || result.Outcome != AdmissionRefused {
		t.Fatal("duplicate original producer claim", result)
	}
	wrongOwner := *secondProducer
	wrongOwner.reservation = &generatedReservation{state: secondProducer.reservation.state, candidate: secondProducer.reservation.candidate}
	if candidate, result := before.ClaimGeneratedOriginalSet(ctx, []*generatedPreparation{firstProducer, &wrongOwner}, env.Trust); candidate != nil || result.Outcome != AdmissionRefused {
		t.Fatal("mixed original producer owners", result)
	}
	if candidate, result := before.ClaimGeneratedOriginalSet(ctx, []*generatedPreparation{firstProducer, secondProducer}, env.Trust); candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("parallel original set claim", result)
	}
	var firstResult, secondResult []byte
	var firstFacts, secondFacts contract.GeneratorSafeFacts
	var firstCode, secondCode contract.CryptoResultCode
	var firstPersist, secondPersist Result
	if !firstProducer.reservation.candidate.bindFirstSend(firstProducer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		var joined sync.WaitGroup
		joined.Add(2)
		go func() {
			defer joined.Done()
			firstResult, firstFacts, firstCode = firstKeys.InvokeGeneratedProducer(ctx, firstProducer.operation.context.AdmissionID, firstProducer.producerLocator, authority)
			if firstCode == contract.CryptoSuccess && len(firstResult) != 0 {
				firstPersist = reservation.reservation.state.persistGeneratedResult(ctx, generatedResultWrite{attempt: firstID, body: firstResult})
			}
		}()
		go func() {
			defer joined.Done()
			secondResult, secondFacts, secondCode = secondKeys.InvokeGeneratedProducer(ctx, secondProducer.operation.context.AdmissionID, secondProducer.producerLocator, authority)
			if secondCode == contract.CryptoSuccess && len(secondResult) != 0 {
				secondPersist = reservation.reservation.state.persistGeneratedResult(ctx, generatedResultWrite{attempt: secondID, body: secondResult})
			}
		}()
		joined.Wait()
		if firstCode != contract.CryptoSuccess {
			return firstCode
		}
		if firstPersist.Outcome != 0 || secondPersist.Outcome != 0 {
			return contract.CryptoCustodyUnavailable
		}
		return secondCode
	}) {
		t.Fatal("parallel producer handoff")
	}
	selected, result := before.selectCandidate(ctx, firstProducer.reservation.candidate)
	if live := env.GeneratedProcess; live != nil {
		if live.AfterCreate != nil {
			for _, returned := range []struct {
				id    contract.ID
				facts contract.GeneratorSafeFacts
			}{{firstID, firstFacts}, {secondID, secondFacts}} {
				if (len(returned.facts.ResourceData) > 0) && !generatedFactsResourceDigest(returned.facts).IsZero() {
					if err := live.AfterCreate(returned.id, returned.facts); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
	firstKeys.RetireGenerated()
	secondKeys.RetireGenerated()
	if selected == nil || result.Outcome != ObservedCurrent || firstCode != contract.CryptoSuccess || secondCode != contract.CryptoSuccess ||
		len(firstResult) == 0 || len(secondResult) == 0 {
		t.Fatal("parallel producer selection", result.Outcome, result.Reason, firstCode, secondCode, len(firstResult), len(secondResult), firstFacts.Disposition, firstFacts.Reason, secondFacts.Disposition, secondFacts.Reason, firstPersist.Outcome, secondPersist.Outcome)
	}
	if env.GeneratedProcess != nil && (firstFacts.Disposition != 1 || secondFacts.Disposition != 1 || len(firstFacts.ResourceData) == 0 || len(secondFacts.ResourceData) == 0 ||
		generatedFactsResourceDigest(firstFacts).IsZero() || generatedFactsResourceDigest(secondFacts).IsZero()) {
		t.Fatal("parallel provider creates lack qualified results")
	}
	return selected, first, second, firstResult, secondResult
}

func runGeneratedWholeSetScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, mixed, retained bool, largeCount int,
	selectedRecipients []contract.ID) {
	t.Helper()
	if env.Context == nil {
		env.Context = ctx
	}
	// Generated fixture helpers inspect their in-memory Store for exact owned
	// objects. Keep that Store concrete; phase callbacks still bind every
	// action to the shared runner plan.
	r := &scenarioRun{t: t, ctx: ctx, env: env, spy: &scenarioSpy{}}
	keys := env.Custody
	plainValue := []byte("mixed public value")
	sealedChoice := custody.AlternateStandardValue
	var f *environmentFixture
	var reservation *generatedPreparation
	var originalIDs [2]contract.ID
	var beforeReceipts contract.MutationReceiptWindows
	var terminalOrder []contract.ID
	r.phase("setup", func() {
		f = newEnvironmentFixture(t, ctx, r.env, nil, false)
		var sources []contract.GeneratorDeclarationEntry
		var canonical []custody.GeneratedCanonicalSelection
		if retained {
			candidate := r.suppliedPreparation(f, []ApplyEntryInput{suppliedSecret(t, env, "retained", "generated mixed retained", custody.StandardValue)})
			if result := f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent {
				t.Fatal("retained fixture selection", result)
			}
			selected, result := Open(ctx, f.admission, r.env.Store)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("retained fixture reopen", result)
			}
			f.session = selected
			selection := sessionConsumerSelection(t, f.session, f.session.admission.recipient, "retained")
			record := contract.RetainedCanonicalRecord{OriginalSlot: selection.Slot, Entry: selection.Entry}
			body, err := contract.EncodeRetainedCanonicalRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			sources = append(sources, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
				Name: "retained", Recipients: record.Entry.Recipients, Payload: body})
			canonical = append(canonical, custody.GeneratedCanonicalSelection{Selection: selection, Record: record})
		}
		if mixed {
			secret := suppliedSecret(t, env, "sealed", "generated mixed sealed", sealedChoice)
			sources = append(sources,
				contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain, Name: "plain",
					Recipients: []contract.ID{f.session.admission.recipient}, Payload: bytes.Clone(plainValue)},
				contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: secret.Name,
					Recipients: secret.Recipients, Payload: secret.InputBytes})
		}
		if largeCount != 0 {
			for i := 0; i < largeCount; i++ {
				name := fmt.Sprintf("large-%03d", i)
				choice := custody.MaximumValue
				if largeCount == 65 && i == 64 {
					choice = custody.AlternateMaximumValue
				}
				secret := suppliedSecret(t, env, name, name+" generated batch", choice, selectedRecipients...)
				sources = append(sources, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed,
					Name: secret.Name, Recipients: secret.Recipients, Payload: secret.InputBytes})
			}
		}
		input := generatedPlanInputForGenerations(t, f.session, generatedVectorID(10), []string{"alpha", "omega"}, defaultGeneratedFixtureProfile(), sources...)
		if len(selectedRecipients) != 0 {
			input = generatedPlanInputForGenerationsMembershipIntent(t, f.session, generatedVectorID(10), []string{"alpha", "omega"},
				selectedRecipients, []byte(`{"name":"generated"}`), defaultGeneratedFixtureProfile(), sources...)
		}
		if live := env.GeneratedProcess; live != nil {
			profile := liveGeneratedProfile(t, live.Implementation, contract.GeneratedRetirementManual)
			input = generatedPlanInputForGenerationsIntent(t, f.session, generatedVectorID(10), []string{"alpha", "omega"}, live.Intent, profile, sources...)
			for i := range input.requestBindings {
				input.requestBindings[i].Digest = live.RequestDigest
			}
		}
		if len(input.requestBindings) != 2 {
			t.Fatal("whole-set fixture requires two original request bindings")
		}
		originalIDs = [2]contract.ID{input.requestBindings[0].AttemptID, input.requestBindings[1].AttemptID}
		var err error
		beforeReceipts, err = f.session.receiptWindows(ctx)
		if err != nil {
			t.Fatal("whole-set predecessor receipt order", err)
		}
		reservation, _ = preparePrivateGeneratedReservation(t, r.env, f.session, input, canonical)
	})

	var selected *StateSession
	r.phase("transition", func() {
		var first, second contract.GeneratorResultExpectation
		var firstResult, secondResult []byte
		choice := custody.StandardValue
		if largeCount == 126 {
			choice = custody.MaximumValue
		}
		selected, first, second, firstResult, secondResult = runParallelGeneratedCreates(t, ctx, r.env, f.session, reservation, originalIDs, choice)
		assertGeneratedReceiptOrder(t, ctx, selected, beforeReceipts.Order)

		keys.RetireGenerated()
		firstPlan, err := selected.generatedRecordRequest(context.Background(), first.Template.AttemptID, firstResult, generatedPlanInputFixture(t, selected).context)
		if err != nil {
			t.Fatal("first record request", err)
		}
		firstRecord := preparePrivateGeneratedRecord(t, r.env, selected, firstPlan)
		var res Result
		selected, res = selected.selectCandidate(ctx, firstRecord.reservation.candidate)
		if selected == nil || res.Outcome != ObservedCurrent {
			t.Fatal("first record selection", res)
		}
		assertGeneratedReceiptOrder(t, ctx, selected, beforeReceipts.Order)

		keys.RetireGenerated()
		if env.GeneratedProcess != nil {
			selected = env.FreshGeneratedRecord(t, selected, second.Template.AttemptID, secondResult)
		} else {
			secondContext := generatedPlanInputFixture(t, selected).context
			secondContext.AdmissionID, secondContext.SessionID = testID("second generated record admission"), testID("second generated record session")
			secondPlan, err := selected.generatedRecordRequest(context.Background(), second.Template.AttemptID, secondResult, secondContext)
			if err != nil {
				t.Fatal("second record request", err)
			}
			secondRecord := preparePrivateGeneratedRecord(t, r.env, selected, secondPlan)
			selected, res = selected.selectCandidate(ctx, secondRecord.reservation.candidate)
			if selected == nil || res.Outcome != ObservedCurrent {
				t.Fatal("second record selection", res)
			}
		}
		assertGeneratedReceiptOrder(t, ctx, selected, beforeReceipts.Order)

		keys.RetireGenerated()
		finalContext := generatedPlanInputFixture(t, selected).context
		finalContext.AdmissionID, finalContext.SessionID = testID("generated final admission"), testID("generated final session")
		finalPlan, err := selected.generatedFinalRequest(t.Context(), finalContext)
		if err != nil {
			t.Fatal("final request", err)
		}
		g, err := selected.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(finalPlan.entryPlans) != 2 {
			t.Fatal("whole-set Final must prepare both generated entries", len(finalPlan.entryPlans))
		}
		incompleteInput := generatedFinalInput(ctx, t, selected, g, finalPlan.results[0].attempt.record.AttemptID)
		incompleteInput.Plan.Canonical = generatedCanonicalInputs(t, selected, g, incompleteInput.Plan.Declaration)
		incompleteInput.ExpectedResults = make([]contract.GeneratorResultExpectation, len(finalPlan.results))
		incompleteInput.ResultBodies = make([][]byte, len(finalPlan.results))
		references := make([]contract.GeneratorResultReference, len(finalPlan.results))
		for i := range finalPlan.results {
			incompleteInput.ExpectedResults[i], incompleteInput.ResultBodies[i], references[i] = finalPlan.results[i].attempt.expected,
				finalPlan.results[i].attempt.result, finalPlan.results[i].reference
		}
		// Empty entry admissions describe nonselecting preparation. This
		// selecting control omits one of the two required generated entries.
		incompleteEntries := []custody.GeneratedEntryAdmission{{Slot: finalPlan.entryPlans[0].Slot, Generated: finalPlan.entryPlans[0].Generated}}
		public, private := keys.Calls()
		if err := keys.AdmitGeneratedValueEntries(finalPlan.request, currentControlOf(selected), incompleteInput, finalPlan.phase,
			references, incompleteEntries, time.Unix(0, int64(finalPlan.request.Context.Expiry))); err == nil {
			t.Fatal("successful aggregate admitted an incomplete selecting entry set")
		}
		if p, k := keys.Calls(); p != public || k != private {
			t.Fatal("incomplete selecting entry admission entered key access", p-public, k-private)
		}
		var final *generatedPreparation
		parentOperation := selected.root.Generated.ActiveOwner
		if parentOperation.IsZero() {
			t.Fatal("whole-set Final has no selected parent")
		}
		selected, final = preparePrivateGeneratedFinal(t, r.env, selected, finalPlan)
		selected, res = selected.selectCandidate(ctx, final.reservation.candidate)
		wantEntryCount, wantAccess := uint32(2), uint32(2)
		if mixed {
			wantEntryCount, wantAccess = 4, 3
		}
		if retained {
			wantEntryCount++
			wantAccess++
		}
		if largeCount != 0 {
			wantEntryCount, wantAccess = uint32(largeCount+2), uint32(largeCount+2)
		}
		if selected == nil || res.Outcome != ObservedCurrent || selected.root.ValueEntryCount != wantEntryCount || selected.root.Generated.GeneratedCurrent != 2 ||
			!selected.root.Generated.ActiveOwner.IsZero() || selected.root.AccessRecordCount != wantAccess {
			t.Fatal("whole generated set selection", res)
		}
		afterReceipts, err := selected.receiptWindows(ctx)
		if err != nil || len(afterReceipts.Successes) != len(beforeReceipts.Successes)+1 || len(afterReceipts.Failures) != len(beforeReceipts.Failures) || afterReceipts.Successes[len(afterReceipts.Successes)-1].OperationID != parentOperation {
			t.Fatal("whole-set Final did not append exactly its parent success receipt", err)
		}
		assertSuccessReceiptOrder(t, beforeReceipts, afterReceipts, parentOperation)
		terminalOrder = slices.Clone(afterReceipts.Order)
		if len(selectedRecipients) != 0 && (selected.root.RawBytes != contract.CryptoMaxRawSet || selected.root.MembershipCount != contract.CryptoMaxMemberships ||
			selected.root.SecretOrdinaryWrapCount != contract.CryptoMaxMemberships) {
			t.Fatal("joint raw and membership limit", selected.root.RawBytes, selected.root.MembershipCount, selected.root.SecretOrdinaryWrapCount)
		}
	})
	want := sessionStateImage(t, selected)
	r.phase("verification", func() {
		cold, res := Open(ctx, f.admission, r.env.Store)
		if cold == nil || res.Outcome != ObservedCurrent {
			t.Fatal("cold whole-set selection", res)
		}
		if cold.head.Core != selected.head.Core {
			t.Fatal("cold whole-set HEAD Core differs")
		}
		assertGeneratedReceiptOrder(t, ctx, cold, terminalOrder)
		if err := cold.validateGeneratedSelection(t.Context(), nil); err != nil {
			t.Fatal("cold whole-set generated selection", err)
		}
		consumeSupplied := func(name string, choice uint8) {
			selection := sessionConsumerSelection(t, cold, cold.admission.recipient, name)
			check := keys.Consume(ctx, selection, choice)
			if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 ||
				len(check.KeyUses) != 1 || check.KeyUses[0].SubjectID != cold.admission.recipient {
				t.Fatal("cold supplied value differs", name, check)
			}
		}
		for _, name := range []string{"alpha", "omega"} {
			index := slices.IndexFunc(cold.root.Names, func(entry format.NameEntry) bool { return entry.Name == name })
			if index < 0 {
				t.Fatal("selected member missing", name)
			}
			valueEntry := cold.valueEntry(cold.root.Names[index].Slot)
			if valueEntry == nil || valueEntry.ValueSource != contract.Generated || valueEntry.ConfidentialityClass != contract.Secret {
				t.Fatal("selected member differs", name)
			}
		}
		if mixed {
			for name, confidentialityClass := range map[string]uint8{"plain": contract.Plain, "sealed": contract.Secret} {
				index := slices.IndexFunc(cold.root.Names, func(entry format.NameEntry) bool { return entry.Name == name })
				if index < 0 {
					t.Fatal("mixed supplied member missing", name)
				}
				valueEntry := cold.valueEntry(cold.root.Names[index].Slot)
				if valueEntry == nil || valueEntry.ValueSource != contract.Supplied || valueEntry.ConfidentialityClass != confidentialityClass {
					t.Fatal("mixed supplied member differs", name)
				}
				if name == "plain" && !bytes.Equal(valueEntry.ValueBytes, plainValue) {
					t.Fatal("cold supplied plain value differs")
				}
			}
			consumeSupplied("sealed", sealedChoice)
		}
		if retained {
			index := slices.IndexFunc(cold.root.Names, func(entry format.NameEntry) bool { return entry.Name == "retained" })
			if index < 0 {
				t.Fatal("retained supplied member missing")
			}
			valueEntry := cold.valueEntry(cold.root.Names[index].Slot)
			if valueEntry == nil || valueEntry.ValueSource != contract.Supplied || valueEntry.ConfidentialityClass != contract.Secret {
				t.Fatal("retained supplied member differs")
			}
			consumeSupplied("retained", custody.StandardValue)
		}
		if largeCount != 0 {
			for i := 0; i < largeCount; i++ {
				name := fmt.Sprintf("large-%03d", i)
				index := slices.IndexFunc(cold.root.Names, func(entry format.NameEntry) bool { return entry.Name == name })
				if index < 0 {
					t.Fatal("batched supplied member missing", name)
				}
				valueEntry := cold.valueEntry(cold.root.Names[index].Slot)
				if valueEntry == nil || valueEntry.ValueSource != contract.Supplied || valueEntry.ConfidentialityClass != contract.Secret {
					t.Fatal("batched supplied member differs", name)
				}
			}
			if largeCount == 65 {
				consumeSupplied("large-000", custody.MaximumValue)
				consumeSupplied("large-064", custody.AlternateMaximumValue)
			}
		}
		assertStateImage(t, cold, want)
	})
	r.phase("reopen", func() {
		if r.env.FreshCurrent == nil {
			t.Fatal("generated scenario requires fresh-process verification")
		}
		r.env.FreshCurrent(t, f.admission, selected)
		if t.Failed() {
			t.FailNow()
		}
	})
}

func assertGeneratedReceiptOrder(t testing.TB, ctx context.Context, selected *StateSession, want []contract.ID) contract.MutationReceiptWindows {
	t.Helper()
	if selected == nil {
		t.Fatal("receipt order assertion has no selected generated state")
	}
	windows, err := selected.receiptWindows(ctx)
	if err != nil || !slices.Equal(windows.Order, want) {
		t.Fatal("selected generated transition changed exact predecessor receipt order", err)
	}
	return windows
}

// full_only: false
func TestGeneratedExhaustedUnknownPrivateFinalRequiresExactTerminalSupport(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	input := generatedPlanInputForGenerations(t, f.session, generatedVectorID(10), []string{"alpha"}, defaultGeneratedFixtureProfile())
	reservation, _ := preparePrivateGeneratedReservation(t, env, f.session, input, nil)
	producer, _ := preparePrivateGeneratedProducer(t, env, f.session, reservation, nil)
	if !producer.reservation.candidate.bindFirstSend(producer, func(context.Context, contract.ID) contract.CryptoResultCode { return contract.CryptoSuccess }) {
		t.Fatal("unknown producer handoff")
	}
	selected, res := f.session.selectCandidate(ctx, producer.reservation.candidate)
	if selected == nil || res.Outcome != ObservedCurrent {
		t.Fatal("unknown producer selection", res)
	}

	unknown := generatedExhaustedUnknownState(t, selected)
	// The state mutator installs a read-only support reader. Private Claim must
	// persist its candidate through the original admitted writable Store.
	fixtureStore, ok := unknown.store.(*generatedFixtureSupportStore)
	if !ok {
		t.Fatal("unknown fixture support Store type")
	}
	store := env.Store.(*memoryStore)
	for key, body := range fixtureStore.objects {
		if object, exists := store.objects[key]; exists {
			if !bytes.Equal(object.Body, body) {
				t.Fatal("unknown fixture support conflicts with immutable Store object")
			}
			continue
		}
		store.objects[key] = stored{Body: bytes.Clone(body), Token: unknown.token}
	}
	unknown.store = store
	finalContext := generatedContinuationContext(t, unknown, 81, 82)
	finalContext.AdmissionID, finalContext.SessionID = testID("unknown final admission"), testID("unknown final session")
	plan, err := unknown.generatedFinalRequest(t.Context(), finalContext)
	if err != nil || plan.selecting || len(plan.results) != 0 || len(plan.entryPlans) != 0 {
		t.Fatal("unknown final request", err)
	}
	_, final := preparePrivateGeneratedFinal(t, env, unknown, plan)
	closure := final.reservation.state
	if closure.validateGeneratedSelection(t.Context(), nil) != nil || closure.root.Generated.Attempts != 2 || closure.root.Generated.Hazards != 2 ||
		closure.root.Generated.Duties != 0 || !closure.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("private unknown final lost exact terminal support")
	}
}

// full_only: false
func TestGeneratedTerminalFailureClosesAfterEveryOriginalResult(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	beforeReceipts, err := f.session.receiptWindows(ctx)
	if err != nil {
		t.Fatal("failed generated predecessor receipt order", err)
	}
	input := generatedPlanInputForGenerations(t, f.session, generatedVectorID(10), []string{"alpha", "omega"}, defaultGeneratedFixtureProfile())
	reservation, _ := preparePrivateGeneratedReservation(t, env, f.session, input, nil)

	if len(input.requestBindings) != 2 {
		t.Fatal("terminal failure fixture requires two original attempts")
	}
	secondKeys := keys.ForkGenerated(t)
	t.Cleanup(keys.RetireGenerated)
	t.Cleanup(secondKeys.RetireGenerated)
	facts := acquireGeneratedProducerFixtureFacts(t, env, f.session, reservation)
	producer, first := preparePrivateGeneratedOriginalProducerForAttempt(t, env, f.session, reservation,
		keys, input.requestBindings[0].AttemptID, facts, custody.StandardValue, nil, nil)
	secondProducer, second := preparePrivateGeneratedOriginalProducerForAttempt(t, env, f.session, reservation,
		secondKeys, input.requestBindings[1].AttemptID, facts, custody.GeneratedTerminalFailure, nil, nil)
	if candidate, result := f.session.ClaimGeneratedOriginalSet(ctx, []*generatedPreparation{producer, secondProducer}, env.Trust); candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("complete original producer set", result)
	}
	var firstResult []byte
	var authority contract.ID
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, accepted contract.ID) contract.CryptoResultCode {
		authority = accepted
		var code contract.CryptoResultCode
		firstResult, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("first producer handoff")
	}
	selected, res := f.session.selectCandidate(ctx, producer.reservation.candidate)
	if selected == nil || res.Outcome != ObservedCurrent || len(firstResult) == 0 || authority.IsZero() {
		t.Fatal("first producer selection", res)
	}
	assertGeneratedReceiptOrder(t, ctx, selected, beforeReceipts.Order)

	keys.RetireGenerated()
	firstContext := generatedPlanInputFixture(t, selected).context
	firstContext.AdmissionID, firstContext.SessionID = testID("terminal first Record admission"), testID("terminal first Record session")
	firstPlan, err := selected.generatedRecordRequest(context.Background(), first.Template.AttemptID, firstResult, firstContext)
	if err != nil {
		t.Fatal(err)
	}
	firstRecord := preparePrivateGeneratedRecord(t, env, selected, firstPlan)
	selected, res = selected.selectCandidate(ctx, firstRecord.reservation.candidate)
	if selected == nil || res.Outcome != ObservedCurrent {
		t.Fatal("first record selection", res)
	}
	assertGeneratedReceiptOrder(t, ctx, selected, beforeReceipts.Order)
	work := mustSelectedGeneratedWork(t, selected)
	if work.phase.FrontierAttemptID != second.Template.AttemptID {
		t.Fatal("first Record did not advance to the retained second original")
	}
	// Record cannot recreate an original send. This caller keeps the second
	// original's claimed custody and the first selection's accepted authority.
	secondResult, secondFacts, code := secondKeys.InvokeGeneratedProducer(ctx, secondProducer.operation.context.AdmissionID, secondProducer.producerLocator, authority)
	if code != contract.CryptoSuccess || len(secondResult) == 0 || second.Template.AttemptID == first.Template.AttemptID ||
		secondFacts.Disposition != contract.GeneratorDispositionOwnedUnusableCreate {
		t.Fatal("retained second original terminal result", code, secondFacts.Disposition)
	}
	secondKeys.RetireGenerated()

	keys.RetireGenerated()
	secondContext := generatedPlanInputFixture(t, selected).context
	secondContext.AdmissionID, secondContext.SessionID = testID("terminal second Record admission"), testID("terminal second Record session")
	secondPlan, err := selected.generatedRecordRequest(context.Background(), second.Template.AttemptID, secondResult, secondContext)
	if err != nil {
		t.Fatal(err)
	}
	secondRecord := preparePrivateGeneratedRecord(t, env, selected, secondPlan)
	selected, res = selected.selectCandidate(ctx, secondRecord.reservation.candidate)
	if selected == nil || res.Outcome != ObservedCurrent {
		t.Fatal("second record selection", res)
	}
	assertGeneratedReceiptOrder(t, ctx, selected, beforeReceipts.Order)

	keys.RetireGenerated()
	finalContext := generatedPlanInputFixture(t, selected).context
	finalContext.AdmissionID, finalContext.SessionID = testID("failed generated final admission"), testID("failed generated final session")
	finalPlan, err := selected.generatedFinalRequest(t.Context(), finalContext)
	if err != nil || finalPlan.selecting || len(finalPlan.entryPlans) != 0 || len(finalPlan.results) != 2 {
		t.Fatal("failed final request", err)
	}
	parentOperation := selected.root.Generated.ActiveOwner
	if parentOperation.IsZero() {
		t.Fatal("failed Final has no selected parent")
	}
	selected, final := preparePrivateGeneratedFinal(t, env, selected, finalPlan)
	selected, res = selected.selectCandidate(ctx, final.reservation.candidate)
	if selected == nil || res.Outcome != ObservedCurrent || selected.root.ValueEntryCount != 0 || selected.root.Generated.GeneratedCurrent != 0 ||
		selected.root.Generated.Duties != 1 || selected.root.Generated.Materials != 1 ||
		!selected.root.Generated.ActiveOwner.IsZero() || !selected.root.Generated.ActivePhase.IsZero() || !selected.root.Generated.ActiveGraph.IsZero() {
		t.Fatal("nonselecting generated closure", res)
	}
	wantOrder := append(slices.Clone(beforeReceipts.Order), parentOperation)
	afterReceipts := assertGeneratedReceiptOrder(t, ctx, selected, wantOrder)
	if !slices.Equal(afterReceipts.Successes, beforeReceipts.Successes) || len(afterReceipts.Failures) != len(beforeReceipts.Failures)+1 || afterReceipts.Failures[len(afterReceipts.Failures)-1].OperationID != parentOperation {
		t.Fatal("failed Final did not append exactly its parent failure receipt")
	}
	cold, res := Open(ctx, f.admission, env.Store)
	if cold == nil || res.Outcome != ObservedCurrent || cold.head.Core != selected.head.Core || cold.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("cold nonselecting closure", res)
	}
	assertGeneratedReceiptOrder(t, ctx, cold, wantOrder)
}
