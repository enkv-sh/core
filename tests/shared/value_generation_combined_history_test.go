package core

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func runGeneratedCombinedLifecycleRecoveryScenario(t testing.TB, ctx context.Context, env fixtureEnvironment) {
	t.Helper()
	if env.Custody == nil || env.ReplacementActors == nil || env.CurrentConsume == nil || env.FreshCurrent == nil || env.FreshGeneratedRecord == nil {
		t.Fatal("combined generated history callbacks are incomplete")
	}
	run := newScenarioRun(t, ctx, env)
	authority, reader := fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")
	shared := []contract.ID{authority, reader}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	var f *environmentFixture
	run.phase("setup", func() { f = newEnvironmentFixture(t, ctx, run.env, []int{1}, false) })
	run.phase("transition", func() {
		beforeState := observeSelectedState(t, f.session)
		plainSlot, plain := observeCurrentValueEntry(t, f.session, beforeState.Root.Names[0].Name)
		input := beforeState.entryInputs()
		input[0].InputBytes = []byte("combined generated plain update")
		input[0].Recipients = shared
		input = append(input, sharingSecret(t, env, "combined generated shared source", shared))
		run.suppliedSelection(f, input)
		selectedSlot, selectedPlain := observeCurrentValueEntry(t, f.session, plain.Name)
		selectedState := observeSelectedState(t, f.session)
		if selectedSlot != plainSlot || selectedPlain.Incarnation != plain.Incarnation ||
			!bytes.Equal(selectedPlain.ValueBytes, input[0].InputBytes) || !slices.Equal(selectedPlain.Recipients, shared) ||
			selectedState.Root.ValueEntryCount != 2 || selectedState.Root.SecretCount != 1 {
			t.Fatal("combined mixed selection changed stable plain identity or complete membership")
		}
		// Equal plaintext in a newly sealed envelope must still be a semantic
		// no-op. It must not select new canonical material or consume entropy.
		originalSource := input[1]
		input[1] = sharingSecret(t, env, "combined generated equal source", shared)
		if bytes.Equal(originalSource.InputBytes, input[1].InputBytes) {
			t.Fatal("combined equal source was not freshly sealed")
		}
		parent := admitSuppliedComparison(t, f.session, env.Custody, input)
		before := observeSelectedState(t, f.session)
		wantEffects := observeScenarioEffects(run.spy)
		wantEffects.StoreRead += 2 * uint64(before.Root.OutputConfiguration.SliceCount)
		comparison, result, remainingEntropy, prepared := compareGeneratedScenarioWithoutEntropy(ctx, f.session, input, parent)
		if comparison != nil || result.Outcome != Unchanged || prepared || remainingEntropy != 32 || observeScenarioEffects(run.spy) != wantEffects {
			t.Fatal("combined equal source changed canonical state or selected effects", result)
		}
		env.Custody.RetireApply()
		assertStateImage(t, f.session, before)
	})
	var successorReader contract.ConsumerSelection
	var predecessorReader contract.ConsumerSelection
	run.phase("transition", func() {
		predecessorReader = sessionConsumerSelection(t, f.session, reader, "secret")
		check := env.readerConsume(predecessorReader, custody.StandardValue)
		if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 ||
			len(check.KeyUses) != 1 || check.KeyUses[0].SubjectID != reader || check.KeyUses[0].BindingID != predecessorReader.Binding.Binding.BindingID {
			t.Fatal("combined original reader did not use its exact private route", check)
		}
		_, successorReader = replaceReaderInSelected(t, ctx, run, f)
	})
	run.phase("verification", func() {
		stale := env.readerConsume(predecessorReader, custody.StandardValue)
		if stale.Code == contract.CryptoSuccess || stale.Delivery != 0 || stale.SinkCalls != 0 || stale.ValueMatched {
			t.Fatal("combined lost reader binding still delivered plaintext", stale)
		}
		check := env.readerSuccessorConsume(successorReader, custody.StandardValue)
		if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
			t.Fatal("combined generated reader successor", check)
		}
	})
	var producer *generatedScenarioProducer
	var inputs generatedScenarioInputs
	var resultBody []byte
	run.phase("transition", func() {
		entries, canonical := generatedCurrentDeclaration(t, f.session)
		input := generatedPlanInputForProfile(t, f.session, generatedVectorID(10), defaultGeneratedFixtureProfile(), entries...)
		inputs = captureGeneratedScenarioInputs(t, input, contract.ID{})
		producer = mustPrepareGeneratedScenarioProducer(t, env, f.session, input, canonical, inputs)
		selected, result := producer.selectCandidate(ctx, f.session)
		var sends int
		resultBody, sends = producer.observation()
		if selected == nil || result.Outcome != ObservedCurrent || len(resultBody) == 0 || sends != 1 {
			t.Fatal("combined generated first entry", result)
		}
		f.session = selected
		env.Custody.RetireGenerated()
	})
	run.phase("transition", func() {
		approval := uint8(contract.NormalSigningRole)
		if env.Recovery != nil {
			approval = contract.RecoverySigningRole
		}
		selectGeneratedAccessReplacement(t, ctx, run, f, 1, 2, approval)
	})
	run.phase("verification", func() {
		attempt, err := observeGeneratedAttempt(ctx, f.session, inputs.expected.Template.AttemptID)
		if err != nil || !attempt.present || attempt.expected != inputs.expected || attempt.record.State != contract.GeneratedEffectTransmitted ||
			attempt.record.Stage != contract.GeneratedStageRetainedResult {
			t.Fatal("combined replacement lost entered generated work", err)
		}
	})
	run.phase("transition", func() {
		if env.FreshGeneratedRecord == nil {
			t.Fatal("combined history requires a fresh generated record route")
		}
		f.session = env.FreshGeneratedRecord(t, f.session, inputs.expected.Template.AttemptID, resultBody)
	})
	run.phase("verification", func() {
		attempt, err := observeGeneratedAttempt(ctx, f.session, inputs.expected.Template.AttemptID)
		_, sends := producer.observation()
		if err != nil || !attempt.present || attempt.expected != inputs.expected || !bytes.Equal(attempt.result, resultBody) || sends != 1 ||
			attempt.record.State != contract.GeneratedEffectSucceeded || attempt.record.Stage != contract.GeneratedStageTerminal {
			t.Fatal("combined late generated result changed", err)
		}
		if repeated, code := producer.replay(ctx); code == contract.CryptoSuccess || len(repeated) != 0 {
			t.Fatal("combined late result restored first-send permission")
		}
		if _, sends := producer.observation(); sends != 1 {
			t.Fatal("combined late result repeated the first-send handoff")
		}
	})
	var refusedOperation contract.ID
	var recoveryReceipt receiptExpectation
	run.phase("transition", func() {
		if env.Recovery == nil {
			refusedOperation = refuseGeneratedRecoveryWithoutConfiguredCapability(t, ctx, run, f.session)
			return
		}
		recoveryReceipt.OperationID, recoveryReceipt.Body = selectGeneratedAccessReplacement(t, ctx, run, f, 3, 8, contract.NormalSigningRole)
	})
	var closed *StateSession
	run.phase("verification", func() {
		if env.Recovery == nil {
			if body, result := f.session.MutationReceipt(ctx, refusedOperation); body != nil || result != refused(AdmissionInvalid) {
				t.Fatal("disabled generated recovery refusal became selected", result)
			}
		}
		if env.Recovery != nil {
			body, result := f.session.MutationReceipt(ctx, recoveryReceipt.OperationID)
			if result.Outcome != ObservedCurrent || !bytes.Equal(body, recoveryReceipt.Body) {
				t.Fatal("combined generated recovery receipt changed before closure", result)
			}
		}
		final := mustPrepareGeneratedScenarioFinal(t, env, f.session, testID("combined generated final admission"), testID("combined generated final session"))
		var result Result
		closed, result = final.selectCandidate(ctx)
		if closed == nil || result.Outcome != ObservedCurrent {
			t.Fatal("combined generated final selection", result)
		}
		state := observeSelectedState(t, closed)
		_, sends := producer.observation()
		if !state.Root.Generated.ActiveOwner.IsZero() || state.Root.ValueEntryCount != 3 || state.Root.Generated.GeneratedCurrent != 1 || sends != 1 {
			t.Fatal("combined generated final closure or first-send count")
		}
		if env.Recovery != nil {
			body, result := closed.MutationReceipt(ctx, recoveryReceipt.OperationID)
			if result.Outcome != ObservedCurrent || !bytes.Equal(body, recoveryReceipt.Body) {
				t.Fatal("combined final closure changed its recovery receipt", result)
			}
		}
		f.session = closed
	})
	run.phase("reopen", func() { env.FreshCurrent(t, f.admission, closed) })
}
