package core

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedFinalDifferentNameSlotReuse(t *testing.T) {
	for _, history := range []string{"supplied-to-supplied", "supplied-to-generated", "generated-to-supplied", "plain-to-secret"} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovery=%t", history, recovery), func(t *testing.T) {
				env, keys := genesisEnvironment(t, contract.GCP, recovery)
				env = syntheticAuthorityScenarioEnvironment(t, env)
				run := newScenarioRun(t, t.Context(), env)
				fixture := newEnvironmentFixture(t, t.Context(), run.env, nil, false)
				readers := []contract.ID{fixture.session.admission.recipient, fixtureID(env.Domain, "reader")}
				slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				before := fixture.session
				if history == "generated-to-supplied" {
					initial := generatedPlanInputForGenerationsMembershipIntent(t, before, testID(t.Name()+" initial"), []string{"old"}, readers,
						[]byte(`{"name":"generated"}`), defaultGeneratedFixtureProfile())
					before = selectPrivateGeneratedOperationInProcess(t, env, before, initial, "slot reuse predecessor")
				} else {
					old := sharingSecretNamed(t, env, "old", "slot reuse shared predecessor", readers)
					if history == "plain-to-secret" {
						old = ApplyEntryInput{Name: "old", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: readers, InputBytes: []byte("public predecessor"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
					}
					before = run.suppliedSelection(fixture, []ApplyEntryInput{old})
				}
				before = generatedLifecycleReopen(t, t.Context(), before, env.Store)
				old := ownScenarioValueEntry(*before.valueEntry(0))
				var sources []contract.GeneratorDeclarationEntry
				generatedNames := []string{"a-new"}
				if history != "supplied-to-generated" {
					sealed := suppliedSecret(t, env, "a-new", "slot reuse fresh source", custody.EmptyValue)
					sources = []contract.GeneratorDeclarationEntry{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed,
						Name: sealed.Name, Recipients: sealed.Recipients, Payload: sealed.InputBytes}}
					generatedNames = []string{"z-effect"}
				}
				input := generatedPlanInputForGenerations(t, before, testID(t.Name()+" successor"), generatedNames, defaultGeneratedFixtureProfile(), sources...)
				if history == "generated-to-supplied" {
					state := generatedReservationInputForState(t, before, input.graph.Header.OperationID, generatedNames, defaultGeneratedFixtureProfile(), 0, nil,
						map[string]contract.ValueEntry{old.Name: old}, sources...)
					input.graph, input.declaration, input.registry = state.graph, state.declaration, state.graph.Request.Registry
					input.requestBindings = slices.Clone(state.requestBindings)
				}
				if input.graph.ValueEntryPlans[0].Name != "a-new" || input.graph.ValueEntryPlans[0].Slot != 0 ||
					input.graph.ValueEntryPlans[0].EntryIncarnationID == old.Incarnation {
					t.Fatal("declaration did not allocate a fresh name in the removed slot")
				}
				prior, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
				recorded, _, _, packet := selectActualGeneratedPacketRecord(t, env, before, prior, custody.StandardValue, true, nil)
				if len(packet) == 0 {
					t.Fatal("slot reuse did not execute and record its generated effect")
				}
				admitted := generatedPlanInputFixture(t, recorded).context
				admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" checkpoint"), testID(t.Name()+" checkpoint session")
				plan, err := recorded.generatedFinalRequest(t.Context(), admitted)
				if err != nil {
					t.Fatal("pre-checkpoint request", err)
				}
				permit := admitPrivateGeneratedFinal(t, env, recorded, plan)
				prepared, result := recorded.PrepareGeneratedFinal(t.Context(), permit)
				if prepared == nil || result.Outcome != ObservedCurrent {
					t.Fatal("pre-checkpoint preparation", result)
				}
				if code := keys.BindGeneratedCandidate(t.Context(), admitted.AdmissionID, generatedPrivateCandidate(t, prepared)); code != contract.CryptoSuccess {
					t.Fatal("checkpoint private binding", code)
				}
				candidate, result := recorded.ClaimGeneratedPreparation(t.Context(), prepared.reservation.candidate, env.Trust)
				if candidate == nil || result.Outcome != ObservedCurrent || candidate.head.Generator == nil || candidate.head.Generator.Purpose != contract.GeneratorAuthorityFinalPreparation {
					t.Fatal("checkpoint claim", result)
				}
				checkpoint, result := recorded.selectCandidate(t.Context(), candidate)
				if checkpoint == nil || result.Outcome != ObservedCurrent || !reflect.DeepEqual(recorded.currentEntryInputs(), checkpoint.currentEntryInputs()) {
					t.Fatal("checkpoint selection changed current values", result)
				}
				keys.RetireGenerated()
				checkpoint = generatedLifecycleReopen(t, t.Context(), checkpoint, env.Store)
				admitted = generatedPlanInputFixture(t, checkpoint).context
				admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" replay"), testID(t.Name()+" replay session")
				plan, err = checkpoint.generatedFinalRequest(t.Context(), admitted)
				if err != nil || plan.materialization == nil {
					t.Fatal("cold checkpoint request", err)
				}
				public, private := keys.Calls()
				checkpoint, final := preparePrivateGeneratedFinal(t, env, checkpoint, plan)
				wantOpens := 3 // operation seed, saved supplied value, saved generated value
				if history == "supplied-to-generated" {
					wantOpens = 2 // operation seed and saved generated value
				}
				assertSlotReuseReplayKeyUses(t, final.keyUses, uint32(wantOpens))
				afterPublic, afterPrivate := keys.Calls()
				if afterPublic != public || afterPrivate-private != wantOpens {
					t.Fatal("cold replay key-route census", afterPublic-public, afterPrivate-private, wantOpens)
				}
				selected, result := checkpoint.selectCandidate(t.Context(), final.reservation.candidate)
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal("actual Final selection", result)
				}
				keys.RetireGenerated()
				selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
				if len(selected.root.Names) != len(input.graph.ValueEntryPlans) {
					t.Fatal("Final selected a different whole value set")
				}
				for _, want := range input.graph.ValueEntryPlans {
					entry := selected.valueEntry(want.Slot)
					if entry == nil || entry.Name != want.Name || entry.Incarnation != want.EntryIncarnationID || entry.Incarnation == old.Incarnation ||
						entry.ValueSource != want.ValueSource || entry.ConfidentialityClass != contract.Secret || !slices.Equal(entry.Recipients, []contract.ID{selected.admission.recipient}) {
						t.Fatal("Final value identity, source or membership differs", want.Name)
					}
					choice := uint8(custody.StandardValue)
					if want.ValueSource == contract.Supplied {
						choice = custody.EmptyValue
					}
					if check := keys.Consume(t.Context(), sessionConsumerSelection(t, selected, selected.admission.recipient, want.Name), choice); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
						t.Fatal("Final selected a different exact value", want.Name, check)
					}
				}
			})
		}
	}
}

func assertSlotReuseReplayKeyUses(t testing.TB, uses []contract.KeyUseRow, wantOpens uint32) {
	t.Helper()
	var opens uint32
	for _, use := range uses {
		if use.Purpose != contract.KeyUseMaterialOpen || use.Outcome != contract.KeyUseCompleted {
			t.Fatal("replay performed an unexpected key use", use.Purpose, use.Outcome)
		}
		opens += use.Count
	}
	if opens != wantOpens {
		t.Fatal("replay opened an unrelated predecessor or missed a saved value", opens, wantOpens)
	}
}
