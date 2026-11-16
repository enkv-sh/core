package core

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedWriterFreshProcessKeepsFutureOutputProfileFacts(t *testing.T) {
	for _, transition := range []string{"writer", "final"} {
		t.Run(transition, func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, false)
			selected := newEnvironmentFixture(t, t.Context(), env, nil, false).session
			store := env.Store.(*memoryStore)
			if transition == "writer" {
				if err := store.useFileBodies(t.TempDir() + "/bodies"); err != nil {
					t.Fatal(err)
				}
			}
			intents := map[string][]byte{"alpha": hermeticGeneratorIntent([]byte("alpha exact writer intent")), "beta": hermeticGeneratorIntent([]byte("beta exact writer intent"))}
			first := generatedWriterPlanInput(t, selected, fixtureID(env.Domain, "output writer alpha"), []string{"alpha"},
				func(name string) []byte { return intents[name] }, 0, nil)
			selected = selectPrivateGeneratedOperationInProcess(t, env, selected, first, "output writer alpha")
			selected = generatedLifecycleReopen(t, t.Context(), selected, store)
			alpha := *selected.valueEntry(entrySlot(t, selected, "alpha"))
			currentTarget := outputConfigurationTarget("alpha", "app-alpha")
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{currentTarget}}},
				routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"app"}}}}
			selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, env.Custody, selected.currentEntryInputs(), output)
			before, result := selected.currentOutputConfigurationForApply(t.Context())
			if result.Outcome != 0 || len(before.Bindings) != 1 || len(before.Bindings[0].Targets) != 1 ||
				before.Bindings[0].Targets[0].EntryIncarnationID != alpha.Incarnation ||
				!reflect.DeepEqual(before.DefaultDestinations, []string{"app"}) || len(before.Routes) != 0 {
				t.Fatal("writer initial output is not the exact alpha-only default source", result)
			}

			// The parent knows beta's derivation before beta exists in selected state.
			futureTarget := outputConfigurationTarget("beta", "app-beta")
			definitions := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", destination: before.Bindings[0].Destination,
				targets: []outputApplyTarget{currentTarget, futureTarget}}}}
			installOutputFixtureSource(t, selected, definitions)
			derived, err := selected.admission.outputInterpreter(t.Context(), "app", before.Bindings[0].Destination, "beta", contract.OutputEncodingRaw)
			unchanged, result := selected.currentOutputConfigurationForApply(t.Context())
			if err != nil || !reflect.DeepEqual(derived, futureTarget.target) || result.Outcome != 0 || !reflect.DeepEqual(unchanged, before) || len(selected.root.Names) != 1 {
				t.Fatal("parent future derivation changed selected output or is unavailable", err, result)
			}

			if transition == "writer" {
				selected = selectFreshGeneratedWriter(t, store, selected, fixtureID(env.Domain, "output writer beta"), "beta", intents["beta"], 0)
			} else {
				input := generatedWriterPlanInput(t, selected, fixtureID(env.Domain, "output final beta"), []string{"beta"},
					func(name string) []byte { return intents[name] }, 0, nil)
				reservation, _ := preparePrivateGeneratedReservation(t, env, selected, input, nil)
				recorded, _, _, _ := selectActualGeneratedPacketRecord(t, env, selected, reservation, custody.StandardValue, true, nil)
				recordedOutput, result := recorded.currentOutputConfigurationForApply(t.Context())
				if recorded.root.Generated.ActiveOwner.IsZero() || len(recorded.root.Names) != 1 || result.Outcome != 0 || !reflect.DeepEqual(recordedOutput, before) {
					t.Fatal("record stage changed current-only output or lost active generation", result)
				}
				selected = env.FreshGeneratedFinal(t, recorded)
			}
			selected = generatedLifecycleReopen(t, t.Context(), selected, store)
			beta := selected.valueEntry(entrySlot(t, selected, "beta"))
			if !reflect.DeepEqual(*selected.valueEntry(entrySlot(t, selected, "alpha")), alpha) || beta.Incarnation == alpha.Incarnation ||
				beta.ValueSource != contract.Generated || beta.ConfidentialityClass != contract.Secret || beta.Generated.ResourceDigest.IsZero() ||
				!reflect.DeepEqual(beta.Recipients, alpha.Recipients) || len(selected.root.Names) != 2 || !selected.root.Generated.ActiveOwner.IsZero() {
				t.Fatal("fresh writer changed carried alpha or lost exact beta generation")
			}
			assertGeneratedWriterState(t, selected, intents)

			want := before
			want.Bindings = slices.Clone(before.Bindings)
			want.Bindings[0].Targets = slices.Clone(before.Bindings[0].Targets)
			newTarget := futureTarget.target
			newTarget.EntryIncarnationID = beta.Incarnation
			want.Bindings[0].Targets = append(want.Bindings[0].Targets, newTarget)
			slices.SortFunc(want.Bindings[0].Targets, func(a, b contract.OutputTarget) int {
				return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:])
			})
			after, result := selected.currentOutputConfigurationForApply(t.Context())
			if result.Outcome != 0 || !reflect.DeepEqual(after, want) {
				t.Fatal("fresh writer lost exact source, two targets, encoding or default route", result)
			}
			relation, err := selectedPublicationRelation(selected.selectedImage())
			if err != nil || len(relation.coordinates) != 2 || len(relation.markers) != 0 {
				t.Fatal("fresh writer acquired publication effects or lost coordinates", err)
			}
			for _, target := range want.Bindings[0].Targets {
				id, err := contract.PublicationCoordinateID(env.Domain, target.ServiceContractID, target.CanonicalTarget)
				coordinate, present := relation.coordinates[id]
				if err != nil || !present || coordinate.ServiceContractID != target.ServiceContractID || coordinate.CanonicalTarget != target.CanonicalTarget ||
					coordinate.BindingState != contract.PublicationBindingActive || coordinate.ActiveBindingIncarnationID != before.Bindings[0].IncarnationID ||
					coordinate.OwnerState != contract.PublicationOwnerNone || !coordinate.OwnedBirthAttemptID.IsZero() ||
					coordinate.LastAdmissionOrdinal != 0 || coordinate.PossibleRemoteObject != 0 || coordinate.LateEffectRisk != 0 {
					t.Fatal("fresh writer changed physical ownership or entered an output effect", coordinate)
				}
			}
		})
	}
}
