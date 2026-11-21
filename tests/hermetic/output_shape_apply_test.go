package core

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// The passive fixture returns one typed target; Core checks its common fields
// before any private preparation or provider call.
func permissiveOutputApplyShape(t *testing.T, selected *StateSession, condition, derivedName string) *int {
	t.Helper()
	interpret := selected.admission.outputInterpreter
	if interpret == nil {
		t.Fatal("target fixture interpreter unavailable")
	}
	calls := new(int)
	selected.admission.outputInterpreter = func(ctx context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
		if name != derivedName {
			t.Fatal("canonical retained target was reinterpreted", name)
		}
		*calls++
		target, err := interpret(ctx, id, destination, name, encoding)
		if err == nil && condition == "invalid-target" {
			target.CanonicalTarget = ""
		}
		return target, err
	}
	return calls
}

// full_only: false
func TestOrdinaryOutputApplyRefusesInvalidDerivedTargets(t *testing.T) {
	for _, shape := range []string{"retained-canonical", "complete", "invalid-target"} {
		t.Run(shape, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, false)
			initial := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
			entries := initial.session.currentEntryInputs()
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget(entries[0].Name, "shape-apply")}}},
				routes: []outputApplyRoute{{entryName: entries[0].Name, destinations: []string{"app"}}}}
			derived := shape != "retained-canonical"
			if derived {
				output.routes = []outputApplyRoute{{defaultRoute: true, destinations: []string{"app"}}}
			}
			selected := selectAdmittedOutputConfiguration(t, t.Context(), initial.session, env, keys, entries, output)
			entries = selected.currentEntryInputs()
			entries[0].InputBytes = []byte("independent changed plain value")
			expected := ownOutputApplyInput(output)
			second := outputConfigurationTarget("second", "shape-apply-second")
			if derived {
				entries = append(entries, ApplyEntryInput{Name: second.entryName, Recipients: slices.Clone(entries[0].Recipients),
					ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("independent second plain value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
				expected.bindings[0].targets = append(expected.bindings[0].targets, second)
			}
			// The parent admits the complete independently authored proposal.
			// Omitted output must derive only the new default target afterward.
			parent := admitSuppliedOutputComparison(t, selected, keys, entries, expected)
			calls := permissiveOutputApplyShape(t, selected, shape, second.entryName)
			store, signer := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs, objects, generation := store.creates, store.cas, signer.signs, len(store.objects), store.generation
			public, private := keys.Calls()
			head, token, configuration := bytes.Clone(selected.body), selected.token, selected.root.OutputConfiguration
			// This is the real ordinary API with omitted output; it must recover
			// and validate the selected source before any private preparation.
			comparison, result := selected.Compare(t.Context(), entries, parent)
			if shape != "invalid-target" {
				wantCalls := 0
				if derived {
					wantCalls = 1
				}
				if comparison == nil || result.Outcome != ObservedCurrent || *calls != wantCalls || comparison.outputChanged != derived || comparison.outputIntent == nil ||
					parent == nil || parent.support == nil || (parent.support.Output != nil) != derived || comparison.support != parent.support {
					t.Fatal("single ordinary apply control refused before derivation", result, *calls)
				}
				permit := admit(t, selected, comparison)
				candidate, prepared := selected.Prepare(t.Context(), comparison, permit, env.Trust)
				if candidate == nil || prepared.Outcome != ObservedCurrent || !selected.prepared || !permit.used || comparison.outputIntent != nil {
					t.Fatal("single ordinary apply control preparation", prepared)
				}
				if result := selected.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
					t.Fatal("single ordinary apply control selection", result)
				}
				if store.creates <= creates || store.cas != cas+1 || signer.signs != signs+1 {
					t.Fatal("single ordinary apply control did not select exactly once")
				}
				opened := generatedLifecycleReopen(t, t.Context(), selected, env.Store)
				current := opened.valueEntry(entrySlot(t, opened, entries[0].Name))
				if !bytes.Equal(current.ValueBytes, entries[0].InputBytes) || !derived && opened.root.OutputConfiguration != configuration {
					t.Fatal("single ordinary apply control lost the changed value or retained output")
				}
				if derived {
					secondEntry := opened.valueEntry(entrySlot(t, opened, second.entryName))
					configurationAfter, result := opened.currentOutputConfigurationForApply(t.Context())
					if result.Outcome != 0 || opened.root.OutputConfiguration == configuration || !bytes.Equal(secondEntry.ValueBytes, entries[1].InputBytes) ||
						len(configurationAfter.Bindings) != 1 || len(configurationAfter.Bindings[0].Targets) != 2 || len(configurationAfter.Routes) != 0 || !slices.Equal(configurationAfter.DefaultDestinations, []string{"app"}) {
						t.Fatal("single ordinary apply control lost its new default target", result)
					}
					for _, named := range expected.bindings[0].targets {
						want := named.target
						want.EntryIncarnationID = opened.valueEntry(entrySlot(t, opened, named.entryName)).Incarnation
						if !slices.ContainsFunc(configurationAfter.Bindings[0].Targets, func(got contract.OutputTarget) bool { return got.Equal(want) }) {
							t.Fatal("single ordinary apply control changed an independently authored target", named.entryName)
						}
					}
				}
				return
			}
			if comparison != nil || result != refused(InvalidIntent) || *calls != 1 || selected.prepared {
				t.Fatal("ordinary non-single Derive result escaped apply admission", result, *calls)
			}
			if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private || store.creates != creates || store.cas != cas || signer.signs != signs || len(store.objects) != objects || store.generation != generation {
				t.Fatal("ordinary shape refusal reached key, signer or Store effects")
			}
			if !bytes.Equal(selected.body, head) || selected.token != token || selected.root.OutputConfiguration != configuration {
				t.Fatal("ordinary shape refusal changed selected state")
			}
		})
	}
}

// full_only: false
func TestGeneratedOutputApplyRefusesInvalidDerivedTargets(t *testing.T) {
	for _, shape := range []string{"retained-canonical", "complete", "invalid-target"} {
		t.Run(shape, func(t *testing.T) {
			env, keys, selected, implementation, effects, _ := normalHandoffGeneratedFixture(t, false)
			entries := selected.currentEntryInputs()
			name := entries[0].Name
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget(name, "shape-apply")}}},
				routes: []outputApplyRoute{{entryName: name, destinations: []string{"app"}}}}
			derived := shape != "retained-canonical"
			if derived {
				output.routes = []outputApplyRoute{{defaultRoute: true, destinations: []string{"app"}}}
			}
			selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, keys, entries, output)
			second := outputConfigurationTarget("second", "shape-apply-second")
			if derived {
				installed := ownOutputApplyInput(output)
				installed.bindings[0].targets = append(installed.bindings[0].targets, second)
				installOutputFixtureSource(t, selected, installed)
			}
			intent, requestBody := hermeticCloudflareIntent()
			profile := nativeGeneratedFixtureProfile(t, implementation)
			input := generatedPlanInputWithCurrentGenerated(t, selected, fixtureID(env.Domain, "shape apply sibling"), []string{"second"}, profile, intent)
			input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
			declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
			if err != nil || contract.ValidateGeneratorDeclarationGraph(declaration, input.graph) != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil {
				t.Fatal("independent generated apply declaration/graph refused", err)
			}
			calls := permissiveOutputApplyShape(t, selected, shape, second.entryName)
			store, signer := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs, objects, generation := store.creates, store.cas, signer.signs, len(store.objects), store.generation
			public, private := keys.Calls()
			providerEffects := effects.Load()
			head, token, configuration := bytes.Clone(selected.body), selected.token, selected.root.OutputConfiguration
			// Use generated admission with a real retained generated entry and
			// independently valid sibling graph, rather than a normalizer probe.
			plan, err := selected.generatedPlanRequest(t.Context(), input)
			if shape != "invalid-target" {
				wantCalls := 0
				if derived {
					wantCalls = 1
				}
				if plan == nil || err != nil || *calls != wantCalls {
					t.Fatal("single generated apply control refused before derivation", err, *calls)
				}
			} else if plan != nil || !errors.Is(err, contract.ErrRecord) || *calls != 1 || selected.prepared {
				t.Fatal("generated non-single Derive result escaped apply admission", err, *calls)
			}
			if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private || store.creates != creates || store.cas != cas || signer.signs != signs || len(store.objects) != objects || store.generation != generation || effects.Load() != providerEffects {
				t.Fatal("generated shape admission reached key, signer, Store or provider effects")
			}
			if providerEffects != 1 || !bytes.Equal(selected.body, head) || selected.token != token || selected.root.OutputConfiguration != configuration {
				t.Fatal("generated shape admission changed selected state or its initial effect")
			}
		})
	}
}
