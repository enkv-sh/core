package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedMembershipKeepsCurrentValueAndEffect(t *testing.T) {
	for _, embedded := range []bool{false, true} {
		form := "reference"
		if embedded {
			form = "embedded"
		}
		for _, addition := range []bool{false, true} {
			direction := "removal"
			if addition {
				direction = "addition"
			}
			t.Run(form+"/"+direction, func(t *testing.T) {
				env, keys, selected, implementation, effects, author := normalHandoffGeneratedFixture(t, false, true)
				authority, reader := selected.admission.recipient, fixtureID(env.Domain, "reader")
				oldName := selected.root.Names[0].Name
				if !addition {
					current := selected.currentEntryInputs()
					current[0].Recipients = []contract.ID{authority, reader}
					slices.SortFunc(current[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
					parent := admitSuppliedComparison(t, selected, keys, current, implementation)
					comparison, result := selected.Compare(t.Context(), current, parent)
					if comparison == nil || result.Outcome != ObservedCurrent {
						t.Fatal("ordinary membership seed comparison", result)
					}
					candidate, result := selected.Prepare(t.Context(), comparison, admit(t, selected, comparison), env.Trust)
					if candidate == nil || result.Outcome != ObservedCurrent {
						t.Fatal("ordinary membership seed preparation", result)
					}
					selected, result = selected.selectCandidate(t.Context(), candidate)
					if selected == nil || result.Outcome != ObservedCurrent {
						t.Fatal("ordinary membership seed selection", result)
					}
					keys.RetireApply()
					selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
				}
				oldSlot := entrySlot(t, selected, oldName)
				old := *selected.valueEntry(oldSlot)
				old.ValueBytes, old.Recipients = bytes.Clone(old.ValueBytes), slices.Clone(old.Recipients)
				beforeAccess, ok := selected.materialAccess(contract.ValueMaterialKind, old.ValueState)
				if !ok {
					t.Fatal("current generated material missing")
				}
				wanted := []contract.ID{authority}
				if addition {
					wanted = append(wanted, reader)
				}
				slices.SortFunc(wanted, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				intent, requestBody := hermeticCloudflareIntent()
				sources := generatedWriterCurrentDeclarations(t, selected, []string{"second"})
				for i := range sources {
					if sources[i].Name != oldName {
						continue
					}
					sources[i].Recipients = slices.Clone(wanted)
					if embedded {
						sources[i].Kind = contract.GeneratorDeclarationGenerated
						var err error
						sources[i].Payload, err = contract.EncodeGeneratorDeclaredGeneration(contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, Epoch: old.Generated.Epoch, RetirementMode: old.Generated.RetirementMode, CompletionClass: old.Generated.CompletionClass, Intent: intent, ConfigContractID: old.Generated.ConfigContractID, ResourceContractID: old.Generated.ResourceContractID, LifecycleMode: contract.GeneratorLifecycleManaged})
						if err != nil {
							t.Fatal("current embedded declaration", err)
						}
					}
				}
				profile := nativeGeneratedFixtureProfile(t, implementation)
				input := generatedPlanInputForGenerationsIntent(t, selected, fixtureID(env.Domain, form+" "+direction), []string{"second"}, intent, profile, sources...)
				for i := range input.graph.ValueEntryPlans {
					plan := &input.graph.ValueEntryPlans[i]
					if plan.Name == oldName {
						plan.ChangeMask = contract.GeneratorValueChangeMembership
					}
				}
				var err error
				input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
				if err != nil {
					t.Fatal("access-only graph", err)
				}
				input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
				declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
				if err != nil || contract.ValidateGeneratorDeclarationGraph(declaration, input.graph) != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil {
					t.Fatal("access-only declaration and graph", err)
				}
				if effects.Load() != 1 {
					t.Fatal("membership planning regenerated current value")
				}
				selected = author.create(selected, input)
				keys.RetireGenerated()
				selected = generatedLifecycleReopen(t, context.Background(), selected, env.Store)
				got := selected.valueEntry(entrySlot(t, selected, oldName))
				if got == nil || effects.Load() != 2 || len(selected.root.Names) != 2 || !slices.Equal(got.Recipients, wanted) {
					t.Fatal("membership changed the intended set or repeated a provider effect")
				}
				if addition {
					want := old
					want.Recipients = wanted
					if !reflect.DeepEqual(*got, want) {
						t.Fatal("grant changed protected material or generated metadata")
					}
				} else {
					metadata := old.Generated
					metadata.GenerationID = got.ValueState
					if got.ValueState == old.ValueState || bytes.Equal(got.ValueBytes, old.ValueBytes) || got.Incarnation != old.Incarnation || got.Generated != metadata {
						t.Fatal("removal reused old protection or changed provider/create/lifecycle facts")
					}
					if _, present := selected.materialAccess(contract.ValueMaterialKind, old.ValueState); present {
						t.Fatal("removal retained unused old material")
					}
				}
				afterAccess, ok := selected.materialAccess(contract.ValueMaterialKind, got.ValueState)
				if !ok || len(afterAccess.Wraps) != len(wanted) || addition && (beforeAccess.PackageCheck != afterAccess.PackageCheck || beforeAccess.MaterialContextDigest != afterAccess.MaterialContextDigest) {
					t.Fatal("membership selected incorrect material or wrap count")
				}
				for _, oldWrap := range beforeAccess.Wraps {
					if !addition || !slices.Contains(wanted, oldWrap.SubjectID) {
						continue
					}
					index := slices.IndexFunc(afterAccess.Wraps, func(row contract.WrapRow) bool {
						return row.SubjectKind == oldWrap.SubjectKind && row.SubjectID == oldWrap.SubjectID
					})
					if index < 0 || !reflect.DeepEqual(afterAccess.Wraps[index], oldWrap) {
						t.Fatal("grant regenerated an existing required wrap")
					}
				}
				selection := sessionConsumerSelection(t, selected, authority, oldName)
				if addition {
					selection = sessionConsumerSelection(t, selected, reader, oldName)
				}
				if got := keys.Consume(t.Context(), selection, custody.HermeticCloudflareValue); got.Code != contract.CryptoSuccess || !got.ValueMatched || got.Delivery != 1 || got.SinkCalls != 1 {
					t.Fatal("changed membership cannot consume complete original value", got.Code)
				}
			})
		}
	}
}
