package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// The shared entry replacement remains effective when one member leaves.
func outputEncodingRecoveryRoutes(name string) []outputApplyRoute {
	return []outputApplyRoute{{entryName: name, destinations: []string{"app"}}}
}

// Author the successor from the selected declaration, with the same shared route.
func outputEncodingRecoveryExpected(before contract.OutputConfiguration, name string) (*outputApplyInput, contract.OutputConfiguration) {
	input := &outputApplyInput{routes: []outputApplyRoute{{defaultRoute: true, destinations: slices.Clone(before.DefaultDestinations)}}}
	for _, binding := range before.Bindings {
		row := outputApplyBinding{destinationID: binding.DestinationID, destination: binding.Destination}
		for _, stored := range binding.Targets {
			target := stored
			target.EntryIncarnationID = contract.ID{}
			row.targets = append(row.targets, outputApplyTarget{entryName: name, target: target})
		}
		input.bindings = append(input.bindings, row)
	}
	for _, route := range before.Routes {
		input.routes = append(input.routes, outputApplyRoute{entryName: name, destinations: slices.Clone(route.Destinations)})
	}
	return input, before
}

func assertOutputEncodingRecovery(t *testing.T, selected *StateSession, want contract.OutputConfiguration, coordinates map[contract.ID]contract.PublicationCoordinate, markers map[contract.ID]contract.PublicationMarker) {
	t.Helper()
	configuration, result := selected.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 || !reflect.DeepEqual(configuration, want) || selected.publicationProof == nil || !selected.publicationProof.validFor(selected.selectedImage()) {
		t.Fatal("recovered output differs from the independent effective-route expectation or lacks complete proof", result)
	}
	wantCoordinates := make(map[contract.ID]contract.PublicationCoordinate, len(coordinates))
	for id, row := range coordinates {
		wantCoordinates[id] = row
	}
	relation, err := selectedPublicationRelation(selected.selectedImage())
	if err != nil || !reflect.DeepEqual(relation.coordinates, wantCoordinates) || !reflect.DeepEqual(relation.markers, markers) {
		t.Fatal("membership recovery changed the retained coordinate or publication history", err)
	}
}

// full_only: false
func TestOutputBase64RecoveryOrdinaryMembership(t *testing.T) {
	for _, mode := range []string{"shared_entry"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, 1, false, 1)
			entries := f.session.currentEntryInputs()
			authority, reader := f.session.admission.recipient, fixtureID(f.session.root.Domain, "reader")
			entries[0].Recipients = []contract.ID{authority, reader}
			entries[0].OutputEncoding = contract.OutputEncodingBase64
			slices.SortFunc(entries[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			target := publicationEngineTarget(entries[0].Name, "encoding-recovery")
			target.target.PayloadEncoding = contract.OutputEncodingBase64
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{entryName: entries[0].Name, destinations: []string{"app"}}}}
			selectOutputConfiguration(t, f, entries, output)
			pins := []publicationNamespace{{domain: f.session.root.Domain, service: "controlled-provider", physical: "encoding-recovery", premise: fixtureID(f.session.root.Domain, "independent recovery namespace")}}
			f.admission.admission.publicationNamespaces, f.session.admission.publicationNamespaces = pins, pins
			private := newPublicationControlledPrivate()
			sends := 0
			private.onSend = func() { sends++ }
			publication := publicationInput{names: []string{entries[0].Name}, acting: authority, deadline: time.Now().Add(30 * time.Second)}
			created := publicationEnginePlan(t, f, publication, private).execute(t.Context(), private.callbacks(), publicationEngineCurrent(f))
			if created.summary != contract.PublicationSummaryComplete || sends != 1 {
				t.Fatal("initial selected Base64 ownership was not acknowledged", created.state)
			}
			publicationEngineReopen(t, f)
			output = &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target}}}, routes: outputEncodingRecoveryRoutes(entries[0].Name)}
			before := selectOutputConfiguration(t, f, entries, output)
			wantBindings := 1
			if f.session.valueEntry(entrySlot(t, f.session, entries[0].Name)).OutputEncoding != contract.OutputEncodingBase64 || len(before.Bindings) != wantBindings || len(before.Bindings[0].Targets) != 1 || before.Bindings[0].Targets[0].PayloadEncoding != contract.OutputEncodingBase64 {
				t.Fatal("initial source lacks the effective Base64 pair")
			}
			old := *f.session.valueEntry(f.session.root.Names[0].Slot)
			relation, err := selectedPublicationRelation(f.session.selectedImage())
			if err != nil || len(relation.markers) != 1 {
				t.Fatal("initial selected publication history", err)
			}
			coordinate := relation.coordinates[created.output.Entries[0].CoordinateID]
			if coordinate.OwnerState != contract.PublicationOwnerQualified || coordinate.DeletionPayloadEncoding != contract.OutputEncodingBase64 {
				t.Fatal("initial Base64 birth was not retained")
			}
			proposed := f.session.currentEntryInputs()
			proposed[0].Recipients = []contract.ID{authority}
			expectedSource, want := outputEncodingRecoveryExpected(before, old.Name)
			parent := admitSuppliedOutputComparison(t, f.session, nil, proposed, expectedSource)
			creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
			owners := len(private.owners)
			// The actual API omits output and must recover the selected source.
			comparison, result := f.session.Compare(t.Context(), proposed, parent)
			if comparison == nil || result.Outcome != ObservedCurrent {
				if f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs || sends != 1 || len(private.owners) != owners {
					t.Fatal("membership comparison refusal caused effects")
				}
				t.Fatal("omitted output refused membership removal with a retained shared Base64 route", result)
			}
			candidate, result := f.session.Prepare(t.Context(), comparison, admit(t, f.session, comparison), f.trust)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("recovered membership preparation", result)
			}
			selected, result := f.session.selectCandidate(t.Context(), candidate)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("recovered membership selection", result)
			}
			selected = generatedLifecycleReopen(t, t.Context(), selected, f.store)
			current := selected.valueEntry(entrySlot(t, selected, old.Name))
			wantEntry := old
			wantEntry.Recipients = []contract.ID{authority}
			if !reflect.DeepEqual(*current, wantEntry) || len(selected.root.Names) != 1 || sends != 1 || len(private.owners) != owners {
				t.Fatal("ordinary route recovery changed canonical value/source/incarnation or caused implicit publication")
			}
			assertOutputEncodingRecovery(t, selected, want, relation.coordinates, relation.markers)
		})
	}
}

// full_only: false
func TestOutputBase64RecoveryGeneratedMembership(t *testing.T) {
	for _, mode := range []string{"shared_entry"} {
		t.Run(mode, func(t *testing.T) {
			env, keys, selected, row, effects, author := normalHandoffGeneratedFixture(t, false, true)
			authority, reader := selected.admission.recipient, fixtureID(env.Domain, "reader")
			proposed := selected.currentEntryInputs()
			proposed[0].Recipients = []contract.ID{authority, reader}
			slices.SortFunc(proposed[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			target := publicationEngineTarget(proposed[0].Name, "encoding-recovery")
			target.target.PayloadEncoding = contract.OutputEncodingBase64
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target}}}, routes: outputEncodingRecoveryRoutes(proposed[0].Name)}
			selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, keys, proposed, output, row)
			before, result := selected.currentOutputConfigurationForApply(t.Context())
			wantBindings := 1
			if result.Outcome != 0 || selected.valueEntry(entrySlot(t, selected, proposed[0].Name)).OutputEncoding != contract.OutputEncodingBase64 || len(before.Bindings) != wantBindings || len(before.Bindings[0].Targets) != 1 || effects.Load() != 1 {
				t.Fatal("generated initial Base64 source", result)
			}
			oldSlot := entrySlot(t, selected, proposed[0].Name)
			old := *selected.valueEntry(oldSlot)
			relation, err := selectedPublicationRelation(selected.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			_, want := outputEncodingRecoveryExpected(before, old.Name)
			sources := generatedWriterCurrentDeclarations(t, selected, []string{"second"})
			for i := range sources {
				if sources[i].Name == old.Name {
					if sources[i].Kind != contract.GeneratorDeclarationGeneratedReference {
						t.Fatal("retained member is not an actual generated reference")
					}
					sources[i].Recipients = []contract.ID{authority}
				}
			}
			intent, requestBody := hermeticCloudflareIntent()
			profile := nativeGeneratedFixtureProfile(t, row)
			input := generatedPlanInputForGenerationsIntent(t, selected, fixtureID(env.Domain, "Base64 recovery "+mode), []string{"second"}, intent, profile, sources...)
			found := false
			for i := range input.graph.ValueEntryPlans {
				plan := &input.graph.ValueEntryPlans[i]
				if plan.Name == old.Name {
					if plan.EntryIncarnationID != old.Incarnation || plan.Slot != oldSlot || plan.ValueSource != contract.Generated || plan.Epoch != old.Generated.Epoch {
						t.Fatal("membership declaration regenerated the retained source")
					}
					plan.ChangeMask |= contract.GeneratorValueChangeMembership
					found = true
				}
			}
			if !found {
				t.Fatal("retained generated plan missing")
			}
			input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
			if err != nil {
				t.Fatal(err)
			}
			input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
			declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
			if err != nil || contract.ValidateGeneratorDeclarationGraph(declaration, input.graph) != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil {
				t.Fatal("independently authored membership declaration/graph is invalid", err)
			}
			store, signer := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, signer.signs
			publicCalls, privateCalls := keys.Calls()
			plan, err := selected.generatedPlanRequest(t.Context(), input)
			if plan == nil || err != nil {
				afterPublic, afterPrivate := keys.Calls()
				if store.creates != creates || store.cas != cas || signer.signs != signs || publicCalls != afterPublic || privateCalls != afterPrivate || effects.Load() != 1 {
					t.Fatal("generated recovery refusal caused key, Store or provider effects")
				}
				t.Fatal("generated admission refused removal of the final effective Base64 route", err)
			}
			selected = author.create(selected, input)
			keys.RetireGenerated()
			selected = generatedLifecycleReopen(t, context.Background(), selected, env.Store)
			current := selected.valueEntry(entrySlot(t, selected, old.Name))
			if current == nil {
				t.Fatal("generated current value absent")
			}
			oldPayload, err := contract.InspectCanonicalPayload(old.ValueBytes)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := contract.InspectCanonicalPayload(current.ValueBytes)
			if err != nil {
				t.Fatal(err)
			}
			metadata := old.Generated
			metadata.GenerationID = current.ValueState
			if current.Incarnation != old.Incarnation || current.InputEncoding != old.InputEncoding || current.OutputEncoding != old.OutputEncoding || current.ContentLength != old.ContentLength || current.RetainedLength != old.RetainedLength || current.ValueSource != old.ValueSource || current.ConfidentialityClass != old.ConfidentialityClass || current.Generated != metadata ||
				current.ValueState == old.ValueState || current.OriginSnapshot == old.OriginSnapshot || current.OriginTransition == old.OriginTransition ||
				payload.DataKeyID == oldPayload.DataKeyID || payload.DataKeyID == oldPayload.CommitmentKeyID || payload.CommitmentKeyID == oldPayload.DataKeyID || payload.CommitmentKeyID == oldPayload.CommitmentKeyID ||
				bytes.Equal(payload.Ciphertext, oldPayload.Ciphertext) || payload.SemanticCommitment == oldPayload.SemanticCommitment || !slices.Equal(current.Recipients, []contract.ID{authority}) ||
				selected.valueEntry(entrySlot(t, selected, "second")).ValueSource != contract.Generated || len(selected.root.Names) != 2 || effects.Load() != 2 {
				t.Fatal("generated removal failed fresh protection, preserved provider/lifecycle facts or exact effect count")
			}
			assertOutputEncodingRecovery(t, selected, want, relation.coordinates, relation.markers)
		})
	}
}

// full_only: false
func TestOutputBase64RecoveryKeepsUnroutedEntryEncodingAndRefusesInvalidTags(t *testing.T) {
	f := newFixture(t, 1, false, 1)
	entries := f.session.currentEntryInputs()
	entries[0].OutputEncoding = contract.OutputEncodingBase64
	target := publicationEngineTarget(entries[0].Name, "encoding-recovery")
	target.target.PayloadEncoding = contract.OutputEncodingBase64
	before := selectOutputConfiguration(t, f, entries, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{entryName: entries[0].Name, destinations: []string{"app"}}}})
	explicit := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", destination: before.Bindings[0].Destination}}}
	for _, tag := range []uint8{contract.OutputEncodingBase64, 0, 99} {
		t.Run(fmt.Sprint(tag), func(t *testing.T) {
			proposed := slices.Clone(entries)
			proposed[0].OutputEncoding = tag
			creates, cas, signs, body := f.store.creates, f.store.cas, f.trust.signs, contract.Hash(f.session.body)
			compare := func() (*Comparison, Result) {
				if tag == contract.OutputEncodingBase64 {
					parent := admitSuppliedOutputComparison(t, f.session, nil, proposed, explicit)
					return f.session.compareWithOutput(t.Context(), proposed, explicit, parent)
				}
				return f.session.compareWithOutput(t.Context(), proposed, explicit, nil)
			}
			comparison, result := compare()
			if tag == contract.OutputEncodingBase64 {
				if comparison == nil || result.Outcome != ObservedCurrent {
					t.Fatal("valid unrouted entry output setting refused", result)
				}
			} else if comparison != nil || result != refused(InvalidIntent) {
				t.Fatal("invalid unrouted entry output tag admitted", result)
			}
			if f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs || contract.Hash(f.session.body) != body {
				t.Fatal("unrouted encoding comparison caused effects")
			}
		})
	}
}
