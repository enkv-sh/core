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
func TestGeneratedFreshProcessKeepsFutureOutputProfileFacts(t *testing.T) {
	env, keys, selected, implementation, effects, author := normalHandoffGeneratedFixture(t, false, true)
	old := *selected.valueEntry(entrySlot(t, selected, "generated"))
	currentTarget := outputConfigurationTarget(old.Name, "app-current")
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{currentTarget}}},
		routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"app"}}}}
	selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, keys, selected.currentEntryInputs(), output)
	before, result := selected.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 || len(before.Bindings) != 1 || len(before.Bindings[0].Targets) != 1 ||
		before.Bindings[0].Targets[0].EntryIncarnationID != old.Incarnation ||
		!reflect.DeepEqual(before.DefaultDestinations, []string{"app"}) || len(before.Routes) != 0 || effects.Load() != 1 {
		t.Fatal("initial generated output is not the exact current-only default source", result)
	}

	// The future row is an installed derivation fact, not an offered selected
	// target. A child reconstructed from current targets alone loses this fact.
	const futureName = "future"
	futureTarget := outputConfigurationTarget(futureName, "app-future")
	definitions := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", destination: before.Bindings[0].Destination,
		targets: []outputApplyTarget{currentTarget, futureTarget}}}}
	installOutputFixtureSource(t, selected, definitions)
	derived, err := selected.admission.outputInterpreter(t.Context(), "app", before.Bindings[0].Destination, futureName, contract.OutputEncodingRaw)
	unchanged, result := selected.currentOutputConfigurationForApply(t.Context())
	if err != nil || !reflect.DeepEqual(derived, futureTarget.target) || result.Outcome != 0 || !reflect.DeepEqual(unchanged, before) ||
		len(selected.root.Names) != 1 || effects.Load() != 1 {
		t.Fatal("parent future derivation changed selected output or is unavailable", err, result)
	}

	intent, requestBody := hermeticCloudflareIntent()
	generator := nativeGeneratedFixtureProfile(t, implementation)
	input := generatedPlanInputWithCurrentGenerated(t, selected, fixtureID(env.Domain, "fresh future output operation"), []string{futureName}, generator, intent)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
	var futureID contract.ID
	for _, plan := range input.graph.ValueEntryPlans {
		if plan.Name == futureName {
			futureID = plan.EntryIncarnationID
		}
	}
	if futureID.IsZero() || futureID == old.Incarnation {
		t.Fatal("new generated name has no distinct planned incarnation")
	}
	selected = author.create(selected, input)
	keys.RetireGenerated()
	selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
	current := selected.valueEntry(entrySlot(t, selected, old.Name))
	future := selected.valueEntry(entrySlot(t, selected, futureName))
	if !reflect.DeepEqual(*current, old) || future.Incarnation != futureID || future.ValueSource != contract.Generated ||
		future.ConfidentialityClass != contract.Secret || !reflect.DeepEqual(future.Recipients, old.Recipients) ||
		future.Generated.ResourceDigest == old.Generated.ResourceDigest ||
		len(selected.root.Names) != 2 || !selected.root.Generated.ActiveOwner.IsZero() || effects.Load() != 2 {
		t.Fatal("cold generated result changed the retained entry, lost the new value or repeated generation")
	}
	want := before
	want.Bindings = slices.Clone(before.Bindings)
	want.Bindings[0].Targets = slices.Clone(before.Bindings[0].Targets)
	newTarget := futureTarget.target
	newTarget.EntryIncarnationID = futureID
	want.Bindings[0].Targets = append(want.Bindings[0].Targets, newTarget)
	slices.SortFunc(want.Bindings[0].Targets, func(a, b contract.OutputTarget) int {
		return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:])
	})
	after, result := selected.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 || !reflect.DeepEqual(after, want) {
		t.Fatal("fresh child/final selection lost exact source, default route, binding or target pair", result)
	}
	relation, err := selectedPublicationRelation(selected.selectedImage())
	if err != nil || len(relation.coordinates) != 2 || len(relation.markers) != 0 {
		t.Fatal("generated output change acquired publication effects or lost coordinates", err)
	}
	for _, target := range want.Bindings[0].Targets {
		id, err := contract.PublicationCoordinateID(env.Domain, target.ServiceContractID, target.CanonicalTarget)
		coordinate, present := relation.coordinates[id]
		if err != nil || !present || coordinate.ServiceContractID != target.ServiceContractID || coordinate.CanonicalTarget != target.CanonicalTarget ||
			coordinate.BindingState != contract.PublicationBindingActive || coordinate.ActiveBindingIncarnationID != before.Bindings[0].IncarnationID ||
			coordinate.OwnerState != contract.PublicationOwnerNone || !coordinate.OwnedBirthAttemptID.IsZero() ||
			coordinate.LastAdmissionOrdinal != 0 || coordinate.PossibleRemoteObject != 0 || coordinate.LateEffectRisk != 0 {
			t.Fatal("generated target changed physical ownership or entered an output effect", coordinate)
		}
	}
	for _, name := range []string{old.Name, futureName} {
		check := keys.Consume(t.Context(), sessionConsumerSelection(t, selected, selected.admission.recipient, name), custody.HermeticCloudflareValue)
		if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 || check.SinkCalls != 1 {
			t.Fatal("cold generated canonical value differs", name, check)
		}
	}
	if effects.Load() != 2 {
		t.Fatal("canonical consumption repeated a generator effect")
	}
}
