package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func checkEmptyEntryReaderRouting(t *testing.T, env fixtureEnvironment, selected *StateSession, want []contract.PublicRoutingRule, generator *contract.GeneratorImplementation) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	validator := NewPublicConfigurationValidator(selected.admission.outputInterpreter)
	e, _, _ := readerEngineFixture(t, env, selected)
	defer e.Close()
	e.validator = validator
	inv := readerInvocationFixture(t, e, ctx)
	defer inv.Close()
	selection, result := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, contract.Hash([]byte("complete public request")), nil)
	if result.Outcome != 0 {
		t.Fatal("Reader did not authenticate the selected empty entry", result)
	}
	projection, failure := e.projectPublicConfiguration(ctx, selection)
	if failure.Outcome != 0 || !projection.Valid || !projection.Complete || !projection.DiagnosticsComplete || len(projection.Diagnostics) != 0 {
		t.Fatal("Reader did not validate the complete empty entry projection", failure, projection.Diagnostics)
	}
	if !reflect.DeepEqual(projection.Configuration.Routing.Value, want) {
		t.Fatal("Reader changed named empty and default route identities", projection.Configuration.Routing.Value, want)
	}
}

// full_only: false
func TestOutputConfigurationEmptyEntryReaderRouting(t *testing.T) {
	for _, defaultRoute := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact_only", true: "exact_and_default"}[defaultRoute], func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, false)
			f := newNamedEnvironmentFixture(t, t.Context(), env, []int{1, 1}, false, []string{"", "other"})
			output := &outputApplyInput{bindings: []outputApplyBinding{
				{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("", "app-empty")}},
				{destinationID: "backup", destination: contract.OutputDestination{ConfigContractID: "aws", ServiceContractID: "aws", CanonicalSettings: hermeticDestinationSettings([][2]string{{"fixture_destination", "backup"}}), Policy: contract.OutputPolicy{}, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)}, targets: []outputApplyTarget{}},
			}, routes: []outputApplyRoute{{entryName: "", destinations: []string{"app"}}}}
			want := []contract.PublicRoutingRule{{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: ""}, Destinations: publicPresent([]string{"app"})}, {Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent([]string(nil))}}
			if defaultRoute {
				output.bindings[1].targets = append(output.bindings[1].targets, outputConfigurationTarget("other", "backup-other"))
				output.routes = append(output.routes, outputApplyRoute{defaultRoute: true, destinations: []string{"backup"}})
				want[1].Destinations = publicPresent([]string{"backup"})
			}
			selected := selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, keys, f.session.currentEntryInputs(), output)
			if !defaultRoute {
				configuration, result := selected.currentOutputConfigurationForApply(t.Context())
				if result.Outcome != 0 || len(configuration.Bindings) != 2 || configuration.Bindings[1].DestinationID != "backup" ||
					!reflect.DeepEqual(configuration.Bindings[1].Destination, output.bindings[1].destination) || len(configuration.Bindings[1].Targets) != 0 {
					t.Fatal("exact empty entry routing lost the declared dormant backup source", result)
				}
			}
			checkEmptyEntryReaderRouting(t, env, selected, want, nil)
		})
	}
}

// full_only: false
func TestOutputConfigurationGeneratedEmptyEntryRouting(t *testing.T) {
	env, keys, selected, row, effects, author := normalHandoffGeneratedFixture(t, false, true)
	entries := append(selected.currentEntryInputs(),
		suppliedSecret(t, env, "", "empty routed supplied source", custody.HermeticCloudflareValue),
		ApplyEntryInput{Name: "other", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{selected.admission.recipient}, InputBytes: []byte("other"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	slices.SortFunc(entries, func(a, b ApplyEntryInput) int { return bytes.Compare([]byte(a.Name), []byte(b.Name)) })
	output := &outputApplyInput{bindings: []outputApplyBinding{
		{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("", "app-empty")}},
		{destinationID: "backup", targets: []outputApplyTarget{outputConfigurationTarget("generated", "backup-generated"), outputConfigurationTarget("other", "backup-other")}},
	}, routes: []outputApplyRoute{
		{entryName: "", destinations: []string{"app"}},
		{defaultRoute: true, destinations: []string{"backup"}},
	}}
	selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, keys, entries, output)
	old := *selected.valueEntry(entrySlot(t, selected, ""))
	intent, requestBody := hermeticCloudflareIntent()
	profile := nativeGeneratedFixtureProfile(t, row)
	input := generatedPlanInputWithCurrentGenerated(t, selected, fixtureID(env.Domain, "empty routed generated operation"), []string{""}, profile, intent)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
	index := slices.IndexFunc(input.graph.ValueEntryPlans, func(plan contract.GeneratorValueEntryPlan) bool { return plan.Name == "" })
	if index < 0 {
		t.Fatal("generated declaration lacks the empty entry")
	}
	wantID := input.graph.ValueEntryPlans[index].EntryIncarnationID
	if wantID.IsZero() || wantID == old.Incarnation {
		t.Fatal("source conversion did not plan a fresh empty entry incarnation")
	}
	selected = author.create(selected, input)
	keys.RetireGenerated()
	selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
	configuration, result := selected.currentOutputConfigurationForApply(t.Context())
	want := []contract.OutputRoute{{EntryIncarnationID: wantID, Destinations: []string{"app"}}}
	if result.Outcome != 0 || !reflect.DeepEqual(configuration.Routes, want) || !slices.Equal(configuration.DefaultDestinations, []string{"backup"}) || effects.Load() != 2 || selected.valueEntry(entrySlot(t, selected, "")).Incarnation != wantID {
		t.Fatal("generated final/cold Open changed the complete empty entry routing", result, configuration.Routes)
	}
	publicWant := []contract.PublicRoutingRule{
		{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: ""}, Destinations: publicPresent([]string{"app"})},
		{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent([]string{"backup"})},
	}
	checkEmptyEntryReaderRouting(t, env, selected, publicWant, &row)
}
