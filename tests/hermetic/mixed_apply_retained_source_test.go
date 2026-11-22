package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestMixedApplyKeepsAnExistingOwnerOfTheSuppliedSecret(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
	authority := f.selected.admission.recipient
	secret := suppliedSecret(t, f.env, "secret", "mixed apply source", custody.StandardValue, authority)
	initial := f.engine(t, f.selected, []ApplyEntryInput{secret}, nil)
	out := initial.Apply(ctx, testID("select supplied source"), []ApplyEntryInput{secret})
	initial.Close()
	if out.Result.Outcome != ObservedCurrent {
		t.Fatal("initial supplied entry", out.Result)
	}
	selected := f.open(t, ctx)
	_, original := observeCurrentValueEntry(t, selected, secret.Name)
	sources, canonical := generatedCurrentDeclaration(t, selected)
	names := []string{"previous"}
	plan := generatedPlanInputForGenerations(t, selected, testID("retain supplied source"), names, defaultGeneratedFixtureProfile(), sources...)
	_, attempt := selectPrivateOwnedUnusableAggregateFromInput(t, f.env, selected, names, plan, canonical)
	parked := f.open(t, ctx)
	owner := attempt.expected.Template.HazardID
	checkSource := func(t *testing.T, s *StateSession) {
		t.Helper()
		retained, result := s.generatedConsumerSelection(ctx, contract.GeneratedHazardSupportKind, owner, original.ValueState, authority)
		if result.Outcome != ObservedCurrent || !reflect.DeepEqual(retained.Selection.Entry, original) {
			t.Fatal("retained owner lost its exact entry", result)
		}
		if check := f.keys.ConsumeGenerated(ctx, retained, custody.StandardValue); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
			t.Fatal("retained owner lost secret access", check.Code)
		}
	}
	checkSource(t, parked)
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	f.env.GeneratedProcess = process
	generation := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema,
		LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual,
		ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
		CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
	input := []ApplyEntryInput{{Name: "generated", Recipients: []contract.ID{authority}, ValueSource: contract.Generated,
		InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw,
		ConfidentialityClass: contract.Secret, Generated: &generation}, secret}
	mixed := installedGeneratedTestEngine(t, ctx, f, parked, input, currentApplyRecipients(parked.registry()), installedGeneratedTestCallbacks(t, f, process))
	out = mixed.Apply(ctx, testID("add generated sibling"), input)
	mixed.Close()
	creates, deletes := effects()
	if out.Result.Outcome != ObservedCurrent || creates != 1 || deletes != 0 {
		t.Fatal("mixed apply did not finish with one create", out.Result, creates, deletes)
	}
	cold := f.open(t, ctx)
	for _, wanted := range input {
		_, entry := observeCurrentValueEntry(t, cold, wanted.Name)
		payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
		if err != nil || entry.ValueSource != wanted.ValueSource || payload.CryptoSupportID != cold.root.CurrentAccess.Core.CryptoSupportID {
			t.Fatal("selected secret lost the Crypto support ID of its control", wanted.Name, err)
		}
	}
	current := sessionConsumerSelection(t, cold, authority, secret.Name)
	material := "original-current-material"
	if current.Entry.ValueState != original.ValueState {
		material = "new-current-material"
	}
	t.Run(material, func(t *testing.T) {
		checkSource(t, cold)
		if check := f.keys.Consume(ctx, current, custody.StandardValue); check.Code != contract.CryptoSuccess || !check.ValueMatched {
			t.Fatal("current reader lost secret access", check.Code)
		}
	})
	ended := retainedReaderEndWork(t, cold, owner, f.env.Trust)
	ended = retainedReaderColdOpen(t, ended, f.env.Store)
	if _, present := mustSelectedGeneratedWork(t, ended).records[generatedRecordKey{contract.GeneratedHazardSupportKind, owner}]; present {
		t.Fatal("exact ending left the retained owner selected")
	}
}
