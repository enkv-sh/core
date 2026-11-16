package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

func installedApplyGeneratedValidator(t testing.TB, selected *StateSession) *PublicConfigurationValidator {
	t.Helper()
	return NewPublicConfigurationValidator(selected.admission.outputInterpreter)
}

func installedApplyCurrentInput(selected *StateSession) []ApplyEntryInput {
	input := selected.currentEntryInputs()
	for i := range input {
		if input[i].ValueSource == contract.Generated {
			input[i].InputBytes = nil
			continue
		}
		if input[i].ConfidentialityClass == contract.Secret {
			for _, named := range selected.root.Names {
				if named.Name == input[i].Name {
					old := selected.valueEntry(named.Slot)
					input[i].Retained = &contract.RetainedSecretInput{Incarnation: old.Incarnation, Material: old.ValueState}
					input[i].InputBytes = nil
					break
				}
			}
		}
	}
	return input
}

// full_only: false
func TestInstalledApplyRegistryAndGeneratedGrantPreserveParkedRetainedWork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	retained := newRetainedReaderFixture(t, true, 2)
	selected := retained.selected
	if !selected.root.Generated.ActiveOwner.IsZero() || selected.root.Generated.GeneratedCurrent == 0 || selected.root.Generated.Hazards != 2 {
		t.Fatal("parked generated/retained setup")
	}
	f := installedApplyTestFixture{env: retained.env, keys: retained.keys, basis: selected.admission.publicBasis(), composition: selected.admission.composition, admitted: OpenContext{admission: &selected.admission}, selected: selected}
	beforeWork, err := selected.workSupportRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeStable := installedApplyStableWork(t, ctx, selected)
	beforeAccess := selected.accessRecords()
	beforeEntries := make(map[string]contract.ValueEntry, len(selected.root.Names))
	for _, named := range selected.root.Names {
		beforeEntries[named.Name] = ownScenarioValueEntry(*selected.valueEntry(named.Slot))
	}
	beforeOutput := selected.root.OutputConfiguration
	input := installedApplyCurrentInput(selected)
	reader := fixtureID(f.env.Domain, "reader")
	changedName := ""
	for i := range input {
		if input[i].ValueSource == contract.Generated {
			input[i].Recipients = append(slices.Clone(input[i].Recipients), reader)
			slices.SortFunc(input[i].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			changedName = input[i].Name
			break
		}
	}
	if changedName == "" {
		t.Fatal("fixture has no generated grant target")
	}
	desired := currentApplyRecipients(selected.registry())
	desired[0].Recipient.DisplayName = "registry and membership selected together"
	validator := installedApplyGeneratedValidator(t, selected)
	engine := f.engineWithValidator(t, selected, input, desired, validator, nil)
	result := engine.Apply(ctx, fixtureID(f.env.Domain, "registry and generated grant"), input)
	engine.Close()
	if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.Payload.ChangedSubjects.Count != 4 {
		t.Fatal("registry and generated grant did not select complete subjects", result.Result)
	}
	fresh := f.open(t, ctx)
	if !reflect.DeepEqual(beforeStable, installedApplyStableWork(t, ctx, fresh)) || fresh.root.Generated.Slices != selected.root.Generated.Slices || fresh.root.OutputConfiguration != beforeOutput || fresh.root.Generated.Attempts != selected.root.Generated.Attempts || fresh.root.Generated.Hazards != selected.root.Generated.Hazards || fresh.root.Generated.Duties != selected.root.Generated.Duties {
		t.Fatal("apply changed Attempts, targets, seeds, duties, hazards, retained rows or output markers")
	}
	for _, named := range fresh.root.Names {
		after := *fresh.valueEntry(named.Slot)
		before := beforeEntries[named.Name]
		if named.Name == changedName {
			before.Recipients = after.Recipients
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatal("registry/grant changed protected selected entry")
		}
	}
	afterAccess := fresh.accessRecords()
	if len(beforeAccess) != len(afterAccess) {
		t.Fatal("registry/grant changed retained material inventory")
	}
	generated := beforeEntries[changedName]
	for i, before := range beforeAccess {
		after := afterAccess[i]
		if before.MaterialKind != after.MaterialKind || before.MaterialID != after.MaterialID {
			t.Fatal("registry/grant changed material identity")
		}
		if before.MaterialID != generated.ValueState {
			if !reflect.DeepEqual(before, after) {
				t.Fatal("unrelated current, seed or retained access changed")
			}
			continue
		}
		if len(after.Wraps) != len(before.Wraps)+1 {
			t.Fatal("generated grant did not add exactly one wrap")
		}
		for _, wrap := range before.Wraps {
			if !slices.ContainsFunc(after.Wraps, func(got contract.WrapRow) bool { return reflect.DeepEqual(got, wrap) }) {
				t.Fatal("generated grant changed an existing wrap")
			}
		}
	}
	var hazards []contract.ID
	for _, row := range beforeWork {
		if row.Kind == contract.GeneratedHazardSupportKind {
			hazards = append(hazards, row.RecordID)
		}
	}
	if len(result.Payload.LiveDutyIDs) != 0 || !slices.Equal(result.Payload.LiveHazardIDs, hazards) {
		t.Fatal("result omitted exact retained hazards")
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.SummaryCounts[contract.ReceiptHazardCount] != 2 || receipt.WarningBits&contract.ReceiptWarningPossibleLive == 0 {
		t.Fatal("receipt omitted retained hazard facts", err)
	}
	repeatInput := installedApplyCurrentInput(fresh)
	repeat := f.engineWithValidator(t, fresh, repeatInput, desired, validator, nil)
	repeated := repeat.Apply(ctx, fixtureID(f.env.Domain, "repeat registry and generated grant"), repeatInput)
	repeat.Close()
	if repeated.Result.Outcome != Unchanged {
		t.Fatal("retained complete repeat did not return unchanged", repeated.Result)
	}
}

// full_only: false
func TestInstalledApplyOccupiedOwnerPermitsValidatedNoopAndRefusesRegistryChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	selected := configurationRecoveryGenerated(t, ctx, f.env, f.selected, "generated-active")
	if selected.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("occupied canonical setup")
	}
	input := installedApplyCurrentInput(selected)
	desired := currentApplyRecipients(selected.registry())
	before, err := selected.workSupportRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	engine := f.engineWithRecipients(t, selected, input, desired, nil)
	unchanged := engine.Apply(ctx, fixtureID(f.env.Domain, "occupied exact noop"), input)
	engine.Close()
	if unchanged.Result.Outcome != Unchanged {
		t.Fatal("occupied owner rejected validated no-op", unchanged.Result)
	}
	desired[0].Recipient.DisplayName = "conflicting registry change"
	engine = f.engineWithRecipients(t, selected, input, desired, nil)
	changed := engine.Apply(ctx, fixtureID(f.env.Domain, "occupied registry change"), input)
	engine.Close()
	if changed.Result.Outcome == ObservedCurrent || changed.Result.Outcome == Unchanged {
		t.Fatal("occupied owner admitted registry mutation", changed.Result)
	}
	fresh := f.open(t, ctx)
	after, err := fresh.workSupportRecords(ctx)
	if err != nil || !reflect.DeepEqual(before, after) || fresh.head.Core.Revision != selected.head.Core.Revision || fresh.root.Generated.ActiveOwner != selected.root.Generated.ActiveOwner {
		t.Fatal("occupied refusal changed selected owner or work", err)
	}
}

func installedApplyStableWork(t testing.TB, ctx context.Context, selected *StateSession) []contract.SupportRecordDigest {
	t.Helper()
	work, err := selected.workSupportRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	all, err := selected.selectedNormalSupportRows()
	if err != nil {
		t.Fatal(err)
	}
	facts := make([]contract.SupportRecordDigest, 0, len(work))
	for _, row := range work {
		_, snapshotOwned, err := snapshotSliceRecord(row, selected.root.Domain, selected.adminIndex.SliceSnapshot)
		if err != nil {
			t.Fatal(err)
		}
		if snapshotOwned {
			continue
		}
		i := slices.IndexFunc(all.Records, func(candidate contract.SupportRecord) bool {
			return candidate.Kind == row.Kind && candidate.RecordID == row.RecordID
		})
		if i < 0 {
			t.Fatal("authenticated work row fact missing")
		}
		facts = append(facts, all.Facts[i])
	}
	return facts
}
