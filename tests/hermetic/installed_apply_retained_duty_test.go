package core

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestInstalledApplyPreservedRetirementDutyKeepsSuccessfulReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, selected := retirementInterruptionFixture(t, ctx, []string{"generated"})
	if !selected.root.Generated.ActiveOwner.IsZero() || selected.root.Generated.Duties != 1 || selected.root.Generated.Hazards != 0 {
		t.Fatal("actual detached retirement duty setup")
	}
	f := installedApplyTestFixture{env: env, keys: env.Custody, basis: selected.admission.publicBasis(), composition: selected.admission.composition, admitted: OpenContext{admission: &selected.admission}, selected: selected}
	before, err := selected.workSupportRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeStable := installedApplyStableWork(t, ctx, selected)
	var duties []contract.ID
	for _, row := range before {
		if row.Kind == contract.GeneratedDutySupportKind {
			duties = append(duties, row.RecordID)
		}
	}
	if len(duties) != 1 {
		t.Fatal("complete live duty set absent")
	}
	input := installedApplyCurrentInput(selected)
	desired := currentApplyRecipients(selected.registry())
	desired[0].Recipient.DisplayName = "display with unrelated retained retirement"
	engine := f.engineWithValidator(t, selected, input, desired, installedApplyGeneratedValidator(t, selected), nil)
	result := engine.Apply(ctx, fixtureID(env.Domain, "metadata preserves existing retirement duty"), input)
	engine.Close()
	if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.Payload.ChangedSubjects.Count != 1 || !slices.Equal(result.Payload.LiveDutyIDs, duties) || len(result.Payload.LiveHazardIDs) != 0 {
		t.Fatal("display change lost exact retained duty result", result.Result)
	}
	fresh := f.open(t, ctx)
	if !reflect.DeepEqual(beforeStable, installedApplyStableWork(t, ctx, fresh)) || fresh.root.Generated.Slices != selected.root.Generated.Slices || !slices.Equal(fresh.generatedSliceLocations, selected.generatedSliceLocations) {
		t.Fatal("display change altered exact unrelated duty, target, content or generated work")
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.SummaryCounts[contract.ReceiptDutyCount] != 1 || receipt.SummaryCounts[contract.ReceiptHazardCount] != 0 {
		t.Fatal("receipt lost complete retained duty counts", err)
	}
	if receipt.StateResult != contract.ReceiptStateSuccess {
		t.Fatal("preserved unrelated duty changed successful Apply into newly pending retirement", receipt.StateResult)
	}
}
