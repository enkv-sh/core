package core

import (
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicNoResourceGeneratorOwnsAbsentResourceFields(t *testing.T) {
	validator := NewPublicConfigurationValidator(nil)
	input := publicConfigurationFixture(t)
	entry := publicFixtureEntry(input, "local")
	entry.Source = publicPresent(contract.Generated)
	entry.Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleNone)
	input.Entries = publicPresent([]contract.PublicEntry{entry})
	valid := validator.Validate(t.Context(), input)
	if !valid.Valid || !valid.Complete || valid.Configuration.Entries.Value[0].Generated.LifecycleMode.Value != contract.GeneratorLifecycleNone {
		t.Fatal("no-resource intent refused", valid.Diagnostics)
	}
	if unsafe.Sizeof(contract.GeneratedPlanningEntry{}) != 312 {
		t.Fatal("planning row layout differs")
	}
	for _, damage := range []func(*contract.PublicGeneratedSettings){
		func(g *contract.PublicGeneratedSettings) { g.ResourceContractID = publicPresent(generatedVectorID(4)) },
		func(g *contract.PublicGeneratedSettings) { g.Retirement = publicPresent(uint8(1)) },
		func(g *contract.PublicGeneratedSettings) { g.Completion = publicPresent(uint8(1)) },
		func(g *contract.PublicGeneratedSettings) {
			g.ContentIntent = publicPresent(publicFixtureIntent(contract.GeneratorLifecycleManaged, []byte(`{}`)))
		},
	} {
		bad := *entry.Generated
		damage(&bad)
		input.Entries.Value[0].Generated = &bad
		if got := validator.Validate(t.Context(), input); got.Valid {
			t.Fatal("no-resource intent accepted conflicting fields")
		}
	}
}

// full_only: false
func TestGeneratedPlanningUsesCurrentResourceLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name              string
		current, proposed contract.GeneratorLifecycleMode
		remove, supplied  bool
		want              contract.GeneratedPlanningRetirement
	}{
		{name: "no_resource_rotation", current: contract.GeneratorLifecycleNone, proposed: contract.GeneratorLifecycleNone, want: contract.GeneratedPlanningNoRetirement},
		{name: "no_resource_removal", current: contract.GeneratorLifecycleNone, remove: true, want: contract.GeneratedPlanningNoRetirement},
		{name: "no_resource_to_supplied", current: contract.GeneratorLifecycleNone, supplied: true, want: contract.GeneratedPlanningNoRetirement},
		{name: "no_resource_to_managed", current: contract.GeneratorLifecycleNone, proposed: contract.GeneratorLifecycleManaged, want: contract.GeneratedPlanningNoRetirement},
		{name: "managed_to_no_resource", current: contract.GeneratorLifecycleManaged, proposed: contract.GeneratorLifecycleNone, want: contract.GeneratedPlanningRetireAfterSuccessor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := generatedPlanningUnitEntry(t, "value")
			localize := func(e *contract.PublicEntry) {
				epoch := e.Generated.Epoch.Value
				e.Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleNone)
				e.Generated.Epoch.Value = epoch
			}
			if tc.current == contract.GeneratorLifecycleNone {
				localize(&before)
			}
			after := before
			settings := *before.Generated
			after.Generated = &settings
			after.Generated.Epoch.Value++
			switch tc.proposed {
			case contract.GeneratorLifecycleNone:
				localize(&after)
			case contract.GeneratorLifecycleManaged:
				after = generatedPlanningUnitEntry(t, "value")
				after.Generated.Epoch.Value = before.Generated.Epoch.Value + 1
			}
			proposed := &after
			if tc.remove {
				proposed = nil
			}
			if tc.supplied {
				after.Source = publicPresent(contract.Supplied)
				after.Generated = nil
			}
			row := classifyGeneratedPlanningEntry(proposed, &before)
			if row.Retirement != tc.want || row.CurrentLifecycleMode != tc.current {
				t.Fatal("retirement did not follow authenticated current kind", row.Retirement, row.CurrentLifecycleMode)
			}
		})
	}
}
