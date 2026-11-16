package catalog

import (
	"reflect"
	"slices"
	"testing"
)

// full_only: false
func TestPublicationCatalogRequiresLocalConditionsAndFreshReopens(t *testing.T) {
	want := []string{
		"publication.separate-values-and-noop", "publication.value-policy-delete",
		"publication.ack-then-unknown", "publication.unknown-then-ack",
		"publication.unqualified-create", "publication.wrong-instance",
		"publication.unauthorized-later-member", "publication.lost-process",
		"publication.cancel-child", "publication.cleanup-failure",
	}
	if !slices.Equal(publicationGroupNames(), want) {
		t.Fatal("publication conditions incomplete or reordered", publicationGroupNames())
	}
	for _, name := range want {
		t.Run(name, func(t *testing.T) {
			row, known := publicationGroup(name)
			definition, declared := HistoricalDefinitionFor(name)
			if !known || !declared || "publication."+row.Condition != name ||
				!slices.Equal(definition.Modes, []string{"hermetic"}) ||
				!slices.Equal(definition.Providers, []string{"memory"}) ||
				!slices.Equal(definition.RecoveryModes, []string{"disabled", "enabled"}) ||
				!slices.Equal(definition.RolesForRecovery("both"), []string{"authority", "recovery"}) {
				t.Fatal("local child condition has incorrect modes or roles", definition)
			}
			wantSteps := []Step{
				{Name: "setup", Role: "authority", Expected: "selected-publication-and-private-child-ready"},
				{Name: "transition", Role: "authority", Expected: name},
				{Name: "verification", Role: "authority", Expected: "complete-publication-result-and-joined-children"},
				{Name: "reopen", Role: "authority", Expected: "success"},
			}
			wantSteps[1].Expected = "publication-" + name[len("publication."):]
			wantShape := Shape{Members: 1, SmallValueCount: 1, SmallValueBytes: 1, RawValueBytes: 1, ValueSeed: "member_index_modulo_256"}
			if !reflect.DeepEqual(definition.Steps, wantSteps) || !reflect.DeepEqual(definition.Fixture, wantShape) {
				t.Fatal("publication declaration changed its fixed steps or initial shape", definition)
			}
			execution, known := HistoricalExecutionFor(name, "hermetic")
			if !known || validateExecution(definition, execution) != nil || execution.Family != FamilyPublication ||
				!execution.HasFixtureCapability(FixturePublication) || len(execution.Writer) != 8 ||
				len(execution.FreshBefore) != 2 || len(execution.FreshAfter) != 2 {
				t.Fatal("publication omitted a phase or fresh process", execution)
			}
			for index, mode := range []string{"disabled", "enabled"} {
				for position, step := range wantSteps {
					step.RecoveryMode = mode
					phase := execution.Writer[4*index+position]
					if phase.Step != step || phase.StepIndex != position || phase.MeasurementsExpected != (position != 3) {
						t.Fatal("publication writer phase changed", phase)
					}
				}
				before, after := execution.FreshBefore[index], execution.FreshAfter[index]
				if before.Purpose != FreshReopen || before.Count != 1 || before.Step.RecoveryMode != mode ||
					before.WriterPosition != 4*index+3 || after.Purpose != FreshReopen || after.Count != 1 ||
					after.WriterPosition != -1 || after.Step.RecoveryMode != mode || before.Role != "authority" || after.Role != "authority" {
					t.Fatal("publication fresh process does not bind its original mode and phase", before, after)
				}
			}
			if _, known := HistoricalExecutionFor(name, "live"); known {
				t.Fatal("conformance child claims live provider coverage")
			}
		})
	}
	if _, known := publicationGroup("publication.unknown"); known {
		t.Fatal("unknown publication condition admitted")
	}
}
