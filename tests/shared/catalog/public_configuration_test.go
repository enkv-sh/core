package catalog

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// full_only: false
func TestPublicConfigurationCatalogRequiresExactLiveRolesAndBoundaries(t *testing.T) {
	conditions := []string{"plugin-contracts", "prepare-complete-loss", "manifest", "materialization", "inspection-receipts", "capacity-gc", "output-standalone", "output-combined", "generated-manual-lifecycle", "generated-auto-rotation", "credential-discovery", "standard-discovery", "empty-initialization", "required-public-denied", "normal-signing-denied", "authority-private-denied", "recovery-signing-denied", "recovery-private-denied", "portable-validation", "fresh-secret-apply", "retained-input-access", "readonly-unknown-outcomes", "recipient-lifecycle"}
	denied := map[string]string{"required-public-denied": "denied-public", "normal-signing-denied": "denied-normal-signing", "authority-private-denied": "denied-authority-private", "recovery-signing-denied": "denied-recovery-signing", "recovery-private-denied": "denied-recovery-private"}
	for _, condition := range conditions {
		t.Run(condition, func(t *testing.T) {
			name := "public-configuration." + condition + "/" + strings.ReplaceAll(condition, "-", "_")
			if condition == "capacity-gc" {
				name = "public-configuration.capacity-gc/bounded_manual_gc"
			}
			if condition == "manifest" {
				name = "public-configuration.manifest/atomic_public_file"
			}
			if condition == "materialization" {
				name = "public-configuration.materialization/atomic_recipient_file"
			}
			row, ok := PublicConfiguration(name)
			definition, known := DefinitionFor(name)
			execution, executable := ExecutionFor(name, "live")
			if !ok || !known || !executable || row.Condition != condition || row.DeniedRole != denied[condition] || !reflect.DeepEqual(definition.Modes, []string{"live"}) || !reflect.DeepEqual(definition.Providers, []string{"aws", "gcp"}) || execution.Family != FamilyPublicConfiguration || !execution.HasFixtureCapability(FixturePublicConfiguration) || len(execution.Writer) != 3 || len(execution.FreshBefore) != 0 || len(execution.FreshAfter) != 1 || execution.FreshAfter[0].Role != "reader" {
				t.Fatal("public executable path or role boundary differs", name)
			}
			if strings.HasPrefix(condition, "generated-") && (!row.Generated || !execution.HasFixtureCapability(FixtureGeneratedProcess) || !slices.Equal(definition.Roles, []string{"authority", "apply", "reader", "cleanup"})) {
				t.Fatal("public generator fixture lost exact installed roles or capability")
			}
			if condition == "inspection-receipts" && (!definition.DistinctParticipants || !slices.Equal(definition.Roles, []string{"authority", "apply", "reader", "cleanup"}) || row.EnabledOnly || row.DisabledOnly || row.Generated || row.Output || row.Replacement != nil) {
				t.Fatal("inspection and receipt reads lost exact public-only roles or Recovery applicability")
			}
			if condition == "capacity-gc" {
				if !definition.DistinctParticipants || !slices.Equal(definition.Roles, []string{"authority", "apply", "reader", "cleanup"}) ||
					!slices.Equal(definition.RecoveryModes, []string{"disabled", "enabled"}) || row.EnabledOnly || row.DisabledOnly || row.Generated || row.Output || row.Replacement != nil {
					t.Fatal("capacity/GC lost its exact public-only roles or both Recovery modes")
				}
				steps := []Step{{Name: "setup", Role: "authority", Expected: "selector-only-source-and-exact-roles-ready"}, {Name: "transition", Role: "authority", Expected: "joined-public-configuration-actions-exact"}, {Name: "verification", Role: "authority", Expected: "independent-public-private-and-source-facts-exact"}}
				for i, want := range steps {
					if execution.Writer[i].Step != want || !execution.Writer[i].MeasurementsExpected {
						t.Fatal("capacity/GC writer steps changed", i)
					}
				}
				if execution.FreshAfter[0].Step.Expected != "pair-only-independent-public-observation-exact" || !execution.FreshAfter[0].MeasurementsExpected {
					t.Fatal("capacity/GC lost its separate final Reader observation")
				}
			}
			if condition == "prepare-complete-loss" && (!definition.DistinctParticipants || !slices.Equal(definition.Roles, []string{"authority", "apply", "reader", "consumer", "cleanup"}) || !slices.Equal(definition.RecoveryModes, []string{"disabled", "enabled"}) || row.EnabledOnly || row.DisabledOnly || row.Generated || row.Output || row.Replacement != nil) {
				t.Fatal("complete-loss preparation changed its exact roles, effects or Recovery applicability")
			}
			if condition == "credential-discovery" && (definition.DistinctParticipants || !slices.Equal(definition.Roles, []string{"authority", "apply", "reader", "consumer", "cleanup"})) {
				t.Fatal("operator authentication case changed principal or logical role contract")
			}
			if condition == "recipient-lifecycle" && !slices.Equal(definition.Roles, []string{"authority", "apply", "proposer", "reader", "consumer", "recipient-consumer", "excluded-consumer", "recovery", "cleanup"}) {
				t.Fatal("recipient preparation requires its distinct public-only Proposer role")
			}
			if _, known := ExecutionFor(name, "hermetic"); known {
				t.Fatal("opt-in live case entered ordinary local discovery")
			}
			for _, role := range []string{"authority", "reader", "cleanup"} {
				if !slices.Contains(definition.Roles, role) {
					t.Fatal("public case omitted mandatory owner", role)
				}
			}
			if row.DeniedRole != "" && !slices.Contains(definition.Roles, row.DeniedRole) {
				t.Fatal("denial case omitted exact selected denied role")
			}
			for _, mode := range []string{"disabled", "enabled"} {
				_, executable := ExecutionForRecovery(name, "live", mode)
				if executable == (row.EnabledOnly && mode == "disabled") {
					t.Fatal("Recovery applicability differs", mode)
				}
				roles := definition.RolesForRecovery(mode)
				if executable && (len(roles) == 0 || mode == "disabled" && slices.Contains(roles, "recovery")) {
					t.Fatal("disabled Recovery acquired unused role")
				}
			}
			first := row.Roles[0]
			row.Roles[0] = "mutated"
			again, _ := PublicConfiguration(name)
			if again.Roles[0] != first {
				t.Fatal("catalog lends mutable role backing")
			}
		})
	}
	if len(publicConfigurationCases) != len(conditions)+19 {
		t.Fatal("public live family inventory changed without exact coverage")
	}
	for _, mode := range []string{"disabled", "enabled", "both"} {
		t.Run("hermetic-regression/"+mode, func(t *testing.T) {
			regression := RegressionNamesForRecovery(mode)
			want := 97
			if mode == "disabled" {
				want = 60
			}
			if len(regression) != want {
				t.Fatal("shared regression inventory changed", mode, len(regression))
			}
			for _, name := range regression {
				definition, known := DefinitionFor(name)
				if !known || !slices.Contains(definition.Modes, "live") || !slices.Contains(definition.Modes, "hermetic") || strings.HasPrefix(name, "public-configuration.") {
					t.Fatal("live-only case became required for local regression coverage", name)
				}
			}
			var hermetic []string
			for _, name := range OrdinaryNames() {
				definition, _ := DefinitionFor(name)
				if slices.Contains(definition.Modes, "hermetic") && len(definition.RolesForRecovery(mode)) != 0 {
					hermetic = append(hermetic, name)
				}
			}
			complete, err := Resolve(Request{Include: hermetic, RecoveryMode: mode, Repetitions: 1})
			if err != nil || !complete.FullCoverage || !slices.Equal(complete.Selected, hermetic) || len(complete.Entries) != len(hermetic) {
				t.Fatal("complete local catalog lost exact regression coverage", mode, err)
			}
			narrow := slices.DeleteFunc(slices.Clone(hermetic), func(name string) bool { return name == regression[0] })
			focused, err := Resolve(Request{Include: narrow, RecoveryMode: mode, Repetitions: 1})
			if err != nil || focused.FullCoverage {
				t.Fatal("missing shared regression case acquired full coverage", mode, err)
			}
		})
	}
}

// full_only: false
func TestPublicConfigurationSmokeCannotOpenInjectedFixtures(t *testing.T) {
	names := []string{"public-configuration.empty-initialization/empty_initialization", "public-configuration.recovery-private-denied/recovery_private_denied"}
	schedule, err := Resolve(Request{Include: names, RecoveryMode: "disabled", Repetitions: 1})
	if err != nil || schedule.SmokePolicy != SmokePublicConfiguration || len(schedule.Entries) != 1 || !schedule.Entries[0].Smoke || schedule.Entries[0].Scenario != names[0] || !reflect.DeepEqual(schedule.NotApplicable, names[1:]) {
		t.Fatal("public smoke changed context or applicability", schedule, err)
	}
	for _, policy := range []SmokePolicy{SmokeSeparatePoint, SmokeFirstSelectedPoint} {
		if _, err := Resolve(Request{Include: names, RecoveryMode: "enabled", Repetitions: 1, SmokePolicy: policy}); err == nil {
			t.Fatal("injected smoke policy entered public SDK path", policy)
		}
	}
	if _, err := Resolve(Request{Include: []string{"state.single-value-update-preserves-other-values/members_32"}, RecoveryMode: "disabled", Repetitions: 1, SmokePolicy: SmokePublicConfiguration}); err == nil {
		t.Fatal("public smoke policy admitted unrelated fixture")
	}
}
