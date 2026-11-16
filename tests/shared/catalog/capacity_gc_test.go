package catalog

import (
	"slices"
	"testing"
)

// full_only: false
func TestCapacityGCCatalogKeepsExactPublicRolesAndProviderModes(t *testing.T) {
	const name = "public-configuration.capacity-gc/bounded_manual_gc"
	row, ok := PublicConfiguration(name)
	definition, declared := DefinitionFor(name)
	execution, executable := ExecutionFor(name, "live")
	roles := []string{"authority", "apply", "reader", "cleanup"}
	if !ok || !declared || !executable || row.Condition != "capacity-gc" || row.Generated || row.Output || row.Replacement != nil || row.EnabledOnly || row.DisabledOnly ||
		!definition.DistinctParticipants || !slices.Equal(definition.Roles, roles) || !slices.Equal(definition.Modes, []string{"live"}) ||
		!slices.Equal(definition.Providers, []string{"aws", "gcp"}) || !slices.Equal(definition.RecoveryModes, []string{"disabled", "enabled"}) ||
		execution.Family != FamilyPublicConfiguration || !execution.HasFixtureCapability(FixturePublicConfiguration) ||
		execution.HasFixtureCapability(FixtureGeneratedProcess) || len(execution.Writer) != 3 || len(execution.FreshAfter) != 1 || execution.FreshAfter[0].Step.Role != "reader" {
		t.Fatal("capacity/GC registration changed its concrete public contract")
	}
	for _, mode := range []string{"disabled", "enabled"} {
		if _, ok := ExecutionForRecovery(name, "live", mode); !ok || !slices.Equal(definition.RolesForRecovery(mode), roles) {
			t.Fatal("capacity/GC registration lost an explicit Recovery mode", mode)
		}
	}
	if _, ok := ExecutionFor(name, "hermetic"); ok {
		t.Fatal("opt-in capacity/GC provider preparation entered local scenario discovery")
	}
	for _, wrong := range []string{"public-configuration.capacity-gc", "public-configuration.capacity-gc/capacity_gc"} {
		if _, ok := PublicConfiguration(wrong); ok {
			t.Fatal("capacity/GC admitted an unregistered case identity")
		}
	}
}
