package catalog

import (
	"slices"
	"testing"
)

// full_only: false
func TestPublicMaterializationCatalogKeepsExactPublicRolesAndProviderModes(t *testing.T) {
	const name = "public-configuration.materialization/atomic_recipient_file"
	row, ok := PublicConfiguration(name)
	definition, declared := DefinitionFor(name)
	execution, executable := ExecutionFor(name, "live")
	roles := []string{"authority", "apply", "reader", "recipient-consumer", "cleanup"}
	if !ok || !declared || !executable || row.Condition != "materialization" || !row.EnabledOnly || row.DisabledOnly || row.Generated || row.Output || row.Replacement != nil ||
		!definition.DistinctParticipants || !slices.Equal(definition.Roles, roles) || !slices.Equal(definition.Modes, []string{"live"}) ||
		!slices.Equal(definition.Providers, []string{"aws", "gcp"}) || !slices.Equal(definition.RecoveryModes, []string{"enabled"}) ||
		execution.Family != FamilyPublicConfiguration || !execution.HasFixtureCapability(FixturePublicConfiguration) || execution.HasFixtureCapability(FixtureGeneratedProcess) ||
		len(execution.Writer) != 3 || len(execution.FreshBefore) != 0 || len(execution.FreshAfter) != 1 || execution.FreshAfter[0].Step.Role != "reader" {
		t.Fatal("materialization lost its exact public roles or two Recovery-enabled provider cells")
	}
	if _, ok := ExecutionForRecovery(name, "live", "enabled"); !ok || !slices.Equal(definition.RolesForRecovery("enabled"), roles) {
		t.Fatal("materialization enabled cell unavailable")
	}
	if _, ok := ExecutionForRecovery(name, "live", "disabled"); ok {
		t.Fatal("materialization admitted an unqualified disabled live cell")
	}
	if _, ok := ExecutionFor(name, "hermetic"); ok {
		t.Fatal("opt-in materialization entered local scenario discovery")
	}
	for _, wrong := range []string{"public-configuration.materialization", "public-configuration.materialization/materialization"} {
		if _, ok := PublicConfiguration(wrong); ok {
			t.Fatal("materialization admitted an undeclared case identity")
		}
	}
}
