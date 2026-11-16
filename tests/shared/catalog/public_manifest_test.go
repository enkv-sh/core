package catalog

import (
	"slices"
	"testing"
)

// full_only: false
func TestPublicManifestCatalogKeepsExactPublicRolesAndProviderModes(t *testing.T) {
	const name = "public-configuration.manifest/atomic_public_file"
	row, ok := PublicConfiguration(name)
	definition, declared := DefinitionFor(name)
	execution, executable := ExecutionFor(name, "live")
	roles := []string{"authority", "apply", "reader", "cleanup"}
	if !ok || !declared || !executable || row.Condition != "manifest" || row.EnabledOnly || row.DisabledOnly || row.Generated || !row.Output || row.Replacement != nil ||
		!definition.DistinctParticipants || !slices.Equal(definition.Roles, roles) || !slices.Equal(definition.Modes, []string{"live"}) ||
		!slices.Equal(definition.Providers, []string{"aws", "gcp"}) || !slices.Equal(definition.RecoveryModes, []string{"disabled", "enabled"}) ||
		execution.Family != FamilyPublicConfiguration || !execution.HasFixtureCapability(FixturePublicConfiguration) || execution.HasFixtureCapability(FixtureGeneratedProcess) ||
		len(execution.Writer) != 3 || len(execution.FreshBefore) != 0 || len(execution.FreshAfter) != 1 || execution.FreshAfter[0].Step.Role != "reader" {
		t.Fatal("manifest lost its exact public roles or four provider and Recovery cells")
	}
	for _, mode := range []string{"disabled", "enabled"} {
		if _, ok := ExecutionForRecovery(name, "live", mode); !ok || !slices.Equal(definition.RolesForRecovery(mode), roles) {
			t.Fatal("manifest provider mode unavailable", mode)
		}
	}
	for _, provider := range []string{"aws", "gcp"} {
		cloud := provider + "-secrets-manager"
		if provider == "gcp" {
			cloud = "gcp-secret-manager"
		}
		if !slices.Equal(row.OutputScopes(provider), []string{cloud}) {
			t.Fatal("manifest setup admitted an unrelated output effect", provider)
		}
	}
	if _, ok := ExecutionFor(name, "hermetic"); ok {
		t.Fatal("opt-in manifest entered local scenario discovery")
	}
	for _, wrong := range []string{"public-configuration.manifest", "public-configuration.manifest/manifest"} {
		if _, ok := PublicConfiguration(wrong); ok {
			t.Fatal("manifest admitted an undeclared case identity")
		}
	}
}
