package catalog

import (
	"reflect"
	"slices"
	"testing"
)

// full_only: false
func TestStockPluginAcceptanceCatalogFixesCloudMatrix(t *testing.T) {
	const name = "public-configuration.plugin-contracts/plugin_contracts"
	row, ok := PublicConfiguration(name)
	definition, known := DefinitionFor(name)
	execution, executable := ExecutionForRecovery(name, "live", "enabled")
	if !ok || !known || !executable {
		t.Fatal("stock plugin acceptance has no executable live case")
	}
	if row.Condition != "plugin-contracts" || !row.EnabledOnly || row.DisabledOnly ||
		!row.Generated || !row.Output || !definition.DistinctParticipants ||
		!slices.Equal(definition.Modes, []string{"live"}) ||
		!slices.Equal(definition.Providers, []string{"aws", "gcp"}) ||
		!slices.Equal(definition.RecoveryModes, []string{"enabled"}) ||
		!slices.Equal(definition.Roles, []string{"authority", "apply", "reader", "consumer", "cleanup"}) {
		t.Fatal("stock acceptance changed its provider, Recovery, effect or role boundary")
	}
	if execution.Family != FamilyPublicConfiguration || len(execution.Writer) != 3 ||
		len(execution.FreshBefore) != 0 || len(execution.FreshAfter) != 1 ||
		execution.FreshAfter[0].Role != "reader" {
		t.Fatal("stock acceptance lost the existing writer and independent post-exit reader")
	}
	for _, mode := range []string{"disabled"} {
		if _, ok := ExecutionForRecovery(name, "live", mode); ok {
			t.Fatal("stock acceptance admitted an undeclared Recovery cell", mode)
		}
	}
	// "both" is the existing catalog name for the complete projection, not
	// a second provider cell (ExecutionForRecovery in named_cases.go).
	if full, ok := ExecutionForRecovery(name, "live", "both"); !ok || !reflect.DeepEqual(full, execution) {
		t.Fatal("complete execution projection differs from the sole enabled cell")
	}
	if _, ok := ExecutionFor(name, "hermetic"); ok {
		t.Fatal("cloud acceptance entered a local scenario run")
	}
	for _, cell := range []struct {
		provider string
		scopes   []string
	}{
		{"aws", []string{"aws-secrets-manager", "github-repository", "github-organization", "github-environment"}},
		{"gcp", []string{"gcp-secret-manager"}},
		{"other", nil},
	} {
		if !slices.Equal(row.OutputScopes(cell.provider), cell.scopes) {
			t.Fatal("stock acceptance changed its declared output matrix", cell.provider)
		}
	}
}
