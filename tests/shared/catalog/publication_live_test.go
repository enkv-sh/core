package catalog

import (
	"slices"
	"testing"
)

// full_only: false
func TestLivePublicationCatalogFixesScopesAndNamespaces(t *testing.T) {
	scopes := []string{"aws-secrets-manager", "gcp-secret-manager", "github-repository", "github-organization", "github-environment"}
	var names []string
	for _, condition := range []string{"plain-secret-lifecycle", "later-member-refusal"} {
		for _, scope := range scopes {
			name := "publication." + scope + "." + condition
			names = append(names, name)
			row, ok := HistoricalLivePublication(name)
			wantNamespace := "positive"
			if condition == "later-member-refusal" {
				wantNamespace = "ambiguity"
			}
			definition, declared := HistoricalDefinitionFor(name)
			providers := []string{"aws", "gcp"}
			switch scope {
			case "aws-secrets-manager":
				providers = []string{"aws"}
			case "gcp-secret-manager":
				providers = []string{"gcp"}
			}
			if !ok || !declared || row.Scope != scope || row.Condition != condition || row.Namespace != wantNamespace ||
				!slices.Equal(definition.Modes, []string{"live"}) || !slices.Equal(definition.Providers, providers) ||
				!slices.Equal(definition.RecoveryModes, []string{"disabled", "enabled"}) {
				t.Fatal("live publication selection differs", name)
			}
			for _, provider := range providers {
				if !slices.Equal(row.OutputScopes(provider), []string{scope}) {
					t.Fatal("publication scope substitution", name, provider)
				}
			}
			execution, known := HistoricalExecutionFor(name, "live")
			if !known || validateExecution(definition, execution) != nil || execution.Family != FamilyPublication ||
				!execution.HasFixtureCapability(FixturePublication) || len(execution.FreshBefore) == 0 || len(execution.FreshAfter) == 0 {
				t.Fatal("live publication omitted its roles or fresh process", name)
			}
			if _, known := HistoricalExecutionFor(name, "hermetic"); known {
				t.Fatal("named live case silently became a local conformance case", name)
			}
		}
	}
	names = append(names, "publication.mixed-destinations")
	if !slices.Equal(livePublicationGroupNames(), names) {
		t.Fatal("live publication inventory differs")
	}
	mixed, ok := HistoricalLivePublication("publication.mixed-destinations")
	if !ok || mixed.Namespace != "positive" ||
		!slices.Equal(mixed.OutputScopes("aws"), []string{"aws-secrets-manager", "github-repository", "github-organization", "github-environment"}) ||
		!slices.Equal(mixed.OutputScopes("gcp"), []string{"gcp-secret-manager", "github-repository", "github-organization", "github-environment"}) {
		t.Fatal("mixed live cell lost a complete destination scope")
	}
	for _, row := range livePublicationCases {
		if row.OutputScopes("memory") != nil || row.Scope == "aws-secrets-manager" && row.OutputScopes("gcp") != nil || row.Scope == "gcp-secret-manager" && row.OutputScopes("aws") != nil {
			t.Fatal("publication crossed the selected State-provider boundary")
		}
	}
	if (LivePublicationCase{Scope: "other"}).OutputScopes("aws") != nil {
		t.Fatal("unknown output scope admitted")
	}
}
