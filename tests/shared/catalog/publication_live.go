package catalog

// LivePublicationCase fixes the output scope and fixture namespace before
// credentials or native artifacts are prepared. A scope is not a State provider.
type LivePublicationCase struct {
	Scope, Condition, Namespace string
}

var livePublicationCases = []LivePublicationCase{
	{"aws-secrets-manager", "plain-secret-lifecycle", "positive"},
	{"gcp-secret-manager", "plain-secret-lifecycle", "positive"},
	{"github-repository", "plain-secret-lifecycle", "positive"},
	{"github-organization", "plain-secret-lifecycle", "positive"},
	{"github-environment", "plain-secret-lifecycle", "positive"},
	{"aws-secrets-manager", "later-member-refusal", "ambiguity"},
	{"gcp-secret-manager", "later-member-refusal", "ambiguity"},
	{"github-repository", "later-member-refusal", "ambiguity"},
	{"github-organization", "later-member-refusal", "ambiguity"},
	{"github-environment", "later-member-refusal", "ambiguity"},
	{"mixed", "mixed-destinations", "positive"},
}

func (c LivePublicationCase) name() string {
	if c.Scope == "mixed" {
		return "publication.mixed-destinations"
	}
	return "publication." + c.Scope + "." + c.Condition
}

func HistoricalLivePublication(name string) (LivePublicationCase, bool) {
	for _, row := range livePublicationCases {
		if row.name() == name {
			return row, true
		}
	}
	return LivePublicationCase{}, false
}

func livePublicationGroupNames() []string {
	names := make([]string, len(livePublicationCases))
	for i, row := range livePublicationCases {
		names[i] = row.name()
	}
	return names
}

// OutputScopes retains one State provider's credential boundary. A mixed cell
// has that provider's cloud output and all three independent GitHub scopes.
func (c LivePublicationCase) OutputScopes(provider string) []string {
	if provider != "aws" && provider != "gcp" {
		return nil
	}
	cloud := "aws-secrets-manager"
	if provider == "gcp" {
		cloud = "gcp-secret-manager"
	}
	if c.Scope == "mixed" {
		return []string{cloud, "github-repository", "github-organization", "github-environment"}
	}
	switch c.Scope {
	case "aws-secrets-manager", "gcp-secret-manager":
		if c.Scope != cloud {
			return nil
		}
	case "github-repository", "github-organization", "github-environment":
	default:
		return nil
	}
	return []string{c.Scope}
}

func livePublicationScenarios() []scenario {
	rows := make([]scenario, 0, len(livePublicationCases))
	for _, row := range livePublicationCases {
		rows = append(rows, scenario{
			name: row.name(), transition: row.Condition,
			title:         "Selected publication: " + row.Scope + " " + row.Condition,
			description:   "Select a complete plain/secret group, use the exact named native output children, retain complete action results, check available consumer evidence, and reopen without restored send permission.",
			explicitShape: true, members: 1, smallBytes: 1,
			execution: baseExecution(FamilyPublication, 3, FixtureSecretState, FixturePublication),
		})
	}
	return rows
}
