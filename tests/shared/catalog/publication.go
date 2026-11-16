package catalog

// PublicationCase names a fixed selected-state condition. The conformance
// artifact supplies controlled results; it does not qualify a cloud service.
type PublicationCase struct {
	Condition string
}

var publicationCases = []PublicationCase{
	{Condition: "separate-values-and-noop"},
	{Condition: "value-policy-delete"},
	{Condition: "ack-then-unknown"},
	{Condition: "unknown-then-ack"},
	{Condition: "unqualified-create"},
	{Condition: "wrong-instance"},
	{Condition: "unauthorized-later-member"},
	{Condition: "lost-process"},
	{Condition: "cancel-child"},
	{Condition: "cleanup-failure"},
}

func publicationGroup(name string) (PublicationCase, bool) {
	for _, row := range publicationCases {
		if name == "publication."+row.Condition {
			return row, true
		}
	}
	return PublicationCase{}, false
}

func publicationGroupNames() []string {
	names := make([]string, len(publicationCases))
	for index, row := range publicationCases {
		names[index] = "publication." + row.Condition
	}
	return names
}

func publicationScenarios() []scenario {
	declarations := make([]scenario, 0, len(publicationCases))
	for _, row := range publicationCases {
		execution := baseExecution(FamilyPublication, 3, FixtureSecretState, FixturePublication)
		description := "Select complete bindings, execute exact single-send actions through an authenticated child, check the complete result and reopen in fresh processes without restored send permission."
		if row.Condition == "lost-process" {
			description = "Select publication reservations, retire volatile preparation without sending, and reopen in a fresh process without restoring send permission; this case does not terminate a process."
		}
		declarations = append(declarations, scenario{
			name: "publication." + row.Condition, transition: row.Condition,
			title:         "Selected publication: " + row.Condition,
			description:   description,
			explicitShape: true, members: 1, smallBytes: 1, execution: execution,
		})
	}
	return append(declarations, livePublicationScenarios()...)
}

func publicationSteps(condition string) []Step {
	return []Step{
		{Name: "setup", Role: "authority", Expected: "selected-publication-and-private-child-ready"},
		{Name: "transition", Role: "authority", Expected: "publication-" + condition},
		{Name: "verification", Role: "authority", Expected: "complete-publication-result-and-joined-children"},
		{Name: "reopen", Role: "authority", Expected: "success"},
	}
}
