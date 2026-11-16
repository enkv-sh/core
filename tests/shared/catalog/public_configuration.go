package catalog

import "slices"

// PublicConfigurationCase selects a finite public CLI path. Roles are resolved
// before any SDK source is selected. These cases never admit a private fixture.
type PublicConfigurationCase struct {
	Condition    string
	DeniedRole   string
	EnabledOnly  bool
	DisabledOnly bool
	Roles        []string
	Generated    bool
	Output       bool
	StockPlugins bool
	Replacement  *PublicReplacementCase
}

// PublicReplacementCase fixes one installed command path before any SDK source is selected.
type PublicReplacementCase struct {
	Target, Change, Authorizer, MaterialSource, DeniedRole string
	Operator                                               bool
}

var publicConfigurationCases = []PublicConfigurationCase{
	{Condition: "plugin-contracts", EnabledOnly: true, Generated: true, Output: true, StockPlugins: true, Roles: []string{"authority", "apply", "reader", "consumer", "cleanup"}},
	{Condition: "prepare-complete-loss", Roles: []string{"authority", "apply", "reader", "consumer", "cleanup"}},
	{Condition: "inspection-receipts", Roles: []string{"authority", "apply", "reader", "cleanup"}},
	{Condition: "manifest", Output: true, Roles: []string{"authority", "apply", "reader", "cleanup"}},
	{Condition: "materialization", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "recipient-consumer", "cleanup"}},
	{Condition: "capacity-gc", Roles: []string{"authority", "apply", "reader", "cleanup"}},
	{Condition: "output-standalone", Output: true, Roles: []string{"authority", "apply", "reader", "cleanup"}},
	{Condition: "output-combined", Output: true, Roles: []string{"authority", "apply", "reader", "cleanup"}},
	{Condition: "generated-manual-lifecycle", Generated: true, Roles: []string{"authority", "apply", "reader", "cleanup"}},
	{Condition: "generated-auto-rotation", Generated: true, Roles: []string{"authority", "apply", "reader", "cleanup"}},
	{Condition: "credential-discovery", Roles: []string{"authority", "apply", "reader", "consumer", "cleanup"}},
	{Condition: "standard-discovery", Roles: []string{"authority", "apply", "reader", "consumer", "cleanup"}},
	{Condition: "empty-initialization", Roles: []string{"authority", "reader", "cleanup"}},
	{Condition: "required-public-denied", DeniedRole: "denied-public", Roles: []string{"authority", "denied-public", "reader", "cleanup"}},
	{Condition: "normal-signing-denied", DeniedRole: "denied-normal-signing", Roles: []string{"authority", "denied-normal-signing", "reader", "cleanup"}},
	{Condition: "authority-private-denied", DeniedRole: "denied-authority-private", Roles: []string{"authority", "denied-authority-private", "reader", "cleanup"}},
	{Condition: "recovery-signing-denied", DeniedRole: "denied-recovery-signing", EnabledOnly: true, Roles: []string{"authority", "denied-recovery-signing", "reader", "cleanup"}},
	{Condition: "recovery-private-denied", DeniedRole: "denied-recovery-private", EnabledOnly: true, Roles: []string{"authority", "denied-recovery-private", "reader", "cleanup"}},
	{Condition: "portable-validation", Roles: []string{"authority", "apply", "reader", "consumer", "successor", "cleanup"}},
	{Condition: "fresh-secret-apply", Roles: []string{"authority", "apply", "reader", "consumer", "recovery", "cleanup"}},
	{Condition: "retained-input-access", Roles: []string{"authority", "apply", "reader", "consumer", "recipient-consumer", "excluded-consumer", "recovery", "cleanup"}},
	{Condition: "readonly-unknown-outcomes", Roles: []string{"authority", "apply", "reader", "consumer", "recovery", "cleanup"}},
	{Condition: "recipient-lifecycle", Roles: []string{"authority", "apply", "proposer", "reader", "consumer", "recipient-consumer", "excluded-consumer", "recovery", "cleanup"}},
	{Condition: "keys-replace-authority-signing-by-authority", Roles: []string{"authority", "apply", "reader", "cleanup"}, Replacement: &PublicReplacementCase{Target: "authority", Change: "signing", Authorizer: "authority", MaterialSource: "", DeniedRole: ""}},
	{Condition: "keys-replace-authority-signing-by-recovery", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup", "successor"}, Replacement: &PublicReplacementCase{Target: "authority", Change: "signing", Authorizer: "recovery", MaterialSource: "", DeniedRole: ""}},
	{Condition: "keys-replace-authority-encryption-by-authority", Roles: []string{"authority", "apply", "reader", "cleanup"}, Replacement: &PublicReplacementCase{Target: "authority", Change: "encryption", Authorizer: "authority", MaterialSource: "authority", DeniedRole: ""}},
	{Condition: "keys-replace-authority-encryption-by-recovery", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup", "successor"}, Replacement: &PublicReplacementCase{Target: "authority", Change: "encryption", Authorizer: "recovery", MaterialSource: "authority", DeniedRole: ""}},
	{Condition: "keys-replace-authority-both-by-authority", Roles: []string{"authority", "apply", "reader", "cleanup"}, Replacement: &PublicReplacementCase{Target: "authority", Change: "both", Authorizer: "authority", MaterialSource: "authority", DeniedRole: ""}},
	{Condition: "keys-replace-authority-both-by-recovery", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup", "successor"}, Replacement: &PublicReplacementCase{Target: "authority", Change: "both", Authorizer: "recovery", MaterialSource: "authority", DeniedRole: ""}},
	{Condition: "keys-replace-recovery-signing-by-authority", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup"}, Replacement: &PublicReplacementCase{Target: "recovery", Change: "signing", Authorizer: "authority", MaterialSource: "", DeniedRole: ""}},
	{Condition: "keys-replace-recovery-signing-by-recovery", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup", "successor"}, Replacement: &PublicReplacementCase{Target: "recovery", Change: "signing", Authorizer: "recovery", MaterialSource: "", DeniedRole: ""}},
	{Condition: "keys-replace-recovery-encryption-by-authority", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup"}, Replacement: &PublicReplacementCase{Target: "recovery", Change: "encryption", Authorizer: "authority", MaterialSource: "recovery", DeniedRole: ""}},
	{Condition: "keys-replace-recovery-encryption-by-recovery", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup", "successor"}, Replacement: &PublicReplacementCase{Target: "recovery", Change: "encryption", Authorizer: "recovery", MaterialSource: "authority", DeniedRole: ""}},
	{Condition: "keys-replace-recovery-both-by-authority", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup"}, Replacement: &PublicReplacementCase{Target: "recovery", Change: "both", Authorizer: "authority", MaterialSource: "recovery", DeniedRole: ""}},
	{Condition: "keys-replace-recovery-both-by-recovery", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup", "successor"}, Replacement: &PublicReplacementCase{Target: "recovery", Change: "both", Authorizer: "recovery", MaterialSource: "authority", DeniedRole: ""}},
	{Condition: "keys-replace-recipient", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup", "reader-successor"}, Replacement: &PublicReplacementCase{Target: "recipient", Change: "encryption", Authorizer: "authority", MaterialSource: "authority", DeniedRole: ""}},
	{Condition: "keys-replace-required-public-denied", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup", "denied-public"}, Replacement: &PublicReplacementCase{Target: "authority", Change: "both", Authorizer: "authority", MaterialSource: "authority", DeniedRole: "denied-public"}},
	{Condition: "keys-replace-normal-signing-denied", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup", "denied-normal-signing"}, Replacement: &PublicReplacementCase{Target: "authority", Change: "both", Authorizer: "authority", MaterialSource: "authority", DeniedRole: "denied-normal-signing"}},
	{Condition: "keys-replace-authority-private-denied", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup", "denied-authority-private"}, Replacement: &PublicReplacementCase{Target: "authority", Change: "both", Authorizer: "authority", MaterialSource: "authority", DeniedRole: "denied-authority-private"}},
	{Condition: "keys-replace-recovery-signing-denied", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup", "successor", "denied-recovery-signing"}, Replacement: &PublicReplacementCase{Target: "authority", Change: "both", Authorizer: "recovery", MaterialSource: "authority", DeniedRole: "denied-recovery-signing"}},
	{Condition: "keys-replace-recovery-private-denied", EnabledOnly: true, Roles: []string{"authority", "apply", "reader", "cleanup", "denied-recovery-private"}, Replacement: &PublicReplacementCase{Target: "authority", Change: "both", Authorizer: "authority", MaterialSource: "recovery", DeniedRole: "denied-recovery-private"}},
	{Condition: "keys-replace-operator-both", DisabledOnly: true, Roles: []string{"authority", "apply", "reader", "consumer", "cleanup"}, Replacement: &PublicReplacementCase{Target: "authority", Change: "both", Authorizer: "authority", MaterialSource: "authority", DeniedRole: "", Operator: true}},
}

// OutputScopes fixes live effect scopes independently of passive locator interpretation.
func (c PublicConfigurationCase) OutputScopes(provider string) []string {
	if !c.Output || provider != "aws" && provider != "gcp" {
		return nil
	}
	cloud := "aws-secrets-manager"
	if provider == "gcp" {
		cloud = "gcp-secret-manager"
	}
	if c.Condition == "manifest" || c.StockPlugins && provider == "gcp" {
		return []string{cloud}
	}
	return []string{cloud, "github-repository", "github-organization", "github-environment"}
}

// UsesOperatorSDKContext identifies the two declared public paths that use one
// operator SDK context for all roles. Restricted functional cases remain distinct.
func (c PublicConfigurationCase) UsesOperatorSDKContext() bool {
	return c.Condition == "credential-discovery" || c.Replacement != nil && c.Replacement.Operator
}

func (c PublicConfigurationCase) group() string { return "public-configuration." + c.Condition }

func HistoricalPublicConfiguration(name string) (PublicConfigurationCase, bool) {
	for _, row := range publicConfigurationCases {
		if row.group() == name {
			row.Roles = slices.Clone(row.Roles)
			if row.Replacement != nil {
				replacement := *row.Replacement
				row.Replacement = &replacement
			}
			return row, true
		}
	}
	return PublicConfigurationCase{}, false
}

func PublicConfiguration(name string) (PublicConfigurationCase, bool) {
	row, ok := lookupCase(name)
	if !ok {
		return PublicConfigurationCase{}, false
	}
	return HistoricalPublicConfiguration(row.group)
}

func publicConfigurationScenarios() []scenario {
	var declarations []scenario
	for _, row := range publicConfigurationCases {
		execution := baseExecution(FamilyPublicConfiguration, 3, FixturePublicConfiguration)
		if row.Generated && !row.StockPlugins {
			execution.capabilities = append(execution.capabilities, FixtureGeneratedProcess)
		}
		execution.children = nil // Every public CLI child is joined by the writer.
		execution.liveFinalAfterOnly = true
		execution.postExit.role = "reader"
		declarations = append(declarations, scenario{name: row.group(), title: "Public configuration: " + row.Condition,
			description: "Run standard SDK or ADC contexts through joined public executable processes; verify exact source preservation and independent current observations; clean only the owned run prefix.",
			roles:       slices.Clone(row.Roles), distinct: row.StockPlugins || row.Condition == "prepare-complete-loss" || row.Condition == "inspection-receipts" || row.Condition == "capacity-gc" || row.Condition == "materialization" || row.Condition == "manifest", explicitShape: true, members: 1, smallBytes: 1, execution: execution})
	}
	return declarations
}

func publicConfigurationSteps() []Step {
	return []Step{
		{Name: "setup", Role: "authority", Expected: "selector-only-source-and-exact-roles-ready"},
		{Name: "transition", Role: "authority", Expected: "joined-public-configuration-actions-exact"},
		{Name: "verification", Role: "authority", Expected: "independent-public-private-and-source-facts-exact"},
		{Name: "reopen", Role: "reader", Expected: "pair-only-independent-public-observation-exact"},
	}
}
