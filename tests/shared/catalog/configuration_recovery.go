package catalog

import (
	"slices"
	"strings"
)

type RecoveryProcessCell struct {
	Provider string `json:"provider"`
	Recovery string `json:"recovery_mode"`
}

type ConfigurationRecoveryCase struct {
	Condition                       string
	EnabledOnly, AWSOnly, Generated bool
	Local                           []RecoveryProcessCell
}

func HistoricalConfigurationRecovery(name string) (ConfigurationRecoveryCase, bool) {
	for _, row := range configurationRecoveryCases {
		if name == "reconstruction."+row.Condition {
			row.Local = slices.Clone(row.Local)
			return row, true
		}
	}
	return ConfigurationRecoveryCase{}, false
}

var configurationRecoveryCases = []ConfigurationRecoveryCase{
	{Condition: "complete", Local: []RecoveryProcessCell{{"aws", "disabled"}, {"aws", "enabled"}, {"gcp", "disabled"}, {"gcp", "enabled"}}},
	{Condition: "zero-secret-genesis"},
	{Condition: "normal-signer-replaced"},
	{Condition: "authority-kek-replaced"},
	{Condition: "normal-combined-replaced"},
	{Condition: "reader-replacement"},
	{Condition: "normal-combined-repeated"},
	{Condition: "normal-signer-by-recovery", EnabledOnly: true},
	{Condition: "authority-kek-by-recovery", EnabledOnly: true},
	{Condition: "normal-restored-by-recovery", EnabledOnly: true},
	{Condition: "recovery-signer-replaced", EnabledOnly: true},
	{Condition: "recovery-signer-by-recovery", EnabledOnly: true},
	{Condition: "recovery-kek-replaced", EnabledOnly: true},
	{Condition: "recovery-kek-by-recovery", EnabledOnly: true},
	{Condition: "recovery-combined-replaced", EnabledOnly: true},
	{Condition: "recovery-combined-by-recovery", EnabledOnly: true},
	{Condition: "both-anchors", EnabledOnly: true},
	{Condition: "recovery-only-inadequate", Local: []RecoveryProcessCell{{"aws", "disabled"}, {"gcp", "enabled"}}},
	{Condition: "unused-recovery-denied", EnabledOnly: true},
	{Condition: "recovery-proof-recovery-only", EnabledOnly: true},
	{Condition: "recovery-proof-both", EnabledOnly: true},
	{Condition: "recovery-proof-normal-only", EnabledOnly: true},
	{Condition: "recovery-proof-two-normal", EnabledOnly: true},
	{Condition: "adequate-anchor-fallback", EnabledOnly: true},
	{Condition: "required-public-denied"},
	{Condition: "required-authority-denied"},
	{Condition: "recovery-key-only", EnabledOnly: true},
	{Condition: "unused-recipient-denied"},
	{Condition: "later-secret-denied"},
	{Condition: "new-domain-no-pin"},
	{Condition: "prior-domain-pin"},
	{Condition: "copied-location"},
	{Condition: "matching-domain-pin"},
	{Condition: "wrong-domain-pin"},
	{Condition: "matching-kek-pin"},
	{Condition: "wrong-kek-pin"},
	{Condition: "wrong-locator"},
	{Condition: "wrong-owner", AWSOnly: true},
	{Condition: "wrong-anchor"},
	{Condition: "mixed-generated", Generated: true},
	{Condition: "generated-repeated-later", Generated: true},
	{Condition: "generated-active", Generated: true},
	{Condition: "generated-retiring", Generated: true},
	{Condition: "generated-uncertain", Generated: true},
	{Condition: "selected-object-disappears"},
}

func configurationRecoveryGroupNames() []string {
	var names []string
	for _, row := range configurationRecoveryCases {
		names = append(names, "reconstruction."+row.Condition)
	}
	return names
}

func configurationRecoveryGeneratedGroupNames() []string {
	var names []string
	for _, row := range configurationRecoveryCases {
		if row.Generated {
			names = append(names, "reconstruction."+row.Condition)
		}
	}
	return names
}

func HistoricalConfigurationRecoveryCells(name, recovery string) []RecoveryProcessCell {
	row, ok := HistoricalConfigurationRecovery(name)
	if !ok || recovery != "both" && recovery != "disabled" && recovery != "enabled" {
		return nil
	}
	if row.EnabledOnly && recovery == "disabled" {
		return nil
	}
	cells := row.Local
	if len(cells) == 0 {
		cell := RecoveryProcessCell{"aws", "disabled"}
		if row.EnabledOnly {
			cell = RecoveryProcessCell{"gcp", "enabled"}
		}
		cells = []RecoveryProcessCell{cell}
	}
	var selected []RecoveryProcessCell
	for _, cell := range cells {
		if recovery == "both" || cell.Recovery == recovery {
			selected = append(selected, cell)
		}
	}
	if len(selected) == 0 && recovery != "both" {
		selected = []RecoveryProcessCell{{cells[0].Provider, recovery}}
	}
	return selected
}

func configurationRecoveryScenarios() []scenario {
	var declarations []scenario
	for _, row := range configurationRecoveryCases {
		declarations = append(declarations, scenario{name: "reconstruction." + row.Condition, title: "Complete loss: " + row.Condition, description: "Join setup and writer processes, remove their local state, reconstruct through the ordinary provider artifact and privately check the exited child's complete observations and remote effects.", roles: configurationRecoveryRoles(row.Condition), explicitShape: true, members: 7, smallBytes: 1, execution: executionDeclaration{family: FamilyConfigurationRecovery, capabilities: []FixtureCapability{FixtureState, FixtureConfigurationRecovery}}})
	}
	return declarations
}

func configurationRecoverySteps() []Step {
	var steps []Step
	for _, name := range []string{"resource-owner", "setup", "writer", "reconstruction-parent", "restricted-child"} {
		steps = append(steps, Step{Name: name, Role: "authority", Expected: "joined-complete-process"})
	}
	return steps
}

func configurationRecoveryHistory(condition string) bool {
	return strings.Contains(condition, "replaced") || strings.Contains(condition, "by-recovery") || strings.HasPrefix(condition, "recovery-proof-") || condition == "normal-combined-repeated" || condition == "generated-repeated-later" || condition == "adequate-anchor-fallback"
}

func configurationRecoveryRoles(condition string) []string {
	roles := []string{"replacement-store", "normal-signer-0", "authority-decrypter-0", "recovery-signer-0", "recovery-decrypter-0"}
	add := func(role string) {
		if !slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}
	// This finite mapping describes actual actors used by the existing history.
	switch condition {
	case "normal-signer-replaced", "normal-signer-by-recovery", "normal-combined-replaced", "normal-restored-by-recovery", "adequate-anchor-fallback":
		add("normal-signer-1")
	case "normal-combined-repeated", "generated-repeated-later":
		add("normal-signer-1")
		add("normal-signer-2")
	case "wrong-anchor", "recovery-only-inadequate":
		add("normal-signer-1")
	}
	switch condition {
	case "authority-kek-replaced", "authority-kek-by-recovery", "normal-combined-replaced", "normal-restored-by-recovery", "adequate-anchor-fallback":
		add("authority-decrypter-1")
	case "normal-combined-repeated", "generated-repeated-later":
		add("authority-decrypter-1")
		add("authority-decrypter-2")
	}
	switch condition {
	case "recovery-signer-replaced", "recovery-signer-by-recovery", "recovery-combined-replaced", "recovery-combined-by-recovery":
		add("recovery-signer-1")
	}
	switch condition {
	case "recovery-kek-replaced", "recovery-kek-by-recovery", "recovery-combined-replaced", "recovery-combined-by-recovery", "recovery-proof-recovery-only", "recovery-proof-both", "recovery-proof-normal-only", "recovery-proof-two-normal":
		add("recovery-decrypter-1")
	}
	if condition == "reader-replacement" {
		add("reader-successor")
	}
	if condition == "required-public-denied" {
		add("denied-observer")
	}
	if condition == "required-authority-denied" {
		add("denied-reader")
	}
	return roles
}
