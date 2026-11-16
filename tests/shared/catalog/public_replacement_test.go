package catalog

import (
	"reflect"
	"testing"
)

// full_only: false
func TestPublicReplacementCatalogFixesExactRoleSourceAndMode(t *testing.T) {
	rows := []struct {
		name, target, change, authorizer, source, denied string
		operator                                         bool
		modes, roles                                     []string
	}{
		{"public-configuration.keys-replace-authority-signing-by-authority/keys_replace_authority_signing_by_authority", "authority", "signing", "authority", "", "", false, []string{"disabled", "enabled"}, []string{"authority", "apply", "reader", "cleanup"}},
		{"public-configuration.keys-replace-authority-signing-by-recovery/keys_replace_authority_signing_by_recovery", "authority", "signing", "recovery", "", "", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup", "successor"}},
		{"public-configuration.keys-replace-authority-encryption-by-authority/keys_replace_authority_encryption_by_authority", "authority", "encryption", "authority", "authority", "", false, []string{"disabled", "enabled"}, []string{"authority", "apply", "reader", "cleanup"}},
		{"public-configuration.keys-replace-authority-encryption-by-recovery/keys_replace_authority_encryption_by_recovery", "authority", "encryption", "recovery", "authority", "", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup", "successor"}},
		{"public-configuration.keys-replace-authority-both-by-authority/keys_replace_authority_both_by_authority", "authority", "both", "authority", "authority", "", false, []string{"disabled", "enabled"}, []string{"authority", "apply", "reader", "cleanup"}},
		{"public-configuration.keys-replace-authority-both-by-recovery/keys_replace_authority_both_by_recovery", "authority", "both", "recovery", "authority", "", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup", "successor"}},
		{"public-configuration.keys-replace-recovery-signing-by-authority/keys_replace_recovery_signing_by_authority", "recovery", "signing", "authority", "", "", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup"}},
		{"public-configuration.keys-replace-recovery-signing-by-recovery/keys_replace_recovery_signing_by_recovery", "recovery", "signing", "recovery", "", "", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup", "successor"}},
		{"public-configuration.keys-replace-recovery-encryption-by-authority/keys_replace_recovery_encryption_by_authority", "recovery", "encryption", "authority", "recovery", "", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup"}},
		{"public-configuration.keys-replace-recovery-encryption-by-recovery/keys_replace_recovery_encryption_by_recovery", "recovery", "encryption", "recovery", "authority", "", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup", "successor"}},
		{"public-configuration.keys-replace-recovery-both-by-authority/keys_replace_recovery_both_by_authority", "recovery", "both", "authority", "recovery", "", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup"}},
		{"public-configuration.keys-replace-recovery-both-by-recovery/keys_replace_recovery_both_by_recovery", "recovery", "both", "recovery", "authority", "", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup", "successor"}},
		{"public-configuration.keys-replace-recipient/keys_replace_recipient", "recipient", "encryption", "authority", "authority", "", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup", "reader-successor"}},
		{"public-configuration.keys-replace-required-public-denied/keys_replace_required_public_denied", "authority", "both", "authority", "authority", "denied-public", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup", "denied-public"}},
		{"public-configuration.keys-replace-normal-signing-denied/keys_replace_normal_signing_denied", "authority", "both", "authority", "authority", "denied-normal-signing", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup", "denied-normal-signing"}},
		{"public-configuration.keys-replace-authority-private-denied/keys_replace_authority_private_denied", "authority", "both", "authority", "authority", "denied-authority-private", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup", "denied-authority-private"}},
		{"public-configuration.keys-replace-recovery-signing-denied/keys_replace_recovery_signing_denied", "authority", "both", "recovery", "authority", "denied-recovery-signing", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup", "successor", "denied-recovery-signing"}},
		{"public-configuration.keys-replace-recovery-private-denied/keys_replace_recovery_private_denied", "authority", "both", "authority", "recovery", "denied-recovery-private", false, []string{"enabled"}, []string{"authority", "apply", "reader", "cleanup", "denied-recovery-private"}},
		{"public-configuration.keys-replace-operator-both/keys_replace_operator_both", "authority", "both", "authority", "authority", "", true, []string{"disabled"}, []string{"authority", "apply", "reader", "consumer", "cleanup"}},
	}
	if len(rows) != 19 {
		t.Fatal("exact replacement inventory changed")
	}
	for _, want := range rows {
		t.Run(want.name, func(t *testing.T) {
			row, ok := PublicConfiguration(want.name)
			definition, known := DefinitionFor(want.name)
			if !ok || !known || row.Replacement == nil || row.DeniedRole != "" || !reflect.DeepEqual(definition.RecoveryModes, want.modes) || !reflect.DeepEqual(definition.Roles, want.roles) {
				t.Fatal("replacement applicability or initialization roles differ")
			}
			got := row.Replacement
			if got.Target != want.target || got.Change != want.change || got.Authorizer != want.authorizer || got.MaterialSource != want.source || got.DeniedRole != want.denied || got.Operator != want.operator {
				t.Fatal("fixed replacement path differs")
			}
			got.Target = "changed"
			again, _ := PublicConfiguration(want.name)
			if again.Replacement.Target != want.target {
				t.Fatal("catalog lends replacement backing")
			}
			if _, ok := ExecutionFor(want.name, "hermetic"); ok {
				t.Fatal("live SDK case entered injected fixture family")
			}
		})
	}
}
