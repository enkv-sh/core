package compositionfull

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestConfigurationRecipientSelectionUsesManagedIdentity(t *testing.T) {
	id := contract.ID{7}
	hexAlias := strings.Repeat("ab", 32)
	model := &configuration.Model{Recipients: []configuration.Recipient{{Reference: "app", ID: id}, {Reference: hexAlias, ID: contract.ID{8}}}}
	for _, row := range []struct {
		name     string
		selector RecipientSelector
		want     contract.ID
		valid    bool
	}{
		{"default", RecipientSelector{}, contract.ID{}, true},
		{"alias", RecipientSelector{Reference: "app"}, id, true},
		{"hex-alias", RecipientSelector{Reference: hexAlias}, contract.ID{8}, true},
		{"exact-absent-locally", RecipientSelector{ID: contract.ID{9}}, contract.ID{9}, true},
		{"unknown-alias", RecipientSelector{Reference: "missing"}, contract.ID{}, false},
		{"hex-is-not-id-fallback", RecipientSelector{Reference: fmt.Sprintf("%x", id)}, contract.ID{}, false},
		{"both", RecipientSelector{Reference: "app", ID: id}, contract.ID{}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, err := row.selector.resolve(model)
			if (err == nil) != row.valid || err == nil && got != row.want {
				t.Fatal("managed identity selection changed", got, err)
			}
		})
	}
}

// full_only: false
func TestConfigurationRecipientAliasRefusalPrecedesConstruction(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, selector := range []RecipientSelector{{Reference: "unknown"}, {Reference: "app", ID: contract.ID{7}}} {
		calls := 0
		result, err := materializeConfigurationSelectedFile(ctx, contract.MaterializationRequest{RequestNonce: contract.ID{1}, Names: []string{"secret"}}, source.path, configuration.JSON, source.path+".env", func(context.Context, MaterializationConfig) (*core.InstalledMaterialization, error) {
			calls++
			return nil, nil
		}, (*configuration.Pair).Close, selector)
		if err != nil || calls != 0 || result.StateResult != contract.MaterializationRefused || result.PreAdmission == nil || result.PreAdmission.Stage != "declaration" {
			t.Fatal("invalid alias reached construction", calls, err, result.PreAdmission)
		}
	}
	source.assertUnchanged(t)
}

// full_only: false
func TestConfigurationRecipientSelectorsRejectConflictingTargets(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	for _, selector := range []RecipientSelector{{}, {ID: contract.ID{8}}, {Reference: "app"}, {Reference: "app", ID: contract.ID{7}}} {
		calls := 0
		initial, err := newConfigurationMaterializationResult(contract.ID{1}, configuration.JSON)
		if err != nil {
			t.Fatal(err)
		}
		result := materializeConfigurationWithIdentity(ctx, contract.MaterializationRequest{RequestNonce: contract.ID{1}, RecipientID: contract.ID{7}, Names: []string{"secret"}}, source.pair, source.path+".env", func(context.Context, MaterializationConfig) (*core.InstalledMaterialization, error) {
			calls++
			return nil, nil
		}, ConfigurationMaterializationResult{MaterializationResult: initial}, selector)
		if calls != 0 || result.PreAdmission == nil || result.PreAdmission.Stage != "declaration" {
			t.Fatal("conflicting materialization target reached construction", calls, result.PreAdmission)
		}
	}
	both := RecipientSelector{Reference: "app", ID: contract.ID{7}}
	result := RetireConfigurationSelectedRecipientFile(ctx, contract.ID{1}, source.path, configuration.JSON, both, source.path+".successor")
	if result.PreAdmission == nil || result.PreAdmission.Stage != "declaration" || result.Delivery.Status != "not-attempted" {
		t.Fatal("ambiguous retirement reached output capture", result.PreAdmission, result.Delivery)
	}
	for _, selector := range []RecipientSelector{both, {Reference: "other"}} {
		result := ReplaceSelectedRecipientKeysConfiguration(ctx, contract.ID{1}, source.path, configuration.JSON, configuration.ReplacementRequest{Target: configuration.ReplaceRecipient, RecipientReference: "app"}, source.path+".successor", selector)
		if result.PreAdmission == nil || result.PreAdmission.Stage != "declaration" || result.Delivery.Status != "not-attempted" {
			t.Fatal("conflicting key target reached output capture", result.PreAdmission, result.Delivery)
		}
	}
	source.assertUnchanged(t)
}
