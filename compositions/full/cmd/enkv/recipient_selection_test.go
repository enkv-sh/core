package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
)

// full_only: false
func TestRecipientCommandSelectorsKeepAliasesAndIDsSeparate(t *testing.T) {
	hexAlias := strings.Repeat("ab", 32)
	for _, row := range []struct {
		name          string
		reference, id replacementFlag
		want          compositionfull.RecipientSelector
		valid         bool
	}{
		{name: "omitted", valid: true},
		{name: "alias", reference: replacementFlag{value: "app", set: true}, want: compositionfull.RecipientSelector{Reference: "app"}, valid: true},
		{name: "hex-alias", reference: replacementFlag{value: hexAlias, set: true}, want: compositionfull.RecipientSelector{Reference: hexAlias}, valid: true},
		{name: "exact-id", id: replacementFlag{value: idText(contract.ID{7}), set: true}, want: compositionfull.RecipientSelector{ID: contract.ID{7}}, valid: true},
		{name: "both", reference: replacementFlag{value: "app", set: true}, id: replacementFlag{value: idText(contract.ID{7}), set: true}},
		{name: "empty-alias", reference: replacementFlag{set: true}},
		{name: "invalid-utf8-alias", reference: replacementFlag{value: string([]byte{0xff}), set: true}},
		{name: "overlong-alias", reference: replacementFlag{value: strings.Repeat("x", 257), set: true}},
		{name: "empty-id", id: replacementFlag{set: true}},
		{name: "zero-id", id: replacementFlag{value: strings.Repeat("0", 64), set: true}},
		{name: "uppercase-id", id: replacementFlag{value: strings.Repeat("AB", 32), set: true}},
		{name: "short-id", id: replacementFlag{value: "01", set: true}},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, valid := commandRecipientSelection(row.reference, row.id)
			if valid != row.valid || valid && got != row.want {
				t.Fatal("selector meaning changed", valid, got)
			}
		})
	}
}

// full_only: false
func TestMaterializeForwardsLocalAliasWithoutParsingItAsID(t *testing.T) {
	for _, alias := range []string{"app", strings.Repeat("ab", 32)} {
		calls := 0
		var out, diagnostic bytes.Buffer
		code := runMaterializeWithExecutor(t.Context(), []string{"--name=VALUE", "--out=application.env", "--recipient=" + alias, "--json"}, &out, &diagnostic, func(_ context.Context, r contract.MaterializationRequest, _ string, _ configuration.Format, _ string, selector compositionfull.RecipientSelector) (compositionfull.ConfigurationMaterializationResult, error) {
			calls++
			if selector.Reference != alias || !selector.ID.IsZero() || !r.RecipientID.IsZero() {
				t.Fatal("alias became an exact ID")
			}
			return materializationCLIResult(t), nil
		})
		if code != 0 || calls != 1 {
			t.Fatal("alias did not reach captured-source operation", code, calls, diagnostic.String())
		}
	}
}

// full_only: false
func TestRecipientFlagsAreConsistentAcrossCommands(t *testing.T) {
	for _, command := range []string{"inspect", "materialize", "manifest", "add-current", "add-create", "rename", "retire", "keys"} {
		for _, row := range []struct {
			name  string
			flags []string
			valid bool
		}{
			{"alias", []string{"--recipient=app"}, true},
			{"id", []string{"--recipient-id=" + idText(contract.ID{7})}, true},
			{"both", []string{"--recipient=app", "--recipient-id=" + idText(contract.ID{7})}, false},
			{"duplicate-alias", []string{"--recipient=app", "--recipient=other"}, false},
			{"duplicate-id", []string{"--recipient-id=" + idText(contract.ID{7}), "--recipient-id=" + idText(contract.ID{8})}, false},
			{"empty-alias", []string{"--recipient="}, false},
			{"empty-id", []string{"--recipient-id="}, false},
			{"zero-id", []string{"--recipient-id=" + strings.Repeat("0", 64)}, false},
		} {
			t.Run(command+"/"+row.name, func(t *testing.T) {
				args := append([]string{"--json"}, row.flags...)
				calls := 0
				var out, diagnostic bytes.Buffer
				switch command {
				case "inspect":
					runInspectWithExecutors(t.Context(), args, &out, &diagnostic, nil, func(context.Context, contract.ID, string, configuration.Format, compositionfull.RecipientSelector) compositionfull.ConfigurationRecipientInspectionResult {
						calls++
						r, _ := compositionfull.NewRecipientInspectionRefusal(0)
						return compositionfull.ConfigurationRecipientInspectionResult{PublicRecipientInspectionResult: r}
					}, nil)
				case "materialize":
					runMaterializeWithExecutor(t.Context(), append(args, "--name=VALUE", "--out=application.env"), &out, &diagnostic, func(context.Context, contract.MaterializationRequest, string, configuration.Format, string, compositionfull.RecipientSelector) (compositionfull.ConfigurationMaterializationResult, error) {
						calls++
						return materializationCLIResult(t), nil
					})
				case "manifest":
					runManifestWithExecutor(t.Context(), append(args, "--plugin=private-renderer", "--out=manifest.json"), &out, &diagnostic, func(context.Context, contract.ID, string, configuration.Format, compositionfull.ManifestOptions, string) compositionfull.ManifestFileResult {
						calls++
						return manifestCLIUnavailable()
					})
				case "add-current", "add-create", "rename":
					action := "recipient-preparation"
					switch command {
					case "rename":
						action = "recipient-reference-rename"
						args = append(args, "--new-reference=renamed")
					case "add-create":
						args = append(args, "--mode=create", "--display-name=App", "--encryption-key="+replacementCLIKey)
					default:
						args = append(args, "--mode=current")
					}
					runLocalEditWithExecutor(t.Context(), action, args, &out, &diagnostic, func(_ context.Context, c localEditCommand) (*compositionfull.LocalEditResult, error) {
						calls++
						return compositionfull.NewLocalEditRefusal(c.action)
					})
				case "retire":
					runAccessMutationWithExecutor(t.Context(), contract.OperationRetireRecipientIdentity, append(args, "--out=successor.yaml"), &out, &diagnostic, func(context.Context, uint16, contract.ID, accessMutationCommand) compositionfull.MaintenanceCommandResult {
						calls++
						return compositionfull.MaintenanceCommandResult{}
					})
				case "keys":
					args = append([]string{"replace", "--target=recipient", "--encryption=" + replacementCLIKey, "--out=successor.yaml"}, args...)
					runKeysWithExecutor(t.Context(), args, &out, &diagnostic, func(context.Context, contract.ID, string, configuration.Format, configuration.ReplacementRequest, string, compositionfull.RecipientSelector) compositionfull.ReplacementCommandResult {
						calls++
						return compositionfull.ReplacementCommandResult{}
					})
				}
				valid := row.valid && (command != "add-create" || row.name != "id")
				if valid && calls != 1 || !valid && calls != 0 {
					t.Fatal("command selector boundary differs", calls, out.String(), diagnostic.String())
				}
			})
		}
	}
}
