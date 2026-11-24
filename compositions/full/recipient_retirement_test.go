package compositionfull

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestRecipientRetirementAdapterUsesExactReferenceAndIgnoresValidPendingIntent(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			t.Run(family+"/"+configurationSourceFormat(format), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				source := configurationMaintenancePair(t, family, format, func(editable, generated map[string]any) {
					editable["entries"] = map[string]any{"pending": map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": "pending-value-sentinel"}}}
					editable["domain"].(map[string]any)["authority"].(map[string]any)["display_name"] = "pending Authority display"
					for _, row := range editable["recipients"].(map[string]any) {
						row.(map[string]any)["display_name"] = "pending Recipient display"
					}
					for _, row := range generated["recipients"].(map[string]any) {
						row.(map[string]any)["creation"] = map[string]any{"snapshot": readerID(contract.ID{88}), "nonce": readerID(contract.ID{89})}
					}
				})
				model, err := configuration.Parse(ctx, source.pair)
				if err != nil || len(model.Recipients) == 0 {
					t.Fatal(err)
				}
				validation := validateInstalledConfiguration(ctx, model.Public)
				if !validation.Valid || !validation.Complete || !validation.DiagnosticsComplete || model.Entries[0].Name != "pending" || model.Recipients[0].Creation == nil {
					t.Fatal("pending proposal is not independently valid", validation.Diagnostics)
				}
				before := maintenanceTestSourceImage(t, ctx, source.pair)
				calls := 0
				result := retireConfigurationRecipientForTest(t, ctx, contract.ID{77}, source.pair, model.Recipients[0].Reference, func(_ context.Context, _ *configuration.Model, i core.RecipientRetirementInstallation) (configurationRetirementEngine, error) {
					calls++
					basis, store, err := configurationPublicBasis(model)
					control, controlErr := basis.ControlCore(model.DomainID, store)
					binding, bindingErr := configurationApplyBinding(model.Provider, model.Recipients[0].Encryption)
					digest, digestErr := contract.PublicBindingDigest(binding)
					if err != nil || controlErr != nil || bindingErr != nil || digestErr != nil || i.ExpectedDomain != model.DomainID || i.ExpectedStore != store || i.ExpectedControl.AuthorityRecipientID != control.AuthorityRecipientID || i.Recipient != (contract.RecipientBindingReference{RecipientID: model.Recipients[0].ID, PublicBindingDigest: digest}) || i.CompositionID != CompatibilityManifest().Identity || i.Store != nil || i.Trust != nil || i.ConfigurationValidator == nil || i.AdmitCustody != nil {
						t.Fatal("retirement lost exact trust/reference or acquired proposal capabilities", err, controlErr, bindingErr, digestErr)
					}
					return nil, ErrCell
				})
				configurationApplyAssertUnavailable(t, result)
				if calls != 1 {
					t.Fatal("valid pending intent blocked retirement")
				}
				configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
			})
		}
	}
}

// full_only: false
func TestRecipientRetirementAdaptersPreserveReadOnlySourceAndBlockers(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	source := configurationMaintenancePair(t, "aws", configuration.JSON, nil)
	model, err := configuration.Parse(ctx, source.pair)
	if err != nil || len(model.Recipients) == 0 {
		t.Fatal(err)
	}
	before := maintenanceTestSourceImage(t, ctx, source.pair)
	request := contract.ID{77}
	for _, reference := range []string{"", "Authority", model.Recipients[0].DisplayName, readerID(model.Recipients[0].ID), "missing-reference"} {
		result := retireConfigurationRecipientForTest(t, ctx, request, source.pair, reference, func(context.Context, *configuration.Model, core.RecipientRetirementInstallation) (configurationRetirementEngine, error) {
			t.Fatal("invalid retirement reference opened resources")
			return nil, ErrCell
		})
		if result.Result.Outcome != core.AdmissionRefused || result.PreAdmission == nil || result.PreAdmission.Stage != "declaration" || result.RequestID != request {
			t.Fatal("reference refusal lost exact correlation")
		}
		configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
	}
	// These are trusted installed-owner returns, not native selection evidence.
	for _, outcome := range []core.Outcome{core.ObservedCurrent, core.Contention, core.UnresolvedCommit, core.AdmissionRefused, core.EvidenceUnavailable, core.IntegrityFailure} {
		r := secretAccessResultFixture(t, contract.OperationRetireRecipientIdentity)
		r.RequestID, r.Result.Outcome = request, outcome
		if outcome != core.ObservedCurrent {
			r.Receipt = nil
		}
		if outcome == core.UnresolvedCommit {
			r.Result.CommitMayHaveOccurred = true
		}
		if outcome == core.AdmissionRefused || outcome == core.EvidenceUnavailable || outcome == core.IntegrityFailure {
			r.Payload = nil
		}
		engine := &configurationSecretAccessTestEngine{result: r}
		result := retireConfigurationRecipientForTest(t, ctx, request, source.pair, model.Recipients[0].Reference, func(context.Context, *configuration.Model, core.RecipientRetirementInstallation) (configurationRetirementEngine, error) {
			return engine, nil
		})
		if result.Result != r.Result || result.RequestIdentity != r.RequestIdentity || engine.calls != 1 || engine.closes != 1 || engine.request != request {
			t.Fatal("retirement replaced installed outcome or lifetime")
		}
		if _, err := RenderRecipientRetirementJSON(result); err != nil {
			t.Fatal("retirement outcome is not renderable", err)
		}
		configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
	}
	blocked := core.PublicApplyResult{RequestID: request, Result: core.Result{Outcome: core.AdmissionRefused}, RetirementBlockers: &core.RecipientRetirementBlockers{Total: 1, Rows: []core.RecipientRetirementBlocker{{MaterialID: contract.ID{1}, OwnerKind: contract.GeneratedDutySupportKind, OwnerID: contract.ID{2}}}}}
	engine := &configurationSecretAccessTestEngine{result: blocked}
	result := retireConfigurationRecipientForTest(t, ctx, request, source.pair, model.Recipients[0].Reference, func(context.Context, *configuration.Model, core.RecipientRetirementInstallation) (configurationRetirementEngine, error) {
		return engine, nil
	})
	if result.RetirementBlockers != blocked.RetirementBlockers || result.PreAdmission == nil || result.PreAdmission.Stage != "retire" || engine.closes != 1 {
		t.Fatal("retained-route refusal lost blockers or lifetime")
	}
	if _, err := RenderRecipientRetirementJSON(result); err != nil {
		t.Fatal("bounded blockers are not renderable", err)
	}
	configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
	cancelled, stop := context.WithCancel(ctx)
	stop()
	result = retireConfigurationRecipientForTest(t, cancelled, request, source.pair, model.Recipients[0].Reference, func(context.Context, *configuration.Model, core.RecipientRetirementInstallation) (configurationRetirementEngine, error) {
		t.Fatal("cancelled retirement opened resources")
		return nil, ErrCell
	})
	if result.Result.Outcome == core.ObservedCurrent || result.Payload != nil || len(result.Receipt) != 0 {
		t.Fatal("cancelled retirement claimed selection")
	}
	configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
}

// full_only: false
func TestRecipientRetirementFilesRefuseInvalidPairsWithoutChanges(t *testing.T) {
	for _, condition := range []string{"missing", "malformed", "unresolved", "missing-generated", "malformed-generated"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			path := filepath.Join(t.TempDir(), "source.json")
			if condition != "missing" {
				body := initializationSetupSource(t, "aws", false, false)
				if condition == "malformed" {
					body = []byte(`{"secret-sentinel":"raw-parser-error-sentinel"}`)
				}
				if condition == "missing-generated" || condition == "malformed-generated" {
					body = append([]byte(`{"generated":".enkv/prod.generated.json",`), body[1:]...)
				}
				if err := os.WriteFile(path, body, 0444); err != nil {
					t.Fatal(err)
				}
				if condition == "malformed-generated" {
					if err := os.Mkdir(filepath.Join(filepath.Dir(path), ".enkv"), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(filepath.Dir(path), ".enkv/prod.generated.json"), []byte(`{"private-generated-sentinel":true}`), 0444); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := configurationApplySourceImage(t, filepath.Dir(path))
			result := RetireConfigurationRecipientFile(ctx, contract.ID{77}, path, configuration.JSON, "recipient", filepath.Join(t.TempDir(), "successor.json"))
			body, err := RenderRecipientRetirementJSON(result.PublicApplyResult)
			if err != nil || result.Result.Outcome != core.AdmissionRefused || result.PreAdmission == nil || result.PreAdmission.RequestNonce != (contract.ID{77}) {
				t.Fatal("invalid pair did not retain safe refusal", err)
			}
			for _, forbidden := range []string{path, "secret-sentinel", "raw-parser-error-sentinel", "private-generated-sentinel"} {
				if bytes.Contains(body, []byte(forbidden)) {
					t.Fatal("invalid pair disclosed private source content")
				}
			}
			configurationApplyAssertUnchanged(t, filepath.Dir(path), before)
		})
	}
}
