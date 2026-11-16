package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type configurationSecretAccessTestEngine struct {
	result        core.PublicApplyResult
	request       contract.ID
	calls, closes int
}

func (e *configurationSecretAccessTestEngine) Rekey(_ context.Context, request contract.ID) core.PublicApplyResult {
	e.request, e.calls = request, e.calls+1
	return e.result
}
func (e *configurationSecretAccessTestEngine) Close() { e.closes++ }

func (e *configurationSecretAccessTestEngine) Retire(_ context.Context, request contract.ID) core.PublicApplyResult {
	e.request, e.calls = request, e.calls+1
	return e.result
}

// full_only: false
func TestSecretAccessAdaptersIgnoreValidatedPendingDeclaration(t *testing.T) {
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
				if err != nil {
					t.Fatal(err)
				}
				validation := validateInstalledConfiguration(ctx, model.Public)
				if !validation.Valid || !validation.Complete || !validation.DiagnosticsComplete {
					t.Fatal("pending proposal is not independently valid", validation.Diagnostics)
				}
				if len(model.Entries) != 1 || model.Entries[0].Name != "pending" || len(model.Recipients) == 0 || model.Recipients[0].Creation == nil {
					t.Fatal("fixture lacks distinct pending intent")
				}
				before := maintenanceTestSourceImage(t, ctx, source.pair)
				request := contract.ID{77}
				check := func(i core.AccessMutationInstallation) {
					basis, store, err := configurationPublicBasis(model)
					control, controlErr := basis.ControlCore(model.DomainID, store)
					if err != nil || controlErr != nil || i.ExpectedDomain != model.DomainID || i.ExpectedStore != store || i.ExpectedControl.AuthorityRecipientID != control.AuthorityRecipientID || i.ExpectedControl.NormalSigning.KeySelector != control.NormalSigning.KeySelector || i.CompositionID != CompatibilityManifest().Identity || i.Store != nil || i.Trust != nil || i.ConfigurationValidator != nil {
						t.Fatal("standalone source mapping lost trust or manufactured capabilities", err, controlErr)
					}
				}
				rekeys := 0
				result := rekeyConfigurationEnvelopeForTest(t, ctx, request, source.pair, "", func(_ context.Context, _ *configuration.Model, i core.EnvelopeRekeyInstallation) (configurationRekeyEngine, error) {
					check(i.AccessMutationInstallation)
					if i.Name != "" {
						t.Fatal("empty current entry name was changed")
					}
					rekeys++
					return nil, ErrCell
				})
				configurationApplyAssertUnavailable(t, result)
				if rekeys != 1 {
					t.Fatal("valid pending proposal blocked standalone re-key")
				}
				configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
			})
		}
	}
}

// full_only: false
func TestSecretAccessFilesRefuseInvalidRecipientJoinsBeforeConstruction(t *testing.T) {
	for _, condition := range []string{"missing-prepared-recipient", "selector-mismatch"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			source := configurationApplyPair(t, "aws", configuration.JSON, nil)
			model, err := configuration.Parse(ctx, source.pair)
			if err != nil || len(model.Recipients) == 0 {
				t.Fatal(err)
			}
			if err := source.pair.Close(); err != nil {
				t.Fatal(err)
			}
			var generated map[string]any
			if err := json.Unmarshal(source.generatedBytes, &generated); err != nil {
				t.Fatal(err)
			}
			rows := generated["recipients"].(map[string]any)
			reference := model.Recipients[0].Reference
			if condition == "missing-prepared-recipient" {
				delete(rows, reference)
			} else {
				rows[reference].(map[string]any)["encryption"].(map[string]any)["selector"] = "private-selector-sentinel"
			}
			body, err := json.Marshal(generated)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(source.generated, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(source.generated, body, 0444); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(source.generated, 0444); err != nil {
				t.Fatal(err)
			}
			before := configurationApplySourceImage(t, filepath.Dir(source.path))
			result := RekeyConfigurationEnvelopeFile(ctx, contract.ID{77}, source.path, configuration.JSON, "secret", filepath.Join(t.TempDir(), "successor.json"))
			resultBody, renderErr := RenderEnvelopeRekeyJSON(result.PublicApplyResult)
			if renderErr != nil || result.Result.Outcome != core.AdmissionRefused || result.PreAdmission == nil || result.PreAdmission.Stage != "capture" && result.PreAdmission.Stage != "parse" || result.PreAdmission.RequestNonce != (contract.ID{77}) {
				t.Fatal("invalid join reached resource construction", renderErr)
			}
			if bytes.Contains(resultBody, []byte("private-selector-sentinel")) {
				t.Fatal("invalid selector entered result")
			}
			configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
		})
	}
}

// full_only: false
func TestSecretAccessAdaptersPreserveReadOnlyPairForReturnedOutcomes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	source := configurationMaintenancePair(t, "aws", configuration.JSON, nil)
	model, err := configuration.Parse(ctx, source.pair)
	if err != nil || len(model.Recipients) == 0 {
		t.Fatal(err)
	}
	before := maintenanceTestSourceImage(t, ctx, source.pair)
	// These are trusted installed-owner returns; native selection is tested at Core.
	for _, outcome := range []core.Outcome{core.ObservedCurrent, core.Contention, core.UnresolvedCommit, core.AdmissionRefused, core.EvidenceUnavailable, core.IntegrityFailure} {
		r := secretAccessResultFixture(t, contract.OperationEnvelopeRekey)
		r.Result.Outcome = outcome
		if outcome != core.ObservedCurrent {
			r.Receipt = nil
		}
		if outcome == core.UnresolvedCommit {
			r.Result.CommitMayHaveOccurred = true
		}
		if outcome == core.AdmissionRefused || outcome == core.EvidenceUnavailable || outcome == core.IntegrityFailure {
			r.Payload = nil
		}
		request := contract.ID{77}
		r.RequestID = request
		engine := &configurationSecretAccessTestEngine{result: r}
		result := rekeyConfigurationEnvelopeForTest(t, ctx, request, source.pair, "secret", func(context.Context, *configuration.Model, core.EnvelopeRekeyInstallation) (configurationRekeyEngine, error) {
			return engine, nil
		})
		if result.Result != r.Result || result.RequestIdentity != r.RequestIdentity || engine.calls != 1 || engine.closes != 1 || engine.request != request {
			t.Fatal("adapter replaced installed outcome or leaked invocation")
		}
		configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
	}
	ctxCancelled, cancelled := context.WithCancel(ctx)
	cancelled()
	result := rekeyConfigurationEnvelopeForTest(t, ctxCancelled, contract.ID{77}, source.pair, "secret", func(context.Context, *configuration.Model, core.EnvelopeRekeyInstallation) (configurationRekeyEngine, error) {
		t.Fatal("cancelled invocation opened resources")
		return nil, ErrCell
	})
	if result.Result.Outcome == core.ObservedCurrent || result.Payload != nil || len(result.Receipt) != 0 {
		t.Fatal("cancelled adapter claimed selection")
	}
	configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
}

// full_only: false
func TestSecretAccessFilesRefuseMissingAndMalformedPairWithoutChanges(t *testing.T) {
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
			var result core.PublicApplyResult
			var body []byte
			var err error
			result = RekeyConfigurationEnvelopeFile(ctx, contract.ID{77}, path, configuration.JSON, "secret", filepath.Join(t.TempDir(), "successor.json")).PublicApplyResult
			body, err = RenderEnvelopeRekeyJSON(result)
			if err != nil || result.Result.Outcome != core.AdmissionRefused || result.PreAdmission == nil || result.PreAdmission.RequestNonce != (contract.ID{77}) {
				t.Fatal("invalid pair did not retain safe refusal", err)
			}
			for _, forbidden := range []string{path, "secret-sentinel", "raw-parser-error-sentinel", "private-generated-sentinel"} {
				if bytes.Contains(body, []byte(forbidden)) {
					t.Fatal("invalid pair disclosed source content")
				}
			}
			configurationApplyAssertUnchanged(t, filepath.Dir(path), before)
		})
	}
}
