package compositionfull

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/compositions/generatorhost"
	"enkv.sh/compositions/outputhost"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	outputprotocol "enkv.sh/sdk/protocols/output"
)

func assertConfigurationPreAdmission(t testing.TB, body []byte, operation string) {
	t.Helper()
	var record struct {
		Schema        string         `json:"schema"`
		Operation     string         `json:"operation_kind"`
		OperationID   string         `json:"operation_id"`
		State         string         `json:"state_result"`
		Identity      map[string]any `json:"request_identity"`
		Replay        string         `json:"replay_identity"`
		Payload       any            `json:"payload"`
		Receipt       string         `json:"receipt_hex"`
		CommitUnknown bool           `json:"commit_may_have_occurred"`
	}
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal("pre-admission result is not structured", err)
	}
	id, err := hex.DecodeString(record.OperationID)
	if err != nil || len(id) != len(contract.ID{}) || bytes.Equal(id, make([]byte, len(id))) {
		t.Error("recognized refusal has no operation correlation")
	}
	if record.Schema != "ProductResult/v1" || record.Operation != operation || record.State != "refused" || record.Replay != "none" || record.Payload != nil && operation != contract.ReaderCompareOperation || record.Receipt != "" || record.CommitUnknown {
		t.Error("pre-admission result claims unavailable operation facts")
	}
	q := record.Identity
	if q["schema"] != "PreAdmissionRequestIdentity/v1" || q["operation_id"] != record.OperationID || q["operation_kind"] != operation || q["source_schema"] != "enkv/configuration/v3" || q["format"] != "json" {
		t.Error("recognized refusal has no typed source identity")
	}
	for _, field := range []string{"stage", "code", "source_profile"} {
		if value, ok := q[field].(string); !ok || value == "" {
			t.Errorf("pre-admission identity has no %s", field)
		}
	}
	for _, field := range []string{"predecessor", "predecessor_digest", "predecessor_revision_id", "selection", "authority_subject", "retry_right"} {
		if _, ok := q[field]; ok {
			t.Errorf("pre-admission identity contains %s", field)
		}
	}
}

// full_only: false
func TestConfigurationComparisonRefusalsRetainPreAdmissionIdentity(t *testing.T) {
	for _, condition := range []string{"missing-source", "malformed-source", "missing-generated", "unsupported-schema"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			path := filepath.Join(t.TempDir(), "private-trusted-source-sentinel.json")
			if condition != "missing-source" {
				body := initializationSetupSource(t, "aws", false, false)
				switch condition {
				case "malformed-source":
					body = []byte(`{"secret-sentinel":"raw-parser-error-sentinel"}`)
				case "missing-generated":
					body = append([]byte(`{"generated":".enkv/prod.generated.json",`), body[1:]...)
				case "unsupported-schema":
					body = bytes.ReplaceAll(body, []byte("enkv/configuration/v3"), []byte("enkv/configuration/v99"))
				}
				if err := os.WriteFile(path, body, 0444); err != nil {
					t.Fatal(err)
				}
			}
			before := configurationApplySourceImage(t, filepath.Dir(path))
			request := contract.Hash([]byte("comparison pre-admission request"))
			result := CompareConfigurationFiles(ctx, request, path, configuration.JSON, "", 0)
			if result.Context.RequestID != request || result.Context.OperationID.IsZero() || result.Observation != nil {
				t.Error("comparison refusal lost request correlation or claimed observation")
			}
			body, err := RenderComparisonJSON(result)
			if err != nil {
				t.Fatal(err)
			}
			assertConfigurationPreAdmission(t, body, contract.ReaderCompareOperation)
			code := "invalid-input"
			switch condition {
			case "missing-generated":
				code = "missing-required-field"
			case "unsupported-schema":
				code = "unsupported-schema"
			}
			if result.PreAdmission == nil || result.PreAdmission.Stage != "capture" || result.PreAdmission.Code != code || result.PreAdmission.RequestNonce != request {
				t.Error("comparison lost exact failure stage, code or available nonce")
			}
			for _, forbidden := range []string{"secret-sentinel", "raw-parser-error-sentinel"} {
				if bytes.Contains(body, []byte(forbidden)) {
					t.Error("comparison refusal exposed source content")
				}
			}
			configurationApplyAssertUnchanged(t, filepath.Dir(path), before)
		})
	}
}

// full_only: false
func TestConfigurationRefusalsRetainPreAdmissionIdentity(t *testing.T) {
	for _, operation := range []string{"init", "apply", "apply-publication"} {
		for _, condition := range []string{"missing-source", "malformed-source", "missing-generated", "unsupported-declaration"} {
			t.Run(operation+"/"+condition, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				path := filepath.Join(t.TempDir(), "private-source-sentinel.json")
				var pair *configuration.Pair
				if condition != "missing-source" {
					body := initializationSetupSource(t, "aws", false, condition == "unsupported-declaration")
					switch condition {
					case "malformed-source":
						body = []byte(`{"secret-sentinel":"raw-parser-error-sentinel"}`)
					case "missing-generated":
						body = append([]byte(`{"generated":".enkv/prod.generated.json",`), body[1:]...)
					}
					if err := os.WriteFile(path, body, 0600); err != nil {
						t.Fatal(err)
					}
					if operation != "init" && condition == "unsupported-declaration" {
						var err error
						pair, err = configuration.Capture(ctx, path, configuration.JSON)
						if err != nil {
							t.Fatal("setup source capture failed", err)
						}
						t.Cleanup(func() {
							if err := pair.Close(); err != nil {
								t.Error(err)
							}
						})
						model, err := configuration.Parse(ctx, pair)
						if err != nil || model.Resolved {
							t.Fatal("setup source is not valid unresolved input", err)
						}
					}
				}
				before := configurationApplySourceImage(t, filepath.Dir(path))
				var body []byte
				var err error
				if operation == "init" {
					result, resultErr := initializeConfiguration(ctx, path, configuration.JSON, func(context.Context, *configuration.Model) (initializationResources, error) {
						t.Fatal("refused source opened initialization resources")
						return initializationResources{}, ErrCell
					})
					if resultErr == nil {
						t.Error("invalid initialization source was accepted")
					}
					body, err = RenderInitializationJSON(result, resultErr)
				} else {
					request := contract.Hash([]byte("pre-admission request"))
					var result core.PublicApplyResult
					if operation == "apply-publication" {
						publicationRequest := contract.Hash([]byte("pre-admission publication request"))
						var combined core.PublicApplyPublicationResult
						if pair == nil {
							combined = ApplyConfigurationAndPublishFile(ctx, request, publicationRequest, path, configuration.JSON, ApplyPublicationOptions{}, ApplyOptions{}).PublicApplyPublicationResult
						} else {
							combined = configurationApplyPublication(ctx, request, publicationRequest, pair, contract.ID{}, ApplyPublicationOptions{},
								func(context.Context, *configuration.Model, core.ApplyInstallation, *configurationInstalledPlugins) (*core.InstalledApply, error) {
									t.Fatal("refused declaration opened apply resources")
									return nil, ErrCell
								},
								func(context.Context, *configuration.Model, core.PublicationInstallation, map[contract.ID]string, *configurationInstalledPlugins) (*core.InstalledPublication, error) {
									t.Fatal("refused declaration opened publication resources")
									return nil, ErrCell
								})
						}
						if combined.Publication.Stage != "unstarted" || combined.Publication.Reason != "apply-incomplete" || combined.Publication.Result != nil {
							t.Error("apply refusal claimed publication progress")
						}
						var rendered bytes.Buffer
						if err := WriteApplyPublicationJSON(&rendered, combined); err != nil {
							t.Fatal("combined refusal is not renderable", err)
						}
						var wire struct {
							Apply json.RawMessage `json:"apply"`
						}
						if err := json.Unmarshal(rendered.Bytes(), &wire); err != nil {
							t.Fatal(err)
						}
						assertConfigurationPreAdmission(t, wire.Apply, "apply-declaration")
						result = combined.Apply
					} else if pair == nil {
						result = ApplyConfigurationFile(ctx, request, path, configuration.JSON, ApplyOptions{}).PublicApplyResult
					} else {
						result = applyConfiguration(ctx, request, pair, func(context.Context, *configuration.Model, core.ApplyInstallation, *configurationInstalledPlugins) (*core.InstalledApply, error) {
							t.Fatal("refused declaration opened apply resources")
							return nil, ErrCell
						})
					}
					if result.RequestID != request || result.OperationID.IsZero() || !result.RequestIdentity.IsZero() {
						t.Error("apply refusal lost request correlation or claimed admission")
					}
					if result.PreAdmission == nil || result.PreAdmission.RequestNonce != request {
						t.Error("apply refusal lost its available nonce")
					}
					body, err = RenderApplyJSON(result)
				}
				if err != nil {
					t.Fatal("refusal is not renderable", err)
				}
				kind := "initialize-empty-domain"
				if operation != "init" {
					kind = "apply-declaration"
				}
				assertConfigurationPreAdmission(t, body, kind)
				var wire struct {
					Identity struct{ Stage, Code string } `json:"request_identity"`
				}
				if err := json.Unmarshal(body, &wire); err != nil {
					t.Fatal(err)
				}
				stage, code := "capture", "invalid-input"
				switch condition {
				case "missing-generated":
					code = "missing-required-field"
				case "unsupported-declaration":
					stage = "declaration"
					if operation != "init" {
						code = "missing-required-field"
					}
				}
				if wire.Identity.Stage != stage || wire.Identity.Code != code {
					t.Errorf("failure identity=%s/%s, want %s/%s", wire.Identity.Stage, wire.Identity.Code, stage, code)
				}
				for _, forbidden := range []string{"secret-sentinel", "raw-parser-error-sentinel"} {
					if bytes.Contains(body, []byte(forbidden)) {
						t.Error("refusal exposed source content")
					}
				}
				if operation != "init" {
					configurationApplyAssertUnchanged(t, filepath.Dir(path), before)
				} else if original, exists := before[filepath.Base(path)]; exists {
					actual, readErr := os.ReadFile(path)
					info, statErr := os.Stat(path)
					if readErr != nil || statErr != nil || !bytes.Equal(actual, original.Body) || info.Mode() != original.Mode {
						t.Fatal("initialization refusal changed source bytes or mode", readErr, statErr)
					}
				} else if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Fatal("initialization refusal created the missing source", statErr)
				}
			})
		}
	}
}

// full_only: false
func TestConfigurationPreAdmissionProjectionPreservesAdmittedFacts(t *testing.T) {
	initial, err := NewInitializationRefusal(configuration.JSON)
	if err != nil {
		t.Fatal(err)
	}
	ready := initializationRenderingFixture(t)
	operation, identity := ready.OperationID, ready.RequestIdentity
	finishInitializationPreAdmission(&ready, initial.OperationID, initial.PreAdmission)
	if ready.OperationID != operation || ready.RequestIdentity != identity || ready.PreAdmission != nil {
		t.Fatal("admitted initialization facts were replaced by request correlation")
	}
	refused := initial
	refused.OperationID = contract.ID{99}
	finishInitializationPreAdmission(&refused, initial.OperationID, initial.PreAdmission)
	if refused.OperationID != (contract.ID{99}) || refused.PreAdmission != initial.PreAdmission {
		t.Fatal("known initialization operation was replaced before request admission")
	}
	apply := suppliedApplyResultFixture(t)
	comparisonCorrelation, err := NewComparisonRefusal(configuration.JSON)
	if err != nil {
		t.Fatal(err)
	}
	admittedComparison := ConfigurationComparisonResult{PublicComparisonResult: core.PublicComparisonResult{Context: core.ReaderOperationContext{Operation: contract.ReaderCompareOperation,
		OperationID: contract.ID{77}, RequestID: contract.ID{78}, ExpectedDomain: contract.ID{79}}}, InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
	contextBefore := admittedComparison.Context
	finishConfigurationComparison(&admittedComparison, comparisonCorrelation)
	if admittedComparison.Context != contextBefore || admittedComparison.PreAdmission != nil {
		t.Fatal("comparison replaced admitted correlation or baseline context")
	}
	for _, row := range []struct {
		name                string
		body                func() ([]byte, error)
		operation, identity contract.ID
	}{
		{"init", func() ([]byte, error) { return RenderInitializationJSON(ready, nil) }, ready.OperationID, ready.RequestIdentity},
		{"apply", func() ([]byte, error) { return RenderApplyJSON(apply) }, apply.OperationID, apply.RequestIdentity},
	} {
		t.Run(row.name, func(t *testing.T) {
			body, err := row.body()
			var wire struct {
				OperationID string `json:"operation_id"`
				Identity    string `json:"request_identity"`
				Receipt     string `json:"receipt_hex"`
			}
			if err != nil || json.Unmarshal(body, &wire) != nil || wire.OperationID != readerID(row.operation) || wire.Identity != readerID(row.identity) || wire.Receipt == "" {
				t.Fatal("admitted result lost its operation, identity or receipt", err)
			}
		})
	}
	ready.PreAdmission = initial.PreAdmission
	apply.PreAdmission = initial.PreAdmission
	if _, err := RenderInitializationJSON(ready, nil); err == nil {
		t.Error("initialization mixed pre-admission and admitted identities")
	}
	if _, err := RenderApplyJSON(apply); err == nil {
		t.Error("apply mixed pre-admission and admitted identities")
	}
	for _, field := range []string{"stage", "code", "format", "schema", "profile"} {
		t.Run("unsafe-"+field, func(t *testing.T) {
			result, err := NewApplyRefusal(configuration.JSON)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "stage":
				result.PreAdmission.Stage = "raw-error-sentinel"
			case "code":
				result.PreAdmission.Code = "raw-error-sentinel"
			case "format":
				result.PreAdmission.Format = "raw-error-sentinel"
			case "schema":
				result.PreAdmission.SourceSchema = "raw-error-sentinel"
			case "profile":
				result.PreAdmission.SourceProfile = "raw-error-sentinel"
			}
			for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderApplyJSON, RenderApplyHuman} {
				if body, err := render(result); err == nil || len(body) != 0 {
					t.Error("unsafe pre-admission field was rendered")
				}
			}
		})
	}
}

// full_only: false
func TestConfigurationPluginFailureClassification(t *testing.T) {
	for _, row := range []struct {
		name           string
		err            error
		cancel, expire bool
		unavailable    bool
		reason         contract.DiagnosticReason
		code           string
	}{
		{name: "missing", err: errors.Join(plugininstallation.ErrInstallation, plugininstallation.ErrMissing), unavailable: true, reason: contract.ReasonEvidenceUnavailable},
		{name: "tampered", err: errors.Join(plugininstallation.ErrInstallation, plugininstallation.ErrIdentity), unavailable: true, reason: contract.ReasonEvidenceUnavailable},
		{name: "early-capture", err: errors.Join(plugininstallation.ErrInstallation, errors.New("private-path-sentinel")), unavailable: true, reason: contract.ReasonEvidenceUnavailable},
		{name: "generator-transport", err: errors.Join(generatorhost.ErrProcess, errors.New("private-process-sentinel")), unavailable: true, reason: contract.ReasonEvidenceUnavailable},
		{name: "output-transport", err: errors.Join(outputhost.ErrProcess, errors.New("private-process-sentinel")), unavailable: true, reason: contract.ReasonEvidenceUnavailable},
		{name: "generator-artifact", err: errors.Join(generatorhost.ErrAdmission, generatorhost.ErrArtifactIdentity), unavailable: true, reason: contract.ReasonEvidenceUnavailable},
		{name: "output-artifact", err: errors.Join(outputhost.ErrAdmission, outputhost.ErrArtifactUnavailable), unavailable: true, reason: contract.ReasonEvidenceUnavailable},
		{name: "generator-construction", err: errors.Join(plugininstallation.ErrInstallation, generatorhost.ErrAdmission), unavailable: true, reason: contract.ReasonEvidenceUnavailable},
		{name: "output-construction", err: errors.Join(plugininstallation.ErrInstallation, outputhost.ErrAdmission), unavailable: true, reason: contract.ReasonEvidenceUnavailable},
		{name: "target-unavailable", err: &configurationNormalizationError{validation: core.PublicConfigurationValidation{DiagnosticsComplete: true, Diagnostics: []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "private-output"}, Path: []contract.DiagnosticField{contract.FieldTargets}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}}}}, unavailable: true, reason: contract.ReasonEvidenceUnavailable},
		{name: "invalid-and-unavailable-target", err: &configurationNormalizationError{validation: core.PublicConfigurationValidation{DiagnosticsComplete: true, Diagnostics: []contract.Diagnostic{
			{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "private-output", Name: "second"}, Path: []contract.DiagnosticField{contract.FieldCanonicalTarget}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonDuplicateKey},
			{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "private-output"}, Path: []contract.DiagnosticField{contract.FieldTargets}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable},
		}}}, reason: contract.ReasonInvalidInput},
		{name: "generator-refusal", err: generatorhost.ErrAdmission, reason: contract.ReasonInvalidInput},
		{name: "output-refusal", err: outputhost.ErrPassiveRefused, reason: contract.ReasonInvalidInput},
		{name: "output-malformed-evidence", err: errors.Join(outputhost.ErrProcess, outputprotocol.ErrProtocol), unavailable: true, reason: contract.ReasonEvidenceUnavailable},
		{name: "changed-source", err: errors.Join(plugininstallation.ErrInstallation, plugininstallation.ErrSourceChanged, configuration.ErrSourceChanged), reason: contract.ReasonInvalidInput},
		{name: "cancelled", err: plugininstallation.ErrInstallation, cancel: true, reason: contract.ReasonCancelled},
		{name: "expired", err: plugininstallation.ErrInstallation, expire: true, reason: contract.ReasonExpired},
		{name: "duplicate-source", err: &configuration.Diagnostic{Reason: "duplicate-key"}, reason: contract.ReasonDuplicateKey},
		{name: "returned-cancelled", err: errors.Join(plugininstallation.ErrInstallation, context.Canceled), reason: contract.ReasonCancelled},
		{name: "returned-expired", err: errors.Join(plugininstallation.ErrInstallation, context.DeadlineExceeded), reason: contract.ReasonExpired},
		{name: "normalized-cancelled", err: &configurationNormalizationError{validation: core.PublicConfigurationValidation{DiagnosticsComplete: true, Diagnostics: []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "private-output"}, Path: []contract.DiagnosticField{contract.FieldTargets}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonCancelled}}}}, reason: contract.ReasonCancelled},
		{name: "normalized-expired", err: &configurationNormalizationError{validation: core.PublicConfigurationValidation{DiagnosticsComplete: true, Diagnostics: []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "private-output"}, Path: []contract.DiagnosticField{contract.FieldTargets}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonExpired}}}}, reason: contract.ReasonExpired},
		{name: "unsupported-change", err: &configuration.Diagnostic{Reason: "unsupported-apply-change"}, reason: contract.ReasonInvalidInput, code: "unsupported-apply-change"},
		{name: "cancelled-unsupported-change", err: &configuration.Diagnostic{Reason: "unsupported-apply-change"}, cancel: true, reason: contract.ReasonCancelled},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx := t.Context()
			if row.cancel {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			} else if row.expire {
				expired, cancel := context.WithDeadline(ctx, time.Unix(1, 0))
				defer cancel()
				ctx = expired
			}
			request, domain := contract.ID{1}, contract.ID{2}
			comparison := configurationComparisonFailure(ctx, request, domain, "trusted", row.err)
			planning := configurationPlanningFailure(ctx, request, domain, "trusted", row.err)
			apply, err := newConfigurationApplyResult(request, configuration.JSON)
			if err != nil {
				t.Fatal(err)
			}
			apply = configurationApplyFailure(ctx, apply, "declaration", row.err)
			wantReader := core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}
			wantApply, wantState, wantStage := wantReader, contract.ReaderRefused, "declaration"
			if row.unavailable {
				wantReader = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
				wantApply = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.CustodyUnavailable}
				wantState, wantStage = contract.ReaderUnavailable, "construction"
			}
			if comparison.Result != wantReader || planning.Result != wantReader || comparison.StateResult != wantState || planning.StateResult != wantState || apply.Result != wantApply {
				t.Fatalf("classification differs: compare=%v plan=%v apply=%v states=%s/%s", comparison.Result, planning.Result, apply.Result, comparison.StateResult, planning.StateResult)
			}
			for _, diagnostics := range [][]contract.Diagnostic{comparison.Diagnostics, planning.Diagnostics, apply.Diagnostics} {
				if len(diagnostics) != 1 || diagnostics[0].Reason != row.reason || diagnostics[0].Subject.Kind != contract.SubjectConfiguration || len(diagnostics[0].Path) != 1 || diagnostics[0].Path[0] != contract.FieldPresence || diagnostics[0].Outcome != contract.DiagnosticUnable || diagnostics[0].SourceLocation != nil {
					t.Fatal("failure lost its exact closed diagnostic")
				}
			}
			wantCode := row.code
			if wantCode == "" {
				wantCode = string(row.reason)
			}
			if apply.PreAdmission == nil || apply.PreAdmission.Stage != wantStage || apply.PreAdmission.Code != wantCode || apply.PreAdmission.RequestNonce != request || configurationFailureCode(ctx, row.err) != wantCode {
				t.Fatal("failure lost its closed identity or original request")
			}
			if comparison.Observation != nil || comparison.Verdict != contract.ComparisonUnable || planning.PrivateComplete || planning.DisplayDelivery != contract.PlanningNotRequested || planning.Context.Operation != contract.PlanningOperation {
				t.Fatal("pre-admission failure claimed observation or private progress")
			}
			body, err := RenderApplyJSON(apply)
			if err != nil || bytes.Contains(body, []byte("private-path-sentinel")) || bytes.Contains(body, []byte("private-process-sentinel")) {
				t.Fatal("failure exposed private error content or was not renderable", err)
			}
		})
	}
}

// full_only: false
func TestConfigurationRequiredPluginFailurePrecedesAllOperationConstruction(t *testing.T) {
	configureLocalPluginTrust(t)
	for _, condition := range []string{"missing", "assembly-unavailable"} {
		for _, operation := range []string{"apply", "apply-publication", "compare", "plan"} {
			t.Run(condition+"/"+operation, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
				keys := installedPluginKeys
				if condition == "assembly-unavailable" {
					installedPluginKeys = ""
				}
				defer func() { installedPluginKeys = keys }()
				source := configurationReaderPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
					basis := generated["public_basis"].(map[string]any)
					descriptor, err := contract.DecodeGenesisDescriptorCore(basis["descriptor"].([]byte))
					if err != nil {
						t.Fatal(err)
					}
					basis["descriptor"], err = contract.EncodeGenesisDescriptorCore(configurationCurrentDescriptor(t, descriptor))
					if err != nil {
						t.Fatal(err)
					}
					editable["entries"].(map[string]any)["secret"].(map[string]any)["source"] = map[string]any{"kind": "generated", "plugin": "private-generator", "settings": map[string]any{}, "epoch": uint64(0), "retirement": "manual"}
					delete(generated["secrets"].(map[string]any), "secret")
				})
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				request := contract.ID{1}
				calls := 0
				openApply := func(context.Context, *configuration.Model, core.ApplyInstallation, *configurationInstalledPlugins) (*core.InstalledApply, error) {
					calls++
					return nil, ErrCell
				}
				var result core.Result
				var identity *core.PreAdmissionRequestIdentity
				var diagnostics []contract.Diagnostic
				var body []byte
				var err error
				stage := "construction"
				switch operation {
				case "apply", "apply-publication":
					var apply core.PublicApplyResult
					if operation == "apply" {
						apply = applyConfiguration(ctx, request, source.pair, openApply)
					} else {
						combined := configurationApplyPublication(ctx, request, contract.ID{2}, source.pair, contract.ID{}, ApplyPublicationOptions{}, openApply,
							func(context.Context, *configuration.Model, core.PublicationInstallation, map[contract.ID]string, *configurationInstalledPlugins) (*core.InstalledPublication, error) {
								calls++
								return nil, ErrCell
							})
						if combined.Publication.Stage != "unstarted" || combined.Publication.Reason != "apply-incomplete" || combined.Publication.Result != nil {
							t.Fatal("failed installation claimed publication progress")
						}
						apply = combined.Apply
					}
					result, identity, diagnostics = apply.Result, apply.PreAdmission, apply.Diagnostics
					if result != (core.Result{Outcome: core.EvidenceUnavailable, Reason: core.CustodyUnavailable}) || !apply.RequestIdentity.IsZero() || apply.RequestID != request {
						t.Fatalf("required plugin failure was not unavailable before apply admission: outcome=%d reason=%d", result.Outcome, result.Reason)
					}
					body, err = RenderApplyJSON(apply)
				case "compare", "plan":
					stage = "public-configuration"
					if operation == "compare" {
						comparison := compareConfiguration(ctx, request, source.pair, nil, func(context.Context, ReaderConfig) (*core.ReaderEngine, error) {
							calls++
							return nil, ErrCell
						})
						result, identity, diagnostics = comparison.Result, comparison.PreAdmission, comparison.Diagnostics
						if comparison.StateResult != contract.ReaderUnavailable || comparison.Observation != nil || comparison.Verdict != contract.ComparisonUnable {
							t.Fatal("required plugin failure claimed comparison evidence")
						}
						body, err = RenderComparisonJSON(comparison)
					} else {
						planning := planConfiguration(ctx, request, source.pair, nil, contract.PlanningOptions{Purpose: contract.PlanningEquality}, nil, func(context.Context, PlanningConfig) (*core.InstalledPlanning, error) {
							calls++
							return nil, ErrCell
						})
						result, identity, diagnostics = planning.Result, planning.PreAdmission, planning.Diagnostics
						if planning.StateResult != contract.ReaderUnavailable || planning.Verdict != contract.ComparisonUnable || planning.PrivateComplete || planning.DisplayDelivery != contract.PlanningNotRequested {
							t.Fatal("required plugin failure claimed private planning evidence")
						}
						body, err = RenderPlanningJSON(planning)
					}
					if result != (core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}) {
						t.Fatalf("required plugin failure was not unavailable before Reader admission: outcome=%d reason=%d", result.Outcome, result.Reason)
					}
				}
				if calls != 0 || identity == nil || identity.Stage != stage || identity.Code != "evidence-unavailable" || identity.RequestNonce != request || len(diagnostics) != 1 || diagnostics[0].Reason != contract.ReasonEvidenceUnavailable || diagnostics[0].Subject.Kind != contract.SubjectConfiguration || diagnostics[0].Outcome != contract.DiagnosticUnable {
					t.Fatal("required plugin failure crossed construction or lost closed request facts")
				}
				if err != nil || bytes.Contains(body, []byte(source.path)) || bytes.Contains(body, []byte(home)) {
					t.Fatal("failure exposed local paths or was not renderable", err)
				}
				source.assertUnchanged(t)
			})
		}
	}
}

func configureLocalPluginTrust(t *testing.T) {
	t.Helper()
	savedOrigin, savedKeys, savedCLIKey, savedRedirects, savedRoots := installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey, installedPluginRedirectHosts, installedPluginTLSRoots
	installedPluginOrigin = "https://127.0.0.1:1/releases/"
	installedPluginKeys = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	installedCLIVerificationKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	installedPluginRedirectHosts, installedPluginTLSRoots = "", ""
	t.Cleanup(func() {
		installedPluginOrigin, installedPluginKeys, installedCLIVerificationKey, installedPluginRedirectHosts, installedPluginTLSRoots = savedOrigin, savedKeys, savedCLIKey, savedRedirects, savedRoots
	})
}
