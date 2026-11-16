package compositionfull

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestConfigurationPlanningPreservesSourcesAndTrustedConstruction(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, proposed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/candidate-%t", family, proposed), func(t *testing.T) {
				trusted := configurationReaderPair(t, family, configuration.JSON, nil)
				var candidate *configuration.Pair
				desiredSource := trusted
				if proposed {
					desiredSource = configurationReaderPair(t, family, configuration.YAML, func(editable, generated map[string]any) {
						editable["domain"].(map[string]any)["store"].(map[string]any)["bucket"] = "candidate-only-bucket"
						generated["public_basis"].(map[string]any)["descriptor"] = []byte{1}
						entries := editable["entries"].(map[string]any)
						entries["new"] = map[string]any{"confidentiality": "secret", "recipients": entries["secret"].(map[string]any)["recipients"], "source": map[string]any{"kind": "supplied"}}
						generated["secrets"].(map[string]any)["new"] = map[string]any{"retained": map[string]any{"incarnation": readerID(contract.Hash([]byte("new incarnation"))), "material": readerID(contract.Hash([]byte("new material")))}}
					})
					candidate = desiredSource.pair
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				desired, err := configuration.Parse(ctx, desiredSource.pair)
				if err != nil {
					t.Fatal(err)
				}
				expectedInputs := []contract.PlanningInput{
					{Name: "encoded", Form: contract.PlanningRetained, Retained: contract.RetainedSecretInput{Incarnation: contract.Hash([]byte("fixture incarnation encoded")), Material: contract.Hash([]byte("fixture material encoded"))}},
					{Name: "secret", Form: contract.PlanningRetained, Retained: contract.RetainedSecretInput{Incarnation: contract.Hash([]byte("fixture incarnation secret")), Material: contract.Hash([]byte("fixture material secret"))}},
				}
				if proposed {
					expectedInputs = append(expectedInputs, contract.PlanningInput{Name: "new", Form: contract.PlanningRetained, Retained: contract.RetainedSecretInput{Incarnation: contract.Hash([]byte("new incarnation")), Material: contract.Hash([]byte("new material"))}})
				}
				actualInputs := configurationPlanningInputs(desired)
				byName := func(rows []contract.PlanningInput) map[string]contract.PlanningInput {
					out := make(map[string]contract.PlanningInput)
					for _, row := range rows {
						out[row.Name] = row
					}
					return out
				}
				if len(actualInputs) != len(expectedInputs) || !reflect.DeepEqual(byName(actualInputs), byName(expectedInputs)) {
					t.Fatal("planning lost complete retained proposed scope")
				}
				expectedDigest, err := core.PlanningInputDigest(desired.Public, expectedInputs)
				if err != nil {
					t.Fatal(err)
				}
				expectedPair := func(source configurationReaderSource) contract.PlanningSourcePair {
					return contract.PlanningSourcePair{FileIdentity: contract.Hash([]byte("Reader file fixture")), EditableDigest: contract.ID(sha256.Sum256(source.editableBytes)), GeneratedDigest: contract.ID(sha256.Sum256(source.generatedBytes)), EditableLength: uint64(len(source.editableBytes)), GeneratedLength: uint64(len(source.generatedBytes))}
				}
				calls := 0
				requestID := contract.Hash([]byte("private captured pair"))
				result := planConfiguration(ctx, requestID, trusted.pair, candidate, contract.PlanningOptions{Purpose: contract.PlanningEquality}, nil, func(_ context.Context, c PlanningConfig) (*core.InstalledPlanning, error) {
					calls++
					if c.Sources != (contract.PlanningSources{Trusted: expectedPair(trusted), Proposed: expectedPair(desiredSource)}) || c.FileIdentity != desired.FileID || c.InputDigest != expectedDigest {
						t.Fatal("captured pair or complete input identity changed")
					}
					if c.Reader.SelectPolicyAction == nil {
						t.Fatal("planning lost captured passive policy selector")
					}
					if c.Reader.Family != trusted.archive.Family {
						t.Fatal("candidate selected provider")
					}
					if c.Reader.AWS != nil {
						if c.Reader.AWS.ExpectedDomain != trusted.archive.Domain || c.Reader.AWS.Candidate.Bucket != trusted.archive.Location.Bucket || c.AWS == nil || c.GCP != nil || c.AWS.Credentials != nil {
							t.Fatal("candidate replaced trusted AWS construction")
						}
						selector, ok := contract.ParseAWSKeySelector(trusted.archive.AuthorityBinding.KeySelector, false)
						if !ok || c.AWS.Region != selector.Region || c.AWS.Account != selector.Account {
							t.Fatal("private AWS route came from candidate")
						}
					} else {
						if c.Reader.GCP.ExpectedDomain != trusted.archive.Domain || c.Reader.GCP.Candidate.Bucket != trusted.archive.Location.Bucket || c.GCP == nil || c.AWS != nil || c.GCP.Client != nil {
							t.Fatal("candidate replaced trusted GCP construction")
						}
						selector, ok := contract.ParseGCPKeySelector(trusted.archive.AuthorityBinding.KeySelector, false)
						if !ok || c.GCP.Region != selector.Region || c.GCP.Project != selector.Project || c.GCP.Endpoint != "https://"+selector.Region+"-cloudkms.googleapis.com/" {
							t.Fatal("private GCP route came from candidate")
						}
					}
					return nil, errors.New("controlled unavailable construction")
				})
				if calls != 1 || result.StateResult != contract.ReaderUnavailable || result.PrivateComplete || result.DisplayDelivery != contract.PlanningNotRequested || result.Context.Operation != contract.PlanningOperation || result.EvidenceLimit != contract.PlanningEvidenceLimit || result.Context.ExpectedDomain != trusted.archive.Domain || result.PreAdmission == nil || result.Context.OperationID.IsZero() || result.PreAdmission.RequestNonce != requestID || result.PreAdmission.Stage != "construction" {
					t.Fatal("unavailable planning lost safe source context", calls, result.StateResult)
				}
				trusted.assertUnchanged(t)
				desiredSource.assertUnchanged(t)
			})
		}
	}
	for _, files := range []bool{false, true} {
		t.Run(fmt.Sprintf("display/files-%t", files), func(t *testing.T) {
			source := configurationReaderPair(t, "aws", configuration.JSON, nil)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			factory, err := newPlanningDisplayWriter(func(context.Context) (planningDisplayOutput, error) {
				t.Fatal("construction-only check acquired display sink")
				return nil, errors.New("unexpected sink acquisition")
			}, true)
			if err != nil {
				t.Fatal(err)
			}
			options := planningDisplayOptions([]string{"secret"}, factory)
			calls := 0
			open := func(_ context.Context, c PlanningConfig) (*core.InstalledPlanning, error) {
				calls++
				if c.DisplayFactory != factory {
					t.Fatal("explicit display factory did not reach construction")
				}
				return nil, errors.New("controlled unavailable construction")
			}
			requestID := contract.Hash([]byte("display factory construction"))
			var result ConfigurationPlanningResult
			if files {
				result = planConfigurationFiles(ctx, requestID, source.path, configuration.JSON, "", configuration.JSON, options, factory, open)
			} else {
				result = planConfiguration(ctx, requestID, source.pair, nil, options, factory, open)
			}
			if calls != 1 || result.StateResult != contract.ReaderUnavailable || result.Context.ExpectedDomain != source.archive.Domain || result.PreAdmission == nil || result.PreAdmission.Stage != "construction" {
				t.Fatal("explicit display lost construction or safe source context")
			}
			source.assertUnchanged(t)
		})
	}
}

// full_only: false
func TestConfigurationPlanningRefusesBeforeConstruction(t *testing.T) {
	for _, condition := range []string{"trusted-unresolved", "candidate-malformed", "candidate-unresolved", "trusted-invalid-output", "candidate-invalid-output", "trusted-wrong-authority", "display", "display-files", "feasibility", "no-deadline", "cancelled"} {
		t.Run(condition, func(t *testing.T) {
			invalidOutput := func(editable, generated map[string]any) {
				editable["outputs"].(map[string]any)["destinations"].(map[string]any)["unused-invalid"] = configurationReaderInvalidBinding(t, generated, "unused-invalid")
			}
			var edit func(map[string]any, map[string]any)
			if condition == "trusted-invalid-output" {
				edit = invalidOutput
			}
			if condition == "trusted-wrong-authority" {
				edit = func(editable, generated map[string]any) {
					selector := "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
					editable["domain"].(map[string]any)["authority"].(map[string]any)["encryption_key"] = selector
					generated["domain"].(map[string]any)["authority"].(map[string]any)["encryption"].(map[string]any)["selector"] = selector
				}
			}
			source := configurationReaderPair(t, "aws", configuration.JSON, edit)
			trusted := source.pair
			var candidate *configuration.Pair
			if condition == "trusted-unresolved" {
				trusted = &configuration.Pair{Editable: trusted.Editable, Format: trusted.Format}
			}
			if condition == "candidate-malformed" {
				candidate = &configuration.Pair{Format: configuration.YAML}
			}
			if condition == "candidate-unresolved" {
				candidate = &configuration.Pair{Editable: source.pair.Editable, Format: source.pair.Format}
			}
			if condition == "candidate-invalid-output" {
				candidate = configurationReaderPair(t, "aws", configuration.YAML, invalidOutput).pair
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			if condition == "no-deadline" {
				ctx = context.Background()
			}
			if condition == "cancelled" {
				cancel()
			}
			options := contract.PlanningOptions{Purpose: contract.PlanningEquality}
			if condition == "display" || condition == "display-files" {
				options = contract.PlanningOptions{Purpose: contract.PlanningDisplay, SelectedNames: []string{"secret"}, SinkID: contract.Hash([]byte("sink"))}
			}
			if condition == "feasibility" {
				options.Purpose = contract.PlanningRetirementFeasibility
			}
			calls := 0
			open := func(context.Context, PlanningConfig) (*core.InstalledPlanning, error) {
				calls++
				return nil, errors.New("must not construct")
			}
			requestID := contract.Hash([]byte("planning refusal"))
			var result ConfigurationPlanningResult
			if condition == "display-files" {
				result = planConfigurationFiles(ctx, requestID, source.path, configuration.JSON, "", configuration.JSON, options, nil, open)
			} else {
				result = planConfiguration(ctx, requestID, trusted, candidate, options, nil, open)
			}
			if calls != 0 || result.StateResult != contract.ReaderRefused || result.Verdict != contract.ComparisonUnable || result.PrivateComplete || result.Observation != nil || result.Context.Operation != contract.PlanningOperation || result.EvidenceLimit != contract.PlanningEvidenceLimit || result.DisplayDelivery != contract.PlanningNotRequested || result.PreAdmission == nil || result.Context.OperationID.IsZero() {
				t.Fatal("invalid planning reached construction or lost safe refusal", calls, result.StateResult)
			}
			if condition == "no-deadline" {
				if result.SourceFailure != nil || result.PreAdmission.Stage != "context" || result.Result.Outcome != core.AdmissionRefused || result.Result.Reason != core.AdmissionInvalid || result.Diagnostics[0].Reason != contract.ReasonExpired {
					t.Fatal("context refusal acquired source facts or changed its cause", result)
				}
				if _, err := RenderPlanningJSON(result); err != nil {
					t.Fatal("context refusal JSON", err)
				}
				if _, err := RenderPlanningHuman(result); err != nil {
					t.Fatal("context refusal human", err)
				}
			}
			source.assertUnchanged(t)
		})
	}
}

// full_only: false
func TestConfigurationPlanningFileCaptureRefusalPreservesTrustedContext(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	candidate := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(candidate, []byte(`{"schema":`), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	requestID := contract.Hash([]byte("planning file capture"))
	result := PlanConfigurationFiles(ctx, requestID, source.path, configuration.JSON, candidate, configuration.JSON, contract.PlanningOptions{Purpose: contract.PlanningEquality})
	if result.StateResult != contract.ReaderRefused || result.Context.ExpectedDomain != source.archive.Domain || result.Context.Operation != contract.PlanningOperation || result.Context.RequestID != requestID || result.PreAdmission == nil || result.Context.OperationID.IsZero() || result.PrivateComplete || result.DisplayDelivery != contract.PlanningNotRequested {
		t.Fatal("explicit malformed candidate did not preserve trusted refusal context")
	}
	source.assertUnchanged(t)
}
