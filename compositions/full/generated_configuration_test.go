package compositionfull

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedAcceptedWorkConstructionIgnoresLocalProposal(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			source := configurationApplyPair(t, family, configuration.JSON, nil)
			defer func() {
				if err := source.pair.Close(); err != nil {
					t.Error("generated configuration source cleanup failed", err)
				}
			}()
			m, err := configuration.Parse(t.Context(), source.pair)
			if err != nil {
				t.Fatal(err)
			}
			m.Entries = []configuration.Entry{{Name: "irrelevant-local-generated-change", Secret: true, Generated: &configuration.Generator{Plugin: "unavailable-private-generator", Settings: []byte(`{"new":"proposal"}`)}}}
			m.Outputs = []configuration.OutputBinding{{DestinationID: "unavailable-proposal-output", Plugin: "unavailable-private-output", Settings: []byte(`{"new":"proposal"}`)}}
			m.Public.Entries = contract.PublicField[[]contract.PublicEntry]{}
			i, err := configurationAcceptedGeneratedInput(m)
			if err != nil {
				t.Fatal(err)
			}
			if m.Entries[0].Generated.Plugin != "unavailable-private-generator" || m.Outputs[0].Plugin != "unavailable-private-output" {
				t.Fatal("accepted input changed the source proposal")
			}
			if i.ExpectedDomain != m.DomainID || i.FileIdentity != m.FileID || len(i.DesiredRecipients) != 1 || i.DesiredRecipients[0].Recipient.RecipientID != m.Authority.ID || len(i.PublicConfiguration.Entries.Value) != 0 || len(i.GeneratorImplementations) != 0 {
				t.Fatal("proposal reached accepted-work construction")
			}
			m.Authority.Signing.PublicKey = []byte("changed trusted authority")
			if _, err := configurationAcceptedGeneratedInput(m); err == nil {
				t.Fatal("trusted authority mismatch ignored")
			}
		})
	}
}

// full_only: false
func TestGeneratedConfigurationConstructionIsFiniteAndReadOnly(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			source := configurationApplyPair(t, family, configuration.JSON, nil)
			defer func() {
				if err := source.pair.Close(); err != nil {
					t.Error("generated configuration source cleanup failed", err)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			opened, invoked := 0, 0
			out := configurationGeneratedMutation(ctx, contract.ID{1}, source.pair, func(*core.InstalledApply) core.PublicApplyResult { invoked++; return core.PublicApplyResult{} }, func(_ context.Context, m *configuration.Model, i core.ApplyInstallation) (*core.InstalledApply, error) {
				opened++
				if i.ExpectedDomain != m.DomainID || len(i.DesiredRecipients) != 1 {
					t.Fatal("incorrect trusted construction")
				}
				return nil, fmt.Errorf("synthetic unavailable construction")
			})
			if opened != 1 || invoked != 0 || out.Result.Outcome != core.EvidenceUnavailable || out.Result.CommitMayHaveOccurred || len(out.Receipt) != 0 {
				t.Fatal("construction failure changed lifecycle", opened, invoked, out.Result)
			}
			opened = 0
			configurationGeneratedMutation(context.Background(), contract.ID{1}, source.pair, func(*core.InstalledApply) core.PublicApplyResult { invoked++; return core.PublicApplyResult{} }, func(context.Context, *configuration.Model, core.ApplyInstallation) (*core.InstalledApply, error) {
				opened++
				return nil, nil
			})
			if opened != 0 || invoked != 0 {
				t.Fatal("unbounded context acquired construction")
			}
		})
	}
}

// full_only: false
func TestGeneratedListConstructionDoesNotValidatePendingIntent(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			source := configurationApplyPair(t, family, configuration.JSON, nil)
			defer func() {
				if err := source.pair.Close(); err != nil {
					t.Error("generated configuration source cleanup failed", err)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			calls := 0
			out := listConfigurationGenerated(ctx, contract.ID{1}, source.pair, func(_ context.Context, c ReaderConfig) (*core.InstalledGeneratedReader, error) {
				calls++
				if c.AWS != nil && c.AWS.Validator != nil || c.GCP != nil && c.GCP.Validator != nil {
					t.Fatal("list constructed intent validator")
				}
				return nil, ErrCell
			})
			if calls != 1 || out.StateResult != contract.ReaderUnavailable || out.View != nil || out.Result.CommitMayHaveOccurred {
				t.Fatal("read construction invented work")
			}
			if b, e := out.RenderJSON(); e != nil || len(b) == 0 {
				t.Fatal("typed list refusal not renderable", e)
			}
		})
	}
}

// full_only: false
func TestGeneratedCleanupPreAdmissionRequiresZeroRequestIdentity(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, admitted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/admitted-%t", family, admitted), func(t *testing.T) {
				source := configurationApplyPair(t, family, configuration.JSON, nil)
				defer func() {
					if err := source.pair.Close(); err != nil {
						t.Error("generated source cleanup failed", err)
					}
				}()
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				request, operation, identity := contract.ID{1}, contract.ID{2}, contract.ID{3}
				opened, invoked := 0, 0
				var domain contract.ID
				out := configurationGeneratedMutation(ctx, request, source.pair, func(*core.InstalledApply) core.PublicApplyResult {
					invoked++
					result := core.PublicApplyResult{RequestID: request, OperationID: operation, DomainID: domain, Result: core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}}
					if admitted {
						result.RequestIdentity = identity
					}
					return result
				}, func(_ context.Context, model *configuration.Model, _ core.ApplyInstallation) (*core.InstalledApply, error) {
					opened++
					domain = model.DomainID
					return &core.InstalledApply{}, nil
				})
				if opened != 1 || invoked != 1 || out.OperationID != operation || out.RequestID != request || out.DomainID != domain || out.Result.Outcome != core.EvidenceUnavailable || out.Result.CommitMayHaveOccurred || out.Generated != nil || out.Payload != nil || out.Cleanup != nil || len(out.Receipt) != 0 {
					t.Fatal("composition changed the unavailable invocation boundary")
				}
				if admitted {
					if out.RequestIdentity != identity || out.PreAdmission != nil {
						t.Fatal("admitted identity became pre-admission failure")
					}
				} else if !out.RequestIdentity.IsZero() || out.PreAdmission == nil || out.PreAdmission.Stage != "observation" || out.PreAdmission.Code != "evidence-unavailable" || out.PreAdmission.RequestNonce != request {
					t.Fatal("zero identity lost its exact observation failure")
				}
				body, err := RenderGeneratedMutationJSON(out, contract.OperationCleanOwnedFailureResidue)
				if err != nil {
					t.Fatal("unavailable cleanup result could not be rendered", err)
				}
				var result struct {
					Identity json.RawMessage `json:"request_identity"`
					Payload  json.RawMessage `json:"payload"`
					Commit   bool            `json:"commit_may_have_occurred"`
				}
				var document map[string]json.RawMessage
				if json.Unmarshal(body, &document) != nil || json.Unmarshal(body, &result) != nil {
					t.Fatal("rendered cleanup result is not structured")
				}
				for name, want := range map[string]string{"schema": "ProductResult/v1", "operation_kind": "clean-owned-failure-residue", "state_result": "unavailable", "effect_summary": "effect-no-change", "output_summary": "not-applicable", "request_id": readerID(request), "operation_id": readerID(operation), "domain_id": readerID(domain), "replay_identity": "none", "evidence_ceiling": "unavailable"} {
					var actual string
					if json.Unmarshal(document[name], &actual) != nil || actual != want {
						t.Fatal("unavailable result changed a typed field", name)
					}
				}
				if result.Commit || string(result.Payload) != "null" {
					t.Fatal("unavailable terminal claimed effects or a payload")
				}
				for _, field := range []string{"requested_revision_id", "observed_revision_id", "cleanup", "transition", "effects", "receipt_hex"} {
					if _, exists := document[field]; exists {
						t.Fatal("unavailable terminal exposed admitted mutation state", field)
					}
				}
				if admitted {
					var actual string
					if json.Unmarshal(result.Identity, &actual) != nil || actual != readerID(identity) {
						t.Fatal("renderer replaced the admitted request identity")
					}
				} else {
					var actual map[string]string
					if json.Unmarshal(result.Identity, &actual) != nil || len(actual) != 9 {
						t.Fatal("pre-admission identity does not have its complete closed shape")
					}
					for name, want := range map[string]string{"schema": "PreAdmissionRequestIdentity/v1", "operation_id": readerID(operation), "operation_kind": "clean-owned-failure-residue", "stage": "observation", "code": "evidence-unavailable", "source_schema": "enkv/configuration/v3", "source_profile": "direct-candidate", "format": "json", "request_nonce": readerID(request)} {
						if actual[name] != want {
							t.Fatal("pre-admission identity changed a bound field", name)
						}
					}
				}
			})
		}
	}
}
