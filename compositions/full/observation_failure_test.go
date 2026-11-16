package compositionfull

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type configurationObservationStore struct {
	descriptor contract.Descriptor
	result     contract.ReadResult
	reads      int
	writes     int
}

func (s *configurationObservationStore) Descriptor() contract.Descriptor { return s.descriptor }
func (s *configurationObservationStore) Read(context.Context, string, uint32) contract.ReadResult {
	s.reads++
	return s.result
}
func (s *configurationObservationStore) Create(context.Context, string, []byte) contract.WriteResult {
	s.writes++
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
}
func (s *configurationObservationStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	s.writes++
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
}
func (s *configurationObservationStore) CompareAndSwap(context.Context, string, contract.Token, []byte) contract.WriteResult {
	s.writes++
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
}

type configurationObservationTrust struct {
	id     contract.ID
	family contract.Family
	signs  int
}

func (s *configurationObservationTrust) Identity() contract.ID   { return s.id }
func (s *configurationObservationTrust) Family() contract.Family { return s.family }
func (s *configurationObservationTrust) Sign(context.Context, contract.SignRequest) contract.SignResult {
	s.signs++
	return contract.SignResult{Reason: contract.ReasonConstruction}
}

// full_only: false
func TestConfigurationMutationPreservesActualObservationFailure(t *testing.T) {
	for _, operation := range []string{"apply", "apply-publication", "continue", "retire"} {
		for _, condition := range []struct {
			name    string
			read    contract.ReadResult
			outcome core.Outcome
			state   string
			code    contract.DiagnosticReason
		}{
			{"malformed", contract.ReadResult{Status: contract.ReadOK, Body: []byte("invalid HEAD"), Token: contract.Token{Family: contract.AWS, Value: `"head"`}}, core.IntegrityFailure, "positive-defect", contract.ReasonSelectedObjectInvalid},
			{"missing", contract.ReadResult{Status: contract.ReadMissing}, core.RootLossUnsupported, "root-loss-unsupported", contract.ReasonSelectedObjectUnavailable},
			{"unavailable", contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}, core.EvidenceUnavailable, "unavailable", contract.ReasonEvidenceUnavailable},
		} {
			t.Run(operation+"/"+condition.name, func(t *testing.T) {
				source := configurationApplyPair(t, "aws", configuration.JSON, nil)
				t.Cleanup(func() {
					if err := source.pair.Close(); err != nil {
						t.Error(err)
					}
				})
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				request, operationID := contract.ID{31}, contract.ID{32}
				store := &configurationObservationStore{result: condition.read}
				var trust *configurationObservationTrust
				closes, private := 0, 0
				open := func(_ context.Context, _ *configuration.Model, i core.ApplyInstallation) (*core.InstalledApply, error) {
					store.descriptor = i.ExpectedStore
					trust = &configurationObservationTrust{id: i.ExpectedControl.NormalSigning.Binding.Trust, family: i.ExpectedControl.Provider}
					i.Store, i.Trust = store, trust
					if i.ConfigurationValidator == nil {
						i.ConfigurationValidator = core.NewPublicConfigurationValidator(nil)
					}
					i.CloseInstalled = func() { closes++ }
					i.AdmitCustody = func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*core.InstalledApplyCustody, error) {
						private++
						return nil, contract.ErrRecord
					}
					return core.NewInstalledApply(i)
				}
				var out core.PublicApplyResult
				if operation == "apply" || operation == "apply-publication" {
					openApply := func(ctx context.Context, model *configuration.Model, i core.ApplyInstallation, _ *configurationInstalledPlugins) (*core.InstalledApply, error) {
						return open(ctx, model, i)
					}
					if operation == "apply" {
						out = applyConfiguration(ctx, request, source.pair, openApply)
					} else {
						combined := configurationApplyPublication(ctx, request, contract.ID{33}, source.pair, contract.ID{}, ApplyPublicationOptions{}, openApply, nil)
						if combined.Publication.Stage != "unstarted" || combined.Publication.Reason != "apply-incomplete" || combined.Publication.Result != nil {
							t.Fatal("failed apply invented publication progress", combined.Publication)
						}
						out = combined.Apply
					}
				} else {
					out = configurationGeneratedMutation(ctx, request, source.pair, func(e *core.InstalledApply) core.PublicApplyResult {
						if operation == "continue" {
							return e.Continue(ctx, request, operationID)
						}
						return e.RetireGenerated(ctx, request, core.GeneratedRetirementRequest{DutyID: operationID})
					}, open)
				}
				if out.Result.Outcome != condition.outcome || out.RequestID != request || out.OperationID.IsZero() || !out.RequestIdentity.IsZero() || out.Payload != nil || len(out.Receipt) != 0 || out.Result.CommitMayHaveOccurred {
					t.Fatalf("observation failure changed operation facts: %+v", out)
				}
				if out.PreAdmission == nil || out.PreAdmission.Code != string(condition.code) || out.PreAdmission.RequestNonce != request {
					t.Errorf("observation failure has unsupported pre-admission cause: %+v", out.PreAdmission)
				}
				body, err := RenderApplyJSON(out)
				if err != nil {
					t.Fatal(err)
				}
				var wire struct {
					State    string `json:"state_result"`
					Identity struct {
						Code string `json:"code"`
					} `json:"request_identity"`
				}
				if err := json.Unmarshal(body, &wire); err != nil || wire.State != condition.state || wire.Identity.Code != string(condition.code) {
					t.Errorf("rendered observation failure differs: %s (%v)", body, err)
				}
				if store.reads != 1 || store.writes != 0 || private != 0 || trust == nil || trust.signs != 0 || closes != 1 {
					t.Fatalf("observation refusal repeated work or lost cleanup: reads=%d writes=%d private=%d trust=%+v closes=%d", store.reads, store.writes, private, trust, closes)
				}
			})
		}
	}
}

// full_only: false
func TestMutationObservationCauseKeepsCompletedClassification(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	for _, interruption := range []struct {
		name   string
		ctx    context.Context
		reason contract.DiagnosticReason
	}{
		{"cancelled", cancelled, contract.ReasonCancelled},
		{"expired", expired, contract.ReasonExpired},
	} {
		for _, classified := range []struct {
			name   string
			result core.Result
			reason contract.DiagnosticReason
		}{
			{"format", core.Result{Outcome: core.IntegrityFailure, Reason: core.InvalidFormat}, contract.ReasonSelectedObjectInvalid},
			{"reference", core.Result{Outcome: core.IntegrityFailure, Reason: core.InvalidReference}, contract.ReasonSelectedObjectInvalid},
			{"proof", core.Result{Outcome: core.IntegrityFailure, Reason: core.InvalidProof}, contract.ReasonProofInvalid},
			{"relation", core.Result{Outcome: core.IntegrityFailure, Reason: core.InvalidRelation}, contract.ReasonSelectedRelationInvalid},
			{"missing", core.Result{Outcome: core.RootLossUnsupported}, contract.ReasonSelectedObjectUnavailable},
			{"contention", core.Result{Outcome: core.Contention}, contract.ReasonReadContention},
			{"capacity", core.Result{Outcome: core.AdmissionRefused, Reason: core.CapacityExceeded}, contract.ReasonLimitExceeded},
		} {
			t.Run(interruption.name+"/"+classified.name, func(t *testing.T) {
				if got := configurationMutationObservationReason(interruption.ctx, classified.result); got != classified.reason {
					t.Fatalf("later context state replaced the completed observation cause: got=%s want=%s", got, classified.reason)
				}
			})
		}
		for _, fallback := range []struct {
			name   string
			result core.Result
		}{
			{"admission", core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}},
			{"unavailable", core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}},
		} {
			t.Run(interruption.name+"/"+fallback.name, func(t *testing.T) {
				if got := configurationMutationObservationReason(interruption.ctx, fallback.result); got != interruption.reason {
					t.Fatalf("interrupted admission or unavailable result lost its exact cause: got=%s want=%s", got, interruption.reason)
				}
			})
		}
	}
}
