package core

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedFinalSelectionStore struct {
	contract.Store
	memory *memoryStore
	swap   func(context.Context, string, contract.Token, []byte) contract.WriteResult
}

func (s *generatedFinalSelectionStore) admittedMemoryStore() *memoryStore { return s.memory }
func (s *generatedFinalSelectionStore) StoreConfiguration() contract.StoreConfiguration {
	return s.memory.StoreConfiguration()
}
func (s *generatedFinalSelectionStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	return s.swap(ctx, key, token, body)
}

// full_only: false
func TestInstalledGeneratedFinalStopsAfterNonCurrentSelection(t *testing.T) {
	for _, path := range []string{"ordinary", "anchor"} {
		t.Run(path, func(t *testing.T) {
			modes := []string{"conflict", "transport", "malformed", "not-sent"}
			if path == "anchor" {
				modes = []string{"conflict", "transport"}
			}
			for _, mode := range modes {
				t.Run(mode, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
					defer cancel()
					process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
					f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
					f.env.GeneratedProcess = process
					generation := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema,
						LifecycleMode: contract.GeneratorLifecycleManaged, ConfigContractID: process.Implementation.ConfigContractID,
						ResourceContractID: hermeticCloudflareResourceContractID(), RetirementMode: contract.GeneratedRetirementManual,
						CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
					input := []ApplyEntryInput{{Name: "generated", Recipients: []contract.ID{f.selected.admission.recipient},
						ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Generated: generation}}
					if path == "anchor" {
						initial := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
						result := initial.Apply(ctx, testID("final selection initial"), input)
						initial.Close()
						if result.Result.Outcome != ObservedCurrent {
							t.Fatal("initial generation was not selected", result.Result)
						}
						f.selected = f.open(t, ctx)
						generation.Epoch, generation.RetirementMode = 1, contract.GeneratedRetirementAuto
					}
					callbacks := installedGeneratedRetirementCallbacks(t, f, process)
					memory := requireAdmittedMemoryStore(t, f.env.Store)
					base := f.env.Store
					proxy := &generatedFinalSelectionStore{Store: base, memory: memory}
					f.env.Store = proxy
					trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
					if !ok {
						t.Fatal("fixture Trust unavailable")
					}
					var admissions, closes, binds, sends, signsBefore int
					var first format.Head
					var original []byte
					var originalToken contract.Token
					landed := false
					admit := callbacks.AdmitFinal
					callbacks.AdmitFinal = func(callctx context.Context, request contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedFinalInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
						owner, err := admit(callctx, request, control, input, deadline)
						if err != nil || owner == nil {
							return owner, err
						}
						admissions++
						closeOwner := owner.Close
						owner.Close = sync.OnceFunc(func() { closeOwner(); closes++ })
						if path == "ordinary" || input.Preparation != nil {
							bind := owner.BindCandidate
							owner.BindCandidate = func(callctx context.Context, candidate contract.GeneratedCandidateInput) contract.CryptoResultCode {
								code := bind(callctx, candidate)
								if code == contract.CryptoSuccess {
									binds++
									if binds == 1 {
										signsBefore = trust.Calls()
									}
								}
								return code
							}
						}
						return owner, nil
					}
					land := func() {
						t.Helper()
						if landed || len(original) == 0 {
							return
						}
						result := base.CompareAndSwap(ctx, base.Descriptor().HeadKey, originalToken, original)
						if result.Status != contract.WriteAcknowledged {
							t.Fatal("delayed original selection failed", result)
						}
						landed = true
					}
					proxy.swap = func(callctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
						if binds == 0 {
							return base.CompareAndSwap(callctx, key, token, body)
						}
						sends++
						if original == nil {
							original, originalToken = bytes.Clone(body), token
							var err error
							first, err = format.DecodeHead(body)
							if err != nil || first.Generator == nil {
								t.Fatal("first Final has no valid identity", err)
							}
						}
						if binds != 1 {
							if mode != "not-sent" {
								land()
							}
							return base.CompareAndSwap(callctx, key, token, body)
						}
						if !bytes.Equal(original, body) || originalToken != token {
							t.Fatal("transport resend changed the frozen request")
						}
						switch mode {
						case "conflict":
							return contract.WriteResult{Status: contract.WriteConflict}
						case "malformed":
							return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
						default:
							return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: mode == "not-sent"}
						}
					}
					request := testID(path + " final selection " + mode)
					engine := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), callbacks)
					got := engine.Apply(ctx, request, input)
					engine.Close()
					if first.Generator == nil {
						t.Fatal("fixture did not reach the selecting Final", got.Result)
					}
					wantAdmissions, wantCreates := 1, 1
					if path == "anchor" {
						wantAdmissions, wantCreates = 2, 2
					}
					wantSends := 1
					if mode == "transport" || mode == "not-sent" {
						wantSends = 3
					}
					if admissions != wantAdmissions || closes != admissions || binds != 1 || sends != wantSends || trust.Calls()-signsBefore != 1 {
						t.Errorf("non-current Final started another episode or lost cleanup: admissions=%d closes=%d binds=%d sends=%d signs=%d", admissions, closes, binds, sends, trust.Calls()-signsBefore)
					}
					wantOutcome, wantUncertain := UnresolvedCommit, true
					wantObserved, wantState := first.Core.PreviousRevision, "commit-outcome-unknown"
					if mode == "not-sent" {
						wantOutcome, wantUncertain = EvidenceUnavailable, false
						wantObserved, wantState = contract.ID{}, "unavailable"
					}
					if got.Result.Outcome != wantOutcome || got.Result.CommitMayHaveOccurred != wantUncertain || got.Result.RequestedRevision != first.Core.Revision || got.Result.ObservedRevision != wantObserved {
						t.Error("Final result did not preserve its first conditional request", got.Result, first.Core)
					}
					if got.RequestID != request || got.DomainID != f.env.Domain || got.OperationID != first.Generator.OperationID || got.RequestIdentity != first.Generator.RequestIdentityDigest || got.Payload != nil || len(got.Receipt) != 0 || got.Generated == nil {
						t.Error("Final result lost its invocation identity or invented terminal payload", got)
					}
					facts := got.Generated
					if facts == nil || facts.StateResult != wantState || facts.CanonicalOutcome != contract.ReceiptCanonicalNotSelected ||
						!facts.EffectsAvailable || !facts.RelatedWorkAvailable || !facts.SummaryCountsAvailable || len(facts.Effects) != 1 ||
						facts.Effects[0].Record.OperationID != got.OperationID || facts.Effects[0].Record.State != contract.GeneratedEffectSucceeded || facts.Effects[0].Action != contract.GeneratorActionCreate {
						t.Error("Final stop lost its complete authenticated create facts", facts)
					}
					creates, deletes := effects()
					if creates != wantCreates || len(deletes) != 0 {
						t.Error("non-current Final repeated a generator effect", creates, deletes)
					}
					if mode != "not-sent" {
						// The original request can land after this invocation returns.
						// A second candidate is not needed to release it.
						land()
						cold := f.open(t, ctx)
						if cold.head.Core.Revision != first.Core.Revision || !bytes.Equal(cold.body, original) {
							t.Fatal("delayed selection changed the original candidate")
						}
						if path == "anchor" {
							work := mustSelectedGeneratedWork(t, cold)
							if !generatedSelectionAnchored(work) {
								t.Fatal("delayed Final did not establish its selection anchor")
							}
						}
					}
				})
			}
		})
	}
}
