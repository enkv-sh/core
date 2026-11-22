package core

import (
	"bytes"
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestInstalledGeneratedAnchoredCanonicalSelectionSurvivesLaterStops(t *testing.T) {
	for _, stop := range []string{"contention", "unknown", "cold-refusal"} {
		t.Run(stop, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
			f.env.GeneratedProcess = process
			input := installedGeneratedRetirementEntries(process, f.selected.admission.recipient, 0, "unchanged supplied sibling")
			initialEngine := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
			initial := initialEngine.Apply(ctx, testID(stop+" canonical initial"), input)
			initialEngine.Close()
			if initial.Result.Outcome != ObservedCurrent {
				t.Fatal("initial generation not selected", initial.Result)
			}
			before := f.open(t, ctx)
			input[0].Generated.Epoch, input[0].Generated.RetirementMode = 1, contract.GeneratedRetirementAuto
			callbacks := installedGeneratedRetirementCallbacks(t, f, process)
			producer := callbacks.AdmitProducer
			store, ok := underlyingAdmittedMemoryStore(f.env.Store)
			if !ok {
				t.Fatal("fixture Store unavailable")
			}
			var anchor contract.ID
			casAtAnchor, failedReads := 0, 0
			callbacks.AdmitProducer = func(callctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, row contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				if in.Expected.Template.Action != contract.GeneratorActionDelete {
					return producer(callctx, q, control, in, row, deadline)
				}
				selected := f.open(t, callctx)
				work := mustSelectedGeneratedWork(t, selected)
				if !generatedSelectionAnchored(work) || !anchor.IsZero() {
					t.Fatal("fault did not follow one exact first-B selection")
				}
				anchor, casAtAnchor = selected.head.Core.Revision, store.cas
				if stop == "cold-refusal" {
					return nil, contract.ErrRecord
				}
				owner, err := producer(callctx, q, control, in, row, deadline)
				if err != nil {
					return owner, err
				}
				if stop == "contention" {
					store.mu.Lock()
					store.put(store.desc.HeadKey, bytes.Clone(store.objects[store.desc.HeadKey].Body))
					store.mu.Unlock()
				} else {
					store.casMode = "lost-after"
					store.readHook = func(key string, r contract.ReadResult) contract.ReadResult {
						if key == store.desc.HeadKey && store.cas > casAtAnchor {
							failedReads++
							return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
						}
						return r
					}
				}
				return owner, nil
			}
			engine := installedGeneratedTestEngine(t, ctx, f, before, input, currentApplyRecipients(before.registry()), callbacks)
			got := engine.Apply(ctx, testID(stop+" anchored rotation"), input)
			engine.Close()
			store.casMode, store.readHook = "", nil
			if anchor.IsZero() {
				t.Fatal("original apply never selected B", got.Result)
			}
			if stop == "cold-refusal" {
				if got.Result.Outcome != ObservedCurrent || got.Result.ObservedRevision != anchor {
					t.Fatal("preparation replaced actual first-B selection", got.Result)
				}
				cold := f.open(t, ctx)
				if got.OperationID.IsZero() || cold.root.Generated.ActiveOwner != got.OperationID {
					t.Fatal("expected automatic retirement to retain the selected owner")
				}
				h := installedReplacementForCurrent(t, f.env, &environmentFixture{admission: f.admitted, session: cold}, ReplacementTargetRecipient, 0, 1, ReplacementMaterialAuthority, true)
				cold = checkOccupiedRecipientReplacement(t, ctx, h, cold)
				coldCallbacks := installedGeneratedRetirementCallbacks(t, f, process)
				coldCallbacks.AdmitProducer = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedProducerInput, contract.GeneratorImplementation, time.Time) (*InstalledGeneratedProducerCustody, error) {
					return nil, contract.ErrRecord
				}
				continued := installedGeneratedRetirementEngine(t, ctx, f, cold, coldCallbacks)
				beforeCAS := store.cas
				got = continued.Continue(ctx, testID("cold anchored preparation refusal"), got.OperationID)
				continued.Close()
				if got.Result.Outcome != AdmissionRefused || !got.Result.RequestedRevision.IsZero() || store.cas != beforeCAS {
					t.Fatal("cold refusal claimed an earlier invocation CAS", got.Result)
				}
			} else if stop == "contention" {
				if got.Result.Outcome != Contention || got.Result.RequestedRevision.IsZero() || got.Result.ObservedRevision != anchor || store.cas != casAtAnchor+1 {
					t.Fatal("later actual contention lost its own result", got.Result)
				}
			} else if got.Result.Outcome != UnresolvedCommit || !got.Result.CommitMayHaveOccurred || got.Result.RequestedRevision.IsZero() || failedReads == 0 || store.cas != casAtAnchor+1 {
				t.Fatal("later actual unknown lost uncertainty", got.Result, failedReads)
			}
			wantState := map[string]string{"contention": "contention", "unknown": "commit-outcome-unknown", "cold-refusal": "refused"}[stop]
			g := got.Generated
			if g == nil || g.StateResult != wantState || g.CanonicalOutcome != contract.ReceiptCanonicalSelected || !g.HasObservedCanonicalSelection(got.DomainID, got.OperationID, got.RequestIdentity) || got.Payload != nil || len(got.Receipt) != 0 {
				t.Fatal("later stop erased authenticated original apply selection", got.Result, g)
			}
			if g.HasObservedCanonicalSelection(testID("different domain"), got.OperationID, got.RequestIdentity) || g.HasObservedCanonicalSelection(got.DomainID, testID("different operation"), got.RequestIdentity) || g.HasObservedCanonicalSelection(got.DomainID, got.OperationID, testID("different request")) {
				t.Fatal("selection proof crossed identity")
			}
			creates, deletes := effects()
			if creates != 2 || len(deletes) != 0 {
				t.Fatal("stop restored provider authority", creates, deletes)
			}
		})
	}
}
