package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestGCMutationAdmissionHEADReadPreservesFailureFacts(t *testing.T) {
	for _, route := range []string{"apply", "continue"} {
		t.Run(route, func(t *testing.T) {
			for _, observation := range []string{"unavailable", "missing", "invalid", "unknown-status", "unavailable-no-reason", "invalid-token", "empty-body", "oversized-body", "reason", "wrong-family", "different-valid-head"} {
				t.Run(observation, func(t *testing.T) {
					state, store, input, plan, encoded := gcExecutionFixture(t)
					ctx := gcReadContext(t)
					progress, err := gcInitialProgress(plan)
					if err != nil {
						t.Fatal(err)
					}
					if route == "continue" {
						state, progress = gcRuntimeSelectOnly(t, ctx, state, input, plan, encoded)
					}
					var alternate *Candidate
					if observation == "different-valid-head" || observation == "invalid-token" {
						phase := contract.GCSelect
						if route == "continue" {
							phase = contract.GCReserve
							progress.Ordinal++
							progress.Targets[0].Consumed = 1
						}
						var result Result
						alternate, result = state.prepareGCPhase(ctx, plan, gcTestID("alternate-head-admission"), phase, &progress)
						if alternate == nil {
							t.Fatal("prepare authentic alternate HEAD", result)
						}
						alternate, result = state.persistCandidate(ctx, alternate, testtrust.New(t, contract.GCP, state.admission.trust))
						if alternate == nil {
							t.Fatal("persist authentic alternate HEAD", result)
						}
					}
					want := Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonAccess}
					wantState := "unavailable"
					read := contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
					switch observation {
					case "missing":
						read = contract.ReadResult{Status: contract.ReadMissing}
						want = Result{Outcome: RootLossUnsupported, Reason: MissingSelectedObject}
						wantState = "root-loss-unsupported"
					case "invalid":
						read = contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
						want = Result{Outcome: IntegrityFailure, Reason: InvalidFormat}
						wantState = "positive-defect"
					case "unknown-status":
						read = contract.ReadResult{Status: 255, Reason: contract.ReasonAccess}
						want.StoreReason = contract.ReasonMalformed
					case "unavailable-no-reason":
						read = contract.ReadResult{Status: contract.ReadUnavailable}
						want.StoreReason = contract.ReasonMalformed
					case "invalid-token", "empty-body", "oversized-body", "reason", "wrong-family":
						read = contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(state.body), Token: state.token}
						want = Result{Outcome: IntegrityFailure, Reason: InvalidFormat}
						wantState = "positive-defect"
						switch observation {
						case "invalid-token":
							read.Body, read.Token = bytes.Clone(alternate.body), contract.Token{}
						case "empty-body":
							read.Body = nil
						case "oversized-body":
							read.Body = make([]byte, contract.MaxHeadLength+1)
						case "reason":
							read.Reason = contract.ReasonAccess
						case "wrong-family":
							read.Token.Family = contract.AWS
						}
					case "different-valid-head":
						want = Result{Outcome: Contention, Reason: DifferentSelection}
						wantState = "contention"
					}
					key := gcObjectTestKey(t, store.Descriptor(), state.root.Domain, plan.Targets[0].Object)
					observationBasis := PublicObservation{DomainID: state.root.Domain, HeadRevisionID: state.head.Core.Revision, SnapshotID: state.root.Snapshot, RootDigest: state.head.Core.Root.Digest}
					phases := len(store.phases)
					var headReads, targetReads, factories, resourcesClosed, readerClosed int
					input.CloseInstalled = func() { readerClosed++ }
					reader, err := NewInstalledCapacityReader(input)
					if err != nil {
						t.Fatal(err)
					}
					signer := testtrust.New(t, contract.GCP, state.admission.trust)
					engine, err := NewInstalledGC(GCInstallation{Reader: reader, CompositionID: state.admission.composition, ConstructMutation: func(context.Context) (GCMutationResources, error) {
						factories++
						if observation == "different-valid-head" {
							written := store.gcPublicFixtureStore.CompareAndSwap(ctx, store.descriptor.HeadKey, state.token, alternate.body)
							if written.Status != contract.WriteAcknowledged {
								t.Fatal("select authentic alternate HEAD", written)
							}
						} else {
							store.onRead = func(actual string) *contract.ReadResult {
								if actual == store.descriptor.HeadKey {
									return &read
								}
								return nil
							}
						}
						headReads, targetReads = store.reads[store.descriptor.HeadKey], store.reads[key]
						return GCMutationResources{Store: store, Trust: signer, Close: func() error { resourcesClosed++; return nil }}, nil
					}})
					if err != nil {
						t.Fatal(err)
					}
					nonce := gcTestID("mutation-admission-observation")
					var out PublicGCResult
					if route == "apply" {
						out = engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: nonce, EncodedPlan: encoded})
					} else {
						out = engine.Continue(ctx, GCContinueRequest{RequestNonce: nonce, OperationID: plan.OperationID})
					}
					if err := engine.Close(); err != nil || resourcesClosed != 1 || readerClosed != 1 {
						t.Error("mutation admission did not close both installed owners", err, resourcesClosed, readerClosed)
					}
					ordinal := uint32(0)
					if route == "continue" {
						wantState, ordinal = "effect-pending", 1
					}
					if out.Result != want || out.StateResult != wantState {
						t.Error("mutation HEAD observation lost its exact failure facts", out.Result, want, out.StateResult, wantState)
					}
					planDigest, err := contract.GCPlanDigest(plan)
					if err != nil {
						t.Fatal(err)
					}
					identity, err := contract.GCPlanRequestIdentity(plan)
					if err != nil {
						t.Fatal(err)
					}
					targets, err := contract.GCTargetsDescriptor(plan.Targets)
					if err != nil {
						t.Fatal(err)
					}
					p := out.Payload
					if out.RequestID != nonce || out.OperationID != plan.OperationID || out.DomainID != plan.DomainID || out.RequestIdentity != identity || p == nil || p.RequestIdentity != identity || p.PlanDigest != planDigest || p.TargetsDescriptor != targets || p.MarkDigest != plan.MarkDigest || p.EnumerationDigest != plan.EnumerationDigest || p.Observation != observationBasis || p.ProgressOrdinal != ordinal || p.RemainingCount != uint16(len(plan.Targets)) || p.Active != (route == "continue") || p.Closed || p.SelectionUncertain || len(p.Failures) != 0 || !reflect.DeepEqual(p.Candidates, plan.Candidates) || len(p.Targets) != 1 || p.Targets[0].Object != plan.Targets[0].Object || p.Targets[0].Digest != plan.Targets[0].Digest || p.Targets[0].Length != plan.Targets[0].Length || p.Targets[0].Selected != (contract.GCTargetProgress{Disposition: contract.GCTargetPending}) || p.Targets[0].Observed != 0 || p.Targets[0].PermissionOwned || p.Targets[0].DeleteAttempted {
						t.Error("mutation admission failure rewrote admitted plan or retained progress", out)
					}
					if factories != 1 || signer.Calls() != 0 || engine.guard == nil || engine.guard.creates != 0 || engine.guard.cas != 0 || engine.guard.deletes != 0 || len(store.phases) != phases || len(store.deletes) != 0 || store.reads[store.descriptor.HeadKey]-headReads != 1 || store.reads[key] != targetReads {
						t.Error("HEAD classification entered effects or repeated target/HEAD reads", factories, signer.Calls(), store.phases, store.deletes, store.reads[store.descriptor.HeadKey]-headReads, store.reads[key]-targetReads)
					}
					if err := out.Validate(); err != nil {
						t.Fatal("mutation admission failure became unrenderable", err)
					}
				})
			}
		})
	}
}
