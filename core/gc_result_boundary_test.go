package core

import (
	"fmt"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func gcUnenteredResultFixture(t *testing.T) PublicGCResult {
	t.Helper()
	out := gcSuccessfulResultFixture(t)
	out.Result = failure(EvidenceUnavailable, ReadUnavailable)
	out.Payload.Closed = false
	out.Payload.Active = true
	out.Payload.RemainingCount = 1
	row := &out.Payload.Targets[0]
	row.Selected = contract.GCTargetProgress{Consumed: 1, Disposition: contract.GCTargetPending}
	row.Observed = 0
	row.ObservationReason = contract.ReasonNone
	row.ObservedEvidence = contract.ID{}
	row.DeleteAttempted = false
	row.DeleteResult = contract.WriteResult{}
	row.PermissionOwned = true
	if err := RefreshGCResult(&out); err != nil {
		t.Fatal("valid unentered result fixture", err)
	}
	return out
}

// full_only: false
func TestGCTargetObservationResultRejectsUnqualifiedTuples(t *testing.T) {
	for _, name := range []string{"none-reason", "pending-reason", "unknown-no-reason", "changed-no-condition", "observed-terminal", "owned-unknown-without-call", "owned-retry-without-call", "owned-terminal-without-call"} {
		t.Run(name, func(t *testing.T) {
			out := gcUnenteredResultFixture(t)
			row := &out.Payload.Targets[0]
			switch name {
			case "none-reason":
				row.ObservationReason = contract.ReasonAccess
			case "pending-reason":
				row.Observed = contract.GCTargetPending
				row.ObservationReason = contract.ReasonTransport
			case "unknown-no-reason":
				row.Observed = contract.GCTargetUnknown
			case "changed-no-condition":
				row.Observed = contract.GCTargetChanged
			case "observed-terminal":
				row.Observed = contract.GCTargetTerminalFailure
				row.ObservationReason = contract.ReasonAccess
			case "owned-unknown-without-call":
				row.Selected.Disposition = contract.GCTargetUnknown
			case "owned-retry-without-call":
				row.Selected.Disposition = contract.GCTargetRetryableNotSent
				row.Selected.EvidenceDigest = gcTestID("unconsumed-owned-witness")
			case "owned-terminal-without-call":
				row.Selected.Disposition = contract.GCTargetTerminalFailure
			}
			if _, err := GCTargetEffectToken(*row); err == nil {
				t.Error("unqualified observation/permission tuple became an effect token", name)
			}
			if _, err := GCSiblingResults(out); err == nil {
				t.Error("unqualified tuple passed structural sibling validation", name)
			}
		})
	}
}

// full_only: false
func TestGCCoreResultFactsRemainClosed(t *testing.T) {
	for _, name := range []string{"unresolved-no-flag", "unresolved-no-requested", "possible-no-requested", "possible-observed", "possible-contention", "possible-unavailable", "possible-invalid-status", "authenticated-no-observation", "observed-no-evidence", "observed-different-requested", "observed-reason", "observed-store-reason", "unchanged-phase"} {
		t.Run(name, func(t *testing.T) {
			out := gcSuccessfulResultFixture(t)
			result := Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure, RequestedRevision: contract.ID{1}, ObservedRevision: contract.ID{1}, ObservedSnapshotID: contract.ID{2}}
			switch name {
			case "unresolved-no-flag":
				result = Result{Outcome: UnresolvedCommit, Reason: WriteUncertain, RequestedRevision: contract.ID{1}}
			case "unresolved-no-requested":
				result = Result{Outcome: UnresolvedCommit, Reason: WriteUncertain, CommitMayHaveOccurred: true}
			case "possible-no-requested":
				result = Result{Outcome: IntegrityFailure, Reason: InvalidFormat, CommitMayHaveOccurred: true}
			case "possible-observed":
				result.CommitMayHaveOccurred = true
			case "possible-contention":
				result = Result{Outcome: Contention, Reason: StalePrecondition, RequestedRevision: contract.ID{1}, CommitMayHaveOccurred: true}
			case "possible-unavailable":
				result = Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, RequestedRevision: contract.ID{1}, CommitMayHaveOccurred: true}
			case "possible-invalid-status":
				result = Result{Outcome: 255, Reason: InvalidFormat, RequestedRevision: contract.ID{1}, CommitMayHaveOccurred: true}
			case "authenticated-no-observation":
				result = Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, Evidence: AuthenticatedClosure}
			case "observed-no-evidence":
				result.Evidence = NoEvidence
			case "observed-different-requested":
				result.RequestedRevision = contract.ID{3}
			case "observed-reason":
				result.Reason = InvalidProof
			case "observed-store-reason":
				result.StoreReason = contract.ReasonTransport
			case "unchanged-phase":
				result = Result{Outcome: Unchanged, Evidence: AuthenticatedClosure, ObservedRevision: contract.ID{1}, ObservedSnapshotID: contract.ID{2}}
			}
			out.Payload.Failures = []GCPhaseFailure{{Phase: contract.GCReserve, Result: result, Write: contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}}}
			if _, err := GCSiblingResults(out); err == nil {
				t.Fatal("impossible phase result facts passed structural validation", name)
			}
		})
	}
	for _, position := range []string{"top-level", "phase-failure"} {
		for _, outcome := range []Outcome{IntegrityFailure, RootLossUnsupported, AdmissionRefused} {
			t.Run(fmt.Sprintf("%s/possible-commit-with-outcome-%d", position, outcome), func(t *testing.T) {
				out := gcUnenteredResultFixture(t)
				result := Result{Outcome: outcome, Reason: InvalidFormat, RequestedRevision: contract.ID{1}, CommitMayHaveOccurred: true}
				out.Payload.SelectionUncertain = true
				if position == "top-level" {
					out.Result = result
				} else {
					out.Payload.Failures = []GCPhaseFailure{{Phase: contract.GCReserve, Result: result, Write: contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}}}
				}
				if err := RefreshGCResult(&out); err != nil {
					t.Fatal("stronger readback failure cannot carry earlier possible commit", err, result)
				}
				if err := out.Validate(); err != nil {
					t.Fatal("possible commit rejected by public validation", err, out)
				}
				if got, err := GCSiblingResults(out); err != nil || got != out.Payload.SiblingResults {
					t.Fatal("possible commit lost its public sibling commitment", got, err)
				}
				if position == "top-level" && out.Result != result || position == "phase-failure" && out.Payload.Failures[0].Result != result {
					t.Fatal("public derivation changed actual possible-commit facts", out)
				}
				if position == "top-level" {
					out.Result.RequestedRevision = contract.ID{}
				} else {
					out.Payload.Failures[0].Result.RequestedRevision = contract.ID{}
				}
				if err := RefreshGCResult(&out); err == nil {
					t.Fatal("possible commit without requested revision passed public admission", out)
				}
			})
		}
	}
	for _, result := range []Result{{Outcome: UnresolvedCommit, Reason: WriteUncertain}, {Outcome: EvidenceUnavailable, Reason: ReadUnavailable, Evidence: AuthenticatedClosure}} {
		out := PublicGCResult{Operation: GCApplyOperation, RequestID: gcTestID("unbound-closed-facts"), Result: result, StateResult: gcStateResult(result)}
		if gcValidateResult(out) == nil {
			t.Error("impossible unbound result passed closed validation", result)
		}
	}
}

// full_only: false
func TestGCMalformedReadResultsRemainRenderable(t *testing.T) {
	for _, boundary := range []string{"public preflight", "selected reserve readback"} {
		t.Run(boundary, func(t *testing.T) {
			state, store, input, plan, encoded := gcExecutionFixture(t)
			ctx := gcReadContext(t)
			armed := false
			key := gcObjectTestKey(t, store.Descriptor(), state.root.Domain, plan.Targets[0].Object)
			store.onRead = func(actual string) *contract.ReadResult {
				if boundary == "public preflight" && actual == key || boundary == "selected reserve readback" && armed && actual == store.descriptor.HeadKey {
					return &contract.ReadResult{Status: contract.ReadUnavailable, Reason: 255}
				}
				return nil
			}
			if boundary == "selected reserve readback" {
				store.onCAS = func(phase contract.GCPhase, body []byte) *contract.WriteResult {
					if phase != contract.GCReserve {
						return nil
					}
					head, err := format.DecodeHead(body)
					if err != nil {
						t.Fatal(err)
					}
					store.gcPublicFixtureStore.CompareAndSwap(ctx, store.descriptor.HeadKey, head.Core.PreviousToken, body)
					armed = true
					return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
				}
			}
			engine, _ := gcExecutionEngine(t, state, store, input)
			out := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("malformed-read-result"), EncodedPlan: encoded})
			if out.Result.StoreReason != contract.ReasonMalformed || len(store.deletes) != 0 {
				t.Error("malformed read escaped safe Store result owner", boundary, out.Result, store.deletes)
			}
			if boundary == "selected reserve readback" && (out.Result.Outcome != UnresolvedCommit || !out.Result.CommitMayHaveOccurred || out.Result.RequestedRevision.IsZero() || out.Payload == nil || len(out.Payload.Failures) != 1) {
				t.Error("malformed readback lost possible commit facts", out)
			}
			if err := out.Validate(); err != nil {
				t.Error("malformed read made actual operation result unrenderable", err, out)
			}
		})
	}
	for _, phase := range []contract.GCPhase{contract.GCReserve, contract.GCRecordProgress, contract.GCClose} {
		for _, readback := range []string{"malformed-head", "missing-head", "unavailable"} {
			t.Run(fmt.Sprintf("phase-%d/%s", phase, readback), func(t *testing.T) {
				state, store, input, plan, encoded := gcExecutionFixture(t)
				ctx := gcReadContext(t)
				var requested contract.ID
				store.onCAS = func(actual contract.GCPhase, body []byte) *contract.WriteResult {
					if actual != phase {
						return nil
					}
					head, err := format.DecodeHead(body)
					if err != nil {
						t.Fatal(err)
					}
					requested = head.Core.Revision
					if got := store.gcPublicFixtureStore.CompareAndSwap(ctx, store.descriptor.HeadKey, head.Core.PreviousToken, body); got.Status != contract.WriteAcknowledged {
						t.Fatal("fixture phase did not commit", got)
					}
					store.onRead = func(key string) *contract.ReadResult {
						if key != store.descriptor.HeadKey {
							return nil
						}
						switch readback {
						case "malformed-head":
							return &contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
						case "missing-head":
							return &contract.ReadResult{Status: contract.ReadMissing}
						default:
							return &contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
						}
					}
					return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
				}
				engine, _ := gcExecutionEngine(t, state, store, input)
				out := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("phase-observation-failure"), EncodedPlan: encoded})
				wantOutcome := UnresolvedCommit
				switch readback {
				case "malformed-head":
					wantOutcome = IntegrityFailure
				case "missing-head":
					wantOutcome = RootLossUnsupported
				}
				if requested.IsZero() || out.Result.Outcome != wantOutcome || !out.Result.CommitMayHaveOccurred || out.Result.RequestedRevision != requested {
					t.Error("public result lost exact uncertain phase or stronger readback failure", out)
				}
				if out.Payload == nil || len(out.Payload.Failures) != 1 {
					t.Fatal("uncertain phase lost its failure and last selected progress", out)
				}
				failure := out.Payload.Failures[0]
				if failure.Phase != phase || failure.Result != out.Result || failure.Write != (contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}) || !out.Payload.SelectionUncertain || !out.Payload.Active || out.Payload.Closed {
					t.Error("unconfirmed phase changed active ownership or failure facts", out)
				}
				wantOrdinal, wantConsumed, wantRemaining := uint32(1), uint8(0), uint16(1)
				wantDisposition, wantDeletes := contract.GCTargetPending, 0
				if phase != contract.GCReserve {
					wantOrdinal, wantConsumed, wantDeletes = 2, 1, 1
				}
				if phase == contract.GCClose {
					wantOrdinal, wantRemaining, wantDisposition = 3, 0, contract.GCTargetAbsent
				}
				row := out.Payload.Targets[0]
				if out.Payload.ProgressOrdinal != wantOrdinal || out.Payload.RemainingCount != wantRemaining || row.Selected.Consumed != wantConsumed || row.Selected.Disposition != wantDisposition || row.PermissionOwned != (wantDeletes == 1) {
					t.Error("unconfirmed phase replaced last selected counters or local permission", out.Payload)
				}
				if len(store.phases) != int(phase)-1 || len(store.deletes) != wantDeletes {
					t.Error("uncertain phase repeated CAS or dispatched without confirmed reserve", store.phases, store.deletes)
				}
				if wantDeletes == 1 {
					key := gcObjectTestKey(t, store.Descriptor(), state.root.Domain, plan.Targets[0].Object)
					if store.deletes[0] != (gcDeleteCall{key, plan.Targets[0].Token}) {
						t.Error("uncertainty changed original deletion condition", store.deletes)
					}
				}
				if err := out.Validate(); err != nil {
					t.Error("possible commit with readback failure became unrenderable", err, out)
				}
			})
		}
	}
}

// full_only: false
func TestUnavailableStoreReadRejectsUnknownEnumFacts(t *testing.T) {
	for _, status := range []contract.ReadStatus{0, contract.ReadOK, contract.ReadMissing, contract.ReadUnavailable, contract.ReadInvalid, 255} {
		for _, reason := range []contract.Reason{contract.ReasonNone, contract.ReasonAccess, contract.ReasonTransport, contract.ReasonMalformed, contract.ReasonCondition, contract.ReasonConstruction, contract.ReasonLimit, contract.ReasonProof, 255} {
			t.Run(fmt.Sprintf("status-%d/reason-%d", status, reason), func(t *testing.T) {
				want := reason
				if status == 0 || status == 255 || reason == 255 || status == contract.ReadUnavailable && reason == contract.ReasonNone {
					want = contract.ReasonMalformed
				}
				result := unavailableStoreRead(contract.ReadResult{Status: status, Reason: reason})
				if result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable || result.StoreReason != want {
					t.Fatal("safe unavailable classification changed or retained invalid enum", result, want)
				}
			})
		}
	}
}
