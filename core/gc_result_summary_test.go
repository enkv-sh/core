package core

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGCTargetEffectSummaryUsesEntryEvidence(t *testing.T) {
	for _, name := range []string{"unused-unknown-observation", "own-unentered", "restart-spent", "selected-not-sent", "changed-unused", "precondition", "access-not-sent", "ack-present", "precondition-then-absence"} {
		t.Run(name, func(t *testing.T) {
			out := gcUnenteredResultFixture(t)
			row := &out.Payload.Targets[0]
			wantToken, wantState := "not-started", "effect-pending"
			switch name {
			case "unused-unknown-observation":
				row.Selected.Consumed = 0
				row.PermissionOwned = false
				row.Observed, row.ObservationReason = contract.GCTargetUnknown, contract.ReasonMalformed
			case "own-unentered":
				wantToken = "prepared"
			case "restart-spent":
				row.PermissionOwned = false
				wantToken, wantState = "unknown", "effect-unknown"
			case "selected-not-sent":
				row.PermissionOwned = false
				row.Selected.Disposition = contract.GCTargetRetryableNotSent
				row.Selected.EvidenceDigest = gcTestID("selected-no-entry")
			case "changed-unused":
				row.PermissionOwned = false
				row.Selected.Consumed = 0
				row.Selected.Disposition = contract.GCTargetChanged
				row.Observed, row.ObservationReason = contract.GCTargetChanged, contract.ReasonCondition
			case "precondition", "precondition-then-absence":
				row.DeleteAttempted = true
				row.DeleteResult = contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
				wantToken, wantState = "confirmed-no-effect", "unavailable"
				if name == "precondition-then-absence" {
					row.Observed = contract.GCTargetAbsent
					row.ObservedEvidence = gcTestID("local-absence-after-condition")
				}
			case "access-not-sent":
				row.DeleteAttempted = true
				row.DeleteResult = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonAccess, NotSent: true}
			case "ack-present":
				row.DeleteAttempted = true
				row.DeleteResult = contract.WriteResult{Status: contract.WriteAcknowledged}
				row.Observed = contract.GCTargetPending
				wantToken, wantState = "unknown", "effect-unknown"
			}
			token, err := GCTargetEffectToken(*row)
			if err != nil || token != wantToken {
				t.Fatal("effect token does not preserve actual entry evidence", token, wantToken, err)
			}
			if err := RefreshGCResult(&out); err != nil || out.StateResult != wantState {
				t.Fatal("target observation changed provider-call summary", out.StateResult, wantState, err)
			}
			if err := out.Validate(); err != nil {
				t.Fatal("valid effect-evidence control rejected", err)
			}
		})
	}
}

// full_only: false
func TestGCResultSummaryKeepsCloseAndCommitFactsSeparate(t *testing.T) {
	for _, name := range []string{"complete-known-close-failure", "pending-unresolved-close", "unknown-unresolved-close", "initial-unresolved-select", "confirmed-partial-close"} {
		t.Run(name, func(t *testing.T) {
			out := gcUnenteredResultFixture(t)
			row := &out.Payload.Targets[0]
			want := "effect-pending"
			switch name {
			case "complete-known-close-failure":
				row.Selected = contract.GCTargetProgress{Consumed: 1, Disposition: contract.GCTargetAbsent, EvidenceDigest: gcTestID("complete-before-close")}
				row.PermissionOwned = false
				out.Payload.RemainingCount = 0
				want = "unavailable"
			case "pending-unresolved-close", "unknown-unresolved-close":
				out.Result = Result{Outcome: UnresolvedCommit, Reason: WriteUncertain, RequestedRevision: gcTestID("unresolved-close"), CommitMayHaveOccurred: true, StoreReason: contract.ReasonTransport}
				out.Payload.SelectionUncertain = true
				if name == "unknown-unresolved-close" {
					row.PermissionOwned = false
					want = "effect-unknown"
				}
			case "initial-unresolved-select":
				out.Result = Result{Outcome: UnresolvedCommit, Reason: WriteUncertain, RequestedRevision: gcTestID("unresolved-select"), CommitMayHaveOccurred: true, StoreReason: contract.ReasonTransport}
				out.Payload.ProgressOrdinal = 0
				out.Payload.Active = false
				out.Payload.SelectionUncertain = true
				row.Selected.Consumed = 0
				row.PermissionOwned = false
				want = "commit-outcome-unknown"
			case "confirmed-partial-close":
				out.Result = Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure, RequestedRevision: out.Payload.Observation.HeadRevisionID, ObservedRevision: out.Payload.Observation.HeadRevisionID, ObservedSnapshotID: out.Payload.Observation.SnapshotID}
				out.Payload.Active, out.Payload.Closed = false, true
				want = "gc-partial-garbage"
			}
			original := out.Result
			if err := RefreshGCResult(&out); err != nil || out.StateResult != want || out.Result != original {
				t.Fatal("effect summary lost actual close/commit evidence", out.StateResult, want, out.Result, original, err)
			}
			if err := out.Validate(); err != nil {
				t.Fatal("valid close-summary control rejected", err)
			}
		})
	}
}

// full_only: false
func TestGCResultSummaryPreservesAdmissionCommitUncertainty(t *testing.T) {
	for _, name := range []string{"initial-select", "retained-reacquire", "pending-reserve", "partial-progress", "unknown-progress", "complete-close", "initial-capacity", "initial-integrity", "initial-root-loss", "pre-effect-refusal"} {
		t.Run(name, func(t *testing.T) {
			out := gcUnenteredResultFixture(t)
			out.Result = Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid, RequestedRevision: gcTestID("unresolved-phase"), CommitMayHaveOccurred: true}
			out.Payload.SelectionUncertain = true
			row := &out.Payload.Targets[0]
			want, phase := "effect-pending", contract.GCReserve
			switch name {
			case "initial-select", "initial-capacity", "initial-integrity", "initial-root-loss", "pre-effect-refusal":
				phase = contract.GCSelect
				out.Payload.ProgressOrdinal, out.Payload.Active = 0, false
				row.Selected.Consumed, row.PermissionOwned = 0, false
				want = "commit-outcome-unknown"
				switch name {
				case "initial-capacity":
					out.Result.Reason = CapacityExceeded
				case "initial-integrity":
					out.Result.Outcome, out.Result.Reason, want = IntegrityFailure, InvalidFormat, "positive-defect"
				case "initial-root-loss":
					out.Result.Outcome, out.Result.Reason, want = RootLossUnsupported, MissingSelectedObject, "root-loss-unsupported"
				case "pre-effect-refusal":
					out.Result.CommitMayHaveOccurred, out.Payload.SelectionUncertain, want = false, false, "refused"
				}
			case "retained-reacquire":
				phase = contract.GCReacquire
				out.Payload.Active = false
				row.Selected.Consumed, row.PermissionOwned = 0, false
			case "partial-progress":
				phase, want = contract.GCRecordProgress, "effect-partial"
				complete := *row
				complete.Object.ObjectID[0] ^= 1
				complete.Selected = contract.GCTargetProgress{Consumed: 1, Disposition: contract.GCTargetAbsent, EvidenceDigest: gcTestID("complete-sibling")}
				complete.PermissionOwned = false
				out.Payload.Targets = append(out.Payload.Targets, complete)
				if bytes.Compare(out.Payload.Targets[0].Object.ObjectID[:], out.Payload.Targets[1].Object.ObjectID[:]) > 0 {
					out.Payload.Targets[0], out.Payload.Targets[1] = out.Payload.Targets[1], out.Payload.Targets[0]
				}
				out.Payload.Candidates = nil
				for i, target := range out.Payload.Targets {
					out.Payload.Candidates = append(out.Payload.Candidates, contract.GCCandidate{KeyDigest: target.Digest, Classification: contract.GCCandidateEligible, TargetIndex: uint16(i)})
				}
				var targets []contract.GCTarget
				for _, target := range out.Payload.Targets {
					targets = append(targets, contract.GCTarget{Object: target.Object, Length: target.Length, Digest: target.Digest, Token: contract.Token{Family: contract.GCP, Value: "1"}})
				}
				var err error
				out.Payload.TargetsDescriptor, err = contract.GCTargetsDescriptor(targets)
				if err != nil {
					t.Fatal(err)
				}
			case "unknown-progress":
				phase, want = contract.GCRecordProgress, "effect-unknown"
				row.PermissionOwned = false
			case "complete-close":
				phase, want = contract.GCClose, "commit-outcome-unknown"
				row.Selected = contract.GCTargetProgress{Consumed: 1, Disposition: contract.GCTargetAbsent, EvidenceDigest: gcTestID("complete-before-admission-loss")}
				row.PermissionOwned = false
				out.Payload.RemainingCount = 0
			}
			original := out.Result
			failure := GCPhaseFailure{Phase: phase, Result: original, Write: contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}}
			out.Payload.Failures = []GCPhaseFailure{failure}
			if err := RefreshGCResult(&out); err != nil || out.StateResult != want || out.Result != original || out.Validate() != nil || len(out.Payload.Failures) != 1 || out.Payload.Failures[0] != failure {
				t.Error("public state lost the underlying phase cause or uncertainty", out.StateResult, want, out.Result, original, err)
			}
		})
	}
}
