package compositionfull

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// This is a structural result-width fixture accepted by the public owner. It
// does not claim a historical operation with all these maximum-width facts.
func gcResultEncodingFixture(t *testing.T, count int) GCApplyResult {
	t.Helper()
	id := func(s string) contract.ID { return contract.Hash([]byte("GC rendering/" + s)) }
	plan := id("plan")
	request := contract.Hash(append([]byte("ENKV/GC-REQUEST/v1\x00"), plan[:]...))
	obs := core.PublicObservation{DomainID: id("domain"), HeadRevisionID: id("head"), SnapshotID: id("snapshot"), RootDigest: id("root")}
	p := &core.GCCleanupPayload{PlanDigest: plan, RequestIdentity: request, MarkDigest: id("mark"), EnumerationDigest: id("enumeration"), Observation: obs, Closed: true, ProgressOrdinal: math.MaxUint32}
	targets := make([]contract.GCTarget, count)
	for i := range targets {
		var object contract.ID
		binary.BigEndian.PutUint16(object[30:], uint16(i+1))
		x := contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RootKind, ObjectID: object}
		targets[i] = contract.GCTarget{Object: x, Length: contract.StoreObjectLimit(x), Digest: id(fmt.Sprint("bytes/", i)), Token: contract.Token{Family: contract.AWS, Value: `"` + strings.Repeat("p", 254) + `"`}}
		p.Targets = append(p.Targets, core.GCTargetResult{Object: x, Length: targets[i].Length, Digest: targets[i].Digest, Selected: contract.GCTargetProgress{Consumed: 3, Disposition: contract.GCTargetAbsent, EvidenceDigest: id(fmt.Sprint("selected/", i))}, Observed: contract.GCTargetAbsent, ObservedEvidence: id(fmt.Sprint("observed/", i)), PermissionOwned: true, DeleteAttempted: true, DeleteResult: contract.WriteResult{Status: contract.WriteAcknowledged}})
		p.Candidates = append(p.Candidates, contract.GCCandidate{KeyDigest: id(fmt.Sprint("key/", i)), Classification: contract.GCCandidateEligible, TargetIndex: uint16(i), ListedLength: math.MaxUint64})
	}
	var err error
	p.TargetsDescriptor, err = contract.GCTargetsDescriptor(targets)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []contract.GCPhase{contract.GCSelect, contract.GCReserve, contract.GCRecordProgress, contract.GCClose} {
		p.Failures = append(p.Failures, core.GCPhaseFailure{Phase: phase, Result: core.Result{Outcome: core.UnresolvedCommit, Reason: core.WriteUncertain, StoreReason: contract.ReasonTransport, CommitMayHaveOccurred: true, RequestedRevision: id(fmt.Sprint("requested/", phase)), ObservedRevision: id(fmt.Sprint("observed/", phase)), ObservedSnapshotID: id(fmt.Sprint("snapshot/", phase))}, Write: contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}})
	}
	r := core.PublicGCResult{Operation: core.GCApplyOperation, RequestID: id("nonce"), OperationID: id("operation"), RequestIdentity: request, DomainID: obs.DomainID, Result: core.Result{Outcome: core.ObservedCurrent, RequestedRevision: obs.HeadRevisionID, ObservedRevision: obs.HeadRevisionID, ObservedSnapshotID: obs.SnapshotID, Evidence: core.AuthenticatedClosure}, Payload: p}
	if err := core.RefreshGCResult(&r); err != nil {
		t.Fatal("public result fixture", err)
	}
	return GCApplyResult{Operation: r}
}

// full_only: false
func TestGCResultMaximumJSONAndYAMLEnvelopePreserveAllOwnedRows(t *testing.T) {
	r := gcResultEncodingFixture(t, 256)
	if gcCompactResultLimit != 671744+2048 || MaxGCResultJSONBytes != 67*(671744+2048) {
		t.Fatal("output envelope differs from independent fixed-field budget")
	}
	var jsonBody, human bytes.Buffer
	if err := WriteGCApplyJSON(t.Context(), &jsonBody, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteGCApplyHuman(t.Context(), &human, r); err != nil {
		t.Fatal(err)
	}
	if uint64(jsonBody.Len()) > MaxGCResultJSONBytes || uint64(human.Len()) > gcCompactResultLimit {
		t.Fatal("complete maximum output exceeds finite account")
	}
	if !strings.HasPrefix(human.String(), "gc-apply: success\n") || !strings.Contains(human.String(), "Deletion: 256 succeeded, 0 failed, 0 pending, 0 unknown.\n") || strings.Count(human.String(), "Target ") != 256 || strings.Count(human.String(), ": unresolved_commit / write_uncertain (store: transport);") != 4 || strings.Contains(human.String(), `"schema"`) {
		t.Fatal("maximum human result lost target outcomes or historical phase failures")
	}
	type resultFacts struct {
		Outcome   core.Outcome
		Reason    core.Reason
		Store     contract.Reason `json:"store_reason"`
		Requested string          `json:"requested_revision_id"`
		Observed  string          `json:"observed_revision_id"`
		Snapshot  string          `json:"observed_snapshot_id"`
		Evidence  core.Evidence
		Commit    bool `json:"commit_may_have_occurred"`
	}
	type writeFacts struct {
		Status  contract.WriteStatus
		Reason  contract.Reason
		NotSent bool `json:"not_sent"`
	}
	var got struct {
		State    string `json:"state_result"`
		Effect   string `json:"effect_summary"`
		Evidence string `json:"evidence_ceiling"`
		Result   resultFacts
		Counts   struct{ Success, Failure, Pending, Unknown uint32 } `json:"summary_counts"`
		Payload  struct {
			Sibling struct {
				Count  uint32
				Digest string `json:"root_digest"`
			} `json:"sibling_results"`
			Targets []struct {
				Object   string `json:"object_id"`
				Length   uint32
				Digest   string
				Selected struct {
					Consumed    uint8
					Disposition contract.GCTargetDisposition
					Evidence    string `json:"evidence_digest"`
				}
				Observed         contract.GCTargetDisposition
				ObservedEvidence string          `json:"observed_evidence"`
				Reason           contract.Reason `json:"observation_reason"`
				Permission       bool            `json:"permission_owned"`
				Attempted        bool            `json:"delete_attempted"`
				Write            writeFacts      `json:"delete_result"`
				Effect           string
			}
			Candidates []struct {
				Key    string `json:"key_digest"`
				Class  string `json:"classification"`
				Index  uint16 `json:"target_index"`
				Length uint64 `json:"listed_length"`
			}
			Failures []struct {
				Phase  contract.GCPhase
				Result resultFacts
				Write  writeFacts
			}
		}
	}
	if json.Unmarshal(jsonBody.Bytes(), &got) != nil || got.State != "success" || got.Effect != "effect-complete" || got.Evidence != "provider-facts" || got.Counts.Success != 256 || got.Counts.Failure != 0 || got.Counts.Pending != 0 || got.Counts.Unknown != 0 || len(got.Payload.Targets) != 256 || len(got.Payload.Candidates) != 256 || len(got.Payload.Failures) != 4 {
		t.Fatal("maximum result lost complete vectors or Core axes")
	}
	if got.Result.Outcome != r.Operation.Result.Outcome || got.Result.Snapshot != readerID(r.Operation.Result.ObservedSnapshotID) || got.Payload.Sibling.Count != 256 || got.Payload.Sibling.Digest != readerID(r.Operation.Payload.SiblingResults.RootDigest) {
		t.Fatal("outer facts or sibling commitment changed")
	}
	for i, row := range got.Payload.Targets {
		want := r.Operation.Payload.Targets[i]
		if row.Object != readerID(want.Object.ObjectID) || row.Length != want.Length || row.Digest != readerID(want.Digest) || row.Selected.Consumed != 3 || row.Selected.Disposition != contract.GCTargetAbsent || row.Selected.Evidence != readerID(want.Selected.EvidenceDigest) || row.Observed != contract.GCTargetAbsent || row.ObservedEvidence != readerID(want.ObservedEvidence) || row.Reason != contract.ReasonNone || !row.Permission || !row.Attempted || row.Write.Status != contract.WriteAcknowledged || row.Write.Reason != contract.ReasonNone || row.Write.NotSent || row.Effect != "succeeded" {
			t.Fatal("target sibling row changed", i)
		}
		c := got.Payload.Candidates[i]
		wc := r.Operation.Payload.Candidates[i]
		if c.Key != readerID(wc.KeyDigest) || c.Class != "eligible" || c.Index != uint16(i) || c.Length != math.MaxUint64 {
			t.Fatal("candidate row changed", i)
		}
	}
	for i, f := range got.Payload.Failures {
		want := r.Operation.Payload.Failures[i]
		if f.Phase != want.Phase || f.Result.Outcome != want.Result.Outcome || f.Result.Reason != want.Result.Reason || f.Result.Store != want.Result.StoreReason || f.Result.Requested != readerID(want.Result.RequestedRevision) || f.Result.Observed != readerID(want.Result.ObservedRevision) || f.Result.Snapshot != readerID(want.Result.ObservedSnapshotID) || f.Result.Evidence != want.Result.Evidence || f.Result.Commit != want.Result.CommitMayHaveOccurred || f.Write.Status != want.Write.Status || f.Write.Reason != want.Write.Reason || f.Write.NotSent != want.Write.NotSent {
			t.Fatal("phase failure facts changed", i)
		}
	}
}

// full_only: false
func TestGCResultUsesCoreEffectTokensAndPreflightsEverySibling(t *testing.T) {
	t.Run("possible-commit-with-admission-failure", func(t *testing.T) {
		r := gcResultEncodingFixture(t, 1)
		requested := contract.ID{21}
		want := core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid, RequestedRevision: requested, CommitMayHaveOccurred: true}
		r.Operation.Result = want
		r.Operation.Payload.Active = true
		r.Operation.Payload.Closed = false
		r.Operation.Payload.SelectionUncertain = true
		r.Operation.Payload.Failures = nil
		if err := core.RefreshGCResult(&r.Operation); err != nil || r.Operation.Result != want {
			t.Fatal("public result lost possible commit at admission failure", err, r.Operation)
		}
		for _, human := range []bool{false, true} {
			var out bytes.Buffer
			var err error
			if human {
				err = WriteGCApplyHuman(t.Context(), &out, r)
			} else {
				err = WriteGCApplyJSON(t.Context(), &out, r)
			}
			if human {
				if err != nil || !strings.Contains(out.String(), "Result: admission_refused / admission_invalid; commit may have occurred.\n") || !strings.Contains(out.String(), fmt.Sprintf("Requested revision: %x.\n", requested[:])) {
					t.Fatal("human serializer lost admission failure's possible commit", err, out.String())
				}
			} else if err != nil {
				t.Fatal("public serializer lost admission failure's possible commit", human, err, out.String())
			}
			if !human {
				var decoded struct {
					Result struct {
						Outcome               core.Outcome `json:"outcome"`
						Reason                core.Reason  `json:"reason"`
						CommitMayHaveOccurred bool         `json:"commit_may_have_occurred"`
						Requested             string       `json:"requested_revision_id"`
					} `json:"result"`
				}
				if err := json.Unmarshal(out.Bytes(), &decoded); err != nil || decoded.Result.Outcome != core.AdmissionRefused || decoded.Result.Reason != core.AdmissionInvalid || !decoded.Result.CommitMayHaveOccurred || decoded.Result.Requested != fmt.Sprintf("%x", requested[:]) {
					t.Fatal("serialized top-level failure facts changed", err, decoded)
				}
			}
		}
	})
	for _, token := range []string{"prepared", "unknown", "failed-terminal", "confirmed-no-effect", "not-started"} {
		t.Run(token, func(t *testing.T) {
			r := gcResultEncodingFixture(t, 1)
			p := r.Operation.Payload
			p.Closed = false
			p.Active = true
			p.RemainingCount = 1
			r.Operation.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
			row := &p.Targets[0]
			row.Selected = contract.GCTargetProgress{Consumed: 1, Disposition: contract.GCTargetPending}
			row.Observed = 0
			row.ObservedEvidence = contract.ID{}
			row.DeleteAttempted = false
			row.DeleteResult = contract.WriteResult{}
			switch token {
			case "unknown":
				row.Selected.Disposition = contract.GCTargetUnknown
				row.DeleteAttempted = true
				row.DeleteResult = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
			case "failed-terminal":
				row.Selected.Disposition = contract.GCTargetTerminalFailure
				row.DeleteAttempted = true
				row.DeleteResult = contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
			case "confirmed-no-effect":
				row.Selected.Disposition = contract.GCTargetChanged
				row.Observed = contract.GCTargetChanged
				row.ObservationReason = contract.ReasonCondition
				row.DeleteAttempted = true
				row.DeleteResult = contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
			case "not-started":
				row.Selected.Disposition = contract.GCTargetRetryableNotSent
				row.Selected.EvidenceDigest = contract.Hash([]byte("not-sent evidence"))
				row.DeleteAttempted = true
				row.DeleteResult = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
			}
			if err := core.RefreshGCResult(&r.Operation); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			var decoded struct {
				Payload struct{ Targets []struct{ Effect string } }
			}
			if WriteGCApplyJSON(t.Context(), &out, r) != nil || json.Unmarshal(out.Bytes(), &decoded) != nil || len(decoded.Payload.Targets) != 1 || decoded.Payload.Targets[0].Effect != token {
				t.Fatal("renderer replaced Core effect token", token)
			}
		})
	}
	t.Run("bound-identity-without-payload", func(t *testing.T) {
		malformed := GCApplyResult{Operation: core.PublicGCResult{
			Operation: core.GCApplyOperation, RequestID: contract.ID{1}, OperationID: contract.ID{2},
			RequestIdentity: contract.ID{3}, DomainID: contract.ID{4},
			Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}, StateResult: "refused",
		}}
		for _, human := range []bool{false, true} {
			var out bytes.Buffer
			var err error
			if human {
				err = WriteGCApplyHuman(t.Context(), &out, malformed)
			} else {
				err = WriteGCApplyJSON(t.Context(), &out, malformed)
			}
			if err == nil || out.Len() != 0 {
				t.Errorf("bound identity without plan payload crossed renderer preflight: human=%t error=%v bytes=%d", human, err, out.Len())
			}
		}
	})
	r := gcResultEncodingFixture(t, 256)
	r.Operation.Payload.Targets[255].ObservedEvidence[0] ^= 1
	var out bytes.Buffer
	if WriteGCApplyJSON(t.Context(), &out, r) == nil || out.Len() != 0 {
		t.Fatal("last sibling damage crossed preflight")
	}
	valid := gcResultEncodingFixture(t, 256)
	for _, mode := range []string{"short", "failure", "cancel"} {
		ctx, cancel := context.WithCancel(t.Context())
		writer := &publicQueryDeliveryWriter{}
		switch mode {
		case "short":
			writer.short = true
		case "failure":
			writer.fail = errors.New("private-writer-sentinel")
		case "cancel":
			writer.cancel = cancel
		}
		if WriteGCApplyJSON(ctx, writer, valid) == nil {
			t.Fatal("result delivery failure swallowed", mode)
		}
		cancel()
	}
}

// full_only: false
func TestGCCommitUncertaintyPreservesStateCauseAndExit(t *testing.T) {
	type coreFacts struct {
		Outcome   core.Outcome    `json:"outcome"`
		Reason    core.Reason     `json:"reason"`
		Store     contract.Reason `json:"store_reason"`
		Requested string          `json:"requested_revision_id"`
		Observed  string          `json:"observed_revision_id"`
		Snapshot  string          `json:"observed_snapshot_id"`
		Evidence  core.Evidence   `json:"evidence"`
		Commit    bool            `json:"commit_may_have_occurred"`
	}
	for _, name := range []string{"initial-select", "retained-reacquire", "pending-reserve", "partial-progress", "unknown-progress", "complete-close", "initial-capacity", "initial-integrity", "initial-root-loss", "pre-effect-refusal"} {
		t.Run(name, func(t *testing.T) {
			count := 1
			if name == "partial-progress" {
				count = 2
			}
			r := gcResultEncodingFixture(t, count)
			p := r.Operation.Payload
			p.Closed, p.Active, p.SelectionUncertain = false, true, true
			r.Operation.Result = core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid, RequestedRevision: contract.ID{21}, CommitMayHaveOccurred: true}
			wantState, wantEffect, wantExit, phase := "commit-outcome-unknown", "effect-complete", 3, contract.GCClose
			switch name {
			case "initial-select", "initial-capacity", "initial-integrity", "initial-root-loss", "pre-effect-refusal", "retained-reacquire", "pending-reserve", "partial-progress", "unknown-progress":
				row := &p.Targets[len(p.Targets)-1]
				row.Selected = contract.GCTargetProgress{Disposition: contract.GCTargetPending}
				row.Observed, row.ObservedEvidence = 0, contract.ID{}
				row.DeleteAttempted, row.DeleteResult, row.PermissionOwned = false, contract.WriteResult{}, false
				p.RemainingCount, p.ProgressOrdinal = 1, 1
				wantState, wantEffect = "effect-pending", "effect-pending"
				switch name {
				case "retained-reacquire":
					phase, p.Active = contract.GCReacquire, false
				case "pending-reserve":
					phase = contract.GCReserve
				case "partial-progress":
					phase, wantState, wantEffect = contract.GCRecordProgress, "effect-partial", "effect-partial"
				case "unknown-progress":
					phase, wantState, wantEffect = contract.GCRecordProgress, "effect-unknown", "effect-unknown"
					row.Selected.Consumed = 1
				default:
					phase, p.ProgressOrdinal, p.Active = contract.GCSelect, 0, false
					wantState = "commit-outcome-unknown"
					switch name {
					case "initial-capacity":
						r.Operation.Result.Reason = core.CapacityExceeded
					case "initial-integrity":
						r.Operation.Result.Outcome, r.Operation.Result.Reason, wantState = core.IntegrityFailure, core.InvalidFormat, "positive-defect"
					case "initial-root-loss":
						r.Operation.Result.Outcome, r.Operation.Result.Reason, wantState = core.RootLossUnsupported, core.MissingSelectedObject, "root-loss-unsupported"
					case "pre-effect-refusal":
						r.Operation.Result.CommitMayHaveOccurred, p.SelectionUncertain, wantState, wantExit = false, false, "refused", 2
					}
				}
			}
			wantResult := r.Operation.Result
			write := contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
			p.Failures = []core.GCPhaseFailure{{Phase: phase, Result: wantResult, Write: write}}
			if err := core.RefreshGCResult(&r.Operation); err != nil || r.Operation.Result != wantResult {
				t.Fatal("result refresh changed actual failure facts", err, r.Operation.Result, wantResult)
			}
			if r.Operation.StateResult != wantState || GCApplyExitCode(r) != wantExit {
				t.Error("public state and exit lost uncertainty precedence", r.Operation.StateResult, wantState, GCApplyExitCode(r), wantExit)
			}
			var jsonBody, human bytes.Buffer
			if err := WriteGCApplyJSON(t.Context(), &jsonBody, r); err != nil {
				t.Fatal(err)
			}
			if err := WriteGCApplyHuman(t.Context(), &human, r); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(human.String(), "gc-apply: "+wantState+"\n") || !strings.Contains(human.String(), "Effect: "+wantEffect+";") || strings.Contains(human.String(), "commit may have occurred") != wantResult.CommitMayHaveOccurred || !strings.Contains(human.String(), "Requested revision: "+fmt.Sprintf("%x", wantResult.RequestedRevision[:])+".\n") {
				t.Error("human result lost state, effect or independent selection uncertainty", human.String())
			}
			var got struct {
				State   string    `json:"state_result"`
				Effect  string    `json:"effect_summary"`
				Result  coreFacts `json:"result"`
				Payload struct {
					Uncertain bool `json:"selection_uncertain"`
					Failures  []struct {
						Phase  contract.GCPhase `json:"phase"`
						Result coreFacts        `json:"result"`
						Write  struct {
							Status  contract.WriteStatus `json:"status"`
							Reason  contract.Reason      `json:"reason"`
							NotSent bool                 `json:"not_sent"`
						} `json:"write"`
					} `json:"failures"`
				} `json:"payload"`
			}
			wantFacts := coreFacts{Outcome: wantResult.Outcome, Reason: wantResult.Reason, Store: wantResult.StoreReason, Requested: fmt.Sprintf("%x", wantResult.RequestedRevision[:]), Observed: fmt.Sprintf("%x", wantResult.ObservedRevision[:]), Snapshot: fmt.Sprintf("%x", wantResult.ObservedSnapshotID[:]), Evidence: wantResult.Evidence, Commit: wantResult.CommitMayHaveOccurred}
			if err := json.Unmarshal(jsonBody.Bytes(), &got); err != nil || got.State != wantState || got.Effect != wantEffect || got.Result != wantFacts || got.Payload.Uncertain != wantResult.CommitMayHaveOccurred || len(got.Payload.Failures) != 1 {
				t.Fatal("structured result lost exact state, cause or phase evidence", err, got)
			}
			failure := got.Payload.Failures[0]
			if failure.Phase != phase || failure.Result != wantFacts || failure.Write.Status != write.Status || failure.Write.Reason != write.Reason || failure.Write.NotSent != write.NotSent {
				t.Error("phase evidence changed in delivery", failure)
			}
		})
	}
	for _, name := range []string{"uncertain-with-cleanup-failure", "success-with-cleanup-failure", "refusal-with-cleanup-failure", "invalid-state-with-uncertainty", "invalid-identity-with-uncertainty"} {
		t.Run(name, func(t *testing.T) {
			r := gcResultEncodingFixture(t, 1)
			r.Delivery.CleanupFailed = true
			r.Operation.Result = core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid, RequestedRevision: contract.ID{21}, CommitMayHaveOccurred: true}
			r.Operation.Payload.Closed, r.Operation.Payload.Active, r.Operation.Payload.SelectionUncertain = false, true, true
			wantExit, valid := 3, true
			switch name {
			case "success-with-cleanup-failure":
				r = gcResultEncodingFixture(t, 1)
				r.Delivery.CleanupFailed, wantExit = true, 2
			case "refusal-with-cleanup-failure":
				wantExit = 2
				r.Operation.Result.CommitMayHaveOccurred = false
				p := r.Operation.Payload
				p.SelectionUncertain, p.Active, p.ProgressOrdinal, p.RemainingCount = false, false, 0, 1
				row := &p.Targets[0]
				row.Selected = contract.GCTargetProgress{Disposition: contract.GCTargetPending}
				row.Observed, row.ObservedEvidence = 0, contract.ID{}
				row.PermissionOwned, row.DeleteAttempted, row.DeleteResult = false, false, contract.WriteResult{}
			}
			if err := core.RefreshGCResult(&r.Operation); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "invalid-state-with-uncertainty":
				r.Operation.StateResult, wantExit, valid = "success", 2, false
			case "invalid-identity-with-uncertainty":
				r.PreAdmission, wantExit, valid = &core.PreAdmissionRequestIdentity{}, 2, false
			}
			if got := GCApplyExitCode(r); got != wantExit {
				t.Error("cleanup or malformed result changed exit precedence", got, wantExit)
			}
			for _, human := range []bool{false, true} {
				var out bytes.Buffer
				var err error
				if human {
					err = WriteGCApplyHuman(t.Context(), &out, r)
				} else {
					err = WriteGCApplyJSON(t.Context(), &out, r)
				}
				if !valid {
					if err == nil || out.Len() != 0 {
						t.Error("malformed result crossed delivery preflight", human, err, out.Len())
					}
					continue
				}
				if human {
					current, _, _ := strings.Cut(out.String(), "Effect: ")
					if err != nil || !strings.Contains(out.String(), "Local cleanup failed.\n") || strings.Contains(current, "commit may have occurred") != r.Operation.Result.CommitMayHaveOccurred {
						t.Error("human delivery lost cleanup failure or independent uncertainty", err, out.String())
					}
					continue
				}
				var decoded struct {
					Delivery struct {
						CleanupFailed bool `json:"cleanup_failed"`
					}
					Result struct {
						Commit bool `json:"commit_may_have_occurred"`
					}
				}
				if err != nil || json.Unmarshal(out.Bytes(), &decoded) != nil || !decoded.Delivery.CleanupFailed || decoded.Result.Commit != r.Operation.Result.CommitMayHaveOccurred {
					t.Error("delivery lost cleanup failure or independent uncertainty", human, err, out.String())
				}
			}
		})
	}
}
