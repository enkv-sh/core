package compositionfull

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func generatedInboxCleanupResultFixture(t *testing.T) core.PublicApplyResult {
	t.Helper()
	r := generatedCleanupResultFixture(t)
	r.Cleanup.Basis = core.GeneratedCleanupBasis{Kind: core.GeneratedCleanupInboxRelease, PlanGraphID: contract.ID{4}, SourceKind: contract.PendingInboxReleaseSupportKind, SourceID: contract.ID{5}, OriginalOwnerID: contract.ID{6}, OriginalOperationID: contract.ID{7}, OriginalAttemptID: contract.ID{8},
		OriginalResult: &contract.GeneratorResultReference{Schema: 1, ResultID: contract.ID{9}, ResultBodyDigest: contract.ID{10}, ResultLength: 128}}
	r.Cleanup.RemainingDutyIDs, r.Cleanup.RemainingHazardIDs = nil, nil
	r.Cleanup.Basis.SourceID, _ = contract.GeneratorInboxID(r.DomainID, r.Cleanup.Basis.OriginalOperationID, r.Cleanup.Basis.OriginalAttemptID, r.Cleanup.Basis.OriginalResult.ResultID)
	r.Cleanup.RemainingInboxIDs = []contract.ID{r.Cleanup.Basis.SourceID, {22}}
	slices.SortFunc(r.Cleanup.RemainingInboxIDs, compareGeneratedResultIDs)
	r.Generated.RelatedWorkAvailable = true
	empty := contract.EmptyMutationResultDescriptors()
	r.Generated.RelatedDutiesCommitment, r.Generated.RelatedHazardsCommitment = &empty[3], &empty[4]
	return r
}

// full_only: false
func TestGeneratedCleanupInboxReleaseRendersExactTargetAndUncertainty(t *testing.T) {
	for _, state := range []string{"success", "effect-unknown", "contention", "commit-outcome-unknown"} {
		t.Run(state, func(t *testing.T) {
			r := generatedInboxCleanupResultFixture(t)
			r.Generated.StateResult = state
			switch state {
			case "success", "effect-unknown":
				r.Result = core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, RequestedRevision: contract.ID{23}, ObservedRevision: contract.ID{23}}
				r.Cleanup.RemainingWorkBasis.HeadRevisionID = contract.ID{23}
				r.Generated.CanonicalOutcome = contract.ReceiptCanonicalSelected
				if state == "success" {
					r.Cleanup.RemainingInboxIDs = []contract.ID{{22}}
				}
			case "commit-outcome-unknown":
				r.Result.Outcome, r.Result.CommitMayHaveOccurred = core.UnresolvedCommit, true
			}
			if err := core.RefreshGeneratedCleanupResult(&r); err != nil {
				t.Fatal(err)
			}
			body, err := RenderGeneratedMutationHuman(r, contract.OperationCleanOwnedFailureResidue)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"Cleanup basis: temporary inbox release", "Temporary Inbox: " + readerID(r.Cleanup.Basis.SourceID), "Original result: " + readerID(r.Cleanup.Basis.OriginalResult.ResultID)} {
				if !bytes.Contains(body, []byte(want)) {
					t.Fatal("missing named inbox detail", want)
				}
			}
			if state == "effect-unknown" && !bytes.Contains(body, []byte("Temporary inbox deletion is unresolved.")) {
				t.Fatal("unresolved Store deletion was not identified")
			}
			if state == "commit-outcome-unknown" && !bytes.Contains(body, []byte("Use inspect to check this temporary Inbox")) {
				t.Fatal("unknown release selection omitted the inspection route")
			}
			encoded, err := RenderGeneratedMutationJSON(r, contract.OperationCleanOwnedFailureResidue)
			if err != nil {
				t.Fatal(err)
			}
			var envelope map[string]any
			if json.Unmarshal(encoded, &envelope) != nil {
				t.Fatal("invalid JSON")
			}
			compact, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			serialized := string(compact)
			for _, want := range []string{`"source_kind":12`, `"source_id":"` + readerID(r.Cleanup.Basis.SourceID) + `"`, `"body_digest":"` + readerID(r.Cleanup.Basis.OriginalResult.ResultBodyDigest) + `"`, `"state_result":"` + state + `"`} {
				if !strings.Contains(serialized, want) {
					t.Fatal("JSON omitted named inbox detail", want, serialized)
				}
			}
			if !strings.Contains(serialized, `"effects":[]`) || !strings.Contains(serialized, `"receipt_hex":null`) {
				t.Fatal("temporary cleanup invented a provider effect or receipt")
			}
		})
	}
}

// full_only: false
func TestGeneratedCleanupInboxLostDeletionHintRequiresStoreDiagnostic(t *testing.T) {
	for _, lostDelete := range []bool{false, true} {
		t.Run(map[bool]string{false: "read-unavailable", true: "delete-unconfirmed"}[lostDelete], func(t *testing.T) {
			r := generatedInboxCleanupResultFixture(t)
			r.Result = core.Result{Outcome: core.EvidenceUnavailable}
			r.Generated.StateResult = "unavailable"
			if lostDelete {
				r.Diagnostics = append(r.Diagnostics, contract.Diagnostic{
					Subject: contract.DiagnosticSubject{Kind: contract.SubjectStore},
					Path:    []contract.DiagnosticField{contract.FieldPresence},
					Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable,
				})
			}
			if err := core.RefreshGeneratedCleanupResult(&r); err != nil {
				t.Fatal(err)
			}
			before, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			body, err := RenderGeneratedMutationHuman(r, contract.OperationCleanOwnedFailureResidue)
			if err != nil {
				t.Fatal(err)
			}
			hint := []byte("The Store did not confirm deletion. Use inspect to check this temporary Inbox before another cleanup.")
			if bytes.Contains(body, hint) != lostDelete {
				t.Fatal("Store deletion hint did not follow its diagnostic")
			}
			if !bytes.Contains(body, []byte("cancelled")) {
				t.Fatal("interrupted-result diagnostic was lost")
			}
			encoded, err := RenderGeneratedMutationJSON(r, contract.OperationCleanOwnedFailureResidue)
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				Diagnostics []struct {
					Subject struct {
						Kind contract.DiagnosticSubjectKind `json:"kind"`
					} `json:"subject"`
					Path []struct {
						Field contract.DiagnosticField `json:"field"`
					} `json:"path"`
					Outcome contract.DiagnosticOutcome `json:"outcome"`
					Reason  contract.DiagnosticReason  `json:"reason"`
				} `json:"diagnostics"`
			}
			if json.Unmarshal(encoded, &result) != nil {
				t.Fatal("invalid diagnostic JSON")
			}
			found := false
			for _, d := range result.Diagnostics {
				if d.Subject.Kind == contract.SubjectStore && len(d.Path) == 1 && d.Path[0].Field == contract.FieldPresence && d.Outcome == contract.DiagnosticUnable && d.Reason == contract.ReasonEvidenceUnavailable {
					found = true
				}
			}
			if found != lostDelete {
				t.Fatal("JSON lost the exact Store diagnostic")
			}
			after, err := json.Marshal(r)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rendering changed the captured basis or result", err)
			}
		})
	}
}
