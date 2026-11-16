package compositionfull

import (
	"bytes"
	"encoding/json"
	"enkv.sh/compositions/configuration"
	"os"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func generatedCleanupResultFixture(t *testing.T) core.PublicApplyResult {
	t.Helper()
	id := contract.ID{1}
	empty := contract.EmptyMutationResultDescriptors()
	target := generatedRendererTarget()
	target.Name = strings.Repeat("\x00", contract.CryptoMaxName)
	payload := &core.GeneratedCleanupPayload{Schema: 1,
		Basis: core.GeneratedCleanupBasis{Kind: core.GeneratedCleanupOwnedTarget, PlanGraphID: id, SourceKind: contract.GeneratedDutySupportKind,
			SourceID: id, OriginalOwnerID: id, OriginalOperationID: id, OriginalAttemptID: id, Target: &target},
		PredecessorRevisionID: id,
		RemainingWorkBasis:    core.GeneratedCleanupWorkBasis{HeadRevisionID: id, Snapshot: contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: id, Object: id, Digest: id, Length: 123}}}
	for n := byte(1); n <= 130; n++ {
		payload.RemainingDutyIDs = append(payload.RemainingDutyIDs, contract.ID{n})
		payload.RemainingHazardIDs = append(payload.RemainingHazardIDs, contract.ID{n})
		payload.RemainingInboxIDs = append(payload.RemainingInboxIDs, contract.ID{n})
	}
	r := core.PublicApplyResult{RequestID: id, DomainID: id, OperationID: id, RequestIdentity: id, Cleanup: payload,
		Result: core.Result{Outcome: core.Contention, RequestedRevision: contract.ID{2}, ObservedRevision: contract.ID{3}},
		Generated: &core.GeneratedInvocationResult{OperationKind: contract.OperationCleanOwnedFailureResidue, StateResult: "contention", CanonicalOutcome: contract.ReceiptCanonicalNotSelected,
			EffectSummary: contract.ReceiptEffectNoChange, EvidenceCeiling: contract.ReceiptEvidenceCanonical, SummaryCountsAvailable: true, EffectsAvailable: true, EffectsCommitment: &empty[1]}}
	r.Diagnostics = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation},
		Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonCancelled}}
	if err := core.RefreshGeneratedCleanupResult(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

// full_only: false
func TestGeneratedMutationHumanShowsInvocationAndCleanup(t *testing.T) {
	r := generatedCleanupResultFixture(t)
	body, err := RenderGeneratedMutationHuman(r, contract.OperationCleanOwnedFailureResidue)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Generated cleanup: contention\n", "Operation ID: " + readerID(r.OperationID), "Remaining Inbox: " + readerID(r.Cleanup.RemainingInboxIDs[129]), "Remaining duty: " + readerID(r.Cleanup.RemainingDutyIDs[129]), "Remaining hazard: " + readerID(r.Cleanup.RemainingHazardIDs[129]), "cancelled"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatal("human cleanup omitted an owned invocation fact", want, string(body))
		}
	}
	if bytes.Contains(body, []byte("ProductResult/v1")) || bytes.Contains(body, []byte("CleanupPayload/v2")) {
		t.Fatal("human cleanup exposed an internal envelope")
	}
}

// full_only: false
func TestGeneratedCleanupRendersCompletePayloadAndRejectsStaleCommitment(t *testing.T) {
	r := generatedCleanupResultFixture(t)
	payload := r.Cleanup
	body, err := RenderGeneratedMutationJSON(r, contract.OperationCleanOwnedFailureResidue)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	var cleanup map[string]json.RawMessage
	if err := json.Unmarshal(document["cleanup"], &cleanup); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"remaining_duty_ids", "remaining_hazard_ids", "remaining_inbox_ids"} {
		var ids []string
		if err := json.Unmarshal(cleanup[field], &ids); err != nil || len(ids) != 130 {
			t.Fatal("complete cleanup vector missing", field, err)
		}
		for n, value := range ids {
			if value != readerID(contract.ID{byte(n + 1)}) {
				t.Fatal("cleanup vector changed", field, n)
			}
		}
	}
	if string(cleanup["schema"]) != `"CleanupPayload/v2"` {
		t.Fatal("cleanup payload schema differs")
	}
	if !bytes.Equal(document["transition"], []byte("null")) || !bytes.Contains(cleanup["sibling_results"], []byte(readerID(payload.SiblingResults.RootDigest))) {
		t.Fatal("cleanup changed payload kind or sibling commitment")
	}
	human, err := RenderGeneratedMutationHuman(r, contract.OperationCleanOwnedFailureResidue)
	if err != nil || !bytes.Contains(human, []byte(readerID(payload.RemainingInboxIDs[129]))) {
		t.Fatal("human output omitted the last cleanup identity", err)
	}
	for _, render := range []func(core.PublicApplyResult, uint16) ([]byte, error){RenderGeneratedMutationJSON, RenderGeneratedMutationHuman} {
		if body, err := render(r, contract.OperationCleanOwnedFailureResidue); err != nil || !bytes.Contains(body, []byte("cancelled")) {
			t.Fatal("cleanup renderer lost the committed interruption diagnostic", err)
		}
	}
	payload.RemainingInboxIDs[129] = contract.ID{131}
	for _, render := range []func(core.PublicApplyResult, uint16) ([]byte, error){RenderGeneratedMutationJSON, RenderGeneratedMutationHuman} {
		if body, err := render(r, contract.OperationCleanOwnedFailureResidue); err == nil || body != nil {
			t.Fatal("changed cleanup facts escaped with a stale commitment")
		}
	}
}

// full_only: false
func TestGeneratedCleanupFileCloseCoalescesAndRefreshesCommitment(t *testing.T) {
	for _, alreadyReported := range []bool{false, true} {
		t.Run(map[bool]string{false: "new-cleanup-row", true: "coalesced-cleanup-row"}[alreadyReported], func(t *testing.T) {
			original := generatedCleanupResultFixture(t)
			if alreadyReported {
				original.AddCleanupDiagnostic()
			}
			if err := core.RefreshGeneratedCleanupResult(&original); err != nil {
				t.Fatal(err)
			}
			beforeResult, beforeGenerated, beforeCommitment := original.Result, *original.Generated, original.Cleanup.SiblingResults
			source := configurationSetPair(t, "aws", configuration.JSON, nil)
			got := configurationGeneratedMutationFile(t.Context(), original.RequestID, source.path, configuration.JSON, func(pair *configuration.Pair) ConfigurationApplyResult {
				field := reflect.ValueOf(pair.Editable).Elem().FieldByName("file")
				if field.IsNil() {
					t.Fatal("captured snapshot handle absent")
				}
				if err := (*os.File)(field.UnsafePointer()).Close(); err != nil {
					t.Fatal("controlled snapshot close", err)
				}
				return ConfigurationApplyResult{PublicApplyResult: original}
			})
			if got.Result != beforeResult || !reflect.DeepEqual(*got.Generated, beforeGenerated) || len(got.Diagnostics) != 2 {
				t.Fatal("File cleanup changed committed result or duplicated cleanup diagnostic")
			}
			if (got.Cleanup.SiblingResults == beforeCommitment) != alreadyReported {
				t.Fatal("File cleanup failed to refresh exactly the changed diagnostic sequence")
			}
			for _, render := range []func(core.PublicApplyResult, uint16) ([]byte, error){RenderGeneratedMutationJSON, RenderGeneratedMutationHuman} {
				body, err := render(got.PublicApplyResult, contract.OperationCleanOwnedFailureResidue)
				if err != nil || !bytes.Contains(body, []byte("evidence-unavailable")) || !bytes.Contains(body, []byte("cancelled")) {
					t.Error("File cleanup lost committed facts", err)
				}
			}
		})
	}
	t.Run("visible-refresh-refusal", func(t *testing.T) {
		original := generatedCleanupResultFixture(t)
		beforeResult, beforeGenerated := original.Result, *original.Generated
		source := configurationSetPair(t, "aws", configuration.JSON, nil)
		got := configurationGeneratedMutationFile(t.Context(), original.RequestID, source.path, configuration.JSON, func(pair *configuration.Pair) ConfigurationApplyResult {
			field := reflect.ValueOf(pair.Editable).Elem().FieldByName("file")
			if field.IsNil() {
				t.Fatal("captured snapshot handle absent")
			}
			if err := (*os.File)(field.UnsafePointer()).Close(); err != nil {
				t.Fatal("controlled snapshot close", err)
			}
			original.Cleanup.RemainingInboxIDs[129] = original.Cleanup.RemainingInboxIDs[128]
			return ConfigurationApplyResult{PublicApplyResult: original}
		})
		if got.Result != beforeResult || !reflect.DeepEqual(*got.Generated, beforeGenerated) || !got.Cleanup.SiblingResults.RootDigest.IsZero() || len(got.Diagnostics) != 3 {
			t.Fatal("refresh refusal changed selection or retained a stale commitment")
		}
		last := got.Diagnostics[2]
		if last.Subject != (contract.DiagnosticSubject{Kind: contract.SubjectObservation}) || len(last.Path) != 1 || last.Path[0] != contract.FieldPresence || last.Outcome != contract.DiagnosticUnable || last.Reason != contract.ReasonSelectedRelationInvalid || last.SourceLocation != nil {
			t.Fatal("File cleanup hid commitment refresh refusal")
		}
		for _, render := range []func(core.PublicApplyResult, uint16) ([]byte, error){RenderGeneratedMutationJSON, RenderGeneratedMutationHuman} {
			if body, err := render(got.PublicApplyResult, contract.OperationCleanOwnedFailureResidue); err == nil || body != nil {
				t.Error("invalid cleanup facts escaped refresh refusal")
			}
		}
	})

}
