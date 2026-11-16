package compositionfull

import (
	"bytes"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestPendingResultCleanupHumanShowsOriginalAttemptAndNoAction(t *testing.T) {
	id := contract.ID{1}
	row, effect := generatedRendererRelease(contract.PendingInboxReleaseRecord{Schema: 1, DomainID: id, InboxID: id, OriginalResultID: id, SelectedHandoffDigest: id, HandoffRevisionID: id, CapacityReservation: contract.GeneratorDescriptor{Digest: id, Length: 4}, ObjectLength: uint32(contract.GeneratedResultRecordMaxLength), State: contract.GeneratedReleasePending})
	r := core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: id, ExpectedDomain: id}, Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, ObservedRevision: id, ObservedSnapshotID: id}, StateResult: contract.ReaderSuccess, View: &core.GeneratedListView{DomainID: id, RevisionID: id, SnapshotID: id, Effects: []core.GeneratedEffectFact{effect}, PendingReleases: []core.GeneratedPendingResultCleanup{row}}}
	body, err := RenderGeneratedListHuman(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Pending Store result cleanup", "Inbox: " + readerID(row.InboxID), "Original operation: " + readerID(row.OriginalOperationID), "Original attempt: " + readerID(row.OriginalAttemptID), "create", "succeeded", "No supported generated-work action is available."} {
		if !strings.Contains(string(body), want) {
			t.Fatal("human cleanup result omitted an owned fact", want, string(body))
		}
	}
	if strings.Contains(string(body), "Run generated cleanup") {
		t.Fatal("cleanup status invented permission", string(body))
	}
}

// full_only: false
func TestPendingResultCleanupRequiresExactEffectRelation(t *testing.T) {
	for _, damage := range []string{"effect-index", "operation", "attempt", "inbox", "result", "action", "effect-state", "completion", "domain", "release-state", "duplicate"} {
		t.Run(damage, func(t *testing.T) {
			domain := publicQueryRendererDomain(t)
			id := contract.ID{1}
			row, effect := generatedRendererRelease(contract.PendingInboxReleaseRecord{Schema: 1, DomainID: id, InboxID: id, OriginalResultID: id, SelectedHandoffDigest: id, HandoffRevisionID: id, CapacityReservation: contract.GeneratorDescriptor{Digest: id, Length: 4}, ObjectLength: uint32(contract.GeneratedResultRecordMaxLength), State: contract.GeneratedReleasePending})
			view := core.GeneratedListView{DomainID: id, RevisionID: domain.Result.ObservedRevision, SnapshotID: domain.Result.ObservedSnapshotID, Effects: []core.GeneratedEffectFact{effect}, PendingReleases: []core.GeneratedPendingResultCleanup{row}}
			list := core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: id, ExpectedDomain: id}, Result: domain.Result, StateResult: contract.ReaderSuccess, View: &view}
			if _, err := RenderGeneratedListJSON(list); err != nil {
				t.Fatal("valid cleanup relation control", err)
			}
			switch damage {
			case "effect-index":
				row.EffectIndex = 1
			case "operation":
				row.OriginalOperationID = contract.ID{2}
			case "attempt":
				row.OriginalAttemptID = contract.ID{2}
			case "inbox":
				row.InboxID = contract.ID{2}
			case "result":
				row.OriginalResultID = contract.ID{2}
			case "action":
				row.Action = contract.GeneratorActionDelete
			case "effect-state":
				row.EffectState = contract.GeneratedEffectFailedTerminal
			case "completion":
				row.CompletionClass = contract.GeneratedCompletionConfirmed
			case "domain":
				row.DomainID = contract.ID{2}
			case "release-state":
				row.State = 255
			}
			view.PendingReleases = []core.GeneratedPendingResultCleanup{row}
			if damage == "duplicate" {
				view.PendingReleases = append(view.PendingReleases, row)
			}
			if body, err := RenderGeneratedListJSON(list); err == nil || body != nil {
				t.Fatal("generated list accepted unowned cleanup facts", err, string(body))
			}
			domain.View.Generated.Effects = view.Effects
			domain.View.Generated.PendingReleases = view.PendingReleases
			var out bytes.Buffer
			if err := WriteInspectionJSON(t.Context(), &out, domain); err == nil || out.Len() != 0 {
				t.Fatal("inspection accepted unowned cleanup facts", err, out.String())
			}
		})
	}
}
