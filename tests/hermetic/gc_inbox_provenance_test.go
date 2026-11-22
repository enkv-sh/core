package core

import (
	"context"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGCPreservesHistoricalInboxOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	env, modern, failed, original := pendingInboxProvenanceFixture(t, false)
	store := newGCInterleavingStore(historicalInboxProvenanceIndex(t, env, modern, original.record.InboxID, failed.material.Core.OperationMaterialID, failed.expected.Template.IntentDigest))
	source := retainedReaderColdOpen(t, modern, store)
	disjoint := fixtureID(env.Domain, "unrelated GC")
	want, err := modern.gcPreservedCurrent(ctx, disjoint)
	if err != nil {
		t.Fatal("modern ownership projection", err)
	}
	historical, err := source.gcPreservedCurrent(ctx, disjoint)
	if err != nil || historical != want {
		t.Fatal("equivalent inbox ownership changed unrelated GC preservation", err)
	}

	// An unrelated owner's authenticated facts must survive normalization.
	hazard := slices.IndexFunc(source.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
		return group.GroupID == failed.expected.Template.HazardID
	})
	if hazard < 0 {
		t.Fatal("missing surviving Hazard")
	}
	for _, change := range []string{"evidence", "byte charge", "page charge", "disposable digest"} {
		peer := gcProjectionCopy(source)
		group := &peer.adminIndex.Groups[hazard]
		switch change {
		case "evidence":
			group.Affected.Digest = fixtureID(env.Domain, "different hazard evidence")
		case "byte charge":
			group.ChargedBytes++
		case "page charge":
			group.ChargedPages++
		case "disposable digest":
			group.Disposable.Digest = fixtureID(env.Domain, "different selected support")
		}
		got, err := peer.gcPreservedCurrent(ctx, disjoint)
		if err == nil && (got == want || change != "evidence") {
			t.Fatal("historical projection accepted changed accounting or lost evidence", change)
		}
	}
	peer := gcProjectionCopy(source)
	position := slices.IndexFunc(peer.adminIndex.Pages, func(page format.AdministrativePage) bool {
		return slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool {
			return row.Kind == contract.GeneratedFragmentSupportKind
		})
	})
	if position < 0 {
		t.Fatal("missing fragment page")
	}
	peer.adminIndex.Pages[position].Ref.Digest = fixtureID(env.Domain, "different fragment page")
	peer.root.RequiredSupport[position] = peer.adminIndex.Pages[position].Ref
	if got, err := peer.gcPreservedCurrent(ctx, disjoint); err == nil && got == want {
		t.Fatal("historical projection lost the physical fragment commitment")
	}

	page := *source.recipients[0]
	page.Object = fixtureID(env.Domain, "unselected recipient page")
	body, err := format.EncodeRecipientPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RecipientKind, env.Domain, page.Object, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	target := mustKey(t, store.Descriptor().Prefix, ref)
	store.put(target, body)
	keys := []string{target}
	plan, encoded := gcInterleavingPreview(t, ctx, source, store, keys, "separate inbox GC")
	if len(plan.Targets) != 1 || plan.Targets[0].Object.ObjectID != page.Object {
		t.Fatal("GC did not select the single unreferenced page")
	}
	var reopened []contract.GCPhase
	store.afterCAS = func(ctx context.Context, head format.Head, write contract.WriteResult) {
		if write.Status != contract.WriteAcknowledged || head.GC == nil ||
			(head.GC.Phase != contract.GCSelect && head.GC.Phase != contract.GCReserve) {
			return
		}
		cold := retainedReaderColdOpen(t, source, store)
		selected, progress, err := cold.selectedGCPlan(plan.OperationID)
		if err != nil || cold.root.ActiveGC != plan.OperationID || !slices.Equal(selected.Targets, plan.Targets) || len(progress.Targets) != 1 {
			t.Fatal("cold reader lost selected GC plan", head.GC.Phase, err)
		}
		var consumed uint8
		if head.GC.Phase == contract.GCReserve {
			consumed = 1
		}
		got, err := cold.gcPreservedCurrent(ctx, plan.OperationID)
		if err != nil || got != want || progress.Targets[0].Consumed != consumed {
			t.Fatal("cold reader lost unrelated ownership or GC allowance", head.GC.Phase, err)
		}
		reopened = append(reopened, head.GC.Phase)
	}
	engine := gcInterleavingEngine(t, source, store, keys, env.Trust)
	result := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: disjoint, EncodedPlan: encoded})
	if result.Validate() != nil || result.StateResult != "success" || len(store.deleteCalls) != 1 {
		t.Fatal("unrelated GC completion", result.StateResult, result.Result.Outcome, result.Result.Reason, len(store.deleteCalls))
	}
	if !slices.Equal(reopened, []contract.GCPhase{contract.GCSelect, contract.GCReserve}) {
		t.Fatal("missing cold open before deletion", reopened)
	}
	if result.Payload == nil || !result.Payload.Closed || result.Payload.RemainingCount != 0 ||
		len(result.Payload.Targets) != 1 || result.Payload.Targets[0].Object != plan.Targets[0].Object ||
		result.Payload.Targets[0].Selected.Consumed != 1 {
		t.Fatal("GC lost the selected target or its single spent permission")
	}
	cold := retainedReaderColdOpen(t, source, store)
	preserved, err := cold.gcPreservedCurrent(ctx, plan.OperationID)
	if err != nil || preserved != want || !cold.root.ActiveGC.IsZero() {
		t.Fatal("completed GC changed independent release or Hazard", err)
	}
}
