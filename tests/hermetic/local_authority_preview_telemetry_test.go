package core

import (
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestLocalAuthorityPreviewParentsRequiredFragmentReads(t *testing.T) {
	ctx := context.Background()
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	old := *selected.valueEntry(0)
	operation := generatedVectorID(239)
	profile := defaultGeneratedFixtureProfile()
	incarnations := map[string]contract.ID{old.Name: old.Incarnation}
	retiring := map[string]contract.ValueEntry{old.Name: old}
	input := generatedStatePlanInput(t, selected, operation, []string{old.Name}, profile, old.Generated.Epoch+1, incarnations, retiring)
	replacement := generatedReservationInputForStateIntent(t, selected, operation, []string{old.Name},
		[]byte(`{"name":"distinct-current-intent"}`), profile, old.Generated.Epoch+1, incarnations, retiring)
	input.graph, input.declaration, input.registry, input.recoveryPolicy, input.requestBindings = replacement.graph,
		replacement.declaration, replacement.graph.Request.Registry, replacement.graph.Request.RecoveryPolicyID, slices.Clone(replacement.requestBindings)
	selected = selectPrivateGeneratedOperation(t, env, selected, input, "current intent beside old hazard")
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	probe, result := openAdministrativeEngineFixture(ctx, selected, env.Store, env.Trust, LocalAuthorityPreview)
	if probe == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh administrative admission", result)
	}
	var target contract.ID
	for _, group := range probe.state.adminIndex.Groups {
		work, _, err := probe.state.administrativeWorkClosure(group.GroupID)
		if err != nil {
			t.Fatal(err)
		}
		work, err = probe.state.administrativeWorkWithoutOldReceipts(work)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := probe.state.planAdministrativeCurrentIntents(ctx, work)
		if err != nil {
			t.Fatal(err)
		}
		if plan.changed {
			target = group.GroupID
			break
		}
	}
	if target.IsZero() {
		t.Fatal("no disposition requires a current intent read")
	}
	// Open a separate session so the setup probe cannot warm its fragment reads.
	preview, result := openAdministrativeEngineFixture(ctx, selected, env.Store, env.Trust, LocalAuthorityPreview)
	if preview == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold preview admission", result)
	}
	// Release only authenticated fragment backing. The selected facts retain
	// its exact Ref and row identity; this is the supported cold reread path.
	for i := range preview.state.support {
		for j := range preview.state.support[i].Records {
			if preview.state.support[i].Records[j].Kind == contract.GeneratedFragmentSupportKind {
				preview.state.support[i].Records[j].Body = nil
			}
		}
	}
	preview.state.cache = nil
	recorder := telemetry.NewRecorder()
	ctx = telemetry.WithCapability(ctx, telemetry.NewCapability(nil, recorder))
	view, result := preview.Preview(ctx, target)
	if result.Outcome != ObservedCurrent || view.Identity.IsZero() {
		t.Fatal("preview", result)
	}
	records := localOperatorTelemetryRecords(recorder)
	var parent uint64
	for _, record := range records {
		if record.Event == telemetry.DiagnosticStart && record.Operation == telemetry.OpCorePrepareEndSelectedWork {
			parent = record.Call
		}
	}
	reads := 0
	for _, record := range records {
		if record.Event != telemetry.DiagnosticStart || record.Operation != telemetry.OpCoreStoreRead {
			continue
		}
		reads++
		if parent == 0 || record.ParentCall != parent {
			t.Errorf("required fragment Store read parent=%d, Preview call=%d", record.ParentCall, parent)
		}
	}
	if reads == 0 {
		t.Fatal("preview did not perform a required fragment Store read")
	}
}
