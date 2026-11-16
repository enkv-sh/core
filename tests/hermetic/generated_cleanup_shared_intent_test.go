package core

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// An independent failed generation can share a current generation's Intent.
// Its actual cleanup must preserve that carrier and the exact current entries.
// full_only: false
func TestActualCleanupReleaseSharesCurrentIntentCarrier(t *testing.T) {
	_ = actualSharedIntentReleasePrefix(t)
}

type sharedIntentReleasePrefix struct {
	env      fixtureEnvironment
	selected *StateSession
	entries  []contract.ValueEntry
	original contract.ID
	location contract.GeneratorSliceLocation
	evidence sharedIntentReleaseEvidence
}

func actualSharedIntentReleasePrefix(t *testing.T) sharedIntentReleasePrefix {
	t.Helper()
	ctx := t.Context()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	env.Context = ctx
	defer keys.RetireGenerated()
	defer keys.RetireApply()
	fixture := newNamedEnvironmentFixture(t, ctx, env, []int{1}, false, []string{"a-seed"})
	intent := func(name string) []byte {
		return hermeticGeneratorIntent([]byte("shared carrier real producer Intent " + name))
	}
	names := []string{"current-a", "current-b"}
	input := generatedWriterPlanInput(t, fixture.session, fixtureID(env.Domain, "shared carrier current operation"), names, intent, 0, nil)
	current := selectGeneratedWriterBatch(t, env, fixture.session, input, "shared carrier current", custody.StandardValue)
	current = generatedLifecycleReopen(t, ctx, current, env.Store)
	entries := make([]contract.ValueEntry, len(names))
	for i, name := range names {
		entries[i] = *current.valueEntry(entrySlot(t, current, name))
	}
	entry := entries[0]
	if entry.ValueSource != contract.Generated || current.root.Generated.GeneratedCurrent != 2 {
		t.Fatal("real selecting Final did not produce both current generations")
	}
	initialWork := mustSelectedGeneratedWork(t, current)
	initialLocation := initialWork.content.locations[generatedContentKey{contract.GeneratorContentIntent, entry.Generated.IntentDigest}]
	if initialLocation.BlobID != contract.Hash(input.declaration) {
		t.Fatal("initial selecting Final did not retain its real declaration carrier")
	}
	if len(initialWork.releases) != 0 {
		t.Fatal("selecting Final unexpectedly retained a release")
	}

	// The existing actual failed aggregate producer uses its final name as
	// the terminal owned failure. Its first sibling succeeds but its Final
	// cannot select either proposed generation. Preserve both current names.
	failedNames := []string{"failed-a", "failed-b"}
	shared := intent(names[0])
	// The next real reservation compacts the two current Intents before it
	// adds the failed declaration. Derive that expected physical body from
	// the fixture's exact bytes, independently of the production projection.
	other := intent(names[1])
	currentIntentBytes := append(bytes.Clone(shared), other...)
	expectedLocation := initialLocation
	expectedLocation.Offset = 0
	if bytes.Compare(entries[0].Generated.IntentDigest[:], entries[1].Generated.IntentDigest[:]) > 0 {
		currentIntentBytes = append(bytes.Clone(other), shared...)
		expectedLocation.Offset = uint64(len(other))
	}
	expectedLocation.BlobID = contract.Hash(currentIntentBytes)
	failedInput := generatedWriterPlanInput(t, current, fixtureID(env.Domain, "shared carrier failed operation"), failedNames, func(name string) []byte {
		if name == failedNames[1] {
			return bytes.Clone(shared)
		}
		return intent(name)
	}, 0, nil)
	failed, original := selectPrivateOwnedUnusableAggregateFromInput(t, env, current, failedNames, failedInput, nil)
	failed = generatedLifecycleReopen(t, ctx, failed, env.Store)
	work := mustSelectedGeneratedWork(t, failed)
	if original.expected.Template.IntentDigest != entry.Generated.IntentDigest || original.record.OperationID == entry.Generated.OriginOperationID {
		t.Fatal("failed original is not an independent producer of the exact current Intent")
	}
	location := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, entry.Generated.IntentDigest}]
	if location != expectedLocation || location.Logical() != initialLocation.Logical() || location.BlobID == contract.Hash(failedInput.declaration) {
		t.Fatal("failed Final did not reuse the exact canonical current-Intent carrier")
	}
	body, err := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil || location.BlobID.IsZero() || !bytes.Equal(body, shared) {
		t.Fatal("shared logical Intent lost its selected physical carrier", err)
	}
	var succeededDuty contract.ID
	for key, row := range work.records {
		if key.kind != contract.GeneratedDutySupportKind {
			continue
		}
		duty, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil || duty.Kind != contract.GeneratedDutyUnselectedCleanup || !succeededDuty.IsZero() {
			t.Fatal("failed aggregate lacks exactly one succeeded sibling cleanup Duty", err)
		}
		succeededDuty = duty.DutyID
	}
	if succeededDuty.IsZero() {
		t.Fatal("failed aggregate omitted succeeded sibling cleanup Duty")
	}
	end := func(before *StateSession, group contract.ID) *StateSession {
		t.Helper()
		candidate, result := prepareTestEndSelectedWork(t, before, ctx, group, env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("actual prefix exit preparation", group, result)
		}
		after, result := before.selectCandidate(ctx, candidate)
		if after == nil || result.Outcome != ObservedCurrent {
			t.Fatal("actual prefix exit selection", group, result)
		}
		return generatedLifecycleReopen(t, ctx, after, env.Store)
	}
	failed = end(failed, succeededDuty)
	work = mustSelectedGeneratedWork(t, failed)
	hazardRow, ok := work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, original.expected.Template.HazardID}]
	if !ok {
		t.Fatal("ending the sibling changed the actual failed original Hazard")
	}
	hazard, err := contract.InspectGeneratedHazardRecord(hazardRow.Body)
	if err != nil || hazard.OriginalAttemptID != original.record.AttemptID {
		t.Fatal("remaining Hazard lost exact original ancestry", err)
	}
	target, err := work.generatedCleanupTarget(contract.GeneratedHazardSupportKind, hazard.HazardID, hazard.Target)
	if err != nil {
		t.Fatal(err)
	}
	cleanupInput, canonical := generatedDeletePlanInputForSource(t, failed, fixtureID(env.Domain, "shared carrier actual cleanup operation"), hazardRow, target)
	reservation, _ := preparePrivateGeneratedReservation(t, env, failed, cleanupInput, canonical)
	recorded, _, cleanup, packet := selectActualGeneratedPacketRecord(t, env, failed, reservation, custody.StandardValue, true, nil)
	permit, err := recorded.admitGeneratedOrdinaryCleanupClose(ctx, cleanup.Template.AttemptID, generatedPlanInputFixture(t, recorded).context)
	if err != nil {
		t.Fatal("actual Hazard cleanup close admission", err)
	}
	candidate, result := recorded.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual Hazard cleanup close preparation", result)
	}
	cleaned, result := recorded.selectCandidate(ctx, candidate)
	if cleaned == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual Hazard cleanup close selection", result)
	}
	cleaned = generatedLifecycleReopen(t, ctx, cleaned, env.Store)
	work = mustSelectedGeneratedWork(t, cleaned)
	if len(work.releases) != 2 || cleaned.root.Generated.Hazards != 0 || cleaned.root.Generated.Duties != 0 {
		t.Fatal("actual cleanup did not leave exactly two release mappings")
	}
	for id, want := range map[contract.ID]struct {
		inbox, result contract.ID
		body          []byte
	}{original.record.AttemptID: {original.record.InboxID, original.record.ResultID, original.result},
		cleanup.Template.AttemptID: {cleanup.Template.InboxID, cleanup.Template.ResultID, packet}} {
		mapping, present := work.releases[id]
		if !present || mapping.release.State != contract.GeneratedReleasePending || mapping.release.InboxID != want.inbox ||
			mapping.release.OriginalResultID != want.result || mapping.release.ObjectLength != uint32(len(want.body)) ||
			mapping.release.SelectedHandoffDigest != contract.Hash(want.body) || mapping.release.HandoffRevisionID != cleaned.head.Core.Revision ||
			mapping.release.CapacityReservation != hazard.CapacityReservation {
			t.Fatal("actual cleanup changed exact release provenance", id)
		}
	}
	originalRelease := work.releases[original.record.AttemptID]
	cleaned = end(cleaned, cleanup.Template.InboxID)
	work = mustSelectedGeneratedWork(t, cleaned)
	mapping, present := work.releases[original.record.AttemptID]
	if !present || !reflect.DeepEqual(mapping, originalRelease) || len(work.releases) != 1 || len(cleaned.adminIndex.Groups) != 1 ||
		cleaned.adminIndex.Groups[0].GroupID != mapping.release.InboxID || cleaned.adminIndex.Groups[0].OwnerKind != format.AdministrativeInboxRelease {
		t.Fatal("ending only cleanup release changed independent original release")
	}
	for _, want := range entries {
		if got := cleaned.valueEntry(entrySlot(t, cleaned, want.Name)); got == nil || !reflect.DeepEqual(*got, want) {
			t.Fatal("cleanup changed an exact current generation", want.Name)
		}
	}
	gotLocation := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, entry.Generated.IntentDigest}]
	if gotLocation != location {
		t.Fatal("actual cleanup moved the shared Intent carrier")
	}
	body, err = work.readSelectedSlice(ctx, contract.GeneratorContentIntent, entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil || !bytes.Equal(body, shared) {
		t.Fatal("actual cleanup changed current Intent bytes", err)
	}
	graph, err := work.retainedGraph(original.record.OperationID)
	if err != nil || !slices.ContainsFunc(graph.Lineages, func(lineage contract.GeneratorLineageTemplate) bool {
		return slices.ContainsFunc(lineage.Templates[:lineage.TemplateCount], func(template contract.GeneratorAttemptTemplate) bool {
			return template.AttemptID == original.record.AttemptID && template.IntentDigest == entry.Generated.IntentDigest
		})
	}) {
		t.Fatal("release lost its immutable shared-Intent template", err)
	}
	t.Logf("real shared-Intent prefix current=%d releases=%d groups=%d children=%d child-bytes=%d original=%x",
		cleaned.root.Generated.GeneratedCurrent, len(work.releases), len(cleaned.adminIndex.Groups), cleaned.root.ChildCount,
		cleaned.root.ChildEncodedBytes, original.record.AttemptID)
	evidence := sharedIntentPrefixEvidence(t, cleaned, original.record.AttemptID)
	return sharedIntentReleasePrefix{env, cleaned, entries, original.record.AttemptID, location, evidence}
}
