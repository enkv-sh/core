package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// The caller supplies the known fixture owners. The expected ended descriptor
// uses u32 count, then u32 length=32 and each byte-sorted ID, independently of
// the administrative closure implementation.
func endGeneratedObligation(t *testing.T, operationCtx context.Context, env fixtureEnvironment, before *StateSession,
	targetID contract.ID, endedIDs []contract.ID, wantEntries []ApplyEntryInput, warning uint8, removedMaterials ...contract.ID) *StateSession {
	t.Helper()
	ctx := t.Context()
	before = generatedLifecycleReopen(t, operationCtx, before, before.store)
	var target format.AdministrativeGroup
	for _, group := range before.adminIndex.Groups {
		if group.GroupID == targetID {
			target = group
		}
	}
	if target.GroupID.IsZero() || !slices.Contains(endedIDs, targetID) {
		t.Fatal("known generated obligation has no selected administrative target")
	}
	ids := slices.Clone(endedIDs)
	slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	body := binary.BigEndian.AppendUint32(nil, uint32(len(ids)))
	for _, id := range ids {
		body = binary.BigEndian.AppendUint32(body, 32)
		body = append(body, id[:]...)
	}
	digest := sha256.Sum256(append([]byte("ENKV/admin-descriptor/v1/ended-groups\x00"), body...))
	dependent := contract.GeneratorDescriptor{Digest: contract.ID(digest), Length: uint64(4 + 36*len(ids)), Count: uint32(len(ids))}
	windows, err := before.receiptWindows(ctx)
	if err != nil {
		t.Fatal("obligation predecessor receipt windows", err)
	}
	wantAccess := slices.DeleteFunc(slices.Clone(before.accessRecords()), func(row contract.AccessRecord) bool { return slices.Contains(removedMaterials, row.MaterialID) })
	oldWork := mustSelectedGeneratedWork(t, before)
	currentIntents := make(map[contract.ID][]byte)
	for _, named := range before.root.Names {
		entry := before.valueEntry(named.Slot)
		if entry.ValueSource == contract.Generated {
			intent, err := oldWork.readSelectedSlice(ctx, contract.GeneratorContentIntent, entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
			if err != nil {
				t.Fatal("current Intent before obligation exit", err)
			}
			currentIntents[entry.Generated.IntentDigest] = bytes.Clone(intent)
		}
	}
	public, private := env.Custody.Calls()
	memory, hasMemory := underlyingAdmittedMemoryStore(before.store)
	trust, hasTrust := underlyingAdmittedFixtureTrust(env.Trust)
	var beforeCAS, beforeCreates, beforeSigns int
	var headBody []byte
	var headToken contract.Token
	if hasMemory {
		memory.mu.Lock()
		beforeCAS, beforeCreates = memory.cas, memory.creates
		head := memory.objects[memory.desc.HeadKey]
		headBody, headToken = bytes.Clone(head.Body), head.Token
		memory.mu.Unlock()
	}
	if hasTrust {
		beforeSigns = trust.signs
	}
	candidate, result := prepareTestEndSelectedWork(t, before, ctx, targetID, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent || candidate.firstSend != nil {
		p, k := env.Custody.Calls()
		signerDelta := 0
		if hasTrust {
			signerDelta = trust.signs - beforeSigns
		}
		t.Logf("EndWork phase=prepare outcome=%d reason=%d target_kind=%d children=%d child_bytes=%d index_bytes=%d groups=%d custody_public_delta=%d custody_private_delta=%d signer_measured=%t signer_delta=%d", result.Outcome, result.Reason, target.OwnerKind, before.root.ChildCount, before.root.ChildEncodedBytes, before.root.AdministrativeIndex.Length, len(before.adminIndex.Groups), p-public, k-private, hasTrust, signerDelta)
		if hasMemory {
			memory.mu.Lock()
			casDelta, createDelta, objects := memory.cas-beforeCAS, memory.creates-beforeCreates, len(memory.objects)
			head := memory.objects[memory.desc.HeadKey]
			unchanged := head.Token == headToken && bytes.Equal(head.Body, headBody)
			files := memory.fileBodies
			memory.mu.Unlock()
			var fileBytes, fileCount uint64
			if files != nil {
				files.mu.Lock()
				fileBytes, fileCount = files.used, files.next
				files.mu.Unlock()
			}
			t.Logf("EndWork phase=prepare Store CAS_delta=%d Create_delta=%d head_unchanged=%t objects=%d file_bytes=%d file_count=%d", casDelta, createDelta, unchanged, objects, fileBytes, fileCount)
		}
		t.Fatal("actual generated obligation EndWork preparation", result)
	}
	if candidate.head.EndWork == nil {
		t.Fatal("prepared obligation exit has no subject")
	}
	if got := candidate.head.EndWork.AfterWarningBits; got != warning {
		t.Fatalf("prepared obligation exit warning bits: got %d, want %d", got, warning)
	}
	selected, result := before.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual generated obligation EndWork selection", result)
	}
	// Selection observes an administrative image. Cold Open loads and validates
	// the remaining optional work before a full relation check can use its bodies.
	after := generatedLifecycleReopen(t, operationCtx, selected, before.store)
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("administrative obligation exit invoked a custody key route")
	}
	for _, id := range ids {
		if slices.ContainsFunc(after.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == id }) {
			t.Fatal("obligation exit retained a known ended owner", id)
		}
	}
	if len(after.adminIndex.Groups) != len(before.adminIndex.Groups)-len(ids) ||
		!reflect.DeepEqual(after.currentEntryInputs(), wantEntries) || !slices.EqualFunc(after.accessRecords(), wantAccess, func(a, b contract.AccessRecord) bool { return reflect.DeepEqual(a, b) }) ||
		!reflect.DeepEqual(after.root.Names, before.root.Names) || !reflect.DeepEqual(after.root.Recipients, before.root.Recipients) ||
		after.root.ValueEntryCount != before.root.ValueEntryCount || after.root.SecretCount != before.root.SecretCount ||
		after.root.RawBytes != before.root.RawBytes || after.root.MembershipCount != before.root.MembershipCount {
		t.Fatal("obligation exit changed unrelated owners or current values/access")
	}
	keptWork := mustSelectedGeneratedWork(t, after)
	for _, named := range before.root.Names {
		want := *before.valueEntry(named.Slot)
		if slices.Contains(endedIDs, want.Generated.RetiringDutyID) {
			want.Generated.RetiringDutyPresent, want.Generated.RetiringDutyID = 0, contract.ID{}
		}
		actual := after.valueEntry(named.Slot)
		if actual == nil || !reflect.DeepEqual(*actual, want) {
			t.Fatal("obligation exit changed exact current provenance or retiring pointer", named.Name)
		}
		if want.ValueSource == contract.Generated {
			body, err := keptWork.readSelectedSlice(ctx, contract.GeneratorContentIntent, want.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
			key := generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, want.Generated.CreateResultID}
			if err != nil || !bytes.Equal(body, currentIntents[want.Generated.IntentDigest]) || !bytes.Equal(keptWork.records[key].Body, oldWork.records[key].Body) {
				t.Fatal("obligation exit changed current Intent or create evidence", err)
			}
		}
	}
	q := after.head.EndWork
	if q == nil || q.TargetGroupID != target.GroupID || q.TargetKind != target.OwnerKind || q.TargetOwnerID != target.OwnerID || q.TargetID != target.TargetID ||
		q.SelectedEvidenceSummary != target.SelectedEvidenceSummary || q.DependentGroups != dependent ||
		q.PredecessorRevisionID != before.head.Core.Revision || q.PredecessorFullHEADDigest != contract.Hash(before.body) || q.PredecessorToken != before.token ||
		q.BeforeWarningBits != before.root.WarningBits || q.AfterWarningBits != warning || after.root.WarningBits != warning ||
		q.BeforeChildCount != uint16(before.root.ChildCount) || q.AfterChildCount != uint16(after.root.ChildCount) ||
		q.BeforeChildBytes != before.root.ChildEncodedBytes || q.AfterChildBytes != after.root.ChildEncodedBytes {
		t.Fatal("obligation EndWork envelope differs from the captured predecessor and exact scope")
	}
	got, err := after.receiptWindows(ctx)
	if err != nil || len(got.Successes) == 0 {
		t.Fatal("obligation exit has no selected success receipt", err)
	}
	receipt := got.Successes[len(got.Successes)-1]
	if receipt.OperationKind != contract.OperationEndSelectedWork || receipt.OperationID != q.OperationID || receipt.StateResult != contract.ReceiptStateWorkEnded ||
		receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.EffectSummary != contract.ReceiptEffectNotApplicable ||
		receipt.AdministrativeTargetKind != target.OwnerKind || receipt.AdministrativeTargetID != target.TargetID ||
		receipt.AdministrativeOriginalEvidence != target.SelectedEvidenceSummary || receipt.WarningBits != uint64(warning) ||
		receipt.AdministrativeWarningChanges != warning&^before.root.WarningBits || receipt.PredecessorRevisionID != before.head.Core.Revision || receipt.ObservedRevisionID != after.head.Core.Revision ||
		receipt.AdministrativePageDelta != int16(q.AfterChildCount)-int16(q.BeforeChildCount) || receipt.AdministrativeByteDelta != int64(q.AfterChildBytes)-int64(q.BeforeChildBytes) {
		t.Fatal("obligation exit receipt changed its exact local disposition")
	}
	wantSuccesses := append(slices.Clone(windows.Successes), receipt)
	if len(wantSuccesses) > contract.MutationReceiptWindowLimit {
		wantSuccesses = wantSuccesses[len(wantSuccesses)-contract.MutationReceiptWindowLimit:]
	}
	if !slices.Equal(got.Successes, wantSuccesses) || !slices.Equal(got.Failures, windows.Failures) {
		t.Fatal("obligation exit changed complete receipt append/trim order or failures")
	}
	return after
}

// full_only: false
func TestEndWorkDiscardsGeneratedReleaseMappings(t *testing.T) {
	for _, cut := range []string{"pending", "unknown", "delete_before_ack", "ack_before_release_cas"} {
		t.Run(cut, func(t *testing.T) {
			ctx := t.Context()
			env, _ := genesisEnvironment(t, contract.GCP, false)
			env.Context = ctx
			f := newEnvironmentFixture(t, ctx, env, nil, false)
			before, original := signedCurrentIntentReleasePredecessor(t, ctx, env, f.session, "release exit")
			store := env.Store.(*memoryStore)
			deleteStore := &generatedCleanupDeleteStore{memoryStore: store}
			if cut == "unknown" {
				before = selectActualGeneratedInboxRelease(t, ctx, env, before, deleteStore, original.record.AttemptID, true)
			}
			work := mustSelectedGeneratedWork(t, before)
			mapping, present := work.releases[original.record.AttemptID]
			wantAttempt := original.record
			wantAttempt.Facts = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
			wantAttempt.History = contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)
			wantAttempt.Progress = contract.EmptyGeneratorVector(contract.GeneratorVectorProgress)
			if !present || mapping.release.State != map[bool]uint8{false: contract.GeneratedReleasePending, true: contract.GeneratedReleaseUnknown}[cut == "unknown"] || len(work.releases) != 2 || len(before.adminIndex.Groups) != 2 ||
				mapping.release.InboxID != original.record.InboxID || mapping.release.OriginalResultID != original.record.ResultID ||
				mapping.release.SelectedHandoffDigest != contract.Hash(original.result) || mapping.attempt != wantAttempt {
				t.Fatal("actual cleanup close did not retain the exact original Pending mapping")
			}
			key, err := format.GeneratedResultKey(store.desc.Prefix, before.root.Domain, mapping.release.InboxID)
			if err != nil || cut != "unknown" && !bytes.Equal(store.objects[key].Body, original.result) {
				t.Fatal("original Pending release Inbox differs from the sealed packet", err)
			}
			bundle, err := work.retainedGraph(original.record.OperationID)
			if err != nil {
				t.Fatal("released original graph", err)
			}
			graph := work.content.locations[generatedContentKey{contract.GeneratorContentGraph, bundle.UsePlan.PlanGraphID}]
			warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
			var after *StateSession
			var releaseCandidate *Candidate
			if cut == "delete_before_ack" || cut == "ack_before_release_cas" {
				cutStore := &generatedReleaseCutStore{generatedCleanupDeleteStore: deleteStore}
				before = generatedLifecycleReopen(t, ctx, before, cutStore)
				if cut == "delete_before_ack" {
					cutStore.afterDelete = func() {
						if _, present := store.objects[key]; present {
							t.Fatal("delete cut preceded the exact physical delete")
						}
						after = endGeneratedObligation(t, ctx, env, before, mapping.release.InboxID, []contract.ID{mapping.release.InboxID}, before.currentEntryInputs(), warning)
					}
				}
				permit, err := before.admitGeneratedInboxRelease(ctx, mapping.release.InboxID, generatedPlanInputFixture(t, before).context)
				if err != nil || deleteStore.deletes != 1 || deleteStore.deleteKey != key {
					t.Fatal("exact release delete cut", err)
				}
				var result Result
				releaseCandidate, result = before.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
				if releaseCandidate == nil || result.Outcome != ObservedCurrent {
					t.Fatal("unselected release candidate", result)
				}
				if cut == "ack_before_release_cas" {
					after = endGeneratedObligation(t, ctx, env, before, mapping.release.InboxID, []contract.ID{mapping.release.InboxID}, before.currentEntryInputs(), warning)
				}
			} else {
				after = endGeneratedObligation(t, ctx, env, before, mapping.release.InboxID, []contract.ID{mapping.release.InboxID}, before.currentEntryInputs(), warning)
			}
			if releaseCandidate != nil {
				cas := store.cas
				winner := store.objects[store.desc.HeadKey]
				if selected, result := before.selectCandidate(ctx, releaseCandidate); selected != nil || result.Outcome != Contention || result.Reason != StalePrecondition || result.CommitMayHaveOccurred ||
					result.RequestedRevision != releaseCandidate.head.Core.Revision || result.Evidence != AuthenticatedClosure || result.ObservedRevision != before.head.Core.Revision ||
					result.ObservedSnapshotID != before.root.Snapshot || store.cas != cas+1 || !reflect.DeepEqual(store.objects[store.desc.HeadKey], winner) {
					t.Fatal("late release candidate rebased after EndWork", result)
				}
			}
			kept := mustSelectedGeneratedWork(t, after)
			if len(kept.releases) != 1 || after.root.Generated.PendingReleases != before.root.Generated.PendingReleases-1 ||
				after.root.Generated.Attempts != before.root.Generated.Attempts-1 || after.root.Generated.Graphs.Count != before.root.Generated.Graphs.Count-1 {
				t.Fatal("release exit did not remove its exact Attempt/mapping/graph charge")
			}
			for _, rowKey := range []generatedRecordKey{{contract.GeneratedAttemptSupportKind, original.record.AttemptID}, {contract.PendingInboxReleaseSupportKind, original.record.InboxID}} {
				if _, present := kept.records[rowKey]; present {
					t.Fatal("release exit retained an exclusive original row", rowKey)
				}
			}
			for id, release := range work.releases {
				if id != original.record.AttemptID && !reflect.DeepEqual(kept.releases[id], release) {
					t.Fatal("release exit changed the unrelated exact cleanup release")
				}
			}
			if _, present := kept.content.locations[generatedContentKey{contract.GeneratorContentGraph, bundle.UsePlan.PlanGraphID}]; present ||
				slices.ContainsFunc(after.root.Generated.Fragments, func(ref format.FragmentLocation) bool { return ref.BlobID == graph.BlobID }) {
				t.Fatal("release exit retained its exclusive original graph location or blob")
			}
			if object, present := store.objects[key]; present != (cut == "pending") || present && !bytes.Equal(object.Body, original.result) {
				t.Fatal("local release disposal changed the original Inbox object")
			}
			// Late recreation is immutable Store garbage, not a selected result owner.
			store.put(key, original.result)
			admitted := generatedPlanInputFixture(t, after).context
			admitted.AdmissionID, admitted.SessionID = testID("release absent Record admission"), testID("release absent Record session")
			creates, cas := store.creates, store.cas
			inboxReads := 0
			store.readHook = func(readKey string, reply contract.ReadResult) contract.ReadResult {
				if readKey == key {
					inboxReads++
				}
				return reply
			}
			if plan, err := after.generatedRecordRequest(ctx, original.record.AttemptID, original.result, admitted); plan != nil || !errors.Is(err, contract.ErrRecord) {
				t.Fatal("release disposal restored original Record", err)
			}
			if body, present, result := after.ReadGeneratedResult(ctx, original.record.AttemptID); len(body) != 0 || present || result != refused(AdmissionInvalid) ||
				inboxReads != 0 || store.creates != creates || store.cas != cas {
				t.Fatal("release disposal restored the result reader or reached the old Inbox", result)
			}
			store.readHook = nil
			input := generatedPlanInputForGenerations(t, after, testID("release fresh operation"), []string{"fresh"}, defaultGeneratedFixtureProfile())
			input.context.AdmissionID, input.context.SessionID = testID("release fresh admission"), testID("release fresh session")
			fresh := selectPrivateGeneratedOperationInProcess(t, env, after, input, "release fresh progress")
			fresh = generatedLifecycleReopen(t, ctx, fresh, store)
			entry := fresh.valueEntry(0)
			if entry == nil || entry.Name != "fresh" || entry.ValueSource != contract.Generated || entry.Generated.IntentDigest != input.graph.Lineages[0].Templates[0].IntentDigest || fresh.root.WarningBits != warning {
				t.Fatal("release disposal did not permit exact fresh generated progress")
			}
			consumed := env.Custody.Consume(ctx, sessionConsumerSelection(t, fresh, fresh.admission.recipient, "fresh"), custody.StandardValue)
			if consumed.Code != contract.CryptoSuccess || !consumed.ValueMatched || consumed.SinkCalls != 1 {
				t.Fatal("release disposal fresh value is not privately usable", consumed)
			}
		})
	}
	t.Run("unobserved", func(t *testing.T) {
		native := nativeCleanupObligation(t, t.Context(), true)
		env, before := native.env, native.selected
		work := mustSelectedGeneratedWork(t, before)
		if len(work.releases) != 1 || len(work.attempts) != 0 || len(before.adminIndex.Groups) != 1 {
			t.Fatal("native cleanup did not retain one release-only unknown mapping")
		}
		var mapping generatedReleasedAttempt
		for _, mapping = range work.releases {
		}
		if mapping.release.State != contract.GeneratedReleaseUnobserved || mapping.release.ObjectLength != 0 || mapping.template.Action != contract.GeneratorActionDelete ||
			mapping.attempt.CompletionClass != contract.GeneratedCompletionAcknowledged || mapping.attempt.State != contract.GeneratedEffectUnknown && mapping.attempt.State != contract.GeneratedEffectClosedWithResidue {
			t.Fatal("native unknown mapping invented an observed result or stronger completion")
		}
		store := env.Store.(*memoryStore)
		key, err := format.GeneratedResultKey(store.desc.Prefix, before.root.Domain, mapping.release.InboxID)
		if err != nil {
			t.Fatal(err)
		}
		if _, present := store.objects[key]; present {
			t.Fatal("native Unobserved original has a fabricated Inbox packet")
		}
		warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningLateDestructiveEffect | WarningPossibleStoreGarbage
		after := endGeneratedObligation(t, t.Context(), env, before, mapping.release.InboxID, []contract.ID{mapping.release.InboxID}, before.currentEntryInputs(), warning)
		kept := mustSelectedGeneratedWork(t, after)
		if len(kept.releases) != 0 || after.root.Generated.PendingReleases != 0 || after.root.Generated.Attempts != 0 || after.root.Generated.Graphs.Count != 0 || len(kept.bundles) != 0 {
			t.Fatal("Unobserved release disposal retained its exact mapping/Attempt/graph")
		}
		if _, present := store.objects[key]; present {
			t.Fatal("Unobserved exit created an original Inbox")
		}
		freshGeneratedAfterObligationExit(t, t.Context(), env, after, "native Unobserved fresh progress")
	})

}

func freshGeneratedAfterObligationExit(t *testing.T, operationCtx context.Context, env fixtureEnvironment, after *StateSession, label string) *StateSession {
	t.Helper()
	ctx := t.Context()
	operation := fixtureID(after.root.Domain, label+" operation")
	input := generatedPlanInputForGenerations(t, after, operation, []string{"fresh"}, defaultGeneratedFixtureProfile())
	var old *contract.ValueEntry
	for _, named := range after.root.Names {
		if entry := after.valueEntry(named.Slot); entry.ValueSource == contract.Generated {
			old = entry
			break
		}
	}
	name := "fresh"
	if old != nil {
		name = old.Name
		profile := defaultGeneratedFixtureProfile()
		profile.ConfigContractID, profile.ResourceContractID, profile.LifecycleMode = old.Generated.ConfigContractID, old.Generated.ResourceContractID, old.Generated.LifecycleMode
		profile.CompletionClass, profile.RetirementMode = old.Generated.CompletionClass, old.Generated.RetirementMode
		input = generatedStatePlanInput(t, after, operation, []string{name}, profile, old.Generated.Epoch+1,
			map[string]contract.ID{name: old.Incarnation}, map[string]contract.ValueEntry{name: *old})
	}
	input.context.AdmissionID, input.context.SessionID = fixtureID(after.root.Domain, label+" admission"), fixtureID(after.root.Domain, label+" session")
	fresh := selectPrivateGeneratedOperationInProcess(t, env, after, input, label)
	fresh = generatedLifecycleReopen(t, operationCtx, fresh, env.Store)
	_, entry := lifecycleEntry(t, fresh, name)
	if entry.ValueSource != contract.Generated || entry.Generated.OriginOperationID != operation ||
		entry.Generated.IntentDigest != input.graph.Lineages[0].Templates[0].IntentDigest || fresh.root.WarningBits&after.root.WarningBits != after.root.WarningBits ||
		!fresh.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("exit did not permit exact fresh generated publication with sticky warnings")
	}
	check := env.Custody.Consume(ctx, sessionConsumerSelection(t, fresh, fresh.admission.recipient, name), custody.StandardValue)
	if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.SinkCalls != 1 {
		t.Fatal("fresh post-exit value is not privately usable", check)
	}
	return fresh
}

// full_only: false
func TestEndWorkDiscardsUnfinishedGeneratedObligations(t *testing.T) {
	t.Run("resultless_create_hazard", func(t *testing.T) {
		env, before, original, _ := resultlessCreateObligation(t, t.Context(), custody.StandardValue)
		work := mustSelectedGeneratedWork(t, before)
		row := work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, original.expected.Template.HazardID}]
		hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil || hazard.Exposure != contract.GeneratedExposurePossibleLive || hazard.Fenced != 1 || len(work.attempts[original.record.AttemptID].result) != 0 ||
			hazard.OriginalResults.Count != 0 || before.root.Generated.GeneratedCurrent != 1 || len(before.adminIndex.Groups) != 1 {
			t.Fatal("actual original/residue/successor Final did not retain one resultless create Hazard", err)
		}
		warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
		after := endGeneratedObligation(t, t.Context(), env, before, hazard.HazardID, []contract.ID{hazard.HazardID}, before.currentEntryInputs(), warning, original.material.Core.OperationMaterialID)
		kept := mustSelectedGeneratedWork(t, after)
		if len(kept.attempts) != 0 || after.root.Generated.Hazards != 0 || after.root.Generated.Materials != 0 || after.root.Generated.Graphs.Count != 0 ||
			len(kept.bundles) != 0 || after.root.Generated.Attempts != 0 || after.root.Generated.Results != 0 {
			t.Fatal("resultless Hazard exit retained its exclusive Attempt/material/graph closure")
		}
		freshGeneratedAfterObligationExit(t, t.Context(), env, after, "resultless Hazard fresh progress")
	})

	t.Run("active_cleanup_provider_lost", func(t *testing.T) {
		native := nativeCleanupObligation(t, t.Context(), false)
		env, before := native.env, native.selected
		work := mustSelectedGeneratedWork(t, before)
		if work.parent == nil || work.parent.OperationID != work.attempts[native.cleanup.Template.AttemptID].record.OperationID || work.phase == nil || len(work.attempts[native.cleanup.Template.AttemptID].result) != 0 {
			t.Fatal("native cleanup lost its actual selected parent/frontier")
		}
		parent := *work.parent
		cleanup := work.attempts[native.cleanup.Template.AttemptID]
		// RetireGenerated and cold Open above removed volatile producer custody;
		// closing this exact native server now removes the effect provider itself.
		native.server.Close()
		creates, deletes := native.creates.Load(), native.deletes.Load()
		warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningLateDestructiveEffect | WarningPossibleStoreGarbage
		after := endGeneratedObligation(t, t.Context(), env, before, parent.OperationID, []contract.ID{parent.OperationID}, before.currentEntryInputs(), warning)
		kept := mustSelectedGeneratedWork(t, after)
		if kept.parent != nil || kept.phase != nil || !after.root.Generated.ActiveOwner.IsZero() || native.creates.Load() != creates || native.deletes.Load() != deletes ||
			len(kept.attempts) != 2 || kept.attempts[native.original.record.AttemptID].record.AttemptID.IsZero() ||
			!reflect.DeepEqual(kept.records[generatedRecordKey{contract.GeneratedHazardSupportKind, native.source.HazardID}], work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, native.source.HazardID}]) {
			t.Fatal("cleanup parent exit changed the independent original Hazard or reached unavailable provider")
		}
		if !reflect.DeepEqual(kept.attempts[cleanup.record.AttemptID], cleanup) {
			t.Fatal("cleanup parent exit changed the source-owned cleanup history Attempt")
		}
		if _, present := kept.records[generatedRecordKey{contract.GeneratedPhaseSupportKind, parent.OperationID}]; present {
			t.Fatal("cleanup parent exit retained its exclusive Phase frontier")
		}
		after = endGeneratedObligation(t, t.Context(), env, after, native.source.HazardID, []contract.ID{native.source.HazardID}, after.currentEntryInputs(), warning, native.original.material.Core.OperationMaterialID, cleanup.material.Core.OperationMaterialID)
		if after.root.Generated.Hazards != 0 || after.root.Generated.Attempts != 0 || after.root.Generated.Materials != 0 || after.root.Generated.Graphs.Count != 0 || native.deletes.Load() != deletes {
			t.Fatal("unavailable-provider source exit retained old obligation closure or sent")
		}
		freshGeneratedAfterObligationExit(t, t.Context(), env, after, "unavailable provider fresh progress")
	})
	t.Run("active_cleanup_source_target", func(t *testing.T) {
		native := nativeCleanupObligation(t, t.Context(), false)
		env, before := native.env, native.selected
		work := mustSelectedGeneratedWork(t, before)
		if work.parent == nil || work.phase == nil || len(before.adminIndex.Groups) != 2 {
			t.Fatal("native cleanup has no exact source and active parent")
		}
		parent := *work.parent
		cleanup := work.attempts[native.cleanup.Template.AttemptID]
		native.server.Close()
		creates, deletes := native.creates.Load(), native.deletes.Load()
		warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningLateDestructiveEffect | WarningPossibleStoreGarbage
		after := endGeneratedObligation(t, t.Context(), env, before, native.source.HazardID,
			[]contract.ID{native.source.HazardID, parent.OperationID}, before.currentEntryInputs(), warning,
			native.original.material.Core.OperationMaterialID, cleanup.material.Core.OperationMaterialID)
		if after.root.Generated.ActiveOwner != (contract.ID{}) || after.root.Generated.Hazards != 0 || after.root.Generated.Attempts != 0 ||
			after.root.Generated.Materials != 0 || after.root.Generated.Graphs.Count != 0 || native.creates.Load() != creates || native.deletes.Load() != deletes {
			t.Fatal("source exit orphaned active cleanup or reached the closed native provider")
		}
		freshGeneratedAfterObligationExit(t, t.Context(), env, after, "active source fresh fixture progress")
	})
	for _, cut := range []string{"active_create_duty_target", "active_create_hazard_target"} {
		t.Run(cut, func(t *testing.T) {
			ctx := t.Context()
			a := newGeneratedActualOperation(t, false, custody.StandardValue)
			env := a.env
			env.Context = ctx
			before := generatedLifecycleReopen(t, ctx, a.fixture.session, env.Store)
			target := a.expected.Template.DutyID
			if cut == "active_create_hazard_target" {
				before = selectGeneratedResiduePlan(t, ctx, env, before, a.expected.Template.AttemptID)
				before = generatedLifecycleReopen(t, ctx, before, env.Store)
				target = a.expected.Template.HazardID
			}
			work := mustSelectedGeneratedWork(t, before)
			if work.parent == nil || work.parent.OperationID != work.attempts[a.expected.Template.AttemptID].record.OperationID || len(before.adminIndex.Groups) != 2 {
				t.Fatal("real active child has no selected parent")
			}
			store := env.Store.(*memoryStore)
			headKey := store.desc.HeadKey
			oldHEAD := store.objects[headKey]
			reads, creates, cas := store.reads, store.creates, store.cas
			public, private := env.Custody.Calls()
			if _, _, err := before.administrativeWorkClosure(target); err == nil {
				t.Error("active child was offered as an independent exit target")
			}
			issueTestEndWorkInvocation(t, before)
			candidate, result := before.prepareEndSelectedWork(ctx, target, env.Trust)
			if candidate != nil || result != refused(InvalidRelation) {
				t.Error("active child target did not refuse before preparation", result)
			}
			if p, k := env.Custody.Calls(); p != public || k != private || store.reads != reads || store.creates != creates || store.cas != cas || !reflect.DeepEqual(store.objects[headKey], oldHEAD) {
				t.Error("rejected active child target read, wrote, or used a key route")
			}
			before = generatedLifecycleReopen(t, ctx, before, env.Store)
			warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
			after := endGeneratedObligation(t, ctx, env, before, work.parent.OperationID,
				[]contract.ID{work.parent.OperationID, target}, before.currentEntryInputs(), warning, work.attempts[a.expected.Template.AttemptID].material.Core.OperationMaterialID)
			if after.root.Generated.ActiveOwner != (contract.ID{}) || after.root.Generated.Attempts != 0 || after.root.Generated.Duties != 0 || after.root.Generated.Hazards != 0 {
				t.Fatal("whole-parent exit did not remove its exact active child")
			}
			freshGeneratedAfterObligationExit(t, ctx, env, after, cut+" fresh progress")
		})
	}
	for _, cut := range []string{"controlled_nonfinal_ack", "controlled_failed_terminal_contradiction"} {
		t.Run(cut, func(t *testing.T) {
			ctx := t.Context()
			env, before, duty, target := controlledParkedAcknowledgement(t, false)
			env.Context = ctx
			work := mustSelectedGeneratedWork(t, before)
			progress, err := work.controlledRetirementProgress(duty, nil, true)
			if err != nil || len(progress.rows) != 1 || progress.contradiction || duty.Step != 2 || duty.CompletionClass != contract.GeneratedCompletionConfirmed {
				t.Fatal("real stronger-class nonfinal ACK", err)
			}
			if cut == "controlled_failed_terminal_contradiction" {
				input, inputCanonical := generatedDeletePlanInput(t, before, generatedVectorID(233), duty, target, 2)
				scope := contract.GeneratorControlledRetirementScope(duty.DescriptorID, duty.ConfigContractID, duty.ResultContractID)
				input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(duty.DomainID, duty.ResourceID, target.ResourceDigest, scope, progress.ack.record.ResultID, contract.Hash(progress.ack.result))
				prior, _ := preparePrivateGeneratedReservation(t, env, before, input, inputCanonical)
				responder := custody.NewControlledRetirementResponder(duty.ResourceID, target.ResourceDigest, scope)
				defer responder.Close()
				recorded, _, expected, packet := selectActualGeneratedPacketRecord(t, env, before, prior, custody.StandardValue, true, func(ctx context.Context, c contract.GeneratedProducerCommand) []byte { return responder.Probe(ctx, c) })
				decoded, err := contract.InspectGeneratedResultRecord(packet)
				attempt := mustSelectedGeneratedWork(t, recorded).attempts[expected.Template.AttemptID]
				if err != nil || decoded.SafeFacts.Disposition != contract.GeneratorDispositionContinuedUsability || attempt.record.State != contract.GeneratedEffectFailedTerminal {
					t.Fatal("continued-use producer did not seal the distinct failed-terminal result", err)
				}
				before = selectControlledRetirementClose(t, ctx, env, recorded, expected.Template.AttemptID)
				before = generatedLifecycleReopen(t, ctx, before, env.Store)
				work = mustSelectedGeneratedWork(t, before)
				duty, err = contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{contract.GeneratedDutySupportKind, duty.DutyID}].Body)
				if err != nil {
					t.Fatal("cold retirement duty", err)
				}
				progress, err = work.controlledRetirementProgress(duty, nil, true)
				if err != nil || !progress.contradiction || duty.Step != 2 || duty.Progress.Count != 1 {
					t.Fatal("cold retirement lost its original ACK and contradiction", err)
				}
			}
			if len(work.canonical) != 0 {
				t.Fatal("parked retirement unexpectedly retains an old canonical value")
			}
			var removedMaterials []contract.ID
			for _, attempt := range work.attempts {
				if attempt.expected.Template.Action != contract.GeneratorActionDelete || attempt.record.OwnerID != duty.OwnerID {
					t.Fatal("parked retirement contains an unrelated Attempt")
				}
				removedMaterials = append(removedMaterials, attempt.material.Core.OperationMaterialID)
			}
			warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningLateDestructiveEffect | WarningPossibleStoreGarbage
			after := endGeneratedObligation(t, ctx, env, before, duty.DutyID, []contract.ID{duty.DutyID}, before.currentEntryInputs(), warning, removedMaterials...)
			kept := mustSelectedGeneratedWork(t, after)
			if after.root.Generated.Duties != 0 || after.root.Generated.Hazards != 0 || after.root.Generated.Retiring != 0 || len(kept.attempts) != 0 ||
				after.root.Generated.Materials != 0 || after.root.Generated.Graphs.Count != 0 || len(kept.canonical) != 0 || len(kept.releases) != 0 {
				t.Fatal("unfinished stronger-class retirement exit retained its exact closure or retiring slot")
			}
			freshGeneratedAfterObligationExit(t, ctx, env, after, cut+" fresh progress")
		})
	}
}

// This local server is the effect provider. Each generator invocation uses the
// existing native host and its positive process join; no key loss is substituted
// for closing the server after the selected cleanup cut.
type nativeCleanupObligationFixture struct {
	env              fixtureEnvironment
	selected         *StateSession
	source           contract.GeneratedHazardRecord
	original         generatedAttempt
	cleanup          contract.GeneratorResultExpectation
	server           *httptest.Server
	creates, deletes *atomic.Int32
}

func nativeCleanupObligation(t *testing.T, operationCtx context.Context, cleanupAck bool) nativeCleanupObligationFixture {
	t.Helper()
	ctx := t.Context()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	freshCurrent := env.FreshCurrent
	env = syntheticAuthorityScenarioEnvironment(t, env)
	env.Context, env.FreshCurrent = ctx, freshCurrent
	intent, requestBody := hermeticCloudflareIntent()
	creates, deletes := new(atomic.Int32), new(atomic.Int32)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		if err != nil {
			t.Error("native obligation request", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			creates.Add(1)
			if !bytes.Equal(body, requestBody) || request.URL.Path != "/client/v4/accounts/"+hermeticCloudflareAccount+"/tokens" {
				t.Error("native obligation create differs from its admitted request")
			}
			if _, err := fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%s","value":"%s","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`, hermeticCloudflareToken, hermeticCloudflareSecret, hermeticCloudflarePermission, hermeticCloudflareAccount); err != nil {
				t.Error(err)
			}
			return
		}
		ordinal := deletes.Add(1)
		if request.Method != http.MethodDelete || request.URL.Path != "/client/v4/accounts/"+hermeticCloudflareAccount+"/tokens/"+hermeticCloudflareToken || request.Header.Get("Authorization") != "Bearer "+hermeticCloudflareBearer || len(body) != 0 {
			t.Error("native obligation delete differs from its exact token")
		}
		if ordinal == 1 || !cleanupAck {
			connection, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_, writeErr := buffer.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}")
			if err := buffer.Flush(); err != nil || writeErr != nil {
				t.Error("native ambiguity reply", err, writeErr)
			}
			if err := connection.Close(); err != nil {
				t.Error(err)
			}
			return
		}
		if _, err := fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, hermeticCloudflareToken); err != nil {
			t.Error(err)
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	origin := server.URL + "/client/v4"
	artifact, implementation := buildHermeticCloudflareGenerator(t, origin)
	profile := nativeGeneratedFixtureProfile(t, implementation)
	configure := func(t testing.TB, path string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
		return hermeticCloudflareConfig(t, path, origin, implementation, expected)
	}
	current := newEnvironmentFixture(t, ctx, env, nil, false).session
	input := generatedPlanInputForGenerationsIntent(t, current, generatedVectorID(230), []string{"generated"}, intent, profile)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
	current = selectHermeticGeneratedProcessOperation(t, operationCtx, env, current, input, artifact, configure)
	old := *current.valueEntry(0)
	current = selectPrivateGeneratedOperationInProcess(t, env, current, generatedStatePlanInput(t, current, generatedVectorID(231), []string{old.Name}, profile, old.Generated.Epoch+1,
		map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), "native obligation rotation")
	work := mustSelectedGeneratedWork(t, current)
	duty, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{contract.GeneratedDutySupportKind, current.valueEntry(0).Generated.RetiringDutyID}].Body)
	target, targetErr := work.retirementTarget(ctx, duty)
	if err != nil || targetErr != nil || target.ResourceDigest != hermeticCloudflareResourceDigest(hermeticCloudflareToken) {
		t.Fatal("native obligation exact retirement", err, targetErr)
	}
	deleteInput, deleteInputCanonical := generatedDeletePlanInput(t, current, generatedVectorID(232), duty, target, 2)
	deleteInput.requestBindings[0].Digest = generatedRetirementRequestDigest(target)
	prior, _ := preparePrivateGeneratedReservation(t, env, current, deleteInput, deleteInputCanonical)
	producer, expected := preparePrivateGeneratedProcessProducerWithConfig(t, env, current, prior, artifact, configure)
	var packet []byte
	var facts contract.GeneratorSafeFacts
	if !producer.reservation.candidate.bindFirstSend(producer, func(dispatch context.Context, authority contract.ID) contract.CryptoResultCode {
		var code contract.CryptoResultCode
		packet, facts, code = env.Custody.InvokeGeneratedProducer(dispatch, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("native original delete first send")
	}
	entered, result := current.selectCandidate(ctx, producer.reservation.candidate)
	if entered == nil || result.Outcome != ObservedCurrent || len(packet) != 0 || facts.Disposition != contract.GeneratorDispositionUnknown || facts.Reason != 8 || creates.Load() != 1 || deletes.Load() != 1 {
		t.Fatal("native original deletion did not retain its real incomplete response", result, facts)
	}
	env.Custody.RetireGenerated()
	entered = generatedLifecycleReopen(t, operationCtx, entered, env.Store)
	original := mustSelectedGeneratedWork(t, entered).attempts[expected.Template.AttemptID]
	body, err := contract.EncodeGeneratorSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := entered.admitGeneratedActiveRetirementResidue(context.Background(), duty.DutyID, body, generatedPlanInputFixture(t, entered).context)
	if err != nil {
		t.Fatal("native original active residue", err)
	}
	candidate, result := entered.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("native original residue preparation", result)
	}
	closed, result := entered.selectCandidate(ctx, candidate)
	if closed == nil || result.Outcome != ObservedCurrent {
		t.Fatal("native original residue selection", result)
	}
	closed = generatedLifecycleReopen(t, operationCtx, closed, env.Store)
	work = mustSelectedGeneratedWork(t, closed)
	hazard, err := contract.InspectGeneratedHazardRecord(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, expected.Template.HazardID}].Body)
	cleanup, ok, cleanupErr := work.selectGeneratedCleanup(ctx, nil)
	if err != nil || cleanupErr != nil || !ok || cleanup.hazard.HazardID != hazard.HazardID || cleanup.target != target {
		t.Fatal("native residue exact cleanup source", err, cleanupErr)
	}
	cleanupInput, cleanupInputCanonical := generatedDeletePlanInputForSource(t, closed, generatedVectorID(233), work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, hazard.HazardID}], target)
	cleanupInput.requestBindings[0].Digest = generatedRetirementRequestDigest(target)
	prior, _ = preparePrivateGeneratedReservation(t, env, closed, cleanupInput, cleanupInputCanonical)
	producer, cleanupExpected := preparePrivateGeneratedProcessProducerWithConfig(t, env, closed, prior, artifact, configure)
	packet = nil
	if !producer.reservation.candidate.bindFirstSend(producer, func(dispatch context.Context, authority contract.ID) contract.CryptoResultCode {
		var code contract.CryptoResultCode
		packet, facts, code = env.Custody.InvokeGeneratedProducer(dispatch, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("native cleanup exact first send")
	}
	selected, result := closed.selectCandidate(ctx, producer.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent || deletes.Load() != 2 || creates.Load() != 1 || (len(packet) != 0) != cleanupAck {
		t.Fatal("native selected cleanup cut", result, facts)
	}
	env.Custody.RetireGenerated()
	if cleanupAck {
		if facts.Disposition != contract.GeneratorDispositionRetirementAcknowledged {
			t.Fatal("native acknowledgement became a stronger confirmation")
		}
		selected = env.FreshGeneratedRecord(t, selected, cleanupExpected.Template.AttemptID, packet)
		selected = selectOrdinaryGeneratedCleanupClose(t, ctx, env, selected, cleanupExpected.Template.AttemptID)
		deleteStore := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
		selected = selectActualGeneratedInboxRelease(t, operationCtx, env, selected, deleteStore, cleanupExpected.Template.AttemptID, false)
	} else if facts.Disposition != contract.GeneratorDispositionUnknown {
		t.Fatal("native cleanup uncertainty changed outcome")
	}
	return nativeCleanupObligationFixture{env: env, selected: generatedLifecycleReopen(t, operationCtx, selected, env.Store), source: hazard, original: original, cleanup: cleanupExpected, server: server, creates: creates, deletes: deletes}
}

// A real original enters and returns, but its packet is not recorded. Its fixed
// residue successor then produces/records a real terminal packet before Final.
func resultlessCreateObligation(t *testing.T, operationCtx context.Context, successorDisposition uint8) (fixtureEnvironment, *StateSession, generatedAttempt, []byte) {
	t.Helper()
	ctx := t.Context()
	a := newGeneratedActualOperation(t, false, custody.StandardValue)
	env := a.env
	env.Context = ctx
	before := generatedLifecycleReopen(t, operationCtx, a.fixture.session, env.Store)
	original := mustSelectedGeneratedWork(t, before).attempts[a.expected.Template.AttemptID]
	if a.sends != 1 || len(a.result) == 0 || len(original.result) != 0 {
		t.Fatal("resultless original did not actually enter/return before its missing Record")
	}
	before = selectGeneratedResiduePlan(t, operationCtx, env, before, original.record.AttemptID)
	prior := preparePrivateGeneratedSuccessorReservation(t, env, before)
	recorded, _, _, packet := selectActualGeneratedPacketRecord(t, env, before, prior, successorDisposition, true, nil)
	if len(packet) == 0 {
		t.Fatal("fixed residue successor produced no real packet")
	}
	admitted := generatedPlanInputFixture(t, recorded).context
	admitted.AdmissionID, admitted.SessionID = testID("resultless Final admission"), testID("resultless Final session")
	plan, err := recorded.generatedFinalRequest(ctx, admitted)
	if err != nil {
		t.Fatal("resultless successor Final request", err)
	}
	recorded, final := preparePrivateGeneratedFinal(t, env, recorded, plan)
	closed, result := recorded.selectCandidate(ctx, final.reservation.candidate)
	if closed == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual resultless successor Final", result)
	}
	env.Custody.RetireGenerated()
	return env, generatedLifecycleReopen(t, operationCtx, closed, env.Store), original, bytes.Clone(a.result)
}

// The underlying conditional delete has returned and released its mutex before
// this synchronous cut; its acknowledgement has not yet reached Core.
type generatedReleaseCutStore struct {
	*generatedCleanupDeleteStore
	afterDelete func()
}

func (s *generatedReleaseCutStore) DeleteIfToken(ctx context.Context, key string, token contract.Token) contract.WriteResult {
	result := s.generatedCleanupDeleteStore.DeleteIfToken(ctx, key, token)
	if s.afterDelete != nil {
		s.afterDelete()
	}
	return result
}

// full_only: false
func TestEndWorkIsolatesBadOriginalBeforeUnrelatedCleanup(t *testing.T) {
	t.Run("linked_ancestry_scope", func(t *testing.T) {
		env, before, original, _ := resultlessCreateObligation(t, t.Context(), custody.GeneratedTerminalFailure)
		work := mustSelectedGeneratedWork(t, before)
		var successor generatedAttempt
		for id, attempt := range work.attempts {
			if id != original.record.AttemptID {
				successor = attempt
			}
		}
		if successor.record.PredecessorAttemptID != original.record.AttemptID || successor.record.History.Count != 2 || len(before.adminIndex.Groups) != 2 {
			t.Fatal("real residue successor has no exact unresolved original ancestry")
		}
		warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
		after := endGeneratedObligation(t, t.Context(), env, before, original.expected.Template.HazardID,
			[]contract.ID{original.expected.Template.HazardID, successor.expected.Template.HazardID}, before.currentEntryInputs(), warning, original.material.Core.OperationMaterialID)
		if after.root.Generated.Hazards != 0 || after.root.Generated.Attempts != 0 || after.root.Generated.Materials != 0 || after.root.Generated.Graphs.Count != 0 {
			t.Fatal("ancestor exit did not dispose the exact dependent successor closure")
		}
		freshGeneratedAfterObligationExit(t, t.Context(), env, after, "linked ancestry fresh progress")
	})
	t.Run("qualified_ancestry_independent", func(t *testing.T) {
		ctx := t.Context()
		env, _ := genesisEnvironment(t, contract.GCP, false)
		env.Context = ctx
		f := newEnvironmentFixture(t, ctx, env, nil, false)
		input := generatedPlanInputForGenerations(t, f.session, testID("qualified retry operation"), []string{"omega"}, defaultGeneratedFixtureProfile())
		prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, nil)
		entered, record, first, firstPacket := selectActualGeneratedPacketRecord(t, env, f.session, prior, custody.GeneratedConfirmedNoEffect, false, nil)
		planned, result := entered.selectCandidate(ctx, record.reservation.candidate)
		if planned == nil || result.Outcome != ObservedCurrent {
			t.Fatal("qualified no-effect plan", result)
		}
		prior = preparePrivateGeneratedSuccessorReservation(t, env, planned)
		recorded, _, retry, _ := selectActualGeneratedPacketRecord(t, env, planned, prior, custody.GeneratedTerminalFailure, true, nil)
		recorded = generatedLifecycleReopen(t, ctx, recorded, env.Store)
		work := mustSelectedGeneratedWork(t, recorded)
		original := work.attempts[first.Template.AttemptID]
		failed := work.attempts[retry.Template.AttemptID]
		history, err := work.vectors.resolve(contract.GeneratedAttemptSupportKind, failed.record.AttemptID, contract.GeneratorVectorHistory, failed.record.History)
		if err != nil || len(history) != 2 || work.parent == nil || !bytes.Equal(original.result, firstPacket) {
			t.Fatal("real qualified retry ancestry", err)
		}
		qualified, err := contract.InspectGeneratorHistory(history[0])
		if err != nil || qualified.Outcome != contract.GeneratedEffectConfirmedNoEffect || qualified.PredecessorAttemptID != first.Template.AttemptID ||
			qualified.ResultID != first.Template.ResultID || qualified.ResultDigest != contract.Hash(firstPacket) {
			t.Fatal("retry does not have exact qualified result ancestry", err)
		}
		var parentIndex, retryIndex uint16
		var parentFound, retryFound bool
		for i, group := range recorded.adminIndex.Groups {
			if group.GroupID == work.parent.OperationID {
				parentIndex, parentFound = uint16(i), true
			}
			if group.GroupID == retry.Template.DutyID {
				retryIndex, retryFound = uint16(i), true
			}
		}
		if !parentFound || !retryFound {
			t.Fatal("qualified retry has no actual parent/Duty groups")
		}
		if !slices.Equal(recorded.adminIndex.Groups[retryIndex].RelatedGroupIndexes, []uint16{parentIndex}) {
			t.Error("qualified create ancestry acquired an unnecessary old-owner dependency")
		}
		for pageIndex, page := range recorded.support {
			for ordinal, row := range page.Records {
				oldRow := row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == first.Template.AttemptID || row.Kind == contract.GeneratedResultSupportKind && row.RecordID == first.Template.ResultID
				if row.Kind == contract.GeneratorVectorSupportKind {
					carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					oldRow = carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.OwnerID == first.Template.AttemptID
				}
				if oldRow {
					span, ok := administrativeTestSpanAt(recorded.adminIndex.Pages[pageIndex], ordinal)
					if !ok || slices.Contains(span.GroupIndexes, retryIndex) {
						t.Error("qualified ancestor row was shared with the retry owner", row.Kind)
					}
				}
			}
		}
		admitted := generatedPlanInputFixture(t, recorded).context
		admitted.AdmissionID, admitted.SessionID = testID("qualified retry Final admission"), testID("qualified retry Final session")
		plan, err := recorded.generatedFinalRequest(ctx, admitted)
		if err != nil {
			t.Fatal(err)
		}
		recorded, final := preparePrivateGeneratedFinal(t, env, recorded, plan)
		closed, result := recorded.selectCandidate(ctx, final.reservation.candidate)
		if closed == nil || result.Outcome != ObservedCurrent {
			t.Fatal("real qualified retry Final", result)
		}
		env.Custody.RetireGenerated()
		closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
		kept := mustSelectedGeneratedWork(t, closed)
		if len(closed.adminIndex.Groups) != 1 || closed.adminIndex.Groups[0].GroupID != retry.Template.HazardID || len(closed.adminIndex.Groups[0].RelatedGroupIndexes) != 0 ||
			len(kept.attempts) != 1 || !reflect.DeepEqual(kept.attempts[retry.Template.AttemptID], failed) {
			t.Fatal("qualified retry did not survive with its old Attempt absent")
		}
		if _, retained := kept.records[generatedRecordKey{contract.GeneratedResultSupportKind, first.Template.ResultID}]; retained {
			t.Fatal("qualified old Result remains selected without a consumer")
		}
		wantHistory, err := kept.vectors.resolve(contract.GeneratedAttemptSupportKind, failed.record.AttemptID, contract.GeneratorVectorHistory, failed.record.History)
		if err != nil || !reflect.DeepEqual(wantHistory, history) {
			t.Fatal("qualified immutable history changed", err)
		}
		warning := closed.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
		after := endGeneratedObligation(t, ctx, env, closed, retry.Template.HazardID, []contract.ID{retry.Template.HazardID}, closed.currentEntryInputs(), warning, original.material.Core.OperationMaterialID)
		freshGeneratedAfterObligationExit(t, ctx, env, after, "qualified history fresh progress")
	})
	for _, fault := range []string{"missing", "unavailable", "malformed", "wrong_context", "oversized"} {
		t.Run(fault, func(t *testing.T) {
			ctx := t.Context()
			env, before, original, packet := resultlessCreateObligation(t, ctx, custody.GeneratedTerminalFailure)
			work := mustSelectedGeneratedWork(t, before)
			var successor generatedAttempt
			for id, attempt := range work.attempts {
				if id != original.record.AttemptID {
					successor = attempt
				}
			}
			// Ending the dependent successor is directional: the unresolved
			// original remains. A distinct operation then creates later work.
			warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
			before = endGeneratedObligation(t, ctx, env, before, successor.expected.Template.HazardID,
				[]contract.ID{successor.expected.Template.HazardID}, before.currentEntryInputs(), warning)
			if before.root.Generated.Hazards != 1 || before.root.Generated.Attempts != 1 || mustSelectedGeneratedWork(t, before).attempts[original.record.AttemptID].record.AttemptID != original.record.AttemptID {
				t.Fatal("successor-only disposal changed the unresolved original")
			}
			before, later := selectPrivateOwnedUnusableAggregate(t, env, before, []string{"unrelated"}, testID("unrelated later operation"))
			before = generatedLifecycleReopen(t, ctx, before, env.Store)
			work = mustSelectedGeneratedWork(t, before)
			if len(work.attempts) != 2 || len(before.adminIndex.Groups) != 2 || before.root.Generated.Hazards != 2 ||
				later.record.State != contract.GeneratedEffectFailedTerminal || len(later.result) == 0 || later.record.ResourceID == original.record.ResourceID ||
				later.record.AttemptID == original.record.AttemptID || later.record.OperationID == original.record.OperationID || !later.record.PredecessorAttemptID.IsZero() {
				t.Fatal("real missing original and later owned-unusable successor are not independent exact resources")
			}
			for _, group := range before.adminIndex.Groups {
				if len(group.RelatedGroupIndexes) != 0 {
					t.Fatal("bad-original fixture contains a dependent administrative group")
				}
			}
			store := env.Store.(*memoryStore)
			key := expectedGeneratedResultKey(store.desc.Prefix, original.expected)
			body := bytes.Clone(packet)
			want := Result{}
			switch fault {
			case "missing":
				delete(store.objects, key)
			case "unavailable":
				want = failure(EvidenceUnavailable, ReadUnavailable)
				want.StoreReason = contract.ReasonMalformed
				store.readHook = func(k string, reply contract.ReadResult) contract.ReadResult {
					if k == key {
						return contract.ReadResult{Status: contract.ReadUnavailable}
					}
					return reply
				}
			case "malformed":
				body[0] ^= 1
				want = failure(IntegrityFailure, InvalidRelation)
				store.put(key, body)
			case "wrong_context":
				body = bytes.Clone(later.result)
				want = failure(IntegrityFailure, InvalidRelation)
				store.put(key, body)
			case "oversized":
				body = append(body, make([]byte, contract.GeneratedResultRecordMaxLength+1-len(body))...)
				want = failure(IntegrityFailure, InvalidFormat)
				store.put(key, body)
			}
			object, present := store.objects[key]
			if result, found, outcome := before.ReadGeneratedResult(ctx, original.record.AttemptID); result != nil || found || outcome != want {
				t.Fatal("ordinary original lookup weakened its absence/unusable evidence rule", outcome)
			}
			selection, ok, err := before.readGeneratedCleanup(ctx)
			if fault == "missing" {
				if err != nil || !ok || selection.kind != generatedCleanupHazard || selection.hazard.HazardID != later.expected.Template.HazardID || selection.target.ResourceID != later.record.ResourceID {
					t.Fatal("missing earlier original did not fall through to the exact later cleanup", err)
				}
			} else {
				var read *selectedReadError
				if ok || !errors.As(err, &read) || read.result != want {
					t.Fatal("unavailable/unusable earlier original was skipped", err)
				}
			}
			creates, cas := store.creates, store.cas
			public, private := env.Custody.Calls()
			warning = before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
			// Separate operation IDs and graph histories make these owners independent.
			after := endGeneratedObligation(t, ctx, env, before, original.expected.Template.HazardID, []contract.ID{original.expected.Template.HazardID}, before.currentEntryInputs(), warning, original.material.Core.OperationMaterialID)
			kept := mustSelectedGeneratedWork(t, after)
			if _, found := kept.records[generatedRecordKey{contract.GeneratedHazardSupportKind, original.expected.Template.HazardID}]; found {
				t.Fatal("exact isolation retained the bad original Hazard")
			}
			if _, found := kept.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, original.record.AttemptID}]; found ||
				!reflect.DeepEqual(kept.attempts[later.record.AttemptID], work.attempts[later.record.AttemptID]) ||
				!reflect.DeepEqual(kept.records[generatedRecordKey{contract.GeneratedHazardSupportKind, later.expected.Template.HazardID}], work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, later.expected.Template.HazardID}]) {
				t.Fatal("isolation retained original rights or changed the exact independent later owner")
			}
			if p, k := env.Custody.Calls(); p != public || k != private || store.creates <= creates || store.cas != cas+1 {
				t.Fatal("administrative isolation used a key route or did not select one exact successor")
			}
			if got, found := store.objects[key]; found != present || !reflect.DeepEqual(got, object) {
				t.Fatal("local isolation changed the earlier bad Inbox")
			}
			selection, ok, err = after.readGeneratedCleanup(ctx)
			if err != nil || !ok || selection.kind != generatedCleanupHazard || selection.hazard.HazardID != later.expected.Template.HazardID || selection.target.ResourceID != later.record.ResourceID {
				t.Fatal("exact isolation did not restore later unrelated cleanup", err)
			}
			deleteStore := &generatedCleanupDeleteStore{memoryStore: store}
			closed := closeAndReleaseActualFailure(t, env, after, deleteStore, later, 0)
			closed = generatedLifecycleReopen(t, ctx, closed, deleteStore)
			if closed.root.Generated.Hazards != 0 || closed.root.Generated.Duties != 0 || !closed.root.Generated.ActiveOwner.IsZero() ||
				closed.root.Generated.Materials != 0 || closed.root.Generated.Attempts != 0 || closed.root.Generated.PendingReleases != 0 || len(closed.adminIndex.Groups) != 0 {
				t.Fatal("actual later cleanup did not close/release its exact remaining closure")
			}
			if got, found := store.objects[key]; found != present || !reflect.DeepEqual(got, object) {
				t.Fatal("unrelated ordinary cleanup changed the earlier bad Inbox")
			}
			store.readHook = nil
			freshGeneratedAfterObligationExit(t, ctx, env, closed, "isolated original "+fault+" fresh progress")
		})
	}
}

// full_only: false
func TestEndWorkRejectsOldResultsAfterFreshWorkAndKeyReplacement(t *testing.T) {
	for _, publication := range []string{"selected_original_then_duplicate", "first_original_after_exit_then_duplicate"} {
		t.Run(publication, func(t *testing.T) {
			ctx := t.Context()
			env, keys := genesisEnvironment(t, contract.GCP, true)
			env = syntheticAuthorityScenarioEnvironment(t, env)
			env.Context = ctx
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, nil, false)
			input, canonical := generatedSourcePlanInput(t, run, f, 0)
			prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
			producer, expected := preparePrivateGeneratedProducer(t, env, f.session, prior, nil)
			var original generatedAttempt
			var after *StateSession
			var packet []byte
			var finalCandidate *Candidate
			calls := 0
			if !producer.reservation.candidate.bindFirstSend(producer, func(dispatch context.Context, authority contract.ID) contract.CryptoResultCode {
				calls++
				if publication == "first_original_after_exit_then_duplicate" {
					before, result := Open(ctx, f.admission, env.Store)
					if before == nil || result.Outcome != ObservedCurrent {
						t.Fatal("late original selected reservation cold Open", result)
					}
					work := mustSelectedGeneratedWork(t, before)
					original = work.attempts[expected.Template.AttemptID]
					if work.parent == nil || len(work.attempts) != 1 || len(before.adminIndex.Groups) != 2 || len(original.result) != 0 {
						t.Fatal("late original reservation has no exact parent/Create-Duty closure")
					}
					warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
					after = endGeneratedObligation(t, ctx, env, before, original.record.OperationID, []contract.ID{original.record.OperationID, expected.Template.DutyID}, before.currentEntryInputs(), warning, original.material.Core.OperationMaterialID)
				}
				var code contract.CryptoResultCode
				packet, _, code = keys.InvokeGeneratedProducer(dispatch, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("original producer selected one-use handoff")
			}
			observed, result := f.session.selectCandidate(ctx, producer.reservation.candidate)
			if observed == nil || result.Outcome != ObservedCurrent || calls != 1 || len(packet) == 0 {
				t.Fatal("real original packet at its declared publication cut", result)
			}
			if publication == "selected_original_then_duplicate" {
				keys.RetireGenerated()
				recorded := env.FreshGeneratedRecord(t, observed, expected.Template.AttemptID, packet)
				recorded = generatedLifecycleReopen(t, ctx, recorded, env.Store)
				work := mustSelectedGeneratedWork(t, recorded)
				original = work.attempts[expected.Template.AttemptID]
				if original.record.State != contract.GeneratedEffectSucceeded || !bytes.Equal(original.result, packet) || len(recorded.adminIndex.Groups) != 2 {
					t.Fatal("original was not actually selected before administrative exit")
				}
				admitted := generatedPlanInputFixture(t, recorded).context
				admitted.AdmissionID, admitted.SessionID = testID("old Final admission"), testID("old Final session")
				plan, err := recorded.generatedFinalRequest(ctx, admitted)
				if err != nil {
					t.Fatal(err)
				}
				recorded, final := preparePrivateGeneratedFinal(t, env, recorded, plan)
				finalCandidate = final.reservation.candidate
				keys.RetireGenerated()
				warning := recorded.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
				after = endGeneratedObligation(t, ctx, env, recorded, original.record.OperationID, []contract.ID{original.record.OperationID, expected.Template.DutyID}, recorded.currentEntryInputs(), warning, original.material.Core.OperationMaterialID)
			} else {
				if _, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, producer.reservation.candidate.generated.authority); code != contract.CryptoAlreadyUsed {
					t.Fatal("late original gained a second invocation", code)
				}
				keys.RetireGenerated()
			}
			decoded, err := contract.DecodeGeneratedResultRecord(packet)
			if err != nil || contract.ValidateGeneratedResult(original.expected, original.material, decoded) != nil {
				t.Fatal("held real original packet differs from its captured expectation/material", err)
			}
			if producer.reservation.candidate.bindFirstSend(producer, func(context.Context, contract.ID) contract.CryptoResultCode {
				t.Fatal("old original send rebound")
				return contract.CryptoSuccess
			}) {
				t.Fatal("old selected producer candidate rebound after exit")
			}
			if finalCandidate != nil {
				if selected, result := finalCandidate.session.selectCandidate(ctx, finalCandidate); selected != nil || result.Outcome != Contention || result.Reason != StalePrecondition || result.CommitMayHaveOccurred {
					t.Fatal("old Final candidate rebased after exit", result)
				}
			}
			if after == nil {
				t.Fatal("original cut did not select actual EndWork")
			}
			fresh := freshGeneratedAfterObligationExit(t, ctx, env, after, "old result "+publication+" fresh work")
			f.session, f.admission = fresh, OpenContext{admission: &fresh.admission}
			a := &generatedActualOperation{env: env, fixture: f}
			env = selectActualGeneratedLoss(t, a, generatedActualLoss{name: "later-normal-signer", recovery: true, operation: 1, approval: contract.NormalSigningRole, mask: 1, targetRole: contract.SuccessorNormalSigner})
			fresh = a.fixture.session
			store := env.Store.(*memoryStore)
			inbox := expectedGeneratedResultKey(store.desc.Prefix, expected)
			for replay := 0; replay < 2; replay++ {
				store.put(inbox, packet)
				cold, result := Open(ctx, a.fixture.admission, store)
				if cold == nil || result.Outcome != ObservedCurrent || !reflect.DeepEqual(cold.currentEntryInputs(), fresh.currentEntryInputs()) ||
					!reflect.DeepEqual(cold.accessRecords(), fresh.accessRecords()) || cold.root.WarningBits&after.root.WarningBits != after.root.WarningBits {
					t.Fatal("old original/duplicate after new work/key change altered selected current state", result)
				}
				admitted := generatedPlanInputFixture(t, cold).context
				admitted.AdmissionID, admitted.SessionID = fixtureID(cold.root.Domain, fmt.Sprintf("old replay admission %d", replay)), fixtureID(cold.root.Domain, fmt.Sprintf("old replay session %d", replay))
				if !cold.generatedContextValid(admitted) || cold.prepared {
					t.Fatal("later old-result refusal did not use a fresh valid invocation")
				}
				inboxReads := 0
				store.readHook = func(key string, reply contract.ReadResult) contract.ReadResult {
					if key == inbox {
						inboxReads++
					}
					return reply
				}
				creates, cas := store.creates, store.cas
				if plan, err := cold.generatedRecordRequest(ctx, expected.Template.AttemptID, packet, admitted); plan != nil || !errors.Is(err, contract.ErrRecord) {
					t.Fatal("absent old coordinate regained Record after later key change", err)
				}
				if plan, err := cold.generatedFinalRequest(ctx, admitted); plan != nil || !errors.Is(err, contract.ErrRecord) {
					t.Fatal("absent old parent regained Final after later key change", err)
				}
				if body, present, result := cold.ReadGeneratedResult(ctx, expected.Template.AttemptID); len(body) != 0 || present || result != refused(AdmissionInvalid) {
					t.Fatal("absent old coordinate regained a result reader", result)
				}
				if result := cold.persistGeneratedResult(ctx, generatedResultWrite{attempt: expected.Template.AttemptID, body: packet}); result != refused(AdmissionInvalid) {
					t.Fatal("absent old coordinate regained Inbox persistence", result)
				}
				if inboxReads != 0 || store.creates != creates || store.cas != cas || cold.prepared || !bytes.Equal(store.objects[inbox].Body, packet) {
					t.Fatal("later old-result refusal read/wrote old Inbox or consumed fresh rights")
				}
				store.readHook = nil
			}
		})
	}
}

// full_only: false
func TestEndWorkCandidateBindsExactRetainedImageAndReceipt(t *testing.T) {
	ctx := t.Context()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	env.Context = ctx
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	s, _ := selectPrivateOwnedUnusableAggregate(t, env, f.session, []string{"omega", "psi"}, testID("detached shared candidate operation"))
	s = generatedLifecycleReopen(t, ctx, s, env.Store)
	var duty contract.ID
	for _, group := range s.adminIndex.Groups {
		if group.OwnerKind == format.AdministrativeGeneratedHazard {
			duty = group.GroupID
		}
	}
	if duty.IsZero() {
		t.Fatal("detached shared owner is absent")
	}
	ids := endWorkIDs{operation: generatedVectorID(180), transition: generatedVectorID(181),
		snapshot: generatedVectorID(182), revision: generatedVectorID(183),
		receipts: generatedVectorID(184), receiptIndex: generatedVectorID(185)}
	issueTestEndWorkInvocation(t, s)
	candidate, next, err := s.deriveEndWorkCandidate(t.Context(), duty, ids)
	if err != nil {
		t.Fatal(err)
	}
	checkEndWorkIndexReserveAgainstActual(t, s, next, duty)
	if candidate.head.AuthKind != format.AdministrativeAuth || candidate.head.EndWork == nil ||
		next.root.Snapshot != ids.snapshot || next.root.Transition != ids.transition ||
		next.head.Core.Revision != ids.revision || !next.validEndWorkSelection() ||
		next.root.WarningBits&WarningDiscardedExactEvidence == 0 {
		t.Fatal("end-work candidate lost exact successor or receipt")
	}
	if next.root.Generated.Slices != s.root.Generated.Slices {
		t.Fatal("detached owner exit changed the complete shared Slice descriptor")
	}
	if next.adminIndex.SliceSnapshot != s.adminIndex.SliceSnapshot {
		t.Fatal("unchanged Slice descriptor acquired a new owner snapshot")
	}
	for _, page := range s.adminIndex.Pages {
		if page.ReadRequired && !slices.Contains(next.root.RequiredSupport, page.Ref) {
			t.Fatal("unchanged Slice page was rewritten", page.Ref.Index)
		}
	}
	// The next ordinary writer starts from a selected cold image. The derived
	// candidate above has not yet stored its new receipt/root pages.
	actual, result := prepareTestEndSelectedWork(t, s, ctx, duty, env.Trust)
	if actual == nil || result.Outcome != ObservedCurrent {
		t.Fatal("detached shared exit preparation", result)
	}
	selected, result := s.selectCandidate(ctx, actual)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("detached shared exit selection", result)
	}
	next = generatedLifecycleReopen(t, ctx, selected, env.Store)
	// A later ordinary writer must consume the retained older Slice owner and
	// bind its carriers to the new ordinary snapshot.
	ordinary := *next
	plan := transitionPlan{snapshot: generatedVectorID(210)}
	ordinary.root.Snapshot = plan.snapshot
	for _, page := range next.adminIndex.Pages {
		if page.ReadRequired {
			plan.supportPages[page.Ref.Index] = contract.Hash(append([]byte("ordinary-after-end-work"), byte(page.Ref.Index)))
		}
	}
	images, err := next.rebindGeneratedSnapshot(ctx, &ordinary, plan)
	if err != nil || len(images) == 0 || ordinary.adminIndex.SliceSnapshot != plan.snapshot {
		t.Fatal("ordinary successor could not rebind the retained older Slice owner", err)
	}
	for i, indexed := range ordinary.adminIndex.Pages {
		if !indexed.ReadRequired {
			continue
		}
		for _, row := range ordinary.support[i].Records {
			if _, match, err := snapshotSliceRecord(contract.SupportRecord(row), next.root.Domain, plan.snapshot); err != nil || !match {
				t.Fatal("ordinary successor retained an old Slice carrier", err)
			}
		}
	}
	_, receipt, _ := receiptStateFixture(t)
	receipt.DomainID, receipt.OperationID, receipt.RequestIdentityDigest = next.root.Domain, generatedVectorID(231), contract.ID{}
	windows, err := next.receiptWindows(ctx)
	if err != nil {
		t.Fatal("retained Slice predecessor receipts", err)
	}
	delta := contract.MutationReceiptDeltaPlan{DomainID: next.root.Domain, OperationKind: receipt.OperationKind,
		AddedCount: 1, Before: windows, NewReceipt: contract.CompactMutationReceiptPlan(receipt)}
	receiptPlan := transitionPlan{snapshot: generatedVectorID(232)}
	indexes, err := next.mutationReceiptPageIndexes(ctx)
	if err != nil {
		t.Fatal("ordinary receipt page layout after exit", err)
	}
	for _, index := range indexes {
		receiptPlan.supportPages[index] = contract.Hash(append([]byte("receipt-after-end-work"), byte(index)))
	}
	storage, err := next.encodeMutationReceiptSupport(ctx, receiptPlan, delta, generatedVectorID(233))
	if err != nil {
		t.Fatal("ordinary receipt successor could not rebind old Slice owner", err)
	}
	receipted := *next
	receipted.root.Snapshot = receiptPlan.snapshot
	storage.install(&receipted)
	if receipted.adminIndex.SliceSnapshot != receiptPlan.snapshot {
		t.Fatal("ordinary receipt successor kept an old Slice owner")
	}
	for _, page := range receipted.support {
		if !slices.ContainsFunc(next.adminIndex.Pages, func(indexed format.AdministrativePage) bool {
			return indexed.ReadRequired && indexed.Ref.Index == page.Index
		}) {
			continue
		}
		for _, row := range page.Records {
			if _, match, err := snapshotSliceRecord(contract.SupportRecord(row), next.root.Domain, receiptPlan.snapshot); err != nil || !match {
				t.Fatal("ordinary receipt successor kept an old Slice carrier", err)
			}
		}
	}
	for _, group := range next.adminIndex.Groups {
		if group.GroupID == duty {
			t.Fatal("ended duty is still selected")
		}
	}
	active := newGeneratedActualOperation(t, false, custody.StandardValue)
	s = generatedLifecycleReopen(t, ctx, active.fixture.session, active.env.Store)
	parent := s.root.Generated.ActiveOwner
	parentIDs := endWorkIDs{operation: generatedVectorID(190), transition: generatedVectorID(191),
		snapshot: generatedVectorID(192), revision: generatedVectorID(193),
		receipts: generatedVectorID(194), receiptIndex: generatedVectorID(195)}
	issueTestEndWorkInvocation(t, s)
	parentCandidate, parentNext, err := s.deriveEndWorkCandidate(t.Context(), parent, parentIDs)
	if err != nil {
		t.Fatal("parent candidate", err)
	}
	checkEndWorkIndexReserveAgainstActual(t, s, parentNext, parent)
	if !parentNext.validEndWorkSelection() || len(parentNext.adminIndex.Groups) != 0 ||
		!parentNext.root.Generated.ActiveOwner.IsZero() ||
		parentCandidate.head.EndWork.DependentGroups.Count != 2 {
		t.Fatal("parent closure did not end its complete selected dependent scope")
	}
}
