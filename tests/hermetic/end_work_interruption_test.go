package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// These fixtures have independent detached retirement Duties or Hazards. Their IDs and
// exclusive seed access and prior delete permission are captured before preparation.
func checkInterruptedDetachedExit(t *testing.T, before, after *StateSession, target contract.ID, wantAccess []contract.AccessRecord, deletePermission bool) {
	t.Helper()
	ctx := t.Context()
	var group format.AdministrativeGroup
	for _, candidate := range before.adminIndex.Groups {
		if candidate.GroupID == target {
			group = candidate
		}
	}
	if group.GroupID.IsZero() || (group.OwnerKind != format.AdministrativeGeneratedDuty && group.OwnerKind != format.AdministrativeGeneratedHazard) || group.OwnerKind == format.AdministrativeGeneratedDuty && group.DutyKind != contract.GeneratedDutyRetirement {
		t.Fatal("fixture target is not its exact detached retirement owner")
	}
	if len(after.adminIndex.Groups) != len(before.adminIndex.Groups)-1 || slices.ContainsFunc(after.adminIndex.Groups, func(g format.AdministrativeGroup) bool { return g.GroupID == target }) {
		t.Fatal("exit removed a different detached group")
	}
	oldWork, newWork := mustSelectedGeneratedWork(t, before), mustSelectedGeneratedWork(t, after)
	for _, name := range before.root.Names {
		want := *before.valueEntry(name.Slot)
		if want.Generated.RetiringDutyID == target {
			want.Generated.RetiringDutyPresent, want.Generated.RetiringDutyID = 0, contract.ID{}
		}
		if !reflect.DeepEqual(after.valueEntry(name.Slot), &want) {
			t.Fatal("exit changed current value, origin or unrelated retiring pointer")
		}
		intent, err := oldWork.readSelectedSlice(ctx, contract.GeneratorContentIntent, want.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		got, readErr := newWork.readSelectedSlice(ctx, contract.GeneratorContentIntent, want.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		key := generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, want.Generated.CreateResultID}
		if err != nil || readErr != nil || !bytes.Equal(intent, got) || !bytes.Equal(oldWork.records[key].Body, newWork.records[key].Body) {
			t.Fatal("exit changed exact current Intent or create provenance", err, readErr)
		}
	}
	if !reflect.DeepEqual(after.root.Names, before.root.Names) || !reflect.DeepEqual(after.root.Recipients, before.root.Recipients) ||
		after.root.ValueEntryCount != before.root.ValueEntryCount || after.root.SecretCount != before.root.SecretCount ||
		after.root.RawBytes != before.root.RawBytes || after.root.MembershipCount != before.root.MembershipCount ||
		!slices.EqualFunc(after.accessRecords(), wantAccess, func(a, b contract.AccessRecord) bool { return reflect.DeepEqual(a, b) }) {
		t.Fatal("exit changed exact current membership or access")
	}
	for _, kept := range after.adminIndex.Groups {
		prior, present := oldWork.records[generatedRecordKey{contract.GeneratedDutySupportKind, kept.OwnerID}]
		got := newWork.records[generatedRecordKey{contract.GeneratedDutySupportKind, kept.OwnerID}]
		if !present || !bytes.Equal(prior.Body, got.Body) {
			t.Fatal("exit changed surviving independent Duty")
		}
	}
	kind := uint8(contract.GeneratedDutySupportKind)
	if group.OwnerKind == format.AdministrativeGeneratedHazard {
		kind = contract.GeneratedHazardSupportKind
	}
	if _, present := newWork.records[generatedRecordKey{kind, group.OwnerID}]; present {
		t.Fatal("exit kept its disposed owner row")
	}
	for id, attempt := range oldWork.attempts {
		if attempt.record.OwnerID == group.OwnerID || attempt.expected.Template.HazardID == group.OwnerID {
			if _, present := newWork.attempts[id]; present {
				t.Fatal("exit kept its original result consumer")
			}
		}
	}
	// One independent group: u32 count, u32 ID length, ID bytes.
	body := binary.BigEndian.AppendUint32(nil, 1)
	body = binary.BigEndian.AppendUint32(body, 32)
	body = append(body, target[:]...)
	digest := sha256.Sum256(append([]byte("ENKV/admin-descriptor/v1/ended-groups\x00"), body...))
	wantEnded := contract.GeneratorDescriptor{Digest: contract.ID(digest), Length: 40, Count: 1}
	q := after.head.EndWork
	warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
	if deletePermission {
		warning |= WarningLateDestructiveEffect
	}
	if q == nil || q.TargetGroupID != target || q.TargetKind != group.OwnerKind || q.TargetOwnerID != group.OwnerID || q.TargetID != group.TargetID ||
		q.DependentGroups != wantEnded || q.SelectedEvidenceSummary != group.SelectedEvidenceSummary || q.PredecessorRevisionID != before.head.Core.Revision ||
		q.PredecessorFullHEADDigest != contract.Hash(before.body) || q.PredecessorToken != before.token ||
		q.BeforeWarningBits != before.root.WarningBits || q.AfterWarningBits != warning || after.root.WarningBits != warning {
		t.Fatal("exit envelope changed exact predecessor, target, scope or warnings", warning, after.root.WarningBits)
	}
	prior, err := before.receiptWindows(ctx)
	got, readErr := after.receiptWindows(ctx)
	if err != nil || readErr != nil || len(got.Successes) != len(prior.Successes)+1 ||
		!slices.Equal(got.Successes[:len(prior.Successes)], prior.Successes) || !slices.Equal(got.Failures, prior.Failures) {
		t.Fatal("exit changed prior receipt windows", err, readErr)
	}
	assertSuccessReceiptOrder(t, prior, got, q.OperationID)
	r := got.Successes[len(got.Successes)-1]
	if r.OperationID != q.OperationID || r.OperationKind != contract.OperationEndSelectedWork || r.StateResult != contract.ReceiptStateWorkEnded ||
		r.CanonicalOutcome != contract.ReceiptCanonicalSelected || r.EffectSummary != contract.ReceiptEffectNotApplicable ||
		r.AdministrativeTargetKind != group.OwnerKind || r.AdministrativeTargetID != group.TargetID || r.AdministrativeOriginalEvidence != group.SelectedEvidenceSummary ||
		r.WarningBits != uint64(warning) || r.AdministrativeWarningChanges != warning&^before.root.WarningBits ||
		r.PredecessorRevisionID != before.head.Core.Revision || r.ObservedRevisionID != after.head.Core.Revision {
		t.Fatal("exit did not select exactly its one truthful receipt")
	}
}

// full_only: false
func TestEndWorkPartialImmutablePreparationRequiresFreshOpen(t *testing.T) {
	ctx := t.Context()
	env, selected, original, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	env.Context = ctx
	store := env.Store.(*memoryStore)
	before, result := openAdministrative(ctx, OpenContext{admission: &selected.admission}, store)
	if before == nil || result.Outcome != ObservedCurrent || len(before.adminIndex.Groups) != 1 {
		t.Fatal("partial staging predecessor", result)
	}
	target := original.expected.Template.HazardID
	if before.adminIndex.Groups[0].OwnerKind != format.AdministrativeGeneratedHazard || before.adminIndex.Groups[0].GroupID != target || selected.valueEntry(0).Generated.RetiringDutyPresent != 0 {
		t.Fatal("partial staging target differs from original detached owner")
	}
	known := make(map[string]bool, len(store.objects))
	for key := range store.objects {
		known[key] = true
	}
	oldHEAD := store.objects[before.admission.store.HeadKey]
	oldImage := sessionStateImage(t, selected)
	trust, ok := underlyingAdmittedFixtureTrust(env.Trust)
	if !ok {
		t.Fatal("partial staging has no admitted trust counter")
	}
	creates, cas, signs := store.creates, store.cas, trust.signs
	public, private := env.Custody.Calls()
	var stagedKey string
	var stagedBody []byte
	store.readHook = func(key string, reply contract.ReadResult) contract.ReadResult {
		if !known[key] && reply.Status == contract.ReadOK && stagedKey == "" {
			stagedKey, stagedBody = key, bytes.Clone(reply.Body)
			store.createMode = "lost-before"
		}
		return reply
	}
	defer func() { store.readHook, store.createMode = nil, "" }()
	candidate, result := prepareTestEndSelectedWork(t, before, ctx, target, env.Trust)
	store.readHook, store.createMode = nil, ""
	if candidate != nil || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable || result.StoreReason != contract.ReasonTransport || result.CommitMayHaveOccurred ||
		stagedKey == "" || len(stagedBody) == 0 || store.creates != creates+4 || len(store.objects) != len(known)+1 ||
		store.cas != cas || trust.signs != signs || !reflect.DeepEqual(store.objects[before.admission.store.HeadKey], oldHEAD) || !before.prepared {
		t.Fatal("partial immutable failure changed selection or crossed signing", result, store.creates-creates, len(store.objects)-len(known))
	}
	if !bytes.Equal(store.objects[stagedKey].Body, stagedBody) {
		t.Fatal("first staged immutable object changed")
	}
	reads := store.reads
	if again, refusal := before.prepareEndSelectedWork(ctx, target, env.Trust); again != nil || refusal != refused(AdmissionInvalid) || store.reads != reads || store.creates != creates+4 || trust.signs != signs {
		t.Fatal("used partial preparation was reused", refusal)
	}
	fresh := generatedLifecycleReopen(t, ctx, selected, store)
	if !reflect.DeepEqual(sessionStateImage(t, fresh), oldImage) || fresh.token != oldHEAD.Token {
		t.Fatal("fresh Open did not retain exact predecessor after partial staging")
	}
	completed, result := prepareTestEndSelectedWork(t, fresh, ctx, target, env.Trust)
	if completed == nil || result.Outcome != ObservedCurrent || completed.firstSend != nil {
		t.Fatal("fresh exit preparation", result)
	}
	ended, result := fresh.selectCandidate(ctx, completed)
	if ended == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh exit selection", result)
	}
	after := generatedLifecycleReopen(t, ctx, ended, store)
	wantAccess := slices.DeleteFunc(slices.Clone(selected.accessRecords()), func(row contract.AccessRecord) bool { return row.MaterialKind == contract.OperationSeedMaterialKind })
	checkInterruptedDetachedExit(t, selected, after, target, wantAccess, true)
	if p, k := env.Custody.Calls(); p != public || k != private || !bytes.Equal(store.objects[stagedKey].Body, stagedBody) {
		t.Fatal("administrative recovery invoked Crypto or removed unselected garbage")
	}
	refs := append([]contract.Ref{after.head.Core.Root, after.root.AdministrativeIndex}, after.root.AdministrativeIndexShards...)
	refs = append(refs, after.root.RequiredSupport...)
	refs = append(refs, after.root.CurrentAccess.Core.AccessPageRefs...)
	for _, ref := range after.root.ValueEntryPages {
		if ref != nil {
			refs = append(refs, *ref)
		}
	}
	for _, ref := range after.root.Recipients {
		if ref != nil {
			refs = append(refs, *ref)
		}
	}
	for _, ref := range refs {
		key, err := format.Key(after.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		if key == stagedKey {
			t.Fatal("fresh preparation selected a prior failed preparation's immutable object")
		}
	}
	freshGeneratedAfterObligationExit(t, ctx, env, after, "partial immutable fresh progress")
}

// full_only: false
func TestEndWorkLostCASReplyRequiresExactObservationAndFreshRetry(t *testing.T) {
	for _, commit := range []bool{true, false} {
		for _, readable := range []bool{true, false} {
			name := map[bool]string{true: "committed", false: "not_committed"}[commit] + "/" + map[bool]string{true: "readable_head", false: "unavailable_head"}[readable]
			t.Run(name, func(t *testing.T) {
				ctx := t.Context()
				env, selected, original, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
				env.Context = ctx
				memory := env.Store.(*memoryStore)
				store := &recordingCASStore{Store: memory}
				before, result := openAdministrative(ctx, OpenContext{admission: &selected.admission}, store)
				if before == nil || result.Outcome != ObservedCurrent {
					t.Fatal("lost CAS predecessor", result)
				}
				target := original.expected.Template.HazardID
				if len(before.adminIndex.Groups) != 1 || before.adminIndex.Groups[0].GroupID != target || before.adminIndex.Groups[0].OwnerKind != format.AdministrativeGeneratedHazard {
					t.Fatal("lost CAS fixture has a different exact detached Hazard")
				}
				oldHEAD := memory.objects[before.admission.store.HeadKey]
				candidate, result := prepareTestEndSelectedWork(t, before, ctx, target, env.Trust)
				if candidate == nil || result.Outcome != ObservedCurrent || candidate.firstSend != nil || !reflect.DeepEqual(memory.objects[before.admission.store.HeadKey], oldHEAD) {
					t.Fatal("lost CAS preparation changed the selected HEAD", result)
				}
				body, token := bytes.Clone(candidate.body), before.token
				store.write = func(ctx context.Context, key string, condition contract.Token, body []byte) contract.WriteResult {
					if commit {
						if reply := memory.CompareAndSwap(ctx, key, condition, body); reply.Status != contract.WriteAcknowledged {
							t.Fatal("fixture lost reply did not follow an actual committed CAS", reply)
						}
					}
					// No positive NotSent fact exists for either lost reply.
					return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
				}
				if !readable {
					memory.readHook = func(key string, reply contract.ReadResult) contract.ReadResult {
						if key == before.admission.store.HeadKey {
							return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
						}
						return reply
					}
				}
				defer func() { memory.readHook = nil }()
				trust, _ := underlyingAdmittedFixtureTrust(env.Trust)
				creates, signs := memory.creates, trust.signs
				public, private := env.Custody.Calls()
				observed, result := before.selectCandidate(ctx, candidate)
				want := Result{Outcome: UnresolvedCommit, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport,
					RequestedRevision: candidate.head.Core.Revision, CommitMayHaveOccurred: true}
				calls := 1
				if readable {
					want.Evidence = AuthenticatedClosure
					if commit {
						want.Outcome, want.Reason, want.StoreReason, want.CommitMayHaveOccurred = ObservedCurrent, NoReason, contract.ReasonNone, false
						want.ObservedRevision, want.ObservedSnapshotID = candidate.head.Core.Revision, candidate.head.Core.Root.Object
					} else {
						calls, want.Reason = 3, WriteUncertain
						want.ObservedRevision, want.ObservedSnapshotID = before.head.Core.Revision, before.root.Snapshot
					}
				}
				if result != want || (observed != nil) != readable {
					t.Fatal("lost CAS evidence differs from its exact observation", result, want)
				}
				assertExactSelectionRequest(t, store, before.admission.store.HeadKey, token, body, calls)
				if p, k := env.Custody.Calls(); p != public || k != private || memory.creates != creates || trust.signs != signs || !candidate.used || !bytes.Equal(candidate.body, body) || before.token != token {
					t.Fatal("lost CAS recovery changed the original request or private authority")
				}
				memory.readHook, store.write = nil, nil
				fresh := generatedLifecycleReopen(t, ctx, selected, memory)
				if commit {
					wantAccess := slices.DeleteFunc(slices.Clone(selected.accessRecords()), func(row contract.AccessRecord) bool { return row.MaterialKind == contract.OperationSeedMaterialKind })
					checkInterruptedDetachedExit(t, selected, fresh, target, wantAccess, true)
					reads := memory.reads
					issueTestEndWorkInvocation(t, fresh)
					if second, refusal := fresh.prepareEndSelectedWork(ctx, target, env.Trust); second != nil || refusal != refused(InvalidRelation) || memory.reads != reads || memory.creates != creates || trust.signs != signs {
						t.Fatal("absent original target gained another exit preparation", refusal)
					}
				} else {
					if !reflect.DeepEqual(sessionStateImage(t, fresh), sessionStateImage(t, selected)) || fresh.token != token || !reflect.DeepEqual(memory.objects[before.admission.store.HeadKey], oldHEAD) {
						t.Fatal("fixture noncommit changed its exact predecessor")
					}
					second, prepared := prepareTestEndSelectedWork(t, fresh, ctx, target, env.Trust)
					if second == nil || prepared.Outcome != ObservedCurrent || second.head.Core.Revision == candidate.head.Core.Revision || second.head.EndWork.OperationID == candidate.head.EndWork.OperationID {
						t.Fatal("fresh retry reused the uncertain exit identity", prepared)
					}
					ended, selectedResult := fresh.selectCandidate(ctx, second)
					if ended == nil || selectedResult.Outcome != ObservedCurrent {
						t.Fatal("fresh retry selection", selectedResult)
					}
					fresh = generatedLifecycleReopen(t, ctx, ended, memory)
					wantAccess := slices.DeleteFunc(slices.Clone(selected.accessRecords()), func(row contract.AccessRecord) bool { return row.MaterialKind == contract.OperationSeedMaterialKind })
					checkInterruptedDetachedExit(t, selected, fresh, target, wantAccess, true)
					windows, err := fresh.receiptWindows(ctx)
					if err != nil || slices.ContainsFunc(windows.Successes, func(r contract.CompactMutationReceipt) bool {
						return r.OperationID == candidate.head.EndWork.OperationID
					}) {
						t.Fatal("uncertain noncommit selected a duplicate old receipt", err)
					}
				}
				calls = store.calls
				if reused, refusal := before.selectCandidate(ctx, candidate); reused != nil || refusal != refused(AdmissionInvalid) || store.calls != calls {
					t.Fatal("uncertain old candidate supplied a new CAS", refusal)
				}
				freshGeneratedAfterObligationExit(t, ctx, env, fresh, name+" fresh progress")
			})
		}
	}
}

func retirementInterruptionFixture(t *testing.T, operationCtx context.Context, names []string) (fixtureEnvironment, *StateSession) {
	t.Helper()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	env.Context = t.Context()
	f := newEnvironmentFixture(t, t.Context(), env, nil, false)
	profile := defaultGeneratedFixtureProfile()
	input := generatedPlanInputForGenerations(t, f.session, testID("interruption first operation"), names, profile)
	var first *StateSession
	if len(names) == 1 {
		first = selectPrivateGeneratedOperationInProcess(t, env, f.session, input, "interruption first")
	} else {
		first = selectTwoNameCurrentGeneration(t, operationCtx, env, f.session, input, "interruption first")
	}
	incarnations, retiring := make(map[string]contract.ID), make(map[string]contract.ValueEntry)
	for _, named := range first.root.Names {
		entry := *first.valueEntry(named.Slot)
		incarnations[entry.Name], retiring[entry.Name] = entry.Incarnation, entry
	}
	input = generatedStatePlanInput(t, first, testID("interruption second operation"), names, profile, 2, incarnations, retiring)
	var second *StateSession
	if len(names) == 1 {
		second = selectPrivateGeneratedOperationInProcess(t, env, first, input, "interruption second")
	} else {
		second = selectTwoNameCurrentGeneration(t, operationCtx, env, first, input, "interruption second")
	}
	second = generatedLifecycleReopen(t, operationCtx, second, env.Store)
	work := mustSelectedGeneratedWork(t, second)
	if len(second.adminIndex.Groups) != len(names) || len(work.attempts) != 0 || work.parent != nil || work.phase != nil {
		t.Fatal("two complete generations did not leave only detached retirement Duties")
	}
	for _, named := range second.root.Names {
		entry := second.valueEntry(named.Slot)
		duty, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{contract.GeneratedDutySupportKind, entry.Generated.RetiringDutyID}].Body)
		if err != nil || entry.Generated.RetiringDutyPresent != 1 || duty.DutyID != entry.Generated.RetiringDutyID || duty.OwnerID != duty.DutyID || duty.Kind != contract.GeneratedDutyRetirement ||
			!slices.ContainsFunc(second.adminIndex.Groups, func(g format.AdministrativeGroup) bool {
				return g.GroupID == duty.DutyID && g.OwnerID == duty.OwnerID && len(g.RelatedGroupIndexes) == 0
			}) {
			t.Fatal("retirement fixture lacks the exact independent Duty and current pointer", err)
		}
	}
	return env, second
}

func rejectStaleInterruptionCandidate(t *testing.T, operationCtx context.Context, env fixtureEnvironment, winner, loser *StateSession, candidate *Candidate) {
	t.Helper()
	ctx := t.Context()
	store := env.Store.(*memoryStore)
	image, head, token := sessionStateImage(t, winner), bytes.Clone(winner.body), winner.token
	rows, err := winner.workSupportRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows = ownedProcessWorkRows(t, winner, rows)
	window, err := winner.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldBody, oldToken := bytes.Clone(candidate.body), loser.token
	trust, _ := underlyingAdmittedFixtureTrust(env.Trust)
	creates, signs, cas := store.creates, trust.signs, store.cas
	recorded := loser.store.(*recordingCASStore)
	sends := recorded.calls
	public, private := env.Custody.Calls()
	if selected, result := loser.selectCandidate(ctx, candidate); selected != nil || result.Outcome != Contention || result.Reason != StalePrecondition || result.CommitMayHaveOccurred || result.RequestedRevision != candidate.head.Core.Revision {
		t.Fatal("stale candidate selected, rebased or claimed an unknown commit", result)
	}
	if !candidate.used || candidate.firstSend != nil || loser.token != oldToken || !bytes.Equal(candidate.body, oldBody) || store.cas != cas+1 || store.creates != creates || trust.signs != signs {
		t.Fatal("stale candidate changed its frozen request or produced new immutable effects")
	}
	if recorded.calls != sends+1 || len(recorded.requests) != sends+1 ||
		recorded.requests[sends].key != loser.admission.store.HeadKey || recorded.requests[sends].token != oldToken || !bytes.Equal(recorded.requests[sends].body, oldBody) ||
		store.casConditions[len(store.casConditions)-1] != oldToken || !bytes.Equal(store.casBodies[len(store.casBodies)-1], oldBody) {
		t.Fatal("stale candidate sent a different key, condition or body")
	}
	if selected, result := loser.selectCandidate(ctx, candidate); selected != nil || result != refused(AdmissionInvalid) || store.cas != cas+1 || recorded.calls != sends+1 {
		t.Fatal("stale candidate supplied a second send", result)
	}
	cold := generatedLifecycleReopen(t, operationCtx, winner, store)
	got, err := cold.workSupportRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got = ownedProcessWorkRows(t, cold, got)
	gotWindow, err := cold.receiptWindows(ctx)
	if err != nil || !reflect.DeepEqual(sessionStateImage(t, cold), image) || !bytes.Equal(cold.body, head) || cold.token != token ||
		!reflect.DeepEqual(got, rows) || !reflect.DeepEqual(gotWindow, window) {
		t.Fatal("stale loser changed the winner's complete selection", err)
	}
	operation, ok := observedHeadOperation(candidate.head)
	if !ok {
		t.Fatal("stale candidate has no exact operation identity")
	}
	if slices.Contains(gotWindow.Order, operation) {
		t.Fatal("stale loser selected a common receipt order position")
	}
	for _, receipts := range [][]contract.CompactMutationReceipt{gotWindow.Successes, gotWindow.Failures} {
		if slices.ContainsFunc(receipts, func(r contract.CompactMutationReceipt) bool { return r.OperationID == operation }) {
			t.Fatal("stale loser selected a receipt")
		}
	}
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("stale candidate invoked a custody key route")
	}
}

// full_only: false
func TestEndWorkAndSignerReplacementKeepOneCompleteSelection(t *testing.T) {
	for _, signerWins := range []bool{false, true} {
		t.Run(map[bool]string{false: "end_work_first", true: "signer_first"}[signerWins], func(t *testing.T) {
			ctx := t.Context()
			env, selected := retirementInterruptionFixture(t, ctx, []string{"generated"})
			env = syntheticAuthorityScenarioEnvironment(t, env)
			store := env.Store.(*memoryStore)
			endSession := generatedLifecycleReopen(t, ctx, selected, &recordingCASStore{Store: store})
			signerSession := generatedLifecycleReopen(t, ctx, selected, &recordingCASStore{Store: store})
			if endSession.token != signerSession.token || !bytes.Equal(endSession.body, signerSession.body) || endSession.head.Core != signerSession.head.Core {
				t.Fatal("signer and exit preparations have different predecessors")
			}
			target := selected.valueEntry(0).Generated.RetiringDutyID
			end, result := prepareTestEndSelectedWork(t, endSession, ctx, target, env.Trust)
			if end == nil || result.Outcome != ObservedCurrent {
				t.Fatal("signer race exit preparation", result)
			}
			actors := env.ReplacementActors(t, ctx, signerSession, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole)
			permit := admitAuthorityReplacement(t, signerSession, actors.Keys, actors.After, contract.SuccessionReplaceAuthority, contract.NormalSigningRole, contract.SuccessionChangeNormalSigner, actors.Source)
			signer, result := signerSession.PrepareSuccession(ctx, permit, actors.Signers)
			if signer == nil || result.Outcome != ObservedCurrent {
				t.Fatal("signer race succession preparation", result)
			}
			admission := deliverSuccessionBasis(t, signer)
			if end.firstSend != nil || signer.firstSend != nil || !bytes.Equal(store.objects[store.desc.HeadKey].Body, selected.body) || store.objects[store.desc.HeadKey].Token != selected.token {
				t.Fatal("competing preparation changed HEAD or obtained an effect permit")
			}
			winnerSession, winner, loserSession, loser := endSession, end, signerSession, signer
			if signerWins {
				winnerSession, winner, loserSession, loser = signerSession, signer, endSession, end
			}
			public, private := env.Custody.Calls()
			observed, result := winnerSession.selectCandidate(ctx, winner)
			if observed == nil || result.Outcome != ObservedCurrent {
				t.Fatal("signer race winner selection", result)
			}
			var cold *StateSession
			if signerWins {
				cold, result = Open(ctx, admission, store)
				if cold == nil || result.Outcome != ObservedCurrent {
					t.Fatal("delivered signer winner cold Open", result)
				}
				actors.Activate(t, cold)
				oldRows, err := selected.workSupportRecords(ctx)
				if err != nil {
					t.Fatal(err)
				}
				wantRows := ownedProcessWorkRows(t, selected, oldRows)
				for i, row := range wantRows {
					if row.Kind != contract.GeneratorVectorSupportKind {
						continue
					}
					carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if carrier.VectorKind != contract.GeneratorVectorSlices {
						continue
					}
					if carrier.OwnerID != selected.root.Snapshot || carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.DomainID != selected.root.Domain || len(row.Body) < 120 {
						t.Fatal("predecessor Slice has a different snapshot owner")
					}
					// Wire offsets: schema2/domain32/kind1/owner32/vector-kind1/
					// ordinal4/descriptor44. Only owner bytes change; the ID hashes
					// the u32-framed domain/kind/owner/vector-kind/descriptor/ordinal.
					body := bytes.Clone(row.Body)
					copy(body[35:67], cold.root.Snapshot[:])
					identity := append(bytes.Clone(body[2:68]), body[72:116]...)
					identity = append(identity, body[68:72]...)
					preimage := []byte("ENKV/GENERATOR/v1/support-vector-row\x00")
					preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(identity)))
					wantRows[i].RecordID = contract.ID(sha256.Sum256(append(preimage, identity...)))
					wantRows[i].Body = body
				}
				slices.SortFunc(wantRows, func(a, b contract.SupportRecord) int {
					if a.Kind != b.Kind {
						return int(a.Kind) - int(b.Kind)
					}
					return bytes.Compare(a.RecordID[:], b.RecordID[:])
				})
				gotRows, err := cold.workSupportRecords(ctx)
				if err != nil || !reflect.DeepEqual(ownedProcessWorkRows(t, cold, gotRows), wantRows) {
					t.Fatal("signer winner changed work beyond exact Slice snapshot identity", err)
				}
				prior, err := selected.receiptWindows(ctx)
				got, readErr := cold.receiptWindows(ctx)
				if err != nil || readErr != nil || !reflect.DeepEqual(got, prior) || cold.head.EndWork != nil || cold.head.Succession == nil || !reflect.DeepEqual(cold.head.Succession, signer.head.Succession) {
					t.Fatal("signer winner changed receipt windows or succession evidence", err, readErr)
				}
				if !controlEqual(currentControlOf(cold), actors.After) {
					t.Fatal("signer winner installed a different delivered control")
				}
				if !reflect.DeepEqual(cold.pages, selected.pages) || !reflect.DeepEqual(cold.root.Names, selected.root.Names) || !reflect.DeepEqual(cold.root.Recipients, selected.root.Recipients) {
					t.Fatal("signer winner changed current value or recipient pages")
				}
				wantGenerated, gotGenerated := selected.root.Generated, cold.root.Generated
				wantGenerated.Fragments, gotGenerated.Fragments = nil, nil
				if !reflect.DeepEqual(gotGenerated, wantGenerated) || !slices.Equal(cold.root.Generated.Fragments, selected.root.Generated.Fragments) {
					t.Fatal("signer winner changed generated locations or descriptors", gotGenerated, wantGenerated)
				}
				if !reflect.DeepEqual(cold.accessRecords(), selected.accessRecords()) || !reflect.DeepEqual(cold.root.CurrentAccess.Core.AccessPageRefs, selected.root.CurrentAccess.Core.AccessPageRefs) || cold.root.WarningBits != selected.root.WarningBits {
					t.Fatal("signer winner changed preserved access or warnings")
				}
			} else {
				cold = generatedLifecycleReopen(t, ctx, observed, store)
				wantAccess := slices.DeleteFunc(slices.Clone(selected.accessRecords()), func(row contract.AccessRecord) bool { return row.MaterialKind == contract.OperationSeedMaterialKind })
				checkInterruptedDetachedExit(t, selected, cold, target, wantAccess, false)
				wantControl, gotControl := currentControlOf(selected), currentControlOf(cold)
				wantGeneration := wantControl.AccessGeneration
				if !reflect.DeepEqual(wantAccess, selected.accessRecords()) {
					wantGeneration++
				}
				wantControl.AccessGeneration = gotControl.AccessGeneration
				if !controlEqual(gotControl, wantControl) || gotControl.AccessGeneration != wantGeneration {
					t.Fatal("exit winner changed key identities or access generation", gotControl.AccessGeneration, wantGeneration)
				}
			}
			rejectStaleInterruptionCandidate(t, ctx, env, cold, loserSession, loser)
			if p, k := env.Custody.Calls(); p != public || k != private {
				t.Fatal("signer/exit selection invoked Crypto")
			}
			if signerWins {
				fresh := generatedLifecycleReopen(t, ctx, cold, store)
				freshExit, prepared := prepareTestEndSelectedWork(t, fresh, ctx, target, actors.Signers.NormalSuccessor)
				if freshExit == nil || prepared.Outcome != ObservedCurrent || freshExit.head.EndWork.OperationID == end.head.EndWork.OperationID || freshExit.head.Core.Revision == end.head.Core.Revision || freshExit.head.EndWork.PredecessorRevisionID != cold.head.Core.Revision {
					t.Fatal("fresh current-Authority exit reused the stale subject", prepared)
				}
				ended, result := fresh.selectCandidate(ctx, freshExit)
				if ended == nil || result.Outcome != ObservedCurrent {
					t.Fatal("fresh current-Authority exit selection", result)
				}
				after := generatedLifecycleReopen(t, ctx, ended, store)
				wantAccess := slices.DeleteFunc(slices.Clone(cold.accessRecords()), func(row contract.AccessRecord) bool { return row.MaterialKind == contract.OperationSeedMaterialKind })
				checkInterruptedDetachedExit(t, cold, after, target, wantAccess, false)
				windows, err := after.receiptWindows(ctx)
				if err != nil || slices.ContainsFunc(windows.Successes, func(r contract.CompactMutationReceipt) bool { return r.OperationID == end.head.EndWork.OperationID }) {
					t.Fatal("fresh current-Authority exit selected the old exit receipt", err)
				}
				if p, k := env.Custody.Calls(); p != public || k != private {
					t.Fatal("fresh current-Authority exit invoked Crypto")
				}
				env.Trust = actors.Signers.NormalSuccessor
				cold = after
			}
			freshGeneratedAfterObligationExit(t, ctx, env, cold, "signer exit fresh progress")
		})
	}
}

// full_only: false
func TestCompetingEndWorkCandidatesPreserveTheUnselectedGroup(t *testing.T) {
	for _, first := range []string{"alpha", "omega"} {
		t.Run(first+"_first", func(t *testing.T) {
			ctx := t.Context()
			env, selected := retirementInterruptionFixture(t, ctx, []string{"alpha", "omega"})
			store := env.Store.(*memoryStore)
			targets := make(map[string]contract.ID)
			for _, named := range selected.root.Names {
				targets[named.Name] = selected.valueEntry(named.Slot).Generated.RetiringDutyID
			}
			if selected.valueEntry(0).Generated.IntentDigest != selected.valueEntry(1).Generated.IntentDigest {
				t.Fatal("constant declaration fixture does not share its current Intent")
			}
			alpha := generatedLifecycleReopen(t, ctx, selected, &recordingCASStore{Store: store})
			omega := generatedLifecycleReopen(t, ctx, selected, &recordingCASStore{Store: store})
			if alpha.token != omega.token || alpha.head.Core != omega.head.Core || !bytes.Equal(alpha.body, omega.body) {
				t.Fatal("two exit preparations have different exact predecessors")
			}
			a, result := prepareTestEndSelectedWork(t, alpha, ctx, targets["alpha"], env.Trust)
			if a == nil || result.Outcome != ObservedCurrent {
				t.Fatal("alpha exit preparation", result)
			}
			o, result := prepareTestEndSelectedWork(t, omega, ctx, targets["omega"], env.Trust)
			if o == nil || result.Outcome != ObservedCurrent || a.firstSend != nil || o.firstSend != nil || !bytes.Equal(store.objects[store.desc.HeadKey].Body, selected.body) || store.objects[store.desc.HeadKey].Token != selected.token {
				t.Fatal("omega exit preparation changed selection or effect authority", result)
			}
			winnerSession, winner, loserSession, loser, last := alpha, a, omega, o, "omega"
			if first == "omega" {
				winnerSession, winner, loserSession, loser, last = omega, o, alpha, a, "alpha"
			}
			observed, result := winnerSession.selectCandidate(ctx, winner)
			if observed == nil || result.Outcome != ObservedCurrent {
				t.Fatal("competing exit winner", result)
			}
			cold := generatedLifecycleReopen(t, ctx, observed, store)
			checkInterruptedDetachedExit(t, selected, cold, targets[first], selected.accessRecords(), false)
			rejectStaleInterruptionCandidate(t, ctx, env, cold, loserSession, loser)
			fresh := generatedLifecycleReopen(t, ctx, cold, store)
			second, result := prepareTestEndSelectedWork(t, fresh, ctx, targets[last], env.Trust)
			if second == nil || result.Outcome != ObservedCurrent || second.head.EndWork.OperationID == loser.head.EndWork.OperationID {
				t.Fatal("fresh second exit rebased the old loser", result)
			}
			ended, result := fresh.selectCandidate(ctx, second)
			if ended == nil || result.Outcome != ObservedCurrent {
				t.Fatal("fresh independent second exit", result)
			}
			after := generatedLifecycleReopen(t, ctx, ended, store)
			wantAccess := slices.DeleteFunc(slices.Clone(cold.accessRecords()), func(row contract.AccessRecord) bool { return row.MaterialKind == contract.OperationSeedMaterialKind })
			checkInterruptedDetachedExit(t, cold, after, targets[last], wantAccess, false)
			operation := fixtureID(after.root.Domain, "competing exits fresh operation")
			incarnations := make(map[string]contract.ID)
			retiring := make(map[string]contract.ValueEntry)
			for _, named := range after.root.Names {
				entry := *after.valueEntry(named.Slot)
				if entry.ValueSource != contract.Generated || entry.Generated.Epoch != 2 || entry.Generated.RetiringDutyPresent != 0 {
					t.Fatal("fresh two-name progress has a different predecessor")
				}
				incarnations[named.Name], retiring[named.Name] = entry.Incarnation, entry
			}
			input := generatedStatePlanInput(t, after, operation, []string{"alpha", "omega"}, defaultGeneratedFixtureProfile(), 3, incarnations, retiring)
			progress := selectTwoNameCurrentGeneration(t, ctx, env, after, input, "competing exits fresh progress")
			progress = generatedLifecycleReopen(t, ctx, progress, store)
			if len(progress.root.Names) != 2 || progress.root.WarningBits&after.root.WarningBits != after.root.WarningBits || !progress.root.Generated.ActiveOwner.IsZero() {
				t.Fatal("fresh two-name generation changed warnings or failed to finish")
			}
			for _, named := range progress.root.Names {
				entry := progress.valueEntry(named.Slot)
				var intent contract.ID
				for _, lineage := range input.graph.Lineages {
					if lineage.Name == named.Name {
						intent = lineage.Templates[0].IntentDigest
					}
				}
				if intent.IsZero() || entry.ValueSource != contract.Generated || entry.Generated.Epoch != 3 || entry.Generated.OriginOperationID != operation || entry.Generated.IntentDigest != intent || entry.Incarnation != incarnations[named.Name] {
					t.Fatal("fresh two-name generation selected a different current value")
				}
				check := env.Custody.Consume(ctx, sessionConsumerSelection(t, progress, progress.admission.recipient, named.Name), custody.StandardValue)
				if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.SinkCalls != 1 {
					t.Fatal("fresh two-name current value is not privately usable", check)
				}
			}
		})
	}
}
