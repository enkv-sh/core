package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
// This control uses the small configured fixture and its synthetic full receipt
// windows. It does not claim the actual 1024-CAS receipt history.
func TestGCConfiguredOrdinaryMutationRetainsSuppliedSecretsMemory(t *testing.T) {
	env, fixture, _ := configuredSuccessionMemoryFixture(t, false)
	deadline := time.Now().Add(10 * time.Minute)
	if outer, finite := t.Deadline(); finite && outer.Before(deadline) {
		deadline = outer
	}
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	store := newGCInterleavingStore(requireAdmittedMemoryStore(t, env.Store))
	current, result := Open(ctx, OpenContext{admission: &fixture.session.admission}, store)
	if current == nil || result.Outcome != ObservedCurrent {
		t.Fatal("configured ordinary control cold open", result)
	}
	windows, bodies, err := current.retainedMutationReceiptBodies()
	if err != nil {
		t.Fatal("configured ordinary control receipt bodies", err)
	}
	seed := gcActualJointSeed{env: env, current: current, windows: *windows, bodies: bodies}
	gcJointOrdinaryMutation(t, ctx, seed, store, current)
}

// full_only: true
// Actual receipt production and joint source construction run once. Each GC
// outcome owns an independent Store copy and the same complete maximum image.
func TestGCActualJointMaximumCapacityAndUsefulReclamationMemory(t *testing.T) {
	timing := startCapacityTimer(t)
	defer timing.finish()
	seed := gcActualJointMaximumSeed(t)
	keys := gcJointObsoletePageKeys(t, seed)
	for _, name := range []string{"all-absent", "all-unknown", "partial", "useful-reclamation"} {
		t.Run(name, func(t *testing.T) {
			// Fixture construction is complete. One finite public-operation
			// context bounds this independent branch; no phase renews it.
			deadline := time.Now().Add(10 * time.Minute)
			if outer, finite := t.Deadline(); finite && outer.Before(deadline) {
				deadline = outer
			}
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			defer cancel()
			memory := selectedMemoryStoreCopy(seed.env.Store.(*memoryStore))
			store := newGCInterleavingStore(memory)
			before, result := Open(t.Context(), OpenContext{admission: &seed.current.admission}, store)
			if before == nil || result.Outcome != ObservedCurrent {
				t.Fatal("joint independent branch open", result)
			}
			gcAssertJointMaximum(t, before)
			assertFullReceiptHistoryBytes(t, before, seed.windows, seed.bodies)
			gcJointInspect(t, ctx, before, store, keys, name)
			plan, encoded := gcInterleavingPreview(t, ctx, before, store, keys, "joint maximum "+name)
			gcJointCheckOriginalTargets(t, memory, before.root.Domain, plan, keys)
			original := gcJointObjectLengths(memory)
			var absentOnReserve bool
			if name == "all-absent" {
				store.afterCAS = func(_ context.Context, head format.Head, write contract.WriteResult) {
					if head.GC == nil || head.GC.Phase != contract.GCReserve || write.Status != contract.WriteAcknowledged || absentOnReserve {
						return
					}
					absentOnReserve = true
					// The plan was validated while all original targets existed.
					// A separate actor removes them after the real selected reserve.
					for _, key := range keys {
						object := memory.objects[key]
						if write := store.deleteExact(key, object.Token); write.Status != contract.WriteAcknowledged {
							t.Fatal("qualified external absence setup", write)
						}
					}
				}
			}
			unknown := make(map[string]bool)
			for i, key := range keys {
				if name == "all-unknown" || name == "partial" && i%2 == 1 {
					unknown[key] = true
				}
			}
			store.delete = func(_ context.Context, key string, _ contract.Token) *contract.WriteResult {
				if unknown[key] {
					return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
				}
				return nil
			}
			beforeCAS := memory.cas
			beforeReads := make(map[string]int, len(keys))
			for _, key := range keys {
				beforeReads[key] = store.readCounts[key]
			}
			beforeDeletes := len(store.deleteCalls)
			engine := gcInterleavingEngine(t, before, store, keys, testtrust.NewCurrent(t, currentControlOf(before).NormalSigning))
			out := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: fixtureID(before.root.Domain, name+" apply request"), EncodedPlan: encoded})
			if err := out.Validate(); err != nil || out.Payload == nil || out.Result.Outcome != ObservedCurrent ||
				!out.Payload.Closed || out.Payload.Active || out.Payload.RemainingCount != uint16(len(unknown)) {
				t.Fatal("joint GC outcome", out.StateResult, out.Result, err)
			}
			if err := engine.Close(); err != nil {
				t.Fatal("joint GC positive local retirement", err)
			}
			if memory.cas-beforeCAS != 4 || !slices.Equal(store.phases, []contract.GCPhase{contract.GCSelect, contract.GCReserve, contract.GCRecordProgress, contract.GCClose}) || len(store.deleteCalls) != 256 {
				t.Fatal("joint GC changed its bounded batched phases/transmissions", memory.cas-beforeCAS, store.phases, len(store.deleteCalls))
			}
			var targetGETs int
			for _, key := range keys {
				targetGETs += store.readCounts[key] - beforeReads[key]
			}
			if targetGETs > 256*6 {
				t.Fatal("joint fixed vector exceeded its 1536 physical target GET ceiling", targetGETs)
			}
			for i, call := range store.deleteCalls[beforeDeletes:] {
				if call.key != keys[i] || call.token != plan.Targets[i].Token {
					t.Fatal("joint delete changed original physical key/token", i)
				}
			}
			for i, row := range out.Payload.Targets {
				want := contract.GCTargetAbsent
				if unknown[keys[i]] {
					want = contract.GCTargetUnknown
				}
				if row.Object != plan.Targets[i].Object || row.Length != plan.Targets[i].Length || row.Digest != plan.Targets[i].Digest || row.Selected.Consumed != 1 || row.Selected.Disposition != want || !row.DeleteAttempted {
					t.Fatal("joint GC changed original target/counter/outcome", i, row)
				}
			}
			after, opened := Open(t.Context(), OpenContext{admission: &before.admission}, store)
			if after == nil || opened.Outcome != ObservedCurrent {
				t.Fatal("joint GC cold selected observation", opened)
			}
			gcAssertJointMaximum(t, after)
			assertFullReceiptHistoryBytes(t, after, seed.windows, seed.bodies)
			gcJointCurrentPreserved(t, before, after)
			if !reflect.DeepEqual(before.root.CurrentAccess, after.root.CurrentAccess) || before.root.WarningBits != after.root.WarningBits {
				t.Fatal("GC changed current access facts or permanent warnings")
			}
			gcJointInspect(t, ctx, after, store, keys, name+" selected")
			deleted, created := gcJointImmutableDelta(t, memory, original, keys)
			t.Logf("actual joint GC outcome=%s targets=256 absent=%d pending=%d deleted_original_bytes=%d all_new_GC_immutable_bytes=%d net_reclaimed_bytes=%d", name, 256-len(unknown), len(unknown), deleted, created, int64(deleted)-int64(created))
			if name == "useful-reclamation" && deleted <= created {
				t.Fatal("complete maximum pass did not reclaim net obsolete bytes", deleted, created)
			}
			if len(unknown) != 0 {
				gcJointPendingPreserved(t, ctx, seed, store, after, plan, encoded, keys, unknown, name)
			}
		})
	}
}

func gcJointInspect(t *testing.T, ctx context.Context, s *StateSession, store *gcInterleavingStore, keys []string, label string) {
	t.Helper()
	beforeCreates, beforeCAS := store.creates, store.cas
	reader, err := NewInstalledCapacityReader(gcInterleavingReadInput(t, s, store, keys))
	if err != nil {
		t.Fatal("joint capacity reader", err)
	}
	defer reader.Close()
	out := reader.InspectCapacity(ctx, CapacityInspectionRequest{RequestNonce: fixtureID(s.root.Domain, label+" capacity request")})
	if out.View == nil || out.StateResult != PublicQuerySuccess || out.View.Selected.OutputBindings != 64 || out.View.Selected.PublicationCoordinates != 1024 || out.View.Selected.PublicationMarkers != 2048 || out.View.Encoded.ChildBytes != s.root.ChildEncodedBytes {
		t.Fatal("complete public joint capacity projection", out.Result)
	}
	if store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("joint capacity inspection entered Store mutation")
	}
	bound := out.View.Continuation.Remaining
	if bound.Status != "sufficient" {
		t.Fatal("joint current continuation bound was not established at the measured limits", bound.Status, bound.ChildPages, bound.ChildPageLimit, bound.ChildEncodedBytes, bound.RootBytes, bound.RootByteLimit)
	}
}

func gcJointCheckOriginalTargets(t *testing.T, store *memoryStore, domain contract.ID, plan contract.GCPlan, keys []string) {
	t.Helper()
	if len(plan.Targets) != 256 || len(plan.Candidates) != 256 {
		t.Fatal("joint preview did not retain exactly 256 targets/candidates", len(plan.Targets), len(plan.Candidates))
	}
	var vectorBytes uint64 = 19 + 2
	for i, target := range plan.Targets {
		key, err := contract.StoreObjectKey(store.desc.Prefix, domain, target.Object)
		object, found := store.objects[key]
		if err != nil || key != keys[i] || !found || target.Token != object.Token || uint64(target.Length) != gcJointStoredLength(object) {
			t.Fatal("joint preview changed the original exact physical target", i, err)
		}
		read := readFixtureStoredBody(object, target.Length)
		if read.Status != contract.ReadOK || target.Digest != contract.Hash(read.Body) || plan.Candidates[i].Classification != contract.GCCandidateEligible {
			t.Fatal("joint preview changed original target bytes or classification", i)
		}
		vectorBytes += 77 + uint64(len(target.Token.Value))
	}
	descriptor, err := contract.GCTargetsDescriptor(plan.Targets)
	if err != nil || descriptor.Count != 256 || descriptor.Length != vectorBytes {
		t.Fatal("independent fixed target framing length", descriptor.Length, vectorBytes, err)
	}
}

func gcJointObjectLengths(store *memoryStore) map[string]uint64 {
	before := make(map[string]uint64, len(store.objects))
	for key, value := range store.objects {
		before[key] = gcJointStoredLength(value)
	}
	return before
}

func gcJointImmutableDelta(t *testing.T, store *memoryStore, before map[string]uint64, targets []string) (uint64, uint64) {
	t.Helper()
	wanted := make(map[string]bool, len(targets))
	for _, key := range targets {
		wanted[key] = true
	}
	var deleted, created uint64
	for key, length := range before {
		if _, present := store.objects[key]; !present {
			if !wanted[key] {
				t.Fatal("GC removed an object outside the immutable original vector")
			}
			deleted += length
		}
	}
	for key, value := range store.objects {
		if _, existed := before[key]; !existed && key != store.desc.HeadKey {
			created += gcJointStoredLength(value)
		}
	}
	return deleted, created
}

func gcJointCurrentPreserved(t *testing.T, before, after *StateSession) {
	t.Helper()
	if !reflect.DeepEqual(before.root.Names, after.root.Names) || !reflect.DeepEqual(before.root.ValueEntryPages, after.root.ValueEntryPages) || !reflect.DeepEqual(before.root.Recipients, after.root.Recipients) || before.root.OutputConfiguration != after.root.OutputConfiguration {
		t.Fatal("GC changed current value, recipient or configuration facts")
	}
	for i, page := range before.pages {
		if page == nil {
			continue
		}
		left, err := format.EncodeValueEntryPage(*page)
		right, nextErr := format.EncodeValueEntryPage(*after.pages[i])
		if err != nil || nextErr != nil || !bytes.Equal(left, right) {
			t.Fatal("GC changed exact selected current value bytes", i, err, nextErr)
		}
	}
}

func gcJointOrdinaryMutation(t *testing.T, ctx context.Context, seed gcActualJointSeed, store *gcInterleavingStore, before *StateSession) *StateSession {
	t.Helper()
	input := before.currentEntryInputs()
	changed := -1
	var original contract.ValueEntry
	for i, row := range input {
		entry := before.valueEntry(namedSlot(t, before, row.Name))
		if row.ValueSource == contract.Supplied && row.ConfidentialityClass == contract.Secret {
			input[i].Retained = &contract.RetainedSecretInput{Incarnation: entry.Incarnation, Material: entry.ValueState}
			input[i].InputBytes = nil
			if changed < 0 {
				removed := slices.IndexFunc(entry.Recipients, func(id contract.ID) bool { return id != before.admission.recipient })
				if removed < 0 {
					continue
				}
				for _, recipient := range before.registry() {
					if recipient.Status != contract.CurrentRecipient || recipient.CurrentBinding == nil || slices.Contains(entry.Recipients, recipient.RecipientID) {
						continue
					}
					changed, original = i, *entry
					input[i].Recipients = slices.Clone(entry.Recipients)
					input[i].Recipients[removed] = recipient.RecipientID
					slices.SortFunc(input[i].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
					break
				}
			}
		}
	}
	if changed < 0 {
		t.Fatal("joint ordinary mutation requires a supplied Secret with an Authority-preserving same-count recipient swap")
	}
	wantRecipients := slices.Clone(input[changed].Recipients)
	env := seed.env
	env.Context, env.Store = ctx, store
	env.Trust = &fixtureTrust{Signer: testtrust.NewCurrent(t, currentControlOf(before).NormalSigning)}
	run := newScenarioRun(t, ctx, env)
	counted, opened := Open(ctx, OpenContext{admission: &before.admission}, run.env.Store)
	if counted == nil || opened.Outcome != ObservedCurrent || !bytes.Equal(counted.body, before.body) || counted.token != before.token {
		t.Fatal("joint ordinary mutation did not reopen its exact counted predecessor", opened)
	}
	f := &environmentFixture{session: counted, admission: OpenContext{admission: &counted.admission}}
	beforeCAS := store.cas
	run.suppliedSelection(f, input)
	after, result := Open(ctx, OpenContext{admission: &f.session.admission}, store)
	if after == nil || result.Outcome != ObservedCurrent || store.cas != beforeCAS+1 ||
		bytes.Equal(after.body, before.body) || after.head.Core.Revision == before.head.Core.Revision ||
		after.root.WarningBits != before.root.WarningBits ||
		after.root.Generated.GeneratedCurrent != before.root.Generated.GeneratedCurrent || after.root.RawBytes != before.root.RawBytes ||
		after.root.ValueEntryCount != before.root.ValueEntryCount || after.root.MembershipCount != before.root.MembershipCount || after.root.SecretCount != before.root.SecretCount ||
		after.root.SecretOrdinaryWrapCount != before.root.SecretOrdinaryWrapCount ||
		after.root.AccessRecordCount != before.root.AccessRecordCount {
		t.Fatal("ordinary same-count recipient swap changed its exact expected dimensions", result)
	}
	for _, named := range before.root.Names {
		old, next := before.valueEntry(named.Slot), after.valueEntry(named.Slot)
		if old.Name == original.Name {
			if next == nil || next.Name != old.Name || next.Incarnation != old.Incarnation || next.ValueSource != contract.Supplied || next.ConfidentialityClass != contract.Secret || !slices.Equal(next.Recipients, wantRecipients) || len(next.Recipients) != len(original.Recipients) || !slices.Contains(next.Recipients, before.admission.recipient) {
				t.Fatal("ordinary supplied target did not select its exact Authority-preserving recipient swap")
			}
			assertFreshSecretValue(t, old, next, true)
			oldPayload, oldErr := contract.InspectCanonicalPayload(old.ValueBytes)
			newPayload, newErr := contract.InspectCanonicalPayload(next.ValueBytes)
			if oldErr != nil || newErr != nil || oldPayload.ContentLength != newPayload.ContentLength {
				t.Fatal("ordinary recipient swap changed target raw length", oldErr, newErr)
			}
		} else if !reflect.DeepEqual(old, next) {
			t.Fatal("ordinary mutation changed an unrelated current value", named.Name)
		}
	}
	if before.root.OutputConfiguration != after.root.OutputConfiguration || !reflect.DeepEqual(before.root.Recipients, after.root.Recipients) {
		t.Fatal("ordinary mutation changed unrelated configuration or recipients")
	}
	assertFullReceiptHistoryBytes(t, after, seed.windows, seed.bodies)
	return after
}

func gcJointPendingPreserved(t *testing.T, ctx context.Context, seed gcActualJointSeed, store *gcInterleavingStore, selected *StateSession,
	plan contract.GCPlan, encoded []byte, keys []string, unknown map[string]bool, label string) {
	t.Helper()
	assertPlan := func(current *StateSession) contract.GCProgress {
		t.Helper()
		got, progress, err := current.selectedGCPlan(plan.OperationID)
		body, encodeErr := contract.EncodeGCPlan(got)
		if err != nil || encodeErr != nil || !bytes.Equal(body, encoded) || !current.root.ActiveGC.IsZero() || len(progress.Targets) != 256 || progress.RemainingCount != uint16(len(unknown)) {
			t.Fatal("joint pending GC lost its exact original plan/vector", err, encodeErr)
		}
		for i, row := range progress.Targets {
			want := contract.GCTargetAbsent
			if unknown[keys[i]] {
				want = contract.GCTargetUnknown
			}
			if row.Consumed != 1 || row.Disposition != want {
				t.Fatal("joint pending GC reset a counter or uncertainty", i, row)
			}
		}
		return progress
	}
	progress := assertPlan(selected)
	if label == "partial" {
		selected = gcJointOrdinaryMutation(t, ctx, seed, store, selected)
		if !contract.GCProgressEqual(assertPlan(selected), progress) {
			t.Fatal("ordinary selection changed exact pending GC plan/progress")
		}
	}
	// Matching present bytes do not grant another allowance after an unknown
	// transmission. Reacquisition and close keep the spent original rows.
	beforeDeletes := len(store.deleteCalls)
	engine := gcInterleavingEngine(t, selected, store, keys, testtrust.NewCurrent(t, currentControlOf(selected).NormalSigning))
	out := engine.Continue(ctx, GCContinueRequest{RequestNonce: fixtureID(plan.DomainID, label+" continue"), OperationID: plan.OperationID})
	if err := out.Validate(); err != nil || out.Payload == nil || out.Result.Outcome != ObservedCurrent || !out.Payload.Closed || out.Payload.RemainingCount != uint16(len(unknown)) || len(store.deleteCalls) != beforeDeletes {
		t.Fatal("joint Continue invented a replacement allowance", out.Result, err, len(store.deleteCalls)-beforeDeletes)
	}
	if err := engine.Close(); err != nil {
		t.Fatal("joint Continue local retirement", err)
	}
	current, result := Open(t.Context(), OpenContext{admission: &selected.admission}, store)
	if current == nil || result.Outcome != ObservedCurrent || !contract.GCProgressEqual(assertPlan(current), progress) {
		t.Fatal("joint Continue changed frozen pending progress", result)
	}
	assertFullReceiptHistoryBytes(t, current, seed.windows, seed.bodies)
	reader, err := NewInstalledCapacityReader(gcInterleavingReadInput(t, current, store, keys))
	if err != nil {
		t.Fatal("joint pending preview reader", err)
	}
	preview := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: fixtureID(plan.DomainID, label+" pending query"), OperationID: fixtureID(plan.DomainID, label+" new operation")})
	reader.Close()
	if preview.Payload == nil || len(preview.Payload.Plan.Targets) != 0 || len(preview.Payload.Plan.Candidates) != 256 {
		t.Fatal("joint fresh query readmitted an original pending target", preview.Result)
	}
	for i, candidate := range preview.Payload.Plan.Candidates {
		// Every original target remains excluded while this plan is pending,
		// including rows whose exact absence has already been established.
		if candidate.Classification != contract.GCCandidateAlreadyPending {
			t.Fatal("joint pending exclusion classification", i, candidate.Classification)
		}
	}
	env := seed.env
	env.Store = store.memoryStore
	env.Trust = &fixtureTrust{Signer: testtrust.NewCurrent(t, currentControlOf(current).NormalSigning)}
	projection := reconstructProjectionFixture(t, env, current, store.memoryStore)
	assertReconstructionProjectionExact(t, projection, current, store.memoryStore)
	returned := reconstructedReceiptHistorySession(t, projection, current)
	if !contract.GCProgressEqual(assertPlan(returned), progress) {
		t.Fatal("joint reconstruction changed pending GC progress")
	}
	assertFullReceiptHistoryBytes(t, returned, seed.windows, seed.bodies)
	projection.Close()
	// Signing-only succession uses the existing admitted replacement owner.
	// No private rewrap is needed and no original GC allowance is restored.
	replacementEnv := syntheticAuthorityScenarioEnvironment(t, env)
	signed, actors := selectReaderSuccessionFixture(t, ctx, replacementEnv, current,
		contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole)
	if !contract.GCProgressEqual(assertPlan(signed), progress) || signed.root.WarningBits != current.root.WarningBits {
		t.Fatal("joint signing succession changed pending GC progress")
	}
	assertFullReceiptHistoryBytes(t, signed, seed.windows, seed.bodies)
	env.Trust = actors.Signers.NormalSuccessor
	gcJointExitOrders(t, ctx, env, signed, plan.OperationID, seed.marker)
}

func gcJointExitOrders(t *testing.T, ctx context.Context, env fixtureEnvironment, selected *StateSession, operation, marker contract.ID) {
	t.Helper()
	var gcOwner, markerOwner bool
	for _, group := range selected.adminIndex.Groups {
		switch group.GroupID {
		case operation:
			gcOwner = group.OwnerKind == format.AdministrativeGC && group.GC != nil && group.DestructiveEffect == 0
		case marker:
			markerOwner = group.OwnerKind == format.AdministrativePublicationMarker && group.EffectEntryCeiling == 1 && group.DestructiveEffect == 0
		}
	}
	if !gcOwner || !markerOwner {
		t.Fatal("joint exit warning basis requires the exact GC and publication marker kinds", gcOwner, markerOwner)
	}
	originalPlan, originalProgress, err := selected.selectedGCPlan(operation)
	originalBytes, encodeErr := contract.EncodeGCPlan(originalPlan)
	if err != nil || encodeErr != nil {
		t.Fatal("joint exit original pending GC plan", err, encodeErr)
	}
	for order, pair := range [][2]contract.ID{{operation, marker}, {marker, operation}} {
		t.Run(gcJointBranchLabel("pending exits", order), func(t *testing.T) {
			store := selectedMemoryStoreCopy(requireAdmittedMemoryStore(t, selected.store))
			current, result := Open(t.Context(), OpenContext{admission: &selected.admission}, store)
			if current == nil || result.Outcome != ObservedCurrent {
				t.Fatal("independent joint exit predecessor", result)
			}
			for _, target := range pair {
				windows, bodies, err := current.retainedMutationReceiptBodies()
				if err != nil || len(windows.Successes) != 256 || len(windows.Failures) != 256 {
					t.Fatal("joint exit predecessor receipt windows", err)
				}
				evicted := windows.Successes[0].OperationID
				candidate, prepared := prepareTestEndSelectedWork(t, current, ctx, target, env.Trust)
				if candidate == nil || prepared.Outcome != ObservedCurrent {
					t.Fatal("joint pending/marker exact administrative exit", prepared)
				}
				beforeCAS := store.cas
				after, observed := current.selectCandidate(t.Context(), candidate)
				if after == nil || observed.Outcome != ObservedCurrent || store.cas != beforeCAS+1 || after.head.EndWork == nil || after.head.EndWork.TargetGroupID != target {
					t.Fatal("joint exit did not select its one exact target", observed)
				}
				for _, group := range after.adminIndex.Groups {
					if group.GroupID == target {
						t.Fatal("joint exit retained the ended target")
					}
				}
				checkEndWorkIndexReserveAgainstActual(t, current, after, target)
				fullAfter, opened := Open(t.Context(), OpenContext{admission: &after.admission}, store)
				if fullAfter == nil || opened.Outcome != ObservedCurrent || !bytes.Equal(fullAfter.body, after.body) || fullAfter.token != after.token {
					t.Fatal("joint exit cold selected state changed its exact HEAD body or token", opened)
				}
				after = fullAfter
				warnings := current.root.WarningBits | WarningDiscardedExactEvidence | WarningPossibleStoreGarbage
				if target == operation {
					if after.root.GCPlans.Count != 0 || !after.root.ActiveGC.IsZero() {
						t.Fatal("joint exact GC ending retained its owner")
					}
				} else {
					warnings |= WarningPublicationOrderValue
					if after.root.GCPlans.Count != current.root.GCPlans.Count {
						t.Fatal("independent marker exit changed the GC owner count")
					}
					if after.root.GCPlans.Count != 0 {
						plan, progress, err := after.selectedGCPlan(operation)
						body, encodeErr := contract.EncodeGCPlan(plan)
						if err != nil || encodeErr != nil || !bytes.Equal(body, originalBytes) || !contract.GCProgressEqual(progress, originalProgress) {
							t.Fatal("independent marker exit changed surviving GC ownership", err, encodeErr)
						}
					}
				}
				if after.root.WarningBits != warnings {
					t.Fatal("joint exit changed exact permanent warning saturation", after.root.WarningBits, warnings)
				}
				got, err := after.receiptWindows(t.Context())
				if err != nil || len(got.Successes) != 256 || !slices.Equal(got.Successes[:255], windows.Successes[1:]) || !slices.Equal(got.Failures, windows.Failures) {
					t.Fatal("joint exit changed independent receipt windows", err)
				}
				last := got.Successes[255]
				if last.OperationKind != contract.OperationEndSelectedWork || last.AdministrativeGroupID != target || last.AdministrativeTargetID != publicationExitTarget(current, target) || last.OperationID != after.head.EndWork.OperationID || last.PredecessorRevisionID != current.head.Core.Revision || last.RequestedRevisionID != after.head.Core.Revision || last.ObservedRevisionID != after.head.Core.Revision {
					t.Fatal("joint exit receipt does not bind its real selected target")
				}
				wantOrder := slices.DeleteFunc(slices.Clone(windows.Order), func(id contract.ID) bool { return id == evicted })
				wantOrder = append(wantOrder, last.OperationID)
				if !slices.Equal(got.Order, wantOrder) {
					t.Fatal("joint exit changed common receipt selection order")
				}
				_, retained, err := after.retainedMutationReceiptBodies()
				if err != nil {
					t.Fatal("joint exit retained receipt bytes", err)
				}
				for id, original := range bodies {
					if id != evicted && !bytes.Equal(retained[id], original) {
						t.Fatal("joint exit changed a retained original receipt byte")
					}
				}
				gcJointCurrentPreserved(t, current, after)
				current = after
			}
		})
	}
}
