package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// The maximum fixture is expensive to build. Each order starts from an exact
// copy of its selected Store objects, so neither order can use the other's
// HEAD, new receipt, or discarded support as its predecessor.
func selectedMemoryStoreCopy(source *memoryStore) *memoryStore {
	source.mu.Lock()
	defer source.mu.Unlock()
	copy := &memoryStore{desc: source.desc, configuration: source.configuration, generation: source.generation, fileBodies: source.fileBodies,
		objects: make(map[string]stored, len(source.objects))}
	for key, object := range source.objects {
		object.Body = bytes.Clone(object.Body)
		copy.objects[key] = object
	}
	return copy
}

func checkJointMaximumEndWorkOrders(t *testing.T, env fixtureEnvironment, closed *StateSession) {
	t.Helper()
	if closed.root.ValueEntryCount != 512 || closed.root.MembershipCount != 4096 ||
		closed.root.Generated.Duties != 127 || closed.root.Generated.Hazards != 1 {
		t.Fatal("two-order predecessor is not the selected joint member/attempt maximum")
	}
	var pair [2]contract.ID
	for _, group := range closed.adminIndex.Groups {
		if group.OwnerKind != format.AdministrativeGeneratedDuty {
			continue
		}
		if pair[0].IsZero() {
			pair[0] = group.GroupID
		} else if group.GroupID != pair[0] {
			pair[1] = group.GroupID
			break
		}
	}
	if pair[1].IsZero() {
		t.Fatal("joint maximum has fewer than two independent selected Duties")
	}
	for _, order := range [][2]contract.ID{pair, {pair[1], pair[0]}} {
		t.Run(fmt.Sprintf("first=%x", order[0][:4]), func(t *testing.T) {
			store := selectedMemoryStoreCopy(env.Store.(*memoryStore))
			ctx := context.Background()
			current, observed := Open(ctx, OpenContext{admission: &closed.admission}, store)
			if current == nil || observed.Outcome != ObservedCurrent ||
				len(current.adminIndex.Groups) != len(closed.adminIndex.Groups) {
				t.Fatal("independent maximum Store copy did not cold-open", observed)
			}
			var originalPageDigests [contract.MaxValueEntryPages]contract.ID
			for i, page := range current.pages {
				if page == nil {
					continue
				}
				body, err := format.EncodeValueEntryPage(*page)
				if err != nil {
					t.Fatal("initial maximum value page", err)
				}
				originalPageDigests[i] = contract.Hash(body)
			}
			originalNames := slices.Clone(current.root.Names)
			originalRecipients := current.root.Recipients
			var selectedOperations [2]contract.ID
			var selectedSummaries [2]uint16
			for step, target := range order {
				before := current
				beforeWindows, err := before.receiptWindows(t.Context())
				if err != nil {
					t.Fatal("selected predecessor receipts", err)
				}
				if len(beforeWindows.Successes) != contract.MutationReceiptWindowLimit ||
					len(beforeWindows.Failures) != contract.MutationReceiptWindowLimit {
					t.Fatal("selected predecessor lacks both full receipt windows", step,
						len(beforeWindows.Successes), len(beforeWindows.Failures))
				}
				_, retainedBodies, err := before.retainedMutationReceiptBodies()
				if err != nil {
					t.Fatal("maximum predecessor receipt bodies", err)
				}
				originalBodies := make(map[contract.ID][]byte, len(retainedBodies))
				for id, body := range retainedBodies {
					originalBodies[id] = bytes.Clone(body)
				}
				assertFullReceiptHistoryBytes(t, before, beforeWindows, originalBodies)
				beforeGroups := make(map[contract.ID]format.AdministrativeGroup, len(before.adminIndex.Groups))
				for _, group := range before.adminIndex.Groups {
					beforeGroups[group.GroupID] = group
				}
				targetGroup, found := beforeGroups[target]
				if !found || targetGroup.OwnerKind != format.AdministrativeGeneratedDuty {
					t.Fatal("independent Duty target was not selected", step)
				}
				var exclusivePages int
				var exclusiveBytes uint64
				for _, page := range before.adminIndex.Pages {
					targetOwned, survives := false, false
					for _, span := range page.Spans {
						survives = survives || span.Mandatory
						for _, owner := range span.GroupIndexes {
							if before.adminIndex.Groups[owner].GroupID == target {
								targetOwned = true
							} else {
								survives = true
							}
						}
					}
					if targetOwned && !survives {
						exclusivePages++
						exclusiveBytes += uint64(page.Ref.Length)
						t.Logf("joint exit predecessor target-only support: step=%d page=%d bytes=%d read-required=%t spans=%d rows=%d",
							step, page.Ref.Index, page.Ref.Length, page.ReadRequired, len(page.Spans), len(page.Rows))
					}
				}
				t.Logf("joint exit predecessor: step=%d target=%x owner-kind=%d duty-kind=%d evidence=%d destructive=%d uncertain-create=%d target-only-pages=%d target-only-bytes=%d pending-releases=%d",
					step, target, targetGroup.OwnerKind, targetGroup.DutyKind, targetGroup.SelectedEvidenceSummary,
					targetGroup.DestructiveEffect, targetGroup.UncertainCreateProof, exclusivePages, exclusiveBytes,
					before.root.Generated.PendingReleases)
				beforeCreates, beforeCAS := store.creates, store.cas
				beforePublic, beforePrivate := env.Custody.Calls()
				candidate, prepared := prepareTestEndSelectedWork(t, before, ctx, target, env.Trust)
				if candidate == nil || prepared.Outcome != ObservedCurrent || store.cas != beforeCAS {
					t.Fatal("maximum selected exit was not prepared before CAS", step, prepared)
				}
				selected, outcome := before.selectCandidate(ctx, candidate)
				if selected == nil || outcome.Outcome != ObservedCurrent || store.cas != beforeCAS+1 ||
					store.creates <= beforeCreates {
					t.Fatal("maximum selected exit did not use one real Store CAS", step, outcome)
				}
				current, observed = Open(ctx, OpenContext{admission: &before.admission}, store)
				if current == nil || observed.Outcome != ObservedCurrent || current.head.EndWork == nil ||
					current.head.EndWork.TargetGroupID != target ||
					len(current.adminIndex.Groups) != len(before.adminIndex.Groups)-1 {
					t.Fatal("maximum exit did not cold-open its exact selected owner set", step, observed)
				}
				boundIndexBytes, boundChildren := checkEndWorkIndexReserveAgainstActual(t, before, current, target)
				if public, private := env.Custody.Calls(); public != beforePublic || private != beforePrivate {
					t.Fatal("maximum administrative exit used effect or decryption custody", step, public-beforePublic, private-beforePrivate)
				}
				for _, group := range current.adminIndex.Groups {
					if _, found := beforeGroups[group.GroupID]; !found || group.GroupID == target {
						t.Fatal("maximum exit changed a surviving owner", step, group.GroupID)
					}
					delete(beforeGroups, group.GroupID)
				}
				if len(beforeGroups) != 1 || beforeGroups[target].GroupID != target ||
					current.root.Generated.Duties != uint32(126-step) || current.root.Generated.Hazards != 1 {
					t.Fatal("maximum exit removed the wrong owner or changed work counters", step)
				}
				for i, page := range current.pages {
					if page == nil {
						if !originalPageDigests[i].IsZero() {
							t.Fatal("maximum exit removed a current value page", step, i)
						}
						continue
					}
					body, err := format.EncodeValueEntryPage(*page)
					if err != nil || contract.Hash(body) != originalPageDigests[i] {
						t.Fatal("maximum exit changed a current value page", step, i, err)
					}
				}
				if !reflect.DeepEqual(current.root.Names, originalNames) ||
					!reflect.DeepEqual(current.root.Recipients, originalRecipients) ||
					current.root.ValueEntryCount != 512 || current.root.MembershipCount != 4096 {
					t.Fatal("maximum exit changed the current supplied population", step)
				}
				for _, named := range before.root.Names {
					entry := before.valueEntry(named.Slot)
					if entry == nil || entry.ConfidentialityClass != format.Secret {
						t.Fatal("maximum current secret is missing", step, named.Slot)
					}
					beforeCore, beforePayload, beforeAccess, beforeOK := before.selectedValue(named.Slot)
					afterCore, afterPayload, afterAccess, afterOK := current.selectedValue(named.Slot)
					if !beforeOK || !afterOK || !reflect.DeepEqual(beforeCore, afterCore) ||
						!reflect.DeepEqual(beforePayload, afterPayload) ||
						beforeAccess.MaterialKind != afterAccess.MaterialKind || beforeAccess.MaterialID != afterAccess.MaterialID ||
						beforeAccess.MaterialContextDigest != afterAccess.MaterialContextDigest || beforeAccess.PackageCheck != afterAccess.PackageCheck {
						t.Fatal("maximum exit changed authenticated current material or access availability", step, named.Slot)
					}
					currentWrap := func(rows []contract.WrapRow) []contract.WrapRow {
						var kept []contract.WrapRow
						for _, wrap := range rows {
							if wrap.SubjectKind == 1 && slices.Contains(entry.Recipients, wrap.SubjectID) ||
								wrap.SubjectKind == 2 && before.root.CurrentAccess.Core.Recovery != nil &&
									wrap.SubjectID == before.root.CurrentAccess.Core.Recovery.RoleID {
								kept = append(kept, wrap)
							}
						}
						return kept
					}
					if !reflect.DeepEqual(currentWrap(beforeAccess.Wraps), currentWrap(afterAccess.Wraps)) {
						t.Fatal("maximum exit changed an eligible current wrap", step, named.Slot)
					}
				}
				secret := maximumLifecycleNames("succession-memory")[0]
				selection := sessionConsumerSelection(t, current, current.admission.recipient, secret)
				consumed := env.Custody.Consume(ctx, selection, custody.MaximumValue)
				if consumed.Code != contract.CryptoSuccess || consumed.Delivery != 1 || !consumed.ValueMatched {
					t.Fatal("maximum current secret cannot be consumed after exit", step, consumed)
				}
				q := current.head.EndWork
				beforeIndexBytes, err := format.AdministrativeIndexEncodedLength(before.adminIndex)
				if err != nil {
					t.Fatal("selected predecessor index length", err)
				}
				afterIndexBytes, err := format.AdministrativeIndexEncodedLength(current.adminIndex)
				if err != nil {
					t.Fatal("selected successor index length", err)
				}
				// This fixture starts with a full success window on dedicated
				// receipt pages. Replacing that selected Store object is enough
				// to require the possible-garbage bit on each exit.
				droppedReceiptPage := false
				for i, page := range before.adminIndex.Pages {
					if slices.ContainsFunc(before.support[i].Records, func(row contract.SupportRecordView) bool {
						return row.Kind == contract.MutationReceiptSupportKind
					}) && !slices.Contains(current.root.RequiredSupport, page.Ref) {
						droppedReceiptPage = true
						break
					}
				}
				if !droppedReceiptPage {
					t.Fatal("maximum fixture did not replace a selected old receipt page", step)
				}
				assertEndWorkSelectedDeletePermissionCount(t, before, 0)
				warning := before.root.WarningBits | WarningOrphanGeneratedEffect | WarningDiscardedExactEvidence | WarningPossibleStoreGarbage
				t.Logf("joint exit account: step=%d root-children=%d,%d subject-children=%d,%d root-bytes=%d,%d subject-bytes=%d,%d support-pages=%d,%d access-pages=%d,%d index-shards=%d,%d index-bytes=%d,%d reserve-children=%d reserve-index-bytes=%d slices-changed=%t access-refs-changed=%t",
					step, before.root.ChildCount, current.root.ChildCount, q.BeforeChildCount, q.AfterChildCount,
					before.root.ChildEncodedBytes, current.root.ChildEncodedBytes, q.BeforeChildBytes, q.AfterChildBytes,
					len(before.root.RequiredSupport), len(current.root.RequiredSupport),
					len(before.root.CurrentAccess.Core.AccessPageRefs), len(current.root.CurrentAccess.Core.AccessPageRefs),
					1+len(before.root.AdministrativeIndexShards), 1+len(current.root.AdministrativeIndexShards),
					beforeIndexBytes, afterIndexBytes, boundChildren, boundIndexBytes,
					before.root.Generated.Slices != current.root.Generated.Slices,
					!slices.Equal(before.root.CurrentAccess.Core.AccessPageRefs, current.root.CurrentAccess.Core.AccessPageRefs))
				t.Logf("joint exit warning account: step=%d before=%d actual=%d expected=%d subject-before=%d subject-after=%d",
					step, before.root.WarningBits, current.root.WarningBits, warning, q.BeforeWarningBits, q.AfterWarningBits)
				for _, page := range before.adminIndex.Pages {
					if slices.Contains(current.root.RequiredSupport, page.Ref) {
						continue
					}
					replaced := slices.ContainsFunc(current.root.RequiredSupport, func(ref contract.Ref) bool { return ref.Index == page.Ref.Index })
					t.Logf("joint exit old support unselected: step=%d page=%d bytes=%d read-required=%t spans=%d rows=%d index-reused=%t",
						step, page.Ref.Index, page.Ref.Length, page.ReadRequired, len(page.Spans), len(page.Rows), replaced)
				}
				for _, ref := range current.root.RequiredSupport {
					if !slices.Contains(before.root.RequiredSupport, ref) {
						t.Logf("joint exit new support selected: step=%d page=%d bytes=%d", step, ref.Index, ref.Length)
					}
				}
				assertJointEndWorkPageAccount(t, before, current, target, afterIndexBytes)
				if q.BeforeChildCount != uint16(before.root.ChildCount) || q.AfterChildCount != uint16(current.root.ChildCount) ||
					q.BeforeChildBytes != before.root.ChildEncodedBytes || q.AfterChildBytes != current.root.ChildEncodedBytes ||
					current.root.ChildCount > contract.MaxChildPages ||
					current.root.WarningBits != warning || q.BeforeWarningBits != before.root.WarningBits ||
					q.AfterWarningBits != warning {
					t.Fatalf("maximum exit lost its child account or exact warning: step=%d root-children=%d,%d subject-children=%d,%d root-bytes=%d,%d subject-bytes=%d,%d warnings-before-actual-expected=%d,%d,%d subject-warnings=%d,%d support-pages=%d,%d access-pages=%d,%d index-shards=%d,%d target-only-pages=%d target-only-bytes=%d",
						step, before.root.ChildCount, current.root.ChildCount, q.BeforeChildCount, q.AfterChildCount,
						before.root.ChildEncodedBytes, current.root.ChildEncodedBytes, q.BeforeChildBytes, q.AfterChildBytes,
						before.root.WarningBits, current.root.WarningBits, warning, q.BeforeWarningBits, q.AfterWarningBits,
						len(before.root.RequiredSupport), len(current.root.RequiredSupport),
						len(before.root.CurrentAccess.Core.AccessPageRefs), len(current.root.CurrentAccess.Core.AccessPageRefs),
						1+len(before.root.AdministrativeIndexShards), 1+len(current.root.AdministrativeIndexShards), exclusivePages, exclusiveBytes)
				}
				afterWindows, err := current.receiptWindows(t.Context())
				evicted := beforeWindows.Successes[0].OperationID
				wantOrder := slices.DeleteFunc(slices.Clone(beforeWindows.Order), func(id contract.ID) bool { return id == evicted })
				wantOrder = append(wantOrder, q.OperationID)
				if err != nil || len(afterWindows.Successes) != contract.MutationReceiptWindowLimit ||
					!reflect.DeepEqual(afterWindows.Failures, beforeWindows.Failures) ||
					!reflect.DeepEqual(afterWindows.Successes[:len(afterWindows.Successes)-1], beforeWindows.Successes[1:]) ||
					!slices.Equal(afterWindows.Order, wantOrder) {
					t.Fatal("maximum exit did not append one bounded success receipt", step, err)
				}
				delete(originalBodies, evicted)
				originalBodies[q.OperationID] = actualGeneratedReceipt(t, current, q.OperationID, contract.ReceiptCanonicalSelected)
				wantWindows := contract.MutationReceiptWindows{DomainID: beforeWindows.DomainID, Successes: append(slices.Clone(beforeWindows.Successes[1:]), afterWindows.Successes[255]), Failures: slices.Clone(beforeWindows.Failures), Order: wantOrder}
				assertFullReceiptHistoryBytes(t, current, wantWindows, originalBodies)
				selectedOperations[step] = q.OperationID
				selectedSummaries[step] = q.SelectedEvidenceSummary
				for priorStep := 0; priorStep <= step; priorStep++ {
					found := false
					for _, receipt := range afterWindows.Successes {
						found = found || receipt.OperationID == selectedOperations[priorStep] &&
							receipt.AdministrativeGroupID == order[priorStep] &&
							receipt.AdministrativeOriginalEvidence == selectedSummaries[priorStep] &&
							(priorStep != step || receipt.AdministrativeWarningChanges == warning&^before.root.WarningBits)
					}
					if !found {
						t.Fatal("maximum exit lost a selected administrative receipt", priorStep)
					}
				}
				t.Logf("joint selected exits order=%x,%x children=%d,%d reserve-children=%d receipts=%d/%d index-shards=%d index-bytes=%d,%d reserve-index-bytes=%d",
					order[0], order[1], before.root.ChildCount, current.root.ChildCount,
					boundChildren, len(afterWindows.Successes), len(afterWindows.Failures),
					1+len(current.root.AdministrativeIndexShards), beforeIndexBytes, afterIndexBytes, boundIndexBytes)
			}
		})
	}
}
