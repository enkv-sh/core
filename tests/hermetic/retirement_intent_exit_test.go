package core

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

type retirementExitLedgerRow struct {
	Cohort, Order, Step                                                                int
	Boundary                                                                           string
	Children                                                                           uint32
	ChildBytes                                                                         uint64
	Groups, SupportPages, AccessPages, IndexShards                                     int
	IndexBytes                                                                         uint64
	ReceiptPages, RequiredReadPages                                                    int
	SuccessReceipts, FailureReceipts                                                   int
	WarningBits                                                                        uint8
	RootDigest                                                                         string
	AddedSupport, DroppedSupport, AddedAccess, DroppedAccess, AddedIndex, DroppedIndex int
	AddedBytes, DroppedBytes                                                           uint64
	PreparedObjects, ImmutableCreateAttempts, ImmutableReadbackCalls                   int
}

// full_only: false
func TestRetirementIntentCompactionKeepsRemainingExits(t *testing.T) {
	var snapshots int
	for _, bCount := range []int{20, 26} {
		t.Run(fmt.Sprintf("b%d", bCount), func(t *testing.T) {
			f := actualFailedHistoryRetirementCarriers(t, bCount)
			baseline := f.selected
			groups := sharedIntentGroupIDs(t, baseline)
			expectedFragments, expectedPages := 9, 5
			if bCount == 26 {
				expectedFragments, expectedPages = 11, 6
			}
			var entries []contract.ValueEntry
			for _, named := range baseline.root.Names {
				entry := baseline.valueEntry(named.Slot)
				if entry.ValueSource == contract.Generated {
					entries = append(entries, *entry)
				}
			}
			slices.SortFunc(entries, func(a, b contract.ValueEntry) int {
				return bytes.Compare(a.Generated.IntentDigest[:], b.Generated.IntentDigest[:])
			})
			var canonical []byte
			offsets := make(map[contract.ID]uint64, len(entries))
			for _, entry := range entries {
				body := hermeticSizedGeneratorIntent(entry.Name, entry.Name[0], 393216)
				offsets[entry.Generated.IntentDigest] = uint64(len(canonical))
				canonical = append(canonical, body...)
			}
			compactBlob := contract.ID(sha256.Sum256(canonical))
			blobRefs := func(root format.Root, blob contract.ID) []format.Ref {
				var refs []format.Ref
				for _, location := range root.Generated.Fragments {
					if location.BlobID != blob {
						continue
					}
					for _, ref := range root.RequiredSupport {
						if ref.Index == location.SupportPageIndex && !slices.Contains(refs, ref) {
							refs = append(refs, ref)
						}
					}
				}
				return refs
			}
			aRefs, bRefs := blobRefs(baseline.root, f.aBlob), blobRefs(baseline.root, f.bBlob)
			if len(aRefs) != 1 || len(bRefs) != expectedPages-1 {
				t.Fatal("producer old whole-page identities changed")
			}
			var pressureDuty, pressureHazard contract.ID
			for _, group := range baseline.adminIndex.Groups {
				if group.GroupID == f.dutyA || group.GroupID == f.dutyB {
					continue
				}
				switch group.OwnerKind {
				case format.AdministrativeGeneratedDuty:
					if !pressureDuty.IsZero() || group.DutyKind != contract.GeneratedDutyUnselectedCleanup {
						t.Fatal("pressure Duty shape changed")
					}
					pressureDuty = group.GroupID
				case format.AdministrativeGeneratedHazard:
					if !pressureHazard.IsZero() {
						t.Fatal("pressure Hazard shape changed")
					}
					pressureHazard = group.GroupID
				default:
					t.Fatal("unexpected independent pressure owner")
				}
			}
			if pressureDuty.IsZero() || pressureHazard.IsZero() {
				t.Fatal("pressure owners are absent")
			}
			pressureOwners := []contract.ID{pressureDuty, pressureHazard}
			pressureWork := mustSelectedGeneratedWork(t, baseline)
			pressureRows := make(map[generatedRecordKey][]byte)
			pressureConsumers := make(map[generatedRecordKey][]contract.ID)
			for _, page := range baseline.adminIndex.Pages {
				if page.ReadRequired {
					view, err := baseline.administrativeSelectedSupportPage(page)
					if err != nil {
						t.Fatal("bounded pressure Slice page", err)
					}
					for _, row := range view.Records {
						carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
						if row.Kind != contract.GeneratorVectorSupportKind || err != nil || carrier.VectorKind != contract.GeneratorVectorSlices {
							t.Fatal("bounded producer has a different required-row class")
						}
					}
					continue
				}
				logical := 0
				for _, span := range page.Spans {
					for n := uint16(0); n < span.Count; n++ {
						summary := page.Rows[logical]
						logical++
						key := generatedRecordKey{summary.Kind, summary.RecordID}
						if key.kind == contract.GeneratedFragmentSupportKind {
							continue
						}
						var consumers []contract.ID
						for _, owner := range span.GroupIndexes {
							id := baseline.adminIndex.Groups[owner].GroupID
							if slices.Contains(pressureOwners, id) {
								consumers = append(consumers, id)
							}
						}
						if len(consumers) == 0 {
							continue
						}
						if span.Mandatory || len(consumers) != len(span.GroupIndexes) {
							t.Fatal("pressure row has an unrelated mandatory consumer")
						}
						row, present := pressureWork.records[key]
						if !present {
							t.Fatal("pressure row has no typed selected body")
						}
						if row.Kind == contract.GeneratorVectorSupportKind {
							carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
							if err != nil {
								t.Fatal("pressure vector body", err)
							}
							if carrier.VectorKind == contract.GeneratorVectorSlices {
								continue
							}
						}
						pressureRows[key], pressureConsumers[key] = bytes.Clone(row.Body), consumers
					}
				}
			}
			if len(pressureRows) == 0 || len(pressureWork.attempts) != 2 {
				t.Fatal("pressure witness has no two original Attempts")
			}
			pressureContent := make(map[generatedContentKey][]byte)
			pressureLocations := make(map[generatedContentKey]contract.GeneratorSliceLocation)
			pressureAccess := make(map[contract.ID]contract.AccessRecord)
			for _, attempt := range pressureWork.attempts {
				bundle, err := pressureWork.retainedGraph(attempt.record.OperationID)
				if err != nil {
					t.Fatal("pressure original Graph", err)
				}
				for _, key := range []generatedContentKey{{contract.GeneratorContentIntent, attempt.expected.Template.IntentDigest}, {contract.GeneratorContentGraph, bundle.UsePlan.PlanGraphID}} {
					limit := uint32(contract.GeneratorIntentMaxLength)
					if key.kind == contract.GeneratorContentGraph {
						limit = contract.GeneratorGraphMaxLength
					}
					body, err := pressureWork.readSelectedSlice(t.Context(), key.kind, key.id, limit)
					if err != nil {
						t.Fatal("pressure original content", err)
					}
					pressureContent[key], pressureLocations[key] = bytes.Clone(body), pressureWork.content.locations[key]
				}
				materialID := attempt.material.Core.OperationMaterialID
				for _, page := range f.current.Access {
					if page == nil {
						continue
					}
					for _, row := range page.Records {
						if row.MaterialKind == contract.OperationSeedMaterialKind && row.MaterialID == materialID {
							pressureAccess[materialID] = row
						}
					}
				}
			}
			if len(pressureContent) != 2 || len(pressureAccess) != 1 {
				t.Fatal("pressure originals do not share the exact Intent/Graph/seed")
			}
			for orderIndex, order := range [][4]contract.ID{{f.dutyA, f.dutyB, pressureDuty, pressureHazard}, {f.dutyB, f.dutyA, pressureHazard, pressureDuty}} {
				store := selectedMemoryStoreCopy(f.env.Store.(*memoryStore))
				selected, result := Open(t.Context(), OpenContext{admission: &baseline.admission}, store)
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal("exit order independent cold Open", result)
				}
				var ended []contract.ID
				var firstCompactRefs []format.Ref
				for step, target := range order {
					before := selected
					var targetGroup format.AdministrativeGroup
					for _, group := range before.adminIndex.Groups {
						if group.GroupID == target {
							targetGroup = group
						}
					}
					if targetGroup.GroupID.IsZero() {
						t.Fatal("selected exit target is absent")
					}
					beforeImage := sessionStateImage(t, before)
					beforeRoot := beforeImage.Root
					beforeBody := bytes.Clone(before.body)
					windows, err := before.receiptWindows(t.Context())
					if err != nil || len(windows.Successes) >= contract.MutationReceiptWindowLimit {
						t.Fatal("small exit predecessor receipts", err)
					}
					capture := func(boundary string, root format.Root, index format.AdministrativeIndex, successes, failures int) retirementExitLedgerRow {
						length, err := format.AdministrativeIndexEncodedLength(index)
						if err != nil {
							t.Fatal("exit ledger index encoding", err)
						}
						receiptBlob, err := contract.MutationReceiptIndexBlobID(root.Domain, root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder)
						if err != nil {
							t.Fatal("exit ledger receipt index identity", err)
						}
						receiptPages := make(map[uint16]bool)
						requiredReadPages := 0
						for _, page := range index.Pages {
							if page.ReadRequired {
								requiredReadPages++
							}
							for _, row := range page.Rows {
								if row.Kind == contract.MutationReceiptSupportKind {
									receiptPages[page.Ref.Index] = true
								}
							}
						}
						for _, location := range root.Generated.Fragments {
							if location.BlobID == receiptBlob {
								receiptPages[location.SupportPageIndex] = true
							}
						}
						body, err := format.EncodeRoot(root)
						if err != nil {
							t.Fatal("exit ledger root encoding", err)
						}
						digest := sha256.Sum256(body)
						row := retirementExitLedgerRow{Cohort: bCount, Order: orderIndex, Step: step, Boundary: boundary, Children: root.ChildCount, ChildBytes: root.ChildEncodedBytes,
							Groups: len(index.Groups), SupportPages: len(root.RequiredSupport), AccessPages: len(root.CurrentAccess.Core.AccessPageRefs), IndexShards: 1 + len(root.AdministrativeIndexShards), IndexBytes: length,
							ReceiptPages: len(receiptPages), RequiredReadPages: requiredReadPages, SuccessReceipts: successes, FailureReceipts: failures, WarningBits: root.WarningBits, RootDigest: fmt.Sprintf("%x", digest)}
						snapshots++
						t.Logf("exit ledger %+v", row)
						return row
					}
					prior := capture("predecessor", beforeRoot, beforeImage.AdministrativeIndex, len(windows.Successes), len(windows.Failures))
					beforeCAS, beforeCreates := store.cas, store.creates
					beforeHEAD := store.objects[store.desc.HeadKey]
					beforeHEAD.Body = bytes.Clone(beforeHEAD.Body)
					public, private := f.env.Custody.Calls()
					if store.readHook != nil || store.createMode != "" || store.casMode != "" {
						t.Fatal("exit write ledger requires the unchanged healthy Store fixture")
					}
					type readbackFact struct {
						Calls, OK int
						Length    uint64
						Digest    contract.ID
					}
					readbacks := make(map[string]readbackFact)
					candidate, prepared := func() (*Candidate, Result) {
						store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
							fact := readbacks[key]
							fact.Calls++
							if read.Status == contract.ReadOK {
								fact.OK++
								fact.Length, fact.Digest = uint64(len(read.Body)), contract.Hash(read.Body)
							}
							readbacks[key] = fact
							return read
						}
						defer func() { store.readHook = nil }()
						return prepareTestEndSelectedWork(t, before, t.Context(), target, f.env.Trust)
					}()
					if candidate == nil || prepared.Outcome != ObservedCurrent {
						t.Fatal("actual retirement exit preparation", target, prepared)
					}
					var plannedRoot format.Root
					var rootBody []byte
					for _, object := range candidate.objects {
						if object.ref == candidate.head.Core.Root {
							if rootBody != nil || format.CheckReference(object.ref, object.body) != nil {
								t.Fatal("candidate root image identity")
							}
							rootBody = bytes.Clone(object.body)
							plannedRoot, err = format.DecodeRoot(rootBody)
							if err != nil {
								t.Fatal("candidate root decoding", err)
							}
						}
					}
					if rootBody == nil {
						t.Fatal("candidate omitted exact root image")
					}
					refs := append([]format.Ref{plannedRoot.AdministrativeIndex}, plannedRoot.AdministrativeIndexShards...)
					pages := make([]format.AdministrativeIndexPage, 0, len(refs))
					for _, ref := range refs {
						found := false
						for _, object := range candidate.objects {
							if object.ref == ref {
								if found || format.CheckReference(ref, object.body) != nil {
									t.Fatal("candidate index image identity")
								}
								pages = append(pages, format.AdministrativeIndexPage{Ref: ref, Body: object.body})
								found = true
							}
						}
						if !found {
							t.Fatal("candidate omitted fresh administrative shard")
						}
					}
					plannedIndex, err := format.DecodeAdministrativeIndexPages(pages)
					if err != nil {
						t.Fatal("candidate index decoding", err)
					}
					planned := capture("candidate", plannedRoot, plannedIndex, len(windows.Successes)+1, len(windows.Failures))
					difference := func(old, next []format.Ref) (int, int, uint64, uint64) {
						var added, dropped int
						var addedBytes, droppedBytes uint64
						for _, ref := range next {
							if !slices.Contains(old, ref) {
								added++
								addedBytes += uint64(ref.Length)
							}
						}
						for _, ref := range old {
							if !slices.Contains(next, ref) {
								dropped++
								droppedBytes += uint64(ref.Length)
							}
						}
						return added, dropped, addedBytes, droppedBytes
					}
					var added, dropped uint64
					planned.AddedSupport, planned.DroppedSupport, added, dropped = difference(beforeRoot.RequiredSupport, plannedRoot.RequiredSupport)
					planned.AddedBytes += added
					planned.DroppedBytes += dropped
					planned.AddedAccess, planned.DroppedAccess, added, dropped = difference(beforeRoot.CurrentAccess.Core.AccessPageRefs, plannedRoot.CurrentAccess.Core.AccessPageRefs)
					planned.AddedBytes += added
					planned.DroppedBytes += dropped
					oldIndexRefs := append([]format.Ref{beforeRoot.AdministrativeIndex}, beforeRoot.AdministrativeIndexShards...)
					planned.AddedIndex, planned.DroppedIndex, added, dropped = difference(oldIndexRefs, refs)
					planned.AddedBytes += added
					planned.DroppedBytes += dropped
					planned.PreparedObjects = len(candidate.objects)
					planned.ImmutableCreateAttempts = store.creates - beforeCreates
					for _, object := range candidate.objects {
						key, err := format.Key(store.desc.Prefix, object.ref)
						if err != nil {
							t.Fatal("candidate immutable readback key", err)
						}
						planned.ImmutableReadbackCalls += readbacks[key].Calls
					}
					t.Logf("exit physical delta %+v", planned)
					q := candidate.head.EndWork
					childDelta := planned.AddedSupport - planned.DroppedSupport + planned.AddedAccess - planned.DroppedAccess + planned.AddedIndex - planned.DroppedIndex
					if q == nil || q.TargetGroupID != target || q.TargetOwnerID != targetGroup.OwnerID || q.TargetID != targetGroup.TargetID || q.TargetKind != targetGroup.OwnerKind || q.DutyKind != targetGroup.DutyKind || q.SelectedEvidenceSummary != targetGroup.SelectedEvidenceSummary || q.DependentGroups.Count != 1 || q.BeforeChildCount != uint16(prior.Children) || q.AfterChildCount != uint16(planned.Children) || q.BeforeChildBytes != prior.ChildBytes || q.AfterChildBytes != planned.ChildBytes {
						t.Fatal("actual candidate signed subject differs from physical ledger")
					}
					if int64(planned.Children)-int64(prior.Children) != int64(childDelta) || int64(planned.ChildBytes)-int64(prior.ChildBytes) != int64(planned.AddedBytes)-int64(planned.DroppedBytes) {
						t.Fatal("actual candidate differs from exact physical page delta")
					}
					if !reflect.DeepEqual(beforeRoot.ValueEntryPages, plannedRoot.ValueEntryPages) || !reflect.DeepEqual(beforeRoot.Recipients, plannedRoot.Recipients) {
						t.Fatal("retirement of noncurrent entries changed value or recipient page identity")
					}
					if !reflect.DeepEqual(before.root, beforeRoot) || !reflect.DeepEqual(before.adminIndex, beforeImage.AdministrativeIndex) || !bytes.Equal(before.body, beforeBody) {
						t.Fatal("EndWork preparation changed its selected predecessor")
					}
					// The existing true preparation helper persists and signs immutable
					// candidate objects. Selection alone performs the HEAD CAS.
					expectedObjects := []format.Ref{candidate.head.Core.Root}
					for _, pair := range [][2][]format.Ref{{beforeRoot.RequiredSupport, plannedRoot.RequiredSupport}, {beforeRoot.CurrentAccess.Core.AccessPageRefs, plannedRoot.CurrentAccess.Core.AccessPageRefs}, {oldIndexRefs, refs}} {
						for _, ref := range pair[1] {
							if !slices.Contains(pair[0], ref) {
								expectedObjects = append(expectedObjects, ref)
							}
						}
					}
					seenObjects := make(map[format.Ref]bool, len(candidate.objects))
					for _, object := range candidate.objects {
						if seenObjects[object.ref] || !slices.Contains(expectedObjects, object.ref) {
							t.Fatal("preparation persisted duplicate or uncharged candidate object")
						}
						seenObjects[object.ref] = true
						key, err := format.Key(store.desc.Prefix, object.ref)
						fact := readbacks[key]
						if err != nil || format.CheckReference(object.ref, object.body) != nil || fact.Calls != 1 || fact.OK != 1 || fact.Length != uint64(object.ref.Length) || fact.Digest != object.ref.Digest {
							t.Fatal("candidate immutable lacks one exact successful preparation readback")
						}
					}
					if !reflect.DeepEqual(store.objects[store.desc.HeadKey], beforeHEAD) {
						t.Fatal("EndWork preparation changed the stored HEAD")
					}
					if len(candidate.objects) != len(expectedObjects) || planned.ImmutableCreateAttempts != len(expectedObjects) || planned.ImmutableReadbackCalls != len(expectedObjects) || store.cas != beforeCAS {
						t.Fatalf("preparation immutable writes or selection boundary: objects=%d expected=%d creates=%d cas_delta=%d", len(candidate.objects), len(expectedObjects), planned.ImmutableCreateAttempts, store.cas-beforeCAS)
					}
					selected, result = before.selectCandidate(t.Context(), candidate)
					if selected == nil || result.Outcome != ObservedCurrent || store.cas != beforeCAS+1 {
						t.Fatal("actual retirement exit selection", result)
					}
					selected = generatedLifecycleReopen(t, t.Context(), selected, store)
					afterWindows, err := selected.receiptWindows(t.Context())
					if err != nil {
						t.Fatal("selected exit receipts", err)
					}
					actual := capture("selected_cold", selected.root, selected.adminIndex, len(afterWindows.Successes), len(afterWindows.Failures))
					encoded, err := format.EncodeRoot(selected.root)
					if err != nil || !bytes.Equal(encoded, rootBody) || actual.RootDigest != planned.RootDigest || actual.Children != planned.Children || actual.ChildBytes != planned.ChildBytes || actual.IndexBytes != planned.IndexBytes || actual.IndexShards != planned.IndexShards {
						t.Fatal("selected cold image differs from actual candidate", err)
					}
					assertEndWorkSelectedDeletePermissionCount(t, before, 0)
					if p, k := f.env.Custody.Calls(); p != public || k != private {
						t.Fatal("retirement EndWork used a KMS route")
					}
					if len(afterWindows.Successes) != len(windows.Successes)+1 || !reflect.DeepEqual(afterWindows.Successes[:len(windows.Successes)], windows.Successes) || !reflect.DeepEqual(afterWindows.Failures, windows.Failures) {
						t.Fatal("exit changed old receipt windows")
					}
					receipt := afterWindows.Successes[len(afterWindows.Successes)-1]
					if receipt.OperationID != q.OperationID || receipt.OperationKind != contract.OperationEndSelectedWork || receipt.StateResult != contract.ReceiptStateWorkEnded || receipt.EffectSummary != contract.ReceiptEffectNotApplicable || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.AdministrativeDisposition != q.RequestCoreDigest || receipt.AdministrativeTargetID != q.TargetID || receipt.AdministrativePageDelta != int16(childDelta) || receipt.AdministrativeByteDelta != int64(planned.ChildBytes)-int64(prior.ChildBytes) {
						t.Fatal("selected receipt lost exact administrative disposition")
					}
					if selected.root.WarningBits&beforeRoot.WarningBits != beforeRoot.WarningBits || selected.root.WarningBits&(WarningOrphanGeneratedEffect|WarningDiscardedExactEvidence|WarningPossibleStoreGarbage) != WarningOrphanGeneratedEffect|WarningDiscardedExactEvidence|WarningPossibleStoreGarbage || q.BeforeWarningBits != beforeRoot.WarningBits || q.AfterWarningBits != selected.root.WarningBits {
						t.Fatal("exit lost permanent required warnings")
					}
					ended = append(ended, target)
					assertSharedIntentGroupIDs(t, selected, groups, ended...)
					if step < 2 {
						f.assertPressure(selected)
					}
					f.assertCurrent(selected)
					var wantRetiring, wantDuties, wantHazards uint32
					for _, group := range baseline.adminIndex.Groups {
						if slices.Contains(ended, group.GroupID) {
							continue
						}
						if group.OwnerKind == format.AdministrativeGeneratedDuty {
							wantDuties++
							if group.DutyKind == contract.GeneratedDutyRetirement {
								wantRetiring++
							}
						}
						if group.OwnerKind == format.AdministrativeGeneratedHazard {
							wantHazards++
						}
					}
					if selected.root.Generated.Retiring != wantRetiring || selected.root.Generated.Duties != wantDuties || selected.root.Generated.Hazards != wantHazards || selected.root.Generated.PendingReleases != 0 {
						t.Fatal("exit changed independent generated owner census")
					}
					work := mustSelectedGeneratedWork(t, selected)
					remainingPressure := 0
					for _, id := range pressureOwners {
						if !slices.Contains(ended, id) {
							remainingPressure++
						}
					}
					if len(work.attempts) != remainingPressure || len(work.releases) != 0 {
						t.Fatal("pressure disposition changed original Attempt/release census")
					}
					for key, body := range pressureRows {
						keep := slices.ContainsFunc(pressureConsumers[key], func(id contract.ID) bool { return !slices.Contains(ended, id) })
						got, present := work.records[key]
						if present != keep || keep && !bytes.Equal(got.Body, body) {
							t.Fatal("pressure disposition differs from exact remaining original consumers", key.kind)
						}
					}
					for key, body := range pressureContent {
						location, present := work.content.locations[key]
						if present != (remainingPressure != 0) {
							t.Fatal("pressure original content lifetime changed")
						}
						if present {
							limit := uint32(contract.GeneratorIntentMaxLength)
							if key.kind == contract.GeneratorContentGraph {
								limit = contract.GeneratorGraphMaxLength
							}
							actual, err := work.readSelectedSlice(t.Context(), key.kind, key.id, limit)
							if err != nil || location != pressureLocations[key] || !bytes.Equal(actual, body) {
								t.Fatal("surviving pressure content changed", err)
							}
						}
						for _, ref := range blobRefs(baseline.root, pressureLocations[key].BlobID) {
							if slices.Contains(selected.root.RequiredSupport, ref) != (remainingPressure != 0) {
								t.Fatal("pressure whole-page lifetime changed")
							}
						}
					}
					for id, want := range pressureAccess {
						actual, present := selected.materialAccess(contract.OperationSeedMaterialKind, id)
						if present != (remainingPressure != 0) || present && !reflect.DeepEqual(actual, want) {
							t.Fatal("pressure seed access lifetime changed")
						}
					}
					for _, entry := range entries {
						location, mandatory, _, found := sharedIntentCarrier(t, selected, entry.Generated.IntentDigest)
						if !found || !mandatory || location.BlobID != compactBlob || location.Offset != offsets[entry.Generated.IntentDigest] || location.Length != 393216 {
							t.Fatal("current Intent differs from independent compact body")
						}
					}
					compactRefs := blobRefs(selected.root, compactBlob)
					fragments := 0
					for _, location := range selected.root.Generated.Fragments {
						if location.BlobID == compactBlob {
							fragments++
						}
					}
					if len(compactRefs) != expectedPages || fragments != expectedFragments {
						t.Fatal("actual compact image has wrong fragment/page count")
					}
					if step == 0 {
						firstCompactRefs = slices.Clone(compactRefs)
					} else if !slices.Equal(compactRefs, firstCompactRefs) {
						t.Fatal("remaining exit rewrote the canonical current Intent pages")
					}
					for i, entry := range []contract.ValueEntry{f.a, f.b} {
						_, _, _, found := sharedIntentCarrier(t, selected, entry.Generated.IntentDigest)
						isEnded := slices.Contains(ended, []contract.ID{f.dutyA, f.dutyB}[i])
						if found == isEnded {
							t.Fatal("noncurrent Intent lifetime differs from its exact retirement owner")
						}
						oldRefs := aRefs
						if i == 1 {
							oldRefs = bRefs
						}
						for _, ref := range oldRefs {
							if slices.Contains(selected.root.RequiredSupport, ref) == isEnded {
								t.Fatal("old whole blob page release differs from exact retirement lifetime")
							}
						}
					}
					for _, name := range []string{"a-01", "b-01"} {
						consumed := f.env.Custody.Consume(t.Context(), sessionConsumerSelection(t, selected, selected.admission.recipient, name), custody.StandardValue)
						if consumed.Code != contract.CryptoSuccess || consumed.Delivery != 1 || !consumed.ValueMatched {
							t.Fatal("current cohort value is not privately consumable after exit", name, consumed.Code)
						}
					}
				}
			}
		})
	}
	if !t.Failed() && snapshots != 48 {
		t.Fatal("exit orders did not complete every selected boundary")
	}
}
