package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type preparationFaultStore struct {
	*memoryStore
	target, mode string
	events       []preparationFaultEvent
}

type preparationFaultEvent struct {
	key     string
	write   contract.WriteStatus
	read    contract.ReadStatus
	maximum uint32
	notSent bool
	body    []byte
}

func (s *preparationFaultStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	if key == s.target && (s.mode == "readback-absent" || s.mode == "create-refused") {
		s.createMode = "lost-before"
		defer func() { s.createMode = "" }()
	}
	r := s.memoryStore.Create(ctx, key, body)
	if key == s.target && s.mode == "create-refused" {
		r = contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
	}
	if key == s.target && s.mode == "accepted-conflict" && r.Status == contract.WriteAcknowledged {
		r = contract.WriteResult{Status: contract.WriteConflict, Reason: contract.ReasonCondition}
	}
	if key == s.target && (s.mode == "accepted-lost-reply" || s.mode == "readback-unavailable") && r.Status == contract.WriteAcknowledged {
		r = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	}
	if key == s.target && s.mode == "preexisting-equal-lost-reply" && r.Status == contract.WritePrecondition {
		r = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	}
	s.events = append(s.events, preparationFaultEvent{key: key, write: r.Status, notSent: r.NotSent, body: bytes.Clone(body)})
	return r
}

func (s *preparationFaultStore) Read(ctx context.Context, key string, max uint32) contract.ReadResult {
	r := s.memoryStore.Read(ctx, key, max)
	if key == s.target {
		switch s.mode {
		case "readback-absent":
			r = contract.ReadResult{Status: contract.ReadMissing}
		case "readback-unavailable":
			r = contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
		case "readback-invalid":
			r = contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
		case "readback-different-equal-length":
			r.Body[len(r.Body)-1] ^= 1
		}
	}
	s.events = append(s.events, preparationFaultEvent{key: key, read: r.Status, maximum: max, body: bytes.Clone(r.Body)})
	return r
}

func mixedLifecycleInput(before stateImage) []ApplyEntryInput {
	input := before.entryInputs()
	input = input[:len(input)/2]
	input[0].InputBytes, input[1].InputBytes = []byte("changed first page"), []byte("changed retained page")
	addition := input[0]
	addition.Name, addition.InputBytes = "new-member-a", []byte("added member")
	input = append(input, addition)
	addition.Name, addition.InputBytes = "new-member-b", nil
	return append(input, addition)
}

func expectedImmutableObjects(t *testing.T, before, after stateImage) []objectImage {
	t.Helper()
	var objects []objectImage
	for index, ref := range after.Root.ValueEntryPages {
		if ref == nil || before.Root.ValueEntryPages[index] != nil && *ref == *before.Root.ValueEntryPages[index] {
			continue
		}
		body, err := format.EncodeValueEntryPage(*after.Pages[index])
		if err != nil {
			t.Fatal(err)
		}
		objects = append(objects, objectImage{ref: *ref, body: body})
	}
	for _, ref := range after.Root.RequiredSupport {
		retained := false
		for _, original := range before.Root.RequiredSupport {
			retained = retained || original == ref
		}
		if retained {
			continue
		}
		var page *format.RequiredSupportPageView
		for i := range after.Support {
			if after.Support[i].Index == ref.Index && after.Support[i].Object == ref.Object {
				page = &after.Support[i]
			}
		}
		if page == nil {
			t.Fatal("expected successor support page is absent")
		}
		rows := make([]contract.SupportRecord, len(page.Records))
		for i, row := range page.Records {
			rows[i] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		if err != nil || format.CheckReference(ref, body) != nil {
			t.Fatal("expected successor support page differs", err)
		}
		objects = append(objects, objectImage{ref: ref, body: body})
	}
	indexPages, err := format.EncodeAdministrativeIndexPages(after.AdministrativeIndex)
	if err != nil || len(indexPages) != 1+len(after.Root.AdministrativeIndexShards) || indexPages[0].Ref != after.Root.AdministrativeIndex {
		t.Fatal("expected successor administrative index:", err)
	}
	for i, page := range indexPages {
		if i > 0 && page.Ref != after.Root.AdministrativeIndexShards[i-1] {
			t.Fatal("expected successor administrative index shard differs")
		}
		objects = append(objects, objectImage{ref: page.Ref, body: page.Body})
	}
	body, err := format.EncodeRoot(after.Root)
	if err != nil {
		t.Fatal(err)
	}
	return append(objects, objectImage{ref: after.RootRef, body: body})
}

// full_only: false
func TestPreparationFaultAtEachImmutableObject(t *testing.T) {
	for _, shape := range []struct {
		name       string
		count      int
		fragmented bool
		targets    int
	}{
		{"changed-and-dropped-pages", 32, true, 4},
		{"new-page", 16, false, 3},
		{"dropped-page", 32, false, 2},
		{"last-removal", 1, false, 2},
	} {
		for targetIndex := range shape.targets {
			targetName := fmt.Sprintf("%s/object-%d", shape.name, targetIndex)
			for _, tc := range []struct {
				name        string
				outcome     Outcome
				reason      Reason
				writeStatus contract.WriteStatus
				readStatus  contract.ReadStatus
			}{
				{"preexisting-equal", ObservedCurrent, NoReason, contract.WritePrecondition, contract.ReadOK},
				{"preexisting-equal-lost-reply", ObservedCurrent, NoReason, contract.WriteUnknown, contract.ReadOK},
				{"preexisting-conflicting", IntegrityFailure, ImmutableConflict, contract.WritePrecondition, contract.ReadOK},
				{"accepted-lost-reply", ObservedCurrent, NoReason, contract.WriteUnknown, contract.ReadOK},
				{"accepted-conflict", ObservedCurrent, NoReason, contract.WriteConflict, contract.ReadOK},
				{"create-refused", EvidenceUnavailable, ReadUnavailable, contract.WriteRefused, contract.ReadMissing},
				{"readback-absent", EvidenceUnavailable, ReadUnavailable, contract.WriteUnknown, contract.ReadMissing},
				{"readback-unavailable", EvidenceUnavailable, ReadUnavailable, contract.WriteUnknown, contract.ReadUnavailable},
				{"readback-invalid", IntegrityFailure, ImmutableConflict, contract.WriteAcknowledged, contract.ReadInvalid},
				{"readback-different-equal-length", IntegrityFailure, ImmutableConflict, contract.WriteAcknowledged, contract.ReadOK},
			} {
				t.Run(targetName+"/"+tc.name, func(t *testing.T) {
					ctx := context.Background()
					f := newFixture(t, shape.count, shape.fragmented, 1)
					before := fixtureStateImage(t, f)
					configurationRef := singleConfigurationRef(t, f.store.desc, before)
					configurationKey := mustKey(t, f.store.desc.Prefix, configurationRef)
					selected := f.store.objects[f.store.desc.HeadKey]
					input := before.entryInputs()
					switch shape.name {
					case "changed-and-dropped-pages":
						input = mixedLifecycleInput(before)
					case "new-page":
						addition := input[0]
						addition.Name, addition.InputBytes = "new-page-member", []byte("new page")
						input = append(input, addition)
					case "dropped-page":
						input = input[:16]
					case "last-removal":
						input = nil
					}
					comparison, result := f.session.Compare(context.Background(), input, admitSuppliedComparison(t, f.session, nil, input))
					if comparison == nil {
						t.Fatal(result)
					}
					permit := admit(t, f.session, comparison)
					want := expectedSuccessorImage(t, before, input, observeAllocatedTransitionInputs(permit))
					objects := expectedImmutableObjects(t, before, want)
					if len(objects) != shape.targets {
						t.Fatalf("expected %d objects, got %d", shape.targets, len(objects))
					}
					bodies := make([][]byte, len(objects))
					keys := make([]string, len(objects))
					for i, object := range objects {
						bodies[i], keys[i] = object.body, mustKey(t, f.store.desc.Prefix, object.ref)
					}
					store := &preparationFaultStore{memoryStore: f.store, target: keys[targetIndex], mode: tc.name}
					f.session.store = store
					reads := f.store.reads
					if tc.name == "preexisting-equal" || tc.name == "preexisting-equal-lost-reply" || tc.name == "preexisting-conflicting" {
						body := bytes.Clone(bodies[targetIndex])
						if tc.name == "preexisting-conflicting" {
							body[len(body)-1] ^= 1
						}
						f.store.put(store.target, body)
					}
					// Preseeded collisions belong to the inventory before this
					// attempt. They are not creations by the attempted operation.
					inventory := make(map[string]stored, len(f.store.objects))
					for key, object := range f.store.objects {
						inventory[key] = stored{Body: bytes.Clone(object.Body), Token: object.Token}
					}
					selectedKeys := map[string]bool{f.store.desc.HeadKey: true, mustKey(t, f.store.desc.Prefix, before.RootRef): true,
						mustKey(t, f.store.desc.Prefix, before.Root.AdministrativeIndex): true}
					for _, table := range [][]*format.Ref{before.Root.ValueEntryPages[:], before.Root.Recipients[:]} {
						for _, ref := range table {
							if ref != nil {
								selectedKeys[mustKey(t, f.store.desc.Prefix, *ref)] = true
							}
						}
					}
					for _, table := range [][]format.Ref{before.Root.RequiredSupport, before.Root.AdministrativeIndexShards, before.Root.CurrentAccess.Core.AccessPageRefs} {
						for _, ref := range table {
							selectedKeys[mustKey(t, f.store.desc.Prefix, ref)] = true
						}
					}
					var oldCurrentBytes int
					for key := range selectedKeys {
						oldCurrentBytes += len(inventory[key].Body)
					}
					candidate, result := f.session.Prepare(ctx, comparison, permit, f.trust)
					wantResult := Result{Outcome: tc.outcome, Reason: tc.reason}
					count, signs := targetIndex+1, 0
					physicalWrites, physicalReads := count, count
					switch tc.name {
					case "create-refused":
						wantResult.Reason = WriteUncertain
						wantResult.StoreReason = contract.ReasonAccess
						physicalReads--
					case "readback-absent":
						wantResult.StoreReason = contract.ReasonTransport
						physicalWrites += 2
						physicalReads += 2
					case "readback-unavailable":
						wantResult.StoreReason = contract.ReasonTransport
						physicalReads += 2
					}
					if tc.outcome == ObservedCurrent {
						count, signs = len(objects), 1
						physicalWrites, physicalReads = count, count
						wantResult.RequestedRevision = want.Revision
						wantResult.ObservedRevision, wantResult.ObservedSnapshotID = before.Revision, before.Root.Snapshot
						wantResult.Evidence = AuthenticatedClosure
					}
					receiptReads := processPlainReceiptIndexReadRequests(t, f.store.desc, want)
					physicalReads += 1 + len(receiptReads)
					if result != wantResult || (candidate != nil) != (tc.outcome == ObservedCurrent) {
						t.Fatalf("Prepare = %+v, want %+v; candidate present = %v", result, wantResult, candidate != nil)
					}
					if f.store.creates != physicalWrites || f.store.reads-reads != physicalReads || len(store.events) != physicalWrites+physicalReads || f.trust.signs != signs || f.store.cas != 0 || !permit.used || !f.session.prepared {
						t.Fatalf("preparation boundary: creates=%d reads=%d signs=%d CAS=%d permit used=%v session prepared=%v", f.store.creates, f.store.reads-reads, f.trust.signs, f.store.cas, permit.used, f.session.prepared)
					}
					var knownCount, knownBytes, unknownUpperCount, unknownUpperBytes int
					var knownPresentCount, knownPresentBytes int
					writeStatuses := make([]int, 0, physicalWrites)
					readStatuses := make([]int, 0, physicalReads)
					configurationRead := store.events[0]
					if configurationRead.key != configurationKey || configurationRead.maximum != configurationRef.Length ||
						configurationRead.read != contract.ReadOK || configurationRead.write != 0 ||
						format.CheckReference(configurationRef, configurationRead.body) != nil ||
						!bytes.Equal(configurationRead.body, inventory[configurationKey].Body) {
						t.Fatal("preparation changed the selected configuration read key, bound, authenticated bytes or order")
					}
					t.Logf("preparation selected configuration read: key=%s maximum=%d immutable_readbacks=%d", configurationKey, configurationRef.Length, physicalReads-1-len(receiptReads))
					for index, expected := range receiptReads {
						event := store.events[index+1]
						if event.key != expected.Key || event.maximum != expected.Maximum || event.read != contract.ReadOK || event.write != 0 || !bytes.Equal(event.body, inventory[expected.Key].Body) {
							t.Fatal("prospective receipt authentication changed its exact key, bound, bytes or order")
						}
					}
					eventIndex := 1 + len(receiptReads)
					for i := 0; i < count; i++ {
						sends := 1
						if i == targetIndex && tc.name == "readback-absent" {
							sends = 3
						}
						acknowledged, equalRead := false, false
						for send := 0; send < sends; send++ {
							write := store.events[eventIndex]
							eventIndex++
							wantWrite, wantRead := contract.WriteAcknowledged, contract.ReadOK
							if i == targetIndex {
								wantWrite, wantRead = tc.writeStatus, tc.readStatus
							}
							if write.key != keys[i] || write.write != wantWrite || write.read != 0 || !bytes.Equal(write.body, bodies[i]) {
								t.Fatalf("object %d send %d changed its key, frozen bytes or expected result", i, send)
							}
							writeStatuses = append(writeStatuses, int(write.write))
							if write.write == contract.WriteAcknowledged {
								acknowledged = true
								knownCount++
								knownBytes += len(write.body)
							} else if (write.write == contract.WriteUnknown || write.write == contract.WriteConflict) && !write.notSent {
								unknownUpperCount++
								unknownUpperBytes += len(write.body)
							}
							if tc.name == "readback-absent" && i == targetIndex && !write.notSent {
								t.Fatal("known before-send failure lost its no-send proof")
							}
							readsForSend := 1
							if i == targetIndex {
								switch tc.name {
								case "create-refused":
									readsForSend = 0
								case "readback-unavailable":
									readsForSend = 3
								}
							}
							for readCall := 0; readCall < readsForSend; readCall++ {
								read := store.events[eventIndex]
								eventIndex++
								if read.key != keys[i] || read.maximum != objects[i].ref.Length || read.read != wantRead || read.write != 0 {
									t.Fatalf("object %d read %d changed its key or expected result", i, readCall)
								}
								readStatuses = append(readStatuses, int(read.read))
								if read.read == contract.ReadOK && bytes.Equal(read.body, write.body) {
									equalRead = true
								}
							}
						}
						// Exact readback proves presence, not creation by this
						// attempt: an equal preexisting object's precondition reply
						// can also be lost. An unknown/conflict send retains [0, 1]
						// unless the adapter proved that it did not enter transport.
						if acknowledged || equalRead {
							knownPresentCount++
							knownPresentBytes += len(bodies[i])
						}
						if i < targetIndex || tc.outcome == ObservedCurrent {
							if !bytes.Equal(f.store.objects[keys[i]].Body, bodies[i]) {
								t.Fatalf("verified object %d differs from the independent expected image", i)
							}
						}
					}
					if eventIndex != len(store.events) {
						t.Fatal("preparation sent an unaccounted Store call")
					}
					wantKnownCount, wantUnknownCount, wantActualCount := count, 0, count
					var wantKnownBytes int
					for _, body := range bodies[:count] {
						wantKnownBytes += len(body)
					}
					wantPresentCount, wantPresentBytes := count, wantKnownBytes
					switch tc.name {
					case "preexisting-equal", "preexisting-conflicting", "create-refused":
						wantKnownCount--
						wantActualCount--
						wantKnownBytes -= len(bodies[targetIndex])
					case "accepted-lost-reply", "accepted-conflict", "preexisting-equal-lost-reply", "readback-unavailable":
						wantKnownCount--
						wantUnknownCount = 1
						wantKnownBytes -= len(bodies[targetIndex])
						if tc.name == "preexisting-equal-lost-reply" {
							wantActualCount--
						}
					case "readback-absent":
						wantKnownCount--
						wantActualCount--
						wantKnownBytes -= len(bodies[targetIndex])
					}
					if tc.name == "preexisting-conflicting" || tc.name == "readback-absent" || tc.name == "readback-unavailable" || tc.name == "create-refused" {
						wantPresentCount--
						wantPresentBytes -= len(bodies[targetIndex])
					}
					if knownCount != wantKnownCount || knownBytes != wantKnownBytes || unknownUpperCount != wantUnknownCount || unknownUpperBytes != wantUnknownCount*len(bodies[targetIndex]) {
						t.Fatalf("created evidence: known=%d/%d unknown upper=%d/%d, want known=%d/%d unknown upper=%d/%d", knownCount, knownBytes, unknownUpperCount, unknownUpperBytes, wantKnownCount, wantKnownBytes, wantUnknownCount, wantUnknownCount*len(bodies[targetIndex]))
					}
					if knownPresentCount != wantPresentCount || knownPresentBytes != wantPresentBytes {
						t.Fatalf("present evidence: count/bytes=%d/%d, want %d/%d", knownPresentCount, knownPresentBytes, wantPresentCount, wantPresentBytes)
					}
					for key, old := range inventory {
						object, exists := f.store.objects[key]
						if !exists || object.Token != old.Token || !bytes.Equal(object.Body, old.Body) {
							t.Fatal("preparation changed or removed a pre-attempt object")
						}
					}
					var actualCount, actualBytes, currentBytes int
					for key, object := range f.store.objects {
						if selectedKeys[key] {
							currentBytes += len(object.Body)
						}
						if _, existed := inventory[key]; existed {
							continue
						}
						matched := false
						for i := 0; i < count; i++ {
							if key == keys[i] && bytes.Equal(object.Body, bodies[i]) {
								matched = true
							}
						}
						if !matched || selectedKeys[key] {
							t.Fatal("new immutable object is outside the attempted, unselected image")
						}
						actualCount++
						actualBytes += len(object.Body)
					}
					if actualCount != wantActualCount || actualCount < knownCount || actualCount > knownCount+unknownUpperCount || actualBytes < knownBytes || actualBytes > knownBytes+unknownUpperBytes || currentBytes != oldCurrentBytes {
						t.Fatalf("inventory outside created bounds or selected bytes changed: actual=%d/%d known=%d/%d unknown upper=%d/%d current=%d old current=%d", actualCount, actualBytes, knownCount, knownBytes, unknownUpperCount, unknownUpperBytes, currentBytes, oldCurrentBytes)
					}
					evidence := struct {
						Target, Fault                                                                                    string
						KnownCreatedCount, KnownCreatedBytes, UnknownCreatedUpperCount, UnknownCreatedUpperBytes         int
						KnownPresentCount, KnownPresentBytes                                                             int
						ActualCreatedCount, ActualCreatedBytes, CurrentCount, CurrentBytes, CreateRequests, ReadRequests int
						WriteStatuses                                                                                    []int
						ReadStatuses                                                                                     []int
					}{targetName, tc.name, knownCount, knownBytes, unknownUpperCount, unknownUpperBytes, knownPresentCount, knownPresentBytes, actualCount, actualBytes, len(selectedKeys), currentBytes, f.store.creates, f.store.reads - reads, writeStatuses, readStatuses}
					accounting, err := json.Marshal(evidence)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("preparation accounting: %s", accounting)
					after := f.store.objects[f.store.desc.HeadKey]
					if after.Token != selected.Token || !bytes.Equal(after.Body, selected.Body) {
						t.Fatal("preparation changed selected HEAD")
					}
					reader, result := Open(ctx, f.admission, f.store)
					if reader == nil {
						t.Fatal(result)
					}
					assertStateImage(t, reader, before)
					if candidate != nil {
						wantResult.ObservedRevision, wantResult.ObservedSnapshotID = want.Revision, want.Root.Snapshot
						if result := f.session.Select(ctx, candidate); result != wantResult {
							t.Fatalf("Select = %+v, want %+v", result, wantResult)
						}
						reader, result = Open(ctx, f.admission, f.store)
						if reader == nil {
							t.Fatal(result)
						}
						assertStateImage(t, reader, want)
					}
				})
			}
		}
	}
}
