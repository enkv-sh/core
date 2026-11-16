package core

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestGeneratedCreateHistoryPreservesLateNoEffectResidue(t *testing.T) {
	s, bundle, history := generatedBoundResidueSuccessorState(t)
	g := mustSelectedGeneratedWork(t, s)
	first, next := bundle.Lineages[0].Templates[0], bundle.Lineages[0].Templates[2]
	original := g.attempts[first.AttemptID]
	packet := generatedPublicResultFixture(t, original, contract.GeneratorDispositionConfirmedNoEffect)
	mapping := original.record
	mapping.State, mapping.Stage = contract.GeneratedEffectConfirmedNoEffect, contract.GeneratedStageTerminal
	mapping.Facts, mapping.Progress, mapping.History = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts), contract.EmptyGeneratorVector(contract.GeneratorVectorProgress), contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)
	release := contract.PendingInboxReleaseRecord{Schema: 1, DomainID: mapping.DomainID, InboxID: mapping.InboxID, OriginalResultID: mapping.ResultID,
		SelectedHandoffDigest: contract.Hash(packet), HandoffRevisionID: generatedVectorID(237), CapacityReservation: generatedCapacityReservationFixture(), ObjectLength: uint32(len(packet)), State: contract.GeneratedReleasePending}
	for name, change := range map[string]func(*contract.GeneratedAttemptRecord, *contract.PendingInboxReleaseRecord, *contract.GeneratorHistory){
		"pending": func(*contract.GeneratedAttemptRecord, *contract.PendingInboxReleaseRecord, *contract.GeneratorHistory) {
		},
		"unknown physical release": func(_ *contract.GeneratedAttemptRecord, r *contract.PendingInboxReleaseRecord, _ *contract.GeneratorHistory) {
			r.State = contract.GeneratedReleaseUnknown
		},
		"wrong domain": func(_ *contract.GeneratedAttemptRecord, r *contract.PendingInboxReleaseRecord, _ *contract.GeneratorHistory) {
			r.DomainID = generatedVectorID(238)
		},
		"wrong inbox": func(_ *contract.GeneratedAttemptRecord, r *contract.PendingInboxReleaseRecord, _ *contract.GeneratorHistory) {
			r.InboxID = generatedVectorID(239)
		},
		"wrong result": func(_ *contract.GeneratedAttemptRecord, r *contract.PendingInboxReleaseRecord, _ *contract.GeneratorHistory) {
			r.OriginalResultID = generatedVectorID(240)
		},
		"unobserved": func(_ *contract.GeneratedAttemptRecord, r *contract.PendingInboxReleaseRecord, _ *contract.GeneratorHistory) {
			r.State, r.ObjectLength = contract.GeneratedReleaseUnobserved, 0
		},
		"missing evidence": func(_ *contract.GeneratedAttemptRecord, r *contract.PendingInboxReleaseRecord, _ *contract.GeneratorHistory) {
			r.SelectedHandoffDigest = contract.ID{}
		},
		"delete result": func(a *contract.GeneratedAttemptRecord, _ *contract.PendingInboxReleaseRecord, _ *contract.GeneratorHistory) {
			a.ResultID, _ = contract.GeneratorResultID(a.DomainID, a.OperationID, a.AttemptID, a.TransmissionID, contract.GeneratorActionDelete)
		},
		"nonzero historical result": func(_ *contract.GeneratedAttemptRecord, _ *contract.PendingInboxReleaseRecord, h *contract.GeneratorHistory) {
			h.ResultID, h.ResultDigest = original.record.ResultID, contract.Hash(packet)
		},
		"changed residue edge": func(_ *contract.GeneratedAttemptRecord, _ *contract.PendingInboxReleaseRecord, h *contract.GeneratorHistory) {
			h.Edge = contract.GeneratorGuardQualifiedNoEffect
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, r, rows := mapping, release, slices.Clone(history)
			change(&a, &r, &rows[0])
			var bodies [][]byte
			for _, row := range rows {
				body, err := contract.EncodeGeneratorHistory(row)
				if err != nil {
					t.Fatal("changed history must remain encodable", err)
				}
				bodies = append(bodies, body)
			}
			descriptor, carriers, err := generatedCarrierRows(s.root.Domain, contract.GeneratedAttemptSupportKind, next.AttemptID, contract.GeneratorVectorHistory, bodies)
			if err != nil {
				t.Fatal(err)
			}
			var records []contract.SupportRecord
			for _, row := range s.supportRecords() {
				if row.Kind == contract.GeneratorVectorSupportKind {
					carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.OwnerID == next.AttemptID && carrier.VectorKind == contract.GeneratorVectorHistory {
						continue
					}
				}
				records = append(records, row)
			}
			current := *g
			current.attempts = maps.Clone(g.attempts)
			delete(current.attempts, first.AttemptID)
			current.releases = map[contract.ID]generatedReleasedAttempt{first.AttemptID: {attempt: a, template: first, release: r}}
			current.vectors, err = newGeneratedVectorSet(s.root.Domain, append(records, carriers...))
			if err != nil {
				t.Fatal(err)
			}
			builder := &generatedSelectionBuilder{facts: &current, vectors: newGeneratedVectorValidation(&current.vectors)}
			err = builder.validateCreateHistory(current.attempts[next.AttemptID], contract.GeneratedAttemptSupportKind, next.AttemptID, descriptor)
			valid := name == "pending" || name == "unknown physical release"
			if valid && err != nil || !valid && err == nil {
				t.Fatal("historical residue row lost exact late no-effect release evidence", err)
			}
			if history[0].Outcome != contract.GeneratedEffectClosedWithResidue || !history[0].ResultID.IsZero() || !history[0].ResultDigest.IsZero() || history[0].Edge != contract.GeneratorGuardResidue {
				t.Fatal("validation changed immutable branch evidence")
			}
		})
	}
}

// full_only: false
func TestGeneratedDeleteLifecycleAccessRowsRemoveExactMaterialKinds(t *testing.T) {
	current, retired, removed, retained := generatedVectorID(1), generatedVectorID(2), generatedVectorID(3), generatedVectorID(4)
	rows := []contract.AccessRecord{
		{MaterialKind: 1, MaterialID: current},
		{MaterialKind: 1, MaterialID: retired},
		{MaterialKind: 3, MaterialID: removed},
		{MaterialKind: 3, MaterialID: retained},
	}
	got := generatedDeleteLifecycleAccessRows(rows, generatedDeleteReflection{materials: []contract.ID{removed}, values: []contract.ID{retired}})
	if len(got) != 2 || got[0].MaterialKind != 1 || got[0].MaterialID != current || got[1].MaterialKind != 3 || got[1].MaterialID != retained {
		t.Fatalf("delete cleanup retained stale or removed live access: %+v", got)
	}
}

// full_only: false
func TestGeneratedDeletePrunesAccessForNoncurrentFinalCanonicalConsumer(t *testing.T) {
	s, retained, _ := generatedCanonicalState(t, false)
	var retainedRow contract.SupportRecord
	for _, row := range s.supportRecords() {
		if row.Kind == 6 && row.RecordID == retained.Entry.ValueState {
			retainedRow = row
			break
		}
	}
	if retainedRow.Kind == 0 {
		t.Fatal("retained canonical row is absent")
	}
	g := &generatedSelection{session: s, image: s.selectedImage(), selectedMaterials: selectedMaterialFacts{accessLocations: s.accessLocations, valueReaders: s.valueReaders}}
	rows, values, err := g.generatedPruneRetainedCanonicals([]contract.SupportRecord{retainedRow})
	if err != nil || len(rows) != 0 || len(values) != 0 {
		t.Fatal("current canonical cleanup removed its required access", err)
	}
	current := *s.valueEntry(retained.OriginalSlot)
	current.ValueState = generatedVectorID(240)
	s.pages[0].Slots[retained.OriginalSlot] = &current
	rows, values, err = g.generatedPruneRetainedCanonicals([]contract.SupportRecord{retainedRow})
	if err != nil || len(rows) != 0 || len(values) != 1 || values[0] != retained.Entry.ValueState {
		t.Fatal("noncurrent canonical cleanup did not remove its final access", err)
	}
}

// full_only: false
func TestGeneratedRepeatedDeleteReflectionClosesActualOlderResultAndRetainsUnknownGarbage(t *testing.T) {
	for _, previous := range []int{1, 60} {
		t.Run(fmt.Sprint(previous), func(t *testing.T) {
			s, attempts, duty := generatedRepeatedRetirementState(t, previous)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			current := attempts[len(attempts)-1]
			facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, current, contract.GeneratorDispositionUnknown))
			if err != nil {
				t.Fatal(err)
			}
			residue, err := g.generatedRetirementResidueWithFactsFixture(t.Context(), duty.DutyID, facts)
			if err != nil {
				t.Fatal(err)
			}
			generatedInstallAmbiguityClosure(t, s, g, residue)
			g, err = s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			original := g.attempts[attempts[0].record.AttemptID]
			packet := generatedRetirementResultFixture(t, s, original, contract.GeneratorDispositionRetirementAcknowledged)
			selection, ok, err := g.selectGeneratedCleanup(context.Background(), map[contract.ID][]byte{original.record.ResultID: packet})
			if err != nil || !ok || !selection.closeOwner || selection.attempt.record.AttemptID != original.record.AttemptID || selection.hazard != residue.hazard {
				t.Fatal("older original result was lost or relabelled as the final invocation", err)
			}
			closure, err := g.generatedReflectLateDelete(t.Context(), selection, generatedVectorID(95))
			if err != nil {
				t.Fatal("exact earlier acknowledgement cannot close its shared resource Hazard", err)
			}
			generatedRepackSupportAtLocations(t, s, closure.rows, g.bundles, closure.locations)
			s.root.Generated.Slices = closure.slices
			for _, page := range s.access {
				if page != nil {
					page.Records = slices.DeleteFunc(page.Records, func(row contract.AccessRecord) bool { return row.MaterialKind == 3 })
				}
			}
			s.root.AccessRecordCount = 0
			generatedRefreshClosureCounts(&s.root.Generated, closure.rows)
			s.recountChildren()
			generatedCommitFixtureAccess(t, s)
			if !s.indexSelectedMaterials() {
				t.Fatal("release-only material index")
			}
			after, err := s.selectedGeneratedWork(context.Background())
			if err != nil || len(after.attempts) != 0 || len(after.materials) != 0 || len(after.releases) != len(attempts) ||
				s.root.Generated.Hazards != 0 || s.root.Generated.Duties != 0 || s.root.Generated.Materials != 0 {
				t.Fatal("closure retained adoption or lost an original inbox mapping", err)
			}
			for _, a := range g.attempts {
				r := after.releases[a.record.AttemptID]
				if r.release.OriginalResultID != a.record.ResultID || r.release.InboxID != a.record.InboxID || r.release.SelectedHandoffDigest != contract.Hash(packet) {
					t.Fatal("closure changed an original coordinate or its shared handoff")
				}
				if a.record.AttemptID == original.record.AttemptID {
					if r.release.State != contract.GeneratedReleasePending || r.release.ObjectLength != uint32(len(packet)) || r.attempt.State != contract.GeneratedEffectSucceeded {
						t.Fatal("actual qualified result did not acquire its exact pending release")
					}
				} else if r.release.State != 3 || r.release.ObjectLength != 0 || r.attempt != a.record {
					t.Fatal("unobserved original reply was reported as acknowledged, clean or observed")
				}
			}
			view, err := s.inspectGeneratedWork(context.Background())
			if err != nil || !view.possibleGarbage || len(view.effects) != len(attempts) {
				t.Fatal("unknown original inboxes are not visible as possible garbage", err)
			}
			for _, effect := range view.effects {
				want := contract.ReceiptEvidenceProviderFacts
				if effect.attempt.AttemptID == original.record.AttemptID {
					want = contract.ReceiptEvidenceAcknowledged
				}
				if effect.evidenceCeiling != want {
					t.Fatal("shared closure fabricated a result for another invocation")
				}
			}
			descriptor := s.admission.store
			descriptor.Prefix = "fixture"
			store := &generatedInboxDeleteStore{descriptor: descriptor, read: contract.ReadResult{Status: contract.ReadMissing}}
			s.store, s.admission.store = store, descriptor
			for _, r := range after.releases {
				if r.release.State == 3 {
					if got := s.deleteGeneratedInbox(context.Background(), r.release.InboxID); got != generatedInboxDeleteUnknown || store.readCalls != 0 || store.deleteCalls != 0 {
						t.Fatal("unobserved release used current absence to grant deletion or report clean")
					}
					if _, _, read := s.ReadGeneratedResult(context.Background(), r.attempt.AttemptID); read.Outcome != AdmissionRefused || store.readCalls != 0 {
						t.Fatal("unobserved release restored an original result reader")
					}
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedReflectionPackingUsesSuccessorChildren(t *testing.T) {
	s, g, _ := generatedRepeatedRetirementHazardState(t, 244)
	var original generatedAttempt
	for _, a := range g.attempts {
		if original.record.AttemptID.IsZero() || bytes.Compare(a.record.OperationID[:], original.record.OperationID[:]) < 0 {
			original = a
		}
	}
	if original.record.AttemptID.IsZero() {
		t.Fatal("missing original delete")
	}
	admitted := generatedLifecycleFixture(t, s)
	g = mustSelectedGeneratedWork(t, s)
	original = g.attempts[original.record.AttemptID]
	packet := generatedRetirementResultFixture(t, s, original, contract.GeneratorDispositionRetirementAcknowledged)
	selected, ok, selectErr := g.selectGeneratedCleanup(context.Background(), map[contract.ID][]byte{original.record.ResultID: packet})
	if selectErr != nil || !ok || selected.attempt.record.AttemptID != original.record.AttemptID {
		t.Fatal("reflection selection", selectErr)
	}
	change, changeErr := g.generatedReflectLateDelete(t.Context(), selected, s.head.Core.Revision)
	if changeErr != nil {
		t.Fatal("reflection closure", changeErr)
	}
	groups, err := generatedReservationGroups(change.rows, change.locations, g.bundles)
	if err != nil {
		t.Fatal("successor support groups", err)
	}
	accessPages, err := generatedLifecycleAccessPageCount(generatedLifecycleAccessRows(s.accessRecords(), change.materials...))
	if err != nil {
		t.Fatal("successor access pages", err)
	}
	packed, err := format.PackRequiredSupportRows(s.root.Domain, groups, generatedNonSupportChildCount(s.root, accessPages))
	if err != nil {
		t.Fatal("successor support packing", err)
	}
	assertGeneratedPackingBoundary(t, s.root.Domain, groups, len(packed))
	if _, _, err := s.freshGeneratedLifecyclePlan(t.Context(), len(packed), accessPages); err != nil {
		t.Fatal("fresh lifecycle identity refused", err)
	}
	if _, err := format.ResolveGeneratedSlices(s.root.Domain, s.root.Snapshot, s.root.Generated, s.support); err != nil {
		t.Fatal("resolve predecessor slices", err)
	}
	if _, err := g.generatedReflectLateDelete(t.Context(), selected, s.head.Core.Revision); err != nil {
		t.Fatal("repeat closure", err)
	}
	plan, err := s.generatedReflectionPlan(t.Context(), original.record.ResultID, packet, admitted)
	if err != nil {
		t.Fatal("fitting reflection plan rejected old support as occupied successor capacity", err)
	}
	next, err := s.deriveGeneratedCleanupClose(t.Context(), plan)
	if err != nil || next.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("fitting reflection successor rejected", err)
	}
	if next.state.root.ChildCount > contract.MaxChildPages || s.root.ChildCount+uint32(len(next.state.root.RequiredSupport)) <= contract.MaxChildPages {
		t.Fatal("fixture does not distinguish old-plus-new from successor capacity")
	}
}

// full_only: false
func TestGeneratedOriginalCreateReflectionChangesOnlySameHazard(t *testing.T) {
	s, original, beforeHazard := generatedCreateHazardState(t, 0, 0)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[original.record.AttemptID]
	result := generatedPublicResultFixture(t, a, 1)
	selected, ok, err := g.selectGeneratedCleanup(context.Background(), map[contract.ID][]byte{a.record.ResultID: result})
	if err != nil || !ok {
		t.Fatal("reflection selection", err)
	}
	reflected, err := g.generatedReflectLateCreate(selected)
	if err != nil {
		t.Fatal(err)
	}
	if reflected.hazard.HazardID != beforeHazard.HazardID || reflected.hazard.OwnerID != beforeHazard.OwnerID ||
		reflected.hazard.Exposure != contract.GeneratedExposureLateEffect || reflected.hazard.Eligibility != contract.GeneratedExposureLateEffect ||
		reflected.hazard.Fenced != 1 || reflected.hazard.CompletionClass != beforeHazard.CompletionClass ||
		reflected.attempt.record.AttemptID != original.record.AttemptID || reflected.target.ResourceDigest.IsZero() {
		t.Fatal("reflection replaced its owner or weakened its exact cleanup contract")
	}
	generatedRepackSupport(t, s, reflected.rows, g.bundles)
	s.root.Generated.Results = 1
	after, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("selected reflection relation", err)
	}
	row := after.records[generatedRecordKey{11, beforeHazard.HazardID}]
	h, err := contract.InspectGeneratedHazardRecord(row.Body)
	if err != nil || h != reflected.hazard || !bytes.Equal(after.attempts[original.record.AttemptID].result, result) ||
		s.root.Generated.ActiveOwner != (contract.ID{}) || s.root.Generated.Duties != 0 || s.root.Generated.Hazards != 1 {
		t.Fatal("reflection created an active slot, provider Duty, or changed another owner", err)
	}
}

// full_only: false
func TestGeneratedOriginalDeleteReflectionClosesWithoutProviderCall(t *testing.T) {
	s, original, _, _ := generatedDeleteHazardState(t, 0)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	original = g.attempts[original.record.AttemptID]
	result := generatedRetirementResultFixture(t, s, original, contract.GeneratorDispositionRetirementAcknowledged)
	selection, ok, err := g.selectGeneratedCleanup(context.Background(), map[contract.ID][]byte{original.record.ResultID: result})
	if err != nil || !ok || selection.kind != generatedCleanupReflection || !selection.closeOwner {
		t.Fatal("exact late delete acknowledgement was not selected first", err)
	}
	revision := generatedVectorID(95)
	closure, err := g.generatedReflectLateDelete(t.Context(), selection, revision)
	if err != nil {
		t.Fatal(err)
	}
	if closure.release.InboxID != original.record.InboxID || closure.release.OriginalResultID != original.record.ResultID ||
		closure.release.SelectedHandoffDigest != contract.Hash(result) || closure.release.ObjectLength != uint32(len(result)) ||
		closure.release.HandoffRevisionID != revision || closure.release.State != contract.GeneratedReleasePending ||
		closure.attempt.record.State != contract.GeneratedEffectSucceeded {
		t.Fatal("delete reflection changed its exact acknowledged handoff")
	}

	generatedRepackSupportAtLocations(t, s, closure.rows, g.bundles, closure.locations)
	s.root.Generated.Slices = closure.slices
	for _, page := range s.access {
		if page != nil {
			page.Records = slices.DeleteFunc(page.Records, func(row contract.AccessRecord) bool {
				return row.MaterialKind == 3 && slices.Contains(closure.materials, row.MaterialID)
			})
		}
	}
	s.root.AccessRecordCount = 0
	s.root.Generated.Attempts, s.root.Generated.Hazards, s.root.Generated.Results, s.root.Generated.Materials = 1, 0, 0, 0
	s.root.Generated.PendingReleases = 1
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{closure.release.InboxID})
	if err != nil {
		t.Fatal(err)
	}
	s.recountChildren()
	generatedCommitFixtureAccess(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("delete reflection release material index")
	}
	after, err := s.selectedGeneratedWork(context.Background())
	if err != nil || len(after.attempts) != 0 || !after.hasRecord(generatedRecordKey{12, closure.release.InboxID}) ||
		after.hasRecord(generatedRecordKey{11, closure.hazard.HazardID}) {
		t.Fatal("delete reflection retained provider work or lost its release mapping", err)
	}
}

// full_only: false
func TestGeneratedOriginalCreateReflectionRefusesWrongOwnerOrResult(t *testing.T) {
	s, original, _ := generatedCreateHazardState(t, 0, 0)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[original.record.AttemptID]
	result := generatedPublicResultFixture(t, a, 1)
	selected, ok, err := g.selectGeneratedCleanup(context.Background(), map[contract.ID][]byte{a.record.ResultID: result})
	if err != nil || !ok {
		t.Fatal(err)
	}
	changed := selected
	changed.hazard.HazardID = generatedVectorID(96)
	if _, err := g.generatedReflectLateCreate(changed); err == nil {
		t.Fatal("reflection accepted a caller-substituted Hazard")
	}
	changed = selected
	changed.result = append(bytes.Clone(result), 0)
	if _, err := g.generatedReflectLateCreate(changed); err == nil {
		t.Fatal("reflection accepted unequal original bytes")
	}
}

// full_only: false
func TestGeneratedLateDeleteReflectionRemovesFinalNoncurrentCanonicalAccessPage(t *testing.T) {
	testGeneratedLateDeleteCanonicalPageShrink(t, false)
}

// full_only: false
func TestGeneratedLateDeleteReflectionRemovesRetainedOnlyReaderAccessPage(t *testing.T) {
	testGeneratedLateDeleteCanonicalPageShrink(t, true)
}

// These two fixtures have the same 33 current/retained 127-reader unions and
// two real generated owners. Only the cleanup's Hazard ends. Its final canonical
// is either noncurrent, or current with one retained-only ordinary reader.
// Every expected access row below comes from that explicit ownership relation.
func testGeneratedLateDeleteCanonicalPageShrink(t *testing.T, currentTarget bool) {
	t.Helper()
	s, original, ending, surviving, target, currentReaders := generatedLateDeleteCanonicalPageState(t, currentTarget)
	if _, err := s.validateRelationsMode(t.Context(), false); err != nil {
		t.Fatal("complete selected predecessor relations", err)
	}
	g := mustSelectedGeneratedWork(t, s)
	key := materialIdentity{contract.ValueMaterialKind, target}
	consumers := g.consumers[key]
	if ending == surviving || len(consumers) != 1 || consumers[0].OwnerID != ending ||
		g.parent != nil || len(g.attempts) != 2 || len(g.releases) != 1 || s.root.Generated.Hazards != 2 || s.root.Generated.Materials != 2 {
		t.Fatal("target must have one ending canonical owner and a distinct surviving seed owner")
	}
	for i := 0; i < 33; i++ {
		value := generatedReflectionPageID(1, i)
		owners := g.consumers[materialIdentity{contract.ValueMaterialKind, value}]
		if len(owners) != 1 || owners[0].OwnerID != surviving {
			t.Fatal("127-reader union has no exact surviving canonical owner", i)
		}
		if _, err := g.canonicalConsumer(generatedRecordKey{contract.GeneratedHazardSupportKind, surviving}, value, generatedVectorID(100)); err != nil {
			t.Fatal("surviving owner cannot consume its original retained value", i, err)
		}
	}
	if _, err := g.canonicalConsumer(generatedRecordKey{contract.GeneratedHazardSupportKind, ending}, target, s.admission.recipient); err != nil {
		t.Fatal("ending owner cannot consume its exact retained value", err)
	}
	before := s.accessRecords()
	counts := make([]int, 0, 37)
	for i := 0; i < 33; i++ {
		counts = append(counts, 127)
	}
	wantMemberships := uint32(2176)
	wantBeforePages := []int{2_097_054, 1_257}
	wantSuccessorPages := []int{2_097_054}
	if currentTarget {
		counts = append(counts, 62, 27, 1, 1)
		wantMemberships = 2200
		wantBeforePages = []int{2_096_565, 1_257}
		wantSuccessorPages = []int{2_096_667}
	} else {
		counts = append(counts, 89, 1, 1, 1)
	}
	if len(before) != len(counts) {
		t.Fatal("complete predecessor access inventory", len(before), len(counts))
	}
	for i, row := range before {
		if len(row.Wraps) != counts[i] || (i < 35) != (row.MaterialKind == contract.ValueMaterialKind) {
			t.Fatal("ordered predecessor wrap inventory", i, row.MaterialKind, len(row.Wraps), counts[i])
		}
		for _, wrap := range row.Wraps {
			if wrap.SubjectKind != contract.OrdinaryWrapSubject {
				t.Fatal("Recovery must be disabled in the ordinary packing case")
			}
		}
	}
	if s.root.MembershipCount != wantMemberships || s.root.RecipientCount != 127 || s.root.CurrentAccess.Core.Recovery != nil {
		t.Fatal("current membership or registry changed the fixed packing recipe", s.root.MembershipCount, s.root.RecipientCount)
	}
	assertGeneratedReflectionPageInventory(t, s, wantBeforePages)
	if got := generatedReflectionExpectedPageLengths(t, before); !slices.Equal(got, wantBeforePages) {
		t.Fatal("independent ordered predecessor packing", got, wantBeforePages)
	}

	original = g.attempts[original.record.AttemptID]
	packet := generatedRetirementResultFixture(t, s, original, contract.GeneratorDispositionRetirementAcknowledged)
	selected, ok, err := g.selectGeneratedCleanup(t.Context(), map[contract.ID][]byte{original.record.ResultID: packet})
	if err != nil || !ok || selected.kind != generatedCleanupReflection || !selected.closeOwner ||
		selected.sourceKey().id != ending || selected.attempt.record.AttemptID != original.record.AttemptID {
		t.Fatal("qualified exact late delete did not select its original ending owner", err)
	}
	change, err := g.generatedReflectLateDelete(t.Context(), selected, s.head.Core.Revision)
	if err != nil || !slices.Contains(change.materials, original.material.Core.OperationMaterialID) {
		t.Fatal("qualified reflection did not close the ending seed", err)
	}
	var targetCanonical, endingOwner, survivingOwner bool
	for _, row := range change.rows {
		targetCanonical = targetCanonical || row.Kind == contract.RetainedCanonicalSupportKind && row.RecordID == target
		endingOwner = endingOwner || row.Kind == contract.GeneratedHazardSupportKind && row.RecordID == ending
		survivingOwner = survivingOwner || row.Kind == contract.GeneratedHazardSupportKind && row.RecordID == surviving
	}
	if targetCanonical || endingOwner || !survivingOwner {
		t.Fatal("closure must remove the target's last canonical owner and preserve the other owner")
	}
	if slices.Contains(change.values, target) == currentTarget {
		t.Fatal("closure did not distinguish current access from obsolete canonical access", change.values)
	}
	// Independent successor relation: remove the ending seed; remove a
	// noncurrent target, or keep exactly its 26 current readers. All other
	// rows and their ciphertext bytes remain exact.
	var expected []contract.AccessRecord
	for _, row := range before {
		if row.MaterialKind == contract.OperationSeedMaterialKind && row.MaterialID == original.material.Core.OperationMaterialID {
			continue
		}
		if row.MaterialKind == contract.ValueMaterialKind && row.MaterialID == target {
			if !currentTarget {
				continue
			}
			row.Wraps = slices.DeleteFunc(slices.Clone(row.Wraps), func(w contract.WrapRow) bool { return !slices.Contains(currentReaders, w.SubjectID) })
			if len(row.Wraps) != 26 {
				t.Fatal("independent current-target reader set", len(row.Wraps))
			}
		}
		expected = append(expected, row)
	}
	if got := generatedReflectionExpectedPageLengths(t, expected); !slices.Equal(got, wantSuccessorPages) {
		t.Fatal("independent ordered successor packing", got, wantSuccessorPages)
	}
	plan, err := s.generatedReflectionPlan(t.Context(), original.record.ResultID, packet, generatedContinuationContext(t, s, 201, 202))
	if err != nil {
		t.Fatal("fitting qualified reflection plan", err)
	}
	var plannedAccess int
	for _, id := range plan.identity.accessPages {
		if !id.IsZero() {
			plannedAccess++
		}
	}
	if plannedAccess != len(wantSuccessorPages) {
		t.Errorf("reflection plan reserves %d access pages; exact surviving ownership requires %d", plannedAccess, len(wantSuccessorPages))
	}
	next, err := s.deriveGeneratedCleanupClose(t.Context(), plan)
	if err != nil || next == nil {
		t.Fatal("qualified one-page reflection successor refused at plan/write agreement", err)
	}
	assertGeneratedReflectionPageInventory(t, next.state, wantSuccessorPages)
	after := next.state.accessRecords()
	if len(after) != len(expected) {
		t.Fatal("successor retained obsolete rows or lost a surviving row", len(after), len(expected))
	}
	for i := range expected {
		want, wantErr := contract.EncodeAccessRecord(expected[i])
		got, gotErr := contract.EncodeAccessRecord(after[i])
		if wantErr != nil || gotErr != nil || !bytes.Equal(got, want) {
			t.Fatal("successor differs from the independent exact reader and byte relation", i, wantErr, gotErr)
		}
	}
	// Prove the complete derived image before the unit fixture grants its
	// private candidate-ready fact. Physical selection and cold Open follow.
	next.state.generatedWork, next.state.generatedGraphs = nil, nil
	if err := next.state.validateGeneratedSelection(t.Context(), nil); err != nil {
		t.Fatal("complete derived successor proof", err)
	}
	if _, err := next.state.validateRelationsMode(t.Context(), false); err != nil {
		t.Fatal("complete derived successor relations", err)
	}
	cold := generatedReflectionSelectAndColdOpen(t, s, next)
	assertGeneratedReflectionPageInventory(t, cold, wantSuccessorPages)
	if cold.root.MembershipCount != wantMemberships || cold.root.SecretOrdinaryWrapCount != wantMemberships ||
		cold.root.ValueEntryCount != s.root.ValueEntryCount || cold.root.RecipientCount != 127 {
		t.Fatal("cold selected current membership changed", cold.root.MembershipCount, cold.root.ValueEntryCount, cold.root.RecipientCount)
	}
	after = cold.accessRecords()
	if len(after) != len(expected) {
		t.Fatal("cold selected access row inventory", len(after), len(expected))
	}
	for i := range expected {
		want, wantErr := contract.EncodeAccessRecord(expected[i])
		got, gotErr := contract.EncodeAccessRecord(after[i])
		if wantErr != nil || gotErr != nil || !bytes.Equal(got, want) {
			t.Fatal("cold selected access differs from independent exact rows", i, wantErr, gotErr)
		}
	}
	afterWork := mustSelectedGeneratedWork(t, cold)
	if afterWork.hasRecord(generatedRecordKey{contract.GeneratedHazardSupportKind, ending}) ||
		!afterWork.hasRecord(generatedRecordKey{contract.GeneratedHazardSupportKind, surviving}) ||
		len(afterWork.consumers[key]) != 0 || len(afterWork.releases) != 2 || cold.root.Generated.Materials != 1 {
		t.Fatal("selected successor lost the qualified closure or its surviving owner")
	}
}

// Reuse the existing physical selected-store fixture. Its CAS adapter assumes
// numeric GCP generations; this AWS-only wrapper keeps opaque AWS token rules.
type generatedReflectionSelectionStore struct {
	*observationSelectionStore
	predecessorToken contract.Token
	predecessorBody  []byte
}

func (s *generatedReflectionSelectionStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	if ctx == nil || ctx.Err() != nil || key != s.descriptor.HeadKey || token != s.token || token != s.predecessorToken ||
		token.Family != contract.AWS || !bytes.Equal(s.objects[key], s.predecessorBody) {
		s.t.Fatal("reflection selection did not use its exact current AWS condition")
	}
	s.sends++
	s.objects[key] = bytes.Clone(body)
	s.token = contract.Token{Family: contract.AWS, Value: `"reflection-selected-token"`}
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}

func generatedReflectionSelectAndColdOpen(t *testing.T, predecessor *StateSession, successor *generatedReservation) *StateSession {
	t.Helper()
	observationProtectFixture(t, predecessor)
	physical := observationPhysicalGeneratedStore(t, predecessor)
	// The unchanged source constructor supplies a unit-owned admitted session
	// and a complete relation-valid image. Its before-HEAD is a synthetic unit
	// boundary, not a signed cold-opened historical HEAD. CAS still requires
	// those exact selected bytes and the exact opaque condition before commit.
	physical.objects[predecessor.admission.store.HeadKey] = bytes.Clone(predecessor.body)
	store := &generatedReflectionSelectionStore{observationSelectionStore: physical,
		predecessorToken: predecessor.token, predecessorBody: bytes.Clone(predecessor.body)}
	predecessor.store = store
	signer := testtrust.New(t, contract.AWS, predecessor.admission.trust)
	if !bytes.Equal(signer.PublicKey(), predecessor.admission.publicKey) {
		t.Fatal("physical reflection fixture signer differs from the frozen AWS public basis")
	}
	candidate := successor.candidate
	candidate.head.K1 = bytes.Clone(predecessor.head.K1)
	authority, err := contract.GeneratorAuthorityDigest(*candidate.head.Generator)
	if err != nil {
		t.Fatal(err)
	}
	// This direct Core unit fixture supplies private candidate readiness only
	// after the independent row checks and complete relation proof above. It
	// does not claim that the synthetic wraps passed a Crypto MAC exchange.
	candidate.generated = &generatedCandidateFacts{reservation: successor, authority: authority, claimed: true}
	candidate, result := predecessor.persistCandidate(t.Context(), candidate, signer)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("persist exact signed reflection candidate", result)
	}
	selected, result := predecessor.selectCandidate(t.Context(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure ||
		selected.head.Core.Revision != candidate.head.Core.Revision || store.sends != 1 {
		t.Fatal("select exact physical reflection candidate", result, store.sends)
	}
	admission := predecessor.admission
	admission.composition, admission.entropy = generatedVectorID(239), nil
	selectedRevision, selectedRoot := selected.head.Core.Revision, selected.head.Core.Root
	// Open has no producer session, derived pages, cache or selected-work facts.
	selected, successor.state = nil, nil
	readsBefore := len(store.keys)
	cold, result := Open(t.Context(), OpenContext{admission: &admission}, store)
	if cold == nil || result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure ||
		cold.head.Core.Revision != selectedRevision || cold.head.Core.Root != selectedRoot {
		t.Fatal("cold full Open of physically selected reflection", result)
	}
	for _, ref := range append(slices.Clone(cold.root.CurrentAccess.Core.AccessPageRefs), cold.root.RequiredSupport...) {
		key, err := format.Key(admission.store.Prefix, ref)
		if err != nil || !slices.Contains(store.keys[readsBefore:], key) {
			t.Fatal("cold full Open skipped an exact selected access or support page", ref.Kind, ref.Index, err)
		}
	}
	return cold
}

func generatedReflectionPageID(kind byte, index int) contract.ID {
	id := contract.Hash([]byte(fmt.Sprintf("late-delete canonical page fixture/v1/%d/%d", kind, index)))
	// All ordinary values have this explicit order, independent of hashes.
	id[0], id[1], id[2] = 0x20, kind, byte(index)
	return id
}

func generatedLateDeleteCanonicalPageState(t *testing.T, currentTarget bool) (*StateSession, generatedAttempt, contract.ID, contract.ID, contract.ID, []contract.ID) {
	t.Helper()
	s, original, ending := generatedReflectionPageCleanupSource(t)
	generatedLifecycleFixture(t, s)
	endingAccess := s.accessRecords()
	donor, retained, _ := generatedCanonicalState(t, false)
	current := *donor.valueEntry(retained.OriginalSlot)
	union := slices.Clone(generatedFixtureMaterialAccess(t, donor, contract.ValueMaterialKind, retained.Entry.ValueState).Wraps)
	donor, create := generatedUnselectedCleanupFromReservation(t, donor)
	donor, _, surviving := generatedCreateHazardFromCleanup(t, donor, create, 0)
	endingWork, survivingWork := mustSelectedGeneratedWork(t, s), mustSelectedGeneratedWork(t, donor)
	if ending.HazardID == surviving.HazardID || ending.ResourceID == surviving.ResourceID ||
		original.material.Core.OperationMaterialID == create.material.Core.OperationMaterialID {
		t.Fatal("packing fixture requires two real independent generated owners")
	}
	s.recipients, s.recipient = donor.recipients, donor.recipient
	basis, err := contract.DecodeGenesisDescriptorCore(s.admission.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	basis.Recipients, basis.Recovery = s.registry(), nil
	s.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(basis)
	if err != nil {
		t.Fatal(err)
	}
	clear(s.pages[:])
	s.root.Names = nil
	clear(s.access[:])
	var access []contract.AccessRecord
	var canonicalRows []contract.SupportRecord
	ownerConsumers := make(map[contract.ID][][]byte)
	for _, pair := range []struct {
		work  *generatedSelection
		owner contract.GeneratedHazardRecord
	}{{endingWork, ending}, {survivingWork, surviving}} {
		bodies, err := pair.work.vectors.resolve(contract.GeneratedHazardSupportKind, pair.owner.HazardID, contract.GeneratorVectorConsumers, pair.owner.Consumers)
		if err != nil {
			t.Fatal(err)
		}
		for _, body := range bodies {
			consumer, err := contract.InspectGeneratorConsumer(body)
			if err != nil {
				t.Fatal(err)
			}
			if consumer.SubjectKind != contract.GeneratorConsumerRetainedCanonicalValue {
				ownerConsumers[pair.owner.HazardID] = append(ownerConsumers[pair.owner.HazardID], body)
			}
		}
	}
	var targetReaders []contract.ID
	for i := 0; i < 35; i++ {
		entry := current
		entry.Name = fmt.Sprintf("value-%02d", i)
		entry.ValueState, entry.Incarnation = generatedReflectionPageID(1, i), generatedReflectionPageID(2, i)
		payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
		if err != nil {
			t.Fatal(err)
		}
		payload.DataKeyID, payload.CommitmentKeyID, payload.PackageCheck = generatedReflectionPageID(3, i), generatedReflectionPageID(4, i), generatedReflectionPageID(5, i)
		entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		oldReaders := slices.Clone(retained.Entry.Recipients)
		owner := surviving.HazardID
		keepCurrent, keepRetained := true, true
		if i == 33 {
			if currentTarget {
				entry.Recipients, keepRetained = slices.Clone(current.Recipients[:62]), false
			} else {
				oldReaders = oldReaders[:26]
			}
		}
		if i == 34 {
			owner = ending.HazardID
			if currentTarget {
				entry.Recipients, oldReaders = slices.Clone(current.Recipients[:26]), oldReaders[:2]
				targetReaders = slices.Clone(entry.Recipients)
			} else {
				entry.Recipients, oldReaders, keepCurrent = nil, oldReaders[:1], false
			}
		}
		// Sparse physical slots force exactly five nonempty value pages.
		slot := uint16(2 * i)
		if keepCurrent {
			page := int(slot) / format.PageSlots
			if s.pages[page] == nil {
				s.pages[page] = &format.ValueEntryPage{}
			}
			s.pages[page].Slots[int(slot)%format.PageSlots] = &entry
			s.root.Names = append(s.root.Names, format.NameEntry{Name: entry.Name, Slot: slot})
		}
		core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, entry)
		// A noncurrent record still has its original valid one-reader Entry.
		if !keepCurrent {
			entry.Recipients = slices.Clone(oldReaders)
			core, err = contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, entry)
		}
		if err != nil {
			t.Fatal(err)
		}
		contextDigest, err := contract.ValueMaterialContextDigest(core)
		if err != nil {
			t.Fatal(err)
		}
		readers := slices.Clone(entry.Recipients)
		if keepRetained {
			old := entry
			old.Recipients = slices.Clone(oldReaders)
			body, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: slot, Entry: old})
			if err != nil {
				t.Fatal(err)
			}
			canonicalRows = append(canonicalRows, contract.SupportRecord{Kind: contract.RetainedCanonicalSupportKind, RecordID: old.ValueState, Body: body})
			body, err = contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: owner, MaterialID: old.ValueState,
				ContextDigest: contextDigest, SubjectKind: contract.GeneratorConsumerRetainedCanonicalValue, SubjectID: old.ValueState, Purpose: contract.GeneratorConsumerUseRetainedCanonical})
			if err != nil {
				t.Fatal(err)
			}
			ownerConsumers[owner] = append(ownerConsumers[owner], body)
			for _, reader := range oldReaders {
				if !slices.Contains(readers, reader) {
					readers = append(readers, reader)
				}
			}
		}
		row := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: entry.ValueState,
			MaterialContextDigest: contextDigest, PackageCheck: payload.PackageCheck}
		for _, wrap := range union {
			if slices.Contains(readers, wrap.SubjectID) {
				row.Wraps = append(row.Wraps, wrap)
			}
		}
		if len(row.Wraps) != len(readers) {
			t.Fatal("fixture requested a reader outside the actual 127-recipient registry")
		}
		access = append(access, row)
	}
	// Merge only authentic selected rows and content from the two original
	// owners. Replace their consumer vectors with the exact canonical inputs.
	var rows []contract.SupportRecord
	var locations []contract.GeneratorSliceLocation
	var bundles []contract.GeneratorPlanBundle
	seen := make(map[generatedRecordKey][]byte)
	for _, pair := range []struct {
		state *StateSession
		work  *generatedSelection
		owner contract.GeneratedHazardRecord
	}{{s, endingWork, ending}, {donor, survivingWork, surviving}} {
		generatedMaterializeFixtureSupport(t, pair.state)
		selected, err := pair.state.resolveSelectedGeneratedSlices()
		if err != nil {
			t.Fatal(err)
		}
		locations = append(locations, selected...)
		bundles = append(bundles, pair.work.bundles...)
		for _, row := range pair.state.supportRecords() {
			if row.Kind == contract.RetainedCanonicalSupportKind || row.Kind == contract.GeneratedHazardSupportKind {
				continue
			}
			if row.Kind == contract.GeneratorVectorSupportKind {
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if carrier.VectorKind == contract.GeneratorVectorSlices || carrier.OwnerKind == contract.GeneratedHazardSupportKind && carrier.VectorKind == contract.GeneratorVectorConsumers {
					continue
				}
			}
			key := generatedRecordKey{row.Kind, row.RecordID}
			if prior, found := seen[key]; found {
				if !bytes.Equal(prior, row.Body) {
					t.Fatal("independent owner fixture has conflicting authentic support", key)
				}
				continue
			}
			seen[key], rows = row.Body, append(rows, row)
		}
		bodies := ownerConsumers[pair.owner.HazardID]
		slices.SortFunc(bodies, bytes.Compare)
		var carriers []contract.SupportRecord
		pair.owner.Consumers, carriers = generatedVectorRows(t, contract.GeneratedHazardSupportKind, pair.owner.HazardID, contract.GeneratorVectorConsumers, bodies)
		body, err := contract.EncodeGeneratedHazardRecord(pair.owner)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, carriers...)
		rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedHazardSupportKind, RecordID: pair.owner.HazardID, Body: body})
		seedAccess := endingAccess
		if pair.state == donor {
			seedAccess = donor.accessRecords()
		}
		for _, row := range seedAccess {
			if row.MaterialKind == contract.OperationSeedMaterialKind {
				access = append(access, row)
			}
		}
	}
	rows = append(rows, canonicalRows...)
	locations, err = generatedUniqueLocations(locations)
	if err != nil {
		t.Fatal(err)
	}
	var locationBodies [][]byte
	for _, location := range locations {
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal(err)
		}
		locationBodies = append(locationBodies, body)
	}
	directory, carriers, err := generatedCarrierRows(s.root.Domain, contract.GeneratorSnapshotOwner, s.adminIndex.SliceSnapshot, contract.GeneratorVectorSlices, locationBodies)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, carriers...)
	s.root.Generated.Slices = directory
	generatedRefreshClosureCounts(&s.root.Generated, rows)
	var graphs []contract.ID
	for _, bundle := range bundles {
		graphs = append(graphs, bundle.UsePlan.PlanGraphID)
	}
	slices.SortFunc(graphs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, slices.Compact(graphs))
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(access, func(a, b contract.AccessRecord) int {
		if a.MaterialKind != b.MaterialKind {
			return int(a.MaterialKind) - int(b.MaterialKind)
		}
		return bytes.Compare(a.MaterialID[:], b.MaterialID[:])
	})
	pageIndex, pageLength := 0, 75
	for _, row := range access {
		length := 102 + 489*len(row.Wraps)
		if pageLength+length > 2_097_152 {
			pageIndex, pageLength = pageIndex+1, 75
		}
		if s.access[pageIndex] == nil {
			s.access[pageIndex] = &format.AccessPage{}
		}
		s.access[pageIndex].Records = append(s.access[pageIndex].Records, row)
		pageLength += length
	}
	// Support indexing requires the complete current image's scalar count
	// before it can bind canonical rows to their actual work consumers. The
	// cleanup source shell still has zero current entries at this point.
	s.root.ValueEntryCount = uint32(len(s.root.Names))
	generatedCommitFixtureAccess(t, s)
	generatedRepackSupportAtLocations(t, s, rows, bundles, locations)
	generatedSealSelectedFixture(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("merged actual canonical owner material index")
	}
	return s, original, ending.HazardID, surviving.HazardID, generatedReflectionPageID(1, 34), targetReaders
}

// A create Hazard can own a canonical consumer and a later cleanup invocation.
// A delete-only Hazard cannot: its Consumers vector contains only one exact
// result consumer per delete-history row. Hand off the original create first,
// so this legal source retains its release mapping without a third seed.
func generatedReflectionPageCleanupSource(t *testing.T) (*StateSession, generatedAttempt, contract.GeneratedHazardRecord) {
	t.Helper()
	s, source := generatedOrdinaryCleanupSourceState(t, contract.GeneratedCompletionAcknowledged, true)
	g := mustSelectedGeneratedWork(t, s)
	create := g.attempts[source.OriginalAttemptID]
	s = generatedHazardEvidenceHandoff(t, s, create, source.Hazard, contract.GeneratedReleaseUnknown)
	g = mustSelectedGeneratedWork(t, s)
	var err error
	source, err = contract.InspectGeneratedDeleteSource(g.records[generatedRecordKey{contract.GeneratedHazardSupportKind, source.SourceID}])
	if err != nil || len(g.attempts) != 0 || len(g.releases) != 1 || s.root.Generated.Materials != 0 {
		t.Fatal("detached original create must retain its exact release without a seed", err)
	}
	reserved, err := s.deriveGeneratedReservation(t.Context(), generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(180)))
	if err != nil {
		t.Fatal("reserve real cleanup invocation for detached create Hazard", err)
	}
	s = reserved.state
	g = mustSelectedGeneratedWork(t, s)
	a := g.attempts[g.phase.FrontierAttemptID]
	facts, err := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, a, contract.GeneratorDispositionUnknown))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.generatedOrdinaryCleanupAmbiguityPlan(t.Context(), a.record.AttemptID, facts, generatedLifecycleFixture(t, s))
	if err != nil {
		t.Fatal("park original cleanup invocation", err)
	}
	parked, err := s.deriveGeneratedOrdinaryCleanupAmbiguity(t.Context(), plan)
	if err != nil {
		t.Fatal("select parked original cleanup invocation", err)
	}
	s = parked.state
	g = mustSelectedGeneratedWork(t, s)
	hazard, err := contract.InspectGeneratedHazardRecord(g.records[generatedRecordKey{contract.GeneratedHazardSupportKind, source.SourceID}].Body)
	if err != nil || len(g.attempts) != 1 || len(g.releases) != 1 || s.root.Generated.Materials != 1 {
		t.Fatal("parked cleanup must keep one exact seed and its detached create owner", err)
	}
	return s, g.attempts[a.record.AttemptID], hazard
}

// The Formats wire constants are fixed independently of the lifecycle's
// access projection and page-count functions: 75 page bytes, 102 record bytes,
// 489 per ordinary RSA-3072 wrap, and a 2 MiB maximum page.
func generatedReflectionExpectedPageLengths(t *testing.T, rows []contract.AccessRecord) []int {
	t.Helper()
	var pages []int
	length := 75
	for _, row := range rows {
		encoded, err := contract.EncodeAccessRecord(row)
		want := 102 + 489*len(row.Wraps)
		if err != nil || len(encoded) != want {
			t.Fatal("independent access wire arithmetic", len(encoded), want, err)
		}
		if length+want > 2_097_152 {
			pages, length = append(pages, length), 75
		}
		length += want
	}
	if length > 75 {
		pages = append(pages, length)
	}
	return pages
}

func assertGeneratedReflectionPageInventory(t *testing.T, s *StateSession, wantAccessBytes []int) {
	t.Helper()
	var valuePages, recipientPages uint32
	var childBytes uint64
	for _, ref := range s.root.ValueEntryPages {
		if ref != nil {
			valuePages++
			childBytes += uint64(ref.Length)
		}
	}
	for _, ref := range s.root.Recipients {
		if ref != nil {
			recipientPages++
			childBytes += uint64(ref.Length)
		}
	}
	if valuePages != 5 || recipientPages != 16 || len(s.root.CurrentAccess.Core.AccessPageRefs) != len(wantAccessBytes) {
		t.Fatal("exact selected value, recipient and access page inventory", valuePages, recipientPages, len(s.root.CurrentAccess.Core.AccessPageRefs))
	}
	for i, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
		page, err := format.EncodeAccessPage(*s.access[ref.Index])
		if err != nil || len(page) != wantAccessBytes[i] || ref.Length != uint32(wantAccessBytes[i]) {
			t.Fatal("exact selected physical access page bytes", i, len(page), ref.Length, wantAccessBytes[i], err)
		}
		childBytes += uint64(ref.Length)
	}
	for _, ref := range s.root.RequiredSupport {
		childBytes += uint64(ref.Length)
	}
	childBytes += uint64(s.root.AdministrativeIndex.Length)
	for _, ref := range s.root.AdministrativeIndexShards {
		childBytes += uint64(ref.Length)
	}
	wantChildren := valuePages + recipientPages + uint32(len(wantAccessBytes)+len(s.root.RequiredSupport)+1+len(s.root.AdministrativeIndexShards))
	if s.root.ChildCount != wantChildren || s.root.ChildEncodedBytes != childBytes || wantChildren > contract.MaxChildPages {
		t.Fatal("complete actual successor child inventory", s.root.ChildCount, wantChildren, s.root.ChildEncodedBytes, childBytes)
	}
	t.Logf("selected child inventory: values=%d recipients=%d access=%d support=%d index=%d total=%d bytes=%d", valuePages, recipientPages,
		len(wantAccessBytes), len(s.root.RequiredSupport), 1+len(s.root.AdministrativeIndexShards), wantChildren, childBytes)
}
