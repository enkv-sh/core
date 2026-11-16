package core

import (
	"bytes"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"slices"
	"strconv"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestAdministrativeSelectionChecksSignedCurrentCountsAndReceipt(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	id := generatedVectorID
	s.root.WarningBits = 1
	current, err := administrativePreservedCurrent(s.root, s.pages, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := contract.EndWorkSubject{Schema: contract.CanonicalSchema, DomainID: s.root.Domain,
		OperationID: id(230), AdmissionID: id(232), RequestCoreDigest: id(233),
		PredecessorRevisionID: s.head.Core.Revision, PredecessorFullHEADDigest: id(234), PredecessorToken: s.token,
		TargetGroupID: id(235), TargetOwnerID: id(236), TargetID: id(237), TargetKind: 1,
		SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
		DependentGroups:         contract.GeneratorDescriptor{Digest: id(238), Length: 42, Count: 1},
		RemovedSupport:          contract.GeneratorDescriptor{Digest: id(239), Length: 42, Count: 1},
		PreservedCurrent:        current, AfterWarningBits: 1,
		BeforeAccessRoot: s.root.CurrentAccess.AccessRoot, AfterAccessRoot: s.root.CurrentAccess.AccessRoot,
		BeforeAccessIncarnationID: s.root.CurrentAccess.Core.AccessIncarnationID,
		AfterAccessIncarnationID:  s.root.CurrentAccess.Core.AccessIncarnationID,
		BeforeAccessGeneration:    s.root.CurrentAccess.Core.AccessGeneration,
		AfterAccessGeneration:     s.root.CurrentAccess.Core.AccessGeneration,
		BeforeChildCount:          uint16(s.root.ChildCount), AfterChildCount: uint16(s.root.ChildCount),
		BeforeChildBytes: s.root.ChildEncodedBytes, AfterChildBytes: s.root.ChildEncodedBytes,
		ReceiptDeltaDigest: id(240), HeadCoreDigest: id(241), HeadCoreLength: contract.SuccessorHeadCoreMinLength,
		ConditionalPlanDigest: id(242)}
	q.RequestCoreDigest, err = contract.EndWorkRequestCoreDigest(q)
	if err != nil {
		t.Fatal(err)
	}
	s.head.AuthKind, s.head.EndWork = format.AdministrativeAuth, &q
	s.head.Core.Revision = id(243)
	r := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: contract.OperationEndSelectedWork,
		StateResult: contract.ReceiptStateWorkEnded, EffectSummary: contract.ReceiptEffectNotApplicable,
		EvidenceCeiling: contract.ReceiptEvidenceCanonical, DomainID: q.DomainID, OperationID: q.OperationID,
		RequestIdentityDigest: q.RequestCoreDigest,
		PredecessorRevisionID: q.PredecessorRevisionID, RequestedRevisionID: s.head.Core.Revision,
		ObservedRevisionID: s.head.Core.Revision, CanonicalOutcome: contract.ReceiptCanonicalSelected,
		WarningBits: 1, AdministrativeTargetKind: q.TargetKind, AdministrativeTargetID: q.TargetID,
		AdministrativeGroupID:     q.TargetGroupID,
		AdministrativeDisposition: q.RequestCoreDigest, AdministrativeOriginalEvidence: q.SelectedEvidenceSummary,
		AdministrativeWarningChanges: 1}
	changedID, err := contract.ChangedSubjectIdentityID(q.DomainID, contract.ChangedSubjectSelectedWork, q.TargetGroupID, q.TargetOwnerID)
	if err != nil {
		t.Fatal(err)
	}
	r.ChangedSubjects, err = contract.ChangedSubjectDescriptor([]contract.ChangedSubjectIdentity{{
		Kind: contract.ChangedSubjectSelectedWork, Change: contract.ChangedSubjectRemoved, Identity: changedID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	plan := contract.CompactMutationReceiptPlan(r)
	plan.RequestIdentityDigest = contract.ID{}
	empty := contract.EmptyMutationResultDescriptors()
	r.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{
		Receipt: plan, RequestCoreDigest: q.RequestCoreDigest,
		ChangedAccess: empty[0], Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4],
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeCompactMutationReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	s.support = append(s.support, format.RequiredSupportPageView{Records: []contract.SupportRecordView{{Kind: contract.MutationReceiptSupportKind, RecordID: q.OperationID, Body: body}}})
	if !s.validEndWorkSelection() {
		t.Fatal("matching administrative successor refused")
	}
	for name, change := range map[string]func(*StateSession){
		"warning":           func(s *StateSession) { s.root.WarningBits = 0 },
		"count":             func(s *StateSession) { s.root.ChildCount++ },
		"access root":       func(s *StateSession) { s.root.CurrentAccess.AccessRoot = id(248) },
		"access generation": func(s *StateSession) { s.root.CurrentAccess.Core.AccessGeneration++ },
		"bytes":             func(s *StateSession) { s.root.ChildEncodedBytes++ },
		"current": func(s *StateSession) {
			ref := *s.root.Recipients[0]
			ref.Digest = id(246)
			s.root.Recipients[0] = &ref
		},
		"receipt": func(s *StateSession) { s.support[1].Records[0].RecordID = id(247) },
		"changed subjects": func(s *StateSession) {
			bad := r
			bad.ChangedSubjects.Digest = id(244)
			s.support[1].Records[0].Body, _ = contract.EncodeCompactMutationReceipt(bad)
		},
		"complete result": func(s *StateSession) {
			bad := r
			bad.CompleteResult.Digest = id(245)
			s.support[1].Records[0].Body, _ = contract.EncodeCompactMutationReceipt(bad)
		},
		"same target different group": func(s *StateSession) {
			bad := r
			bad.AdministrativeGroupID = id(249)
			plan := contract.CompactMutationReceiptPlan(bad)
			plan.RequestIdentityDigest, plan.CompleteResult = contract.ID{}, contract.GeneratorDescriptor{}
			var err error
			bad.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{
				Receipt: plan, RequestCoreDigest: q.RequestCoreDigest,
				ChangedAccess: empty[0], Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4],
			})
			if err != nil {
				t.Fatal(err)
			}
			s.support[1].Records[0].Body, err = contract.EncodeCompactMutationReceipt(bad)
			if err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := *s
			bad.root = s.root
			bad.support = append([]format.RequiredSupportPageView(nil), s.support...)
			bad.support[1].Records = append([]contract.SupportRecordView(nil), s.support[1].Records...)
			change(&bad)
			if bad.validEndWorkSelection() {
				t.Fatal("changed successor accepted")
			}
		})
	}
}

// full_only: false
func TestEndWorkPreviewApplyIdentitySurvivesFreshSliceCandidates(t *testing.T) {
	s, owners, expected := endWorkIndependentSliceOwners(t)
	observationProtectFixture(t, s)
	store := observationPhysicalGeneratedStore(t, s)
	store.objects[s.admission.store.HeadKey] = bytes.Clone(s.body)
	// Authenticate the complete fixture through an unrelated GC reservation.
	// This transition preserves every physical Slice row and owner.
	plan := gcTestPlan(t, s, "independent-slice-source")
	s = gcTestSelectState(t, s, plan, gcTestProgress(t, plan), contract.GCSelect, true)
	s, result := Open(t.Context(), OpenContext{admission: &s.admission}, store)
	if s == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold admission of independent Slice owners", result)
	}
	original := mustSelectedGeneratedWork(t, s)
	if len(original.content.locations) != 8 || len(original.bundles) != 4 {
		t.Fatal("cold source lost independent Slice owners")
	}
	originalLocations := make(map[generatedContentKey]contract.GeneratorSliceLocation, len(original.content.locations))
	for key, location := range original.content.locations {
		originalLocations[key] = location
	}
	target := owners[len(owners)-1]
	remaining, _, err := s.administrativeWorkClosure(target)
	if err != nil {
		t.Fatal("real retained owner disposition", err)
	}
	projected, _, err := s.administrativeGeneratedProjection(remaining)
	if err != nil || projected.Slices == s.root.Generated.Slices || projected.Slices.Count != 6 || s.root.Generated.Slices.Count != 8 {
		t.Fatal("disposition did not remove exactly the ending owner's Graph and Intent", projected.Slices, s.root.Generated.Slices, err)
	}
	s.admission.endWorkInvocation = gcTestID("slice-preview-invocation")
	previewer := &AuthoritySession{state: s, mode: LocalAuthorityPreview}
	var want EndWorkPreview
	for round := 0; round < 16; round++ {
		var entropy []byte
		for i := 0; i < 10; i++ {
			id := gcTestID("slice-preview/" + strconv.Itoa(round) + "/" + strconv.Itoa(i))
			entropy = append(entropy, id[:]...)
		}
		s.admission.entropy = bytes.NewReader(entropy)
		got, result := previewer.Preview(t.Context(), target)
		if result.Outcome != ObservedCurrent {
			t.Fatal("preview valid retained Slice graph", result)
		}
		if round == 0 {
			want = got
		} else if !equalEndWorkPreview(got, want) {
			t.Fatal("unchanged semantic disposition changed accepted preview", got, want)
		}
	}
	var entropy []byte
	for i := 0; i < 10; i++ {
		id := gcTestID("slice-apply/" + strconv.Itoa(i))
		entropy = append(entropy, id[:]...)
	}
	s.admission.entropy = bytes.NewReader(entropy)
	apply := &AuthoritySession{state: s, mode: LocalAuthorityEnd, trust: testtrust.New(t, s.admission.store.Family, s.admission.trust)}
	got := apply.End(t.Context(), want)
	if got.Result.Outcome != ObservedCurrent || len(got.Receipt) == 0 {
		t.Fatal("unchanged accepted preview was stale at apply", got.Result)
	}
	cold, result := Open(t.Context(), OpenContext{admission: &s.admission}, store)
	if cold == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold read after preview/apply", result)
	}
	work := mustSelectedGeneratedWork(t, cold)
	if len(work.content.locations) != 6 || len(cold.adminIndex.Groups) != 4 || cold.root.ActiveGC != plan.OperationID {
		t.Fatal("ending discarded unrelated retained work")
	}
	for key, owner := range expected {
		location, present := work.content.locations[key]
		if owner == target {
			if present {
				t.Fatal("ended Slice remained selected", key.kind)
			}
			continue
		}
		if !present || location != originalLocations[key] {
			t.Fatal("surviving Slice changed", key.kind)
		}
		found := false
		for i, page := range cold.adminIndex.Pages {
			if !page.ReadRequired {
				continue
			}
			logical := 0
			for _, span := range page.Spans {
				for n := 0; n < int(span.Count); n++ {
					carrier, match, err := snapshotSliceRecord(contract.SupportRecord(cold.support[i].Records[logical]), cold.root.Domain, cold.adminIndex.SliceSnapshot)
					logical++
					if err != nil || !match {
						t.Fatal("cold retained Slice carrier", err)
					}
					actual, err := contract.InspectGeneratorSliceLocation(carrier.Row)
					if err != nil {
						t.Fatal(err)
					}
					if actual.ContentKind == key.kind && actual.ContentID == key.id {
						if len(span.GroupIndexes) != 1 || cold.adminIndex.Groups[span.GroupIndexes[0]].GroupID != owner || span.Mandatory {
							t.Fatal("cold retained Slice changed its owner")
						}
						found = true
					}
				}
			}
		}
		if !found {
			t.Fatal("surviving Slice has no exact indexed owner")
		}
	}
}

func endWorkIndependentSliceOwners(t *testing.T) (*StateSession, []contract.ID, map[generatedContentKey]contract.ID) {
	t.Helper()
	state := generatedEmptyPredecessor(t)
	rows := state.supportRecords()
	var owners, graphs []contract.ID
	var bundles []contract.GeneratorPlanBundle
	var locations []contract.GeneratorSliceLocation
	blobBodies := make(map[uint8][]byte)
	var access []contract.AccessRecord
	expected := make(map[generatedContentKey]contract.ID)
	for i := 0; i < 4; i++ {
		before := generatedEmptyPredecessor(t)
		name := "retained-" + strconv.Itoa(i)
		input := generatedReservationInputForProfileIntent(t, before, gcTestID("independent-slice-operation/"+name), []string{name}, []byte(`{"name":"`+name+`"}`), defaultGeneratedFixtureProfile())
		reservation, err := before.deriveGeneratedReservation(t.Context(), input)
		if err != nil {
			t.Fatal("independent original reservation", err)
		}
		original := mustSelectedGeneratedWork(t, reservation.state)
		frontier := original.attempts[original.phase.FrontierAttemptID]
		packet := generatedPublicResultFixtureWithRawToken(t, frontier, contract.GeneratorDispositionCompleteCreate, 1, gcTestID("independent-qualified-resource/"+name))
		cleanup, attempt := generatedUnselectedCleanupFromReservation(t, reservation.state, packet)
		selected := mustSelectedGeneratedWork(t, cleanup)
		if selected.parent != nil || len(selected.bundles) != 1 || len(selected.content.locations) != 2 {
			t.Fatal("cleanup must own one Graph and one Intent")
		}
		owner := attempt.record.OwnerID
		owners = append(owners, owner)
		graphs = append(graphs, selected.bundles[0].UsePlan.PlanGraphID)
		bundles = append(bundles, selected.bundles[0])
		for key, location := range selected.content.locations {
			if key.kind != contract.GeneratorContentGraph && key.kind != contract.GeneratorContentIntent {
				t.Fatal("unexpected independent cleanup content")
			}
			if _, duplicate := expected[key]; duplicate {
				t.Fatal("independent cleanup shared logical content")
			}
			body, err := selected.readSelectedSlice(t.Context(), key.kind, key.id, location.Length)
			if err != nil {
				t.Fatal(err)
			}
			location.Offset = uint64(len(blobBodies[key.kind]))
			locations = append(locations, location)
			blobBodies[key.kind] = append(blobBodies[key.kind], body...)
			expected[key] = owner
		}
		for _, row := range cleanup.supportRecords() {
			if row.Kind == contract.GeneratedFragmentSupportKind || row.Kind == contract.OutputConfigurationSliceSupportKind {
				continue
			}
			if row.Kind == contract.GeneratorVectorSupportKind {
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if carrier.OwnerKind == contract.GeneratorSnapshotOwner {
					continue
				}
			}
			rows = append(rows, row)
		}
		access = append(access, cleanup.accessRecords()...)
	}
	var blobs []generatedContentFixtureBlob
	for _, kind := range []uint8{contract.GeneratorContentGraph, contract.GeneratorContentIntent} {
		body := blobBodies[kind]
		blobID := contract.Hash(body)
		for i := range locations {
			if locations[i].ContentKind == kind {
				locations[i].BlobID = blobID
			}
		}
		blobs = append(blobs, generatedContentFixtureBlob{blobID, body})
	}
	content := generatedContentStateAtSnapshot(t, state.root.Snapshot, blobs, locations)
	rows = append(rows, content.supportRecords()...)
	state.root.Generated = content.root.Generated
	state.root.Generated.Attempts, state.root.Generated.Duties, state.root.Generated.Results, state.root.Generated.Materials = 4, 4, 4, 4
	sortedOwners := slices.Clone(owners)
	slices.SortFunc(sortedOwners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	slices.SortFunc(graphs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	var err error
	state.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, sortedOwners)
	if err != nil {
		t.Fatal(err)
	}
	state.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, graphs)
	if err != nil {
		t.Fatal(err)
	}
	state.access[0] = &format.AccessPage{Records: access}
	generatedRepackSupportAtLocations(t, state, rows, bundles, locations)
	generatedSealSelectedFixture(t, state)
	// These are new fixture pages. Place each owner's Graph before its Intent
	// round so retained rows alternate owners after the fourth Duty ends.
	position := -1
	selectedRows := make(map[generatedContentKey]contract.SupportRecordView)
	for i, page := range state.adminIndex.Pages {
		if !page.ReadRequired {
			continue
		}
		if position >= 0 {
			t.Fatal("small Slice fixture unexpectedly uses multiple pages")
		}
		position = i
		for _, row := range state.support[i].Records {
			carrier, match, err := snapshotSliceRecord(contract.SupportRecord(row), state.root.Domain, state.adminIndex.SliceSnapshot)
			if err != nil || !match {
				t.Fatal("independent Slice carrier", err)
			}
			location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
			if err != nil {
				t.Fatal(err)
			}
			selectedRows[generatedContentKey{kind: location.ContentKind, id: location.ContentID}] = row
		}
	}
	if position < 0 || len(selectedRows) != 8 {
		t.Fatal("independent fixture lacks eight packed Slice carriers")
	}
	view := state.support[position]
	view.Object, view.Records = gcTestID("independent-alternating-slice-page"), nil
	for _, kind := range []uint8{contract.GeneratorContentGraph, contract.GeneratorContentIntent} {
		for _, owner := range owners {
			found := false
			for key, row := range selectedRows {
				if key.kind == kind && expected[key] == owner {
					view.Records = append(view.Records, row)
					found = true
					break
				}
			}
			if !found {
				t.Fatal("owner lacks its independent Slice", kind)
			}
		}
	}
	state.support[position] = view
	generatedRefreshSupport(t, state, bundles...)
	rootBody, err := format.EncodeRoot(state.root)
	if err != nil {
		t.Fatal(err)
	}
	state.head.Core.Root, err = format.Reference(contract.RootKind, state.root.Domain, state.root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	generatedVerifySelectedFixtureSlices(t, state)
	if !state.indexSelectedMaterials() {
		t.Fatal("independent cleanup material index")
	}
	if _, err := state.validateRelationsMode(t.Context(), false); err != nil {
		t.Fatal("complete independent cleanup relation", err)
	}
	page := state.adminIndex.Pages[position]
	if !page.ReadRequired || len(page.Spans) != 8 {
		t.Fatal("source owner alternation was not retained")
	}
	for i, span := range page.Spans {
		if span.Count != 1 || span.Mandatory || len(span.GroupIndexes) != 1 || state.adminIndex.Groups[span.GroupIndexes[0]].GroupID != owners[i%4] {
			t.Fatal("source Slice ownership is not the independent alternating sequence", i)
		}
	}
	return state, owners, expected
}
