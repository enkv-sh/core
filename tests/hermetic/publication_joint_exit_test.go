package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func publicationJointSelectedImage(t *testing.T, env fixtureEnvironment, lifecycle, before *StateSession, rows []contract.SupportRecord, orders []format.PublicationCoordinateOrder, evidencePages, markerPages int, label string, isolatedCoordinates ...bool) (fixtureEnvironment, *StateSession) {
	t.Helper()
	store := selectedMemoryStoreCopy(env.Store.(*memoryStore))
	next := *before
	next.store = store
	next.root.Snapshot, next.root.Transition = publicationJointID(env.Domain, label+" snapshot", 0), publicationJointID(env.Domain, label+" transition", 0)
	next.support = slices.Clone(before.support)
	next.root.RequiredSupport = nil
	next.root.RequiredSupportRecordCount = 0
	replacements := make(map[contract.ID]bool)
	replacedRows := make(map[generatedRecordKey]bool)
	for _, row := range rows {
		replacedRows[generatedRecordKey{row.Kind, row.RecordID}] = true
		if row.Kind == contract.PublicationCoordinateSupportKind {
			replacements[row.RecordID] = true
		}
	}
	currentEvidence := make(map[contract.ID]bool)
	if evidencePages != 0 {
		for _, named := range before.root.Names {
			entry := before.valueEntry(named.Slot)
			if entry.ValueSource == contract.Generated {
				currentEvidence[entry.Generated.CreateResultID] = true
			}
		}
	}
	var evidenceRows []contract.SupportRecord
	put := func(ref format.Ref, body []byte) {
		t.Helper()
		if err := format.CheckReference(ref, body); err != nil {
			t.Fatal(err)
		}
		if err := store.putSelected(mustKey(t, store.desc.Prefix, ref), body); err != nil {
			t.Fatal(err)
		}
	}
	next.clearSelectedSupportFacts()
	var pages []format.RequiredSupportPage
	for _, ref := range before.root.RequiredSupport {
		body, result := before.readObjectBorrowedUncached(t.Context(), ref)
		if result.Outcome != 0 {
			t.Fatal("selected physical peer read", result)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		page := format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index}
		position, found := before.selectedSupportPosition(ref)
		if !found || position >= len(before.supportFacts) {
			t.Fatal("missing selected physical ordinals")
		}
		selected := before.supportFacts[position].ordinals
		changed := false
		for _, ordinal := range selected {
			row := contract.SupportRecord(view.Records[ordinal])
			if row.Kind == contract.GeneratedCreateEvidenceSupportKind && currentEvidence[row.RecordID] {
				evidenceRows = append(evidenceRows, row)
				changed = true
				continue
			}
			if replacedRows[generatedRecordKey{row.Kind, row.RecordID}] {
				changed = true
				continue
			}
			page.Records = append(page.Records, row)
		}
		if len(page.Records) == 0 {
			continue
		}
		if changed {
			object := publicationJointID(env.Domain, label+" retained peer", int(page.Index))
			var encoded []byte
			ref, _, encoded, err = endWorkSupportPage(env.Domain, object, page.Index, page.Records, nil)
			if err != nil {
				t.Fatal("partitioned retained peer", err)
			}
			put(ref, encoded)
			page.Object = object
		}
		pages = append(pages, page)
		next.root.RequiredSupport = append(next.root.RequiredSupport, ref)
		next.root.RequiredSupportRecordCount += uint32(len(page.Records))
	}
	var allOrders []format.PublicationCoordinateOrder
	for _, order := range before.adminIndex.PublicationOrder {
		if !replacements[order.CoordinateID] {
			allOrders = append(allOrders, order)
		}
	}
	allOrders = append(allOrders, orders...)
	slices.SortFunc(allOrders, func(a, b format.PublicationCoordinateOrder) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	var mandatory administrativeMandatorySupport
	if _, err := mandatory.selectedPublication(env.Domain, rows, orders); err != nil {
		t.Fatal(err)
	}
	var groups []format.RequiredSupportGroup
	for _, row := range rows {
		keep, err := mandatory.row(row)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, format.RequiredSupportGroup{Class: format.OwnerSupport, Owner: row.RecordID, Mandatory: keep, Records: []contract.SupportRecord{row}})
	}
	otherChildren := before.root.ChildCount - uint32(len(before.root.RequiredSupport)) + uint32(len(pages))
	var packed [][]contract.SupportRecord
	if evidencePages == 0 && markerPages == 0 {
		var err error
		packed, err = format.PackRequiredSupportRows(env.Domain, groups, otherChildren)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		// Partition existing owners; each partition still uses the real packer.
		var coordinates, markers, evidence []format.RequiredSupportGroup
		for _, group := range groups {
			if group.Records[0].Kind == contract.PublicationCoordinateSupportKind {
				coordinates = append(coordinates, group)
			} else if group.Records[0].Kind == contract.PublicationMarkerSupportKind && !group.Mandatory {
				markers = append(markers, group)
			} else {
				t.Fatal("joint partition requires current coordinates and unresolved markers")
			}
		}
		for _, row := range evidenceRows {
			evidence = append(evidence, format.RequiredSupportGroup{Class: format.OldValueSupport, Owner: row.RecordID, Mandatory: true, Records: []contract.SupportRecord{row}})
		}
		if len(evidenceRows) != len(currentEvidence) || evidencePages < 1 || evidencePages > len(evidence) || markerPages < 1 || markerPages > len(markers) {
			t.Fatal("joint existing-owner partition dimensions", len(evidenceRows), len(currentEvidence), evidencePages, markerPages)
		}
		appendPartitions := func(owners []format.RequiredSupportGroup, count int) {
			slices.SortFunc(owners, func(a, b format.RequiredSupportGroup) int { return bytes.Compare(a.Owner[:], b.Owner[:]) })
			for i := 0; i < count; i++ {
				part, err := format.PackRequiredSupportRows(env.Domain, owners[i*len(owners)/count:(i+1)*len(owners)/count], otherChildren+uint32(len(packed)))
				if err != nil || len(part) != 1 {
					t.Fatal("joint actual owner partition", i, len(part), err)
				}
				packed = append(packed, part...)
			}
		}
		coordinatePages := 1
		if len(isolatedCoordinates) != 0 && isolatedCoordinates[0] {
			coordinatePages = len(coordinates)
		}
		appendPartitions(coordinates, coordinatePages)
		appendPartitions(evidence, evidencePages)
		appendPartitions(markers, markerPages)
	}
	for i, part := range packed {
		physical := uint16(0)
		for slices.ContainsFunc(next.root.RequiredSupport, func(ref format.Ref) bool { return ref.Index == physical }) {
			physical++
		}
		object := publicationJointID(env.Domain, label+" page", i)
		ref, view, body, err := endWorkSupportPage(env.Domain, object, physical, part, nil)
		if err != nil {
			t.Fatal(err)
		}
		put(ref, body)
		next.root.RequiredSupport = append(next.root.RequiredSupport, ref)
		next.support = append(next.support, view)
		next.root.RequiredSupportRecordCount += uint32(len(part))
		pages = append(pages, format.RequiredSupportPage{Domain: env.Domain, Object: object, Index: physical, Records: part})
	}
	// Match physical reference order and supply complete selected rows to the
	// existing index builder; cold views intentionally omit opaque bodies.
	for i := range pages {
		for j := i + 1; j < len(pages); j++ {
			if pages[j].Index < pages[i].Index {
				pages[i], pages[j] = pages[j], pages[i]
				next.root.RequiredSupport[i], next.root.RequiredSupport[j] = next.root.RequiredSupport[j], next.root.RequiredSupport[i]
			}
		}
	}
	next.support = nil
	for _, page := range pages {
		view := format.RequiredSupportPageView{Domain: page.Domain, Object: page.Object, Index: page.Index}
		for _, row := range page.Records {
			view.Records = append(view.Records, contract.SupportRecordView(row))
		}
		next.support = append(next.support, view)
	}
	predecessor := *before
	predecessor.adminIndex.PublicationOrder = allOrders
	index, err := predecessor.buildAdministrativeIndex(t.Context(), next.root, pages, nil, nil, &next)
	if err != nil {
		t.Fatal("joint actual index", err)
	}
	next.adminIndex = index
	shards, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil {
		t.Fatal(err)
	}
	next.root.AdministrativeIndex, next.root.AdministrativeIndexShards = shards[0].Ref, nil
	for i, shard := range shards {
		put(shard.Ref, shard.Body)
		if i != 0 {
			next.root.AdministrativeIndexShards = append(next.root.AdministrativeIndexShards, shard.Ref)
		}
	}
	next.recountChildren()
	store, opened := writeSignedCurrentIntentImage(t, env, lifecycle, before, &next, store, label, put)
	env.Store = store
	env.Put = func(_ context.Context, key string, body []byte) error { return store.putSelected(key, body) }
	return env, opened
}

func publicationJointPersistMaterialized(t *testing.T, env fixtureEnvironment, before, next *StateSession, candidate *Candidate, label string) *StateSession {
	t.Helper()
	store := env.Store.(*memoryStore)
	put := func(ref format.Ref, body []byte) {
		t.Helper()
		if err := format.CheckReference(ref, body); err != nil {
			t.Fatal(err)
		}
		if err := store.putSelected(mustKey(t, store.desc.Prefix, ref), body); err != nil {
			t.Fatal(err)
		}
	}
	for _, image := range candidate.objects {
		put(image.ref, image.body)
	}
	_, opened := writeSignedCurrentIntentImage(t, env, before, before, next, store, label, put)
	return opened
}

func publicationJointMaterialize(t *testing.T, env fixtureEnvironment, before *StateSession, rows []contract.SupportRecord, reserve bool, label string) *StateSession {
	t.Helper()
	order, err := publicationOrderForRows(env.Domain, rows, before.adminIndex.PublicationOrder)
	if err != nil {
		t.Fatal(err)
	}
	var mandatory administrativeMandatorySupport
	if _, err := mandatory.selectedPublication(env.Domain, rows, order); err != nil {
		t.Fatal(err)
	}
	plan, err := before.planPublicationRewrite(t.Context(), before.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	var groups []format.RequiredSupportGroup
	for _, row := range rows {
		keep, err := mandatory.row(row)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, format.RequiredSupportGroup{Class: format.OwnerSupport, Owner: row.RecordID, Mandatory: keep, Records: []contract.SupportRecord{row}})
	}
	packed, err := format.PackRequiredSupportRows(env.Domain, groups, uint32(len(plan.peers)))
	if err != nil {
		t.Fatal(err)
	}
	next := *before
	next.root.Snapshot, next.root.Transition = publicationJointID(env.Domain, label+" snapshot", 0), publicationJointID(env.Domain, label+" transition", 0)
	candidate := Candidate{session: before}
	ids := publicationJointPageIDs(env.Domain, label+" page", len(packed))
	construction, err := before.preparePublicationConstruction(t.Context(), rows)
	if err != nil {
		t.Fatal("checked publication construction", label, err)
	}
	if reserve {
		err = before.materializePublicationReservationConstruction(t.Context(), &next, &candidate, construction, ids)
	} else {
		err = before.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, ids)
	}
	if err != nil {
		t.Fatal("actual publication construction", label, err)
	}
	if _, err := next.publicStateProjection(); err != nil {
		t.Fatalf("materialized public-state projection: phase=%s retained-support-pages=%d support-fact-pages=%d err=%v", label, len(next.root.RequiredSupport), len(next.supportFacts), err)
	}
	return publicationJointPersistMaterialized(t, env, before, &next, &candidate, label)
}

// Coordinate disposal removes that retired coordinate and every marker that
// names it. The expected set comes from the selected predecessor, before CAS.
func publicationJointRetiredCoordinateRemovedRows(t *testing.T, before *StateSession, target contract.ID) []generatedRecordKey {
	t.Helper()
	selected, err := selectedPublicationRelation(before.selectedImage())
	if err != nil {
		t.Fatal("exit predecessor publication relation", err)
	}
	coordinate, found := selected.coordinates[target]
	if !found || coordinate.BindingState != contract.PublicationBindingRetired {
		t.Fatal("exit target is not a selected retired coordinate")
	}
	removed := []generatedRecordKey{{contract.PublicationCoordinateSupportKind, target}}
	for id, marker := range selected.markers {
		if marker.CoordinateID == target {
			removed = append(removed, generatedRecordKey{contract.PublicationMarkerSupportKind, id})
		}
	}
	return removed
}

func assertPublicationJointExitPreserved(t *testing.T, after *StateSession, expected map[generatedRecordKey]selectedFragmentFact, order []format.PublicationCoordinateOrder, removed []generatedRecordKey) {
	t.Helper()
	actual, err := capacityConfigurationPreservedFacts(t.Context(), after)
	if err != nil {
		t.Fatal("exit successor configuration/publication facts", err)
	}
	if len(actual) != len(expected) {
		t.Fatalf("exit preserved row count: got=%d want=%d", len(actual), len(expected))
	}
	for key, want := range expected {
		got, present := actual[key]
		if !present || got.row != want.row {
			t.Fatalf("exit changed unaffected configuration/publication row: kind=%d id=%x", key.kind, key.id)
		}
		if got.ref == want.ref && got.physical != want.physical {
			t.Fatalf("exit changed retained physical ordinal: kind=%d id=%x got=%d want=%d", key.kind, key.id, got.physical, want.physical)
		}
	}
	if !reflect.DeepEqual(after.adminIndex.PublicationOrder, order) {
		t.Fatal("exit changed unaffected publication order or retained disposed coordinate order")
	}
	for _, key := range removed {
		if _, present := actual[key]; present || slices.ContainsFunc(after.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == key.id }) {
			t.Fatalf("exit retained exact disposed row or owner: kind=%d id=%x", key.kind, key.id)
		}
	}
}

func publicationJointExit(t *testing.T, env fixtureEnvironment, before *StateSession, target contract.ID) *StateSession {
	t.Helper()
	removed := publicationJointRetiredCoordinateRemovedRows(t, before, target)
	expected, err := capacityConfigurationPreservedFacts(t.Context(), before)
	if err != nil {
		t.Fatal("exit predecessor configuration/publication facts", err)
	}
	for _, key := range removed {
		if _, present := expected[key]; !present {
			t.Fatal("exit expected removed row is absent", key.kind, key.id)
		}
		delete(expected, key)
	}
	var expectedOrder []format.PublicationCoordinateOrder
	for _, row := range before.adminIndex.PublicationOrder {
		if row.CoordinateID != target {
			expectedOrder = append(expectedOrder, format.PublicationCoordinateOrder{CoordinateID: row.CoordinateID, Incarnations: slices.Clone(row.Incarnations)})
		}
	}
	return publicationJointExitWithExpected(t, env, before, target, expected, expectedOrder, removed, contract.ID{})
}

func publicationJointExitWithExpected(t *testing.T, env fixtureEnvironment, before *StateSession, target contract.ID, expected map[generatedRecordKey]selectedFragmentFact, expectedOrder []format.PublicationCoordinateOrder, removed []generatedRecordKey, obsoleteSeed contract.ID, administrative ...bool) *StateSession {
	t.Helper()
	partial := len(administrative) != 0 && administrative[0]
	expectedAccess := publicationJointExpectedAccess(t, before, obsoleteSeed)
	warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningPossibleStoreGarbage
	var targetGroup format.AdministrativeGroup
	for _, group := range before.adminIndex.Groups {
		if group.GroupID == target {
			targetGroup = group
		}
		if group.GroupID != target && !slices.ContainsFunc(removed, func(key generatedRecordKey) bool { return key.id == group.GroupID }) {
			continue
		}
		if group.OwnerKind >= format.AdministrativeGeneratedParent && group.OwnerKind <= format.AdministrativeInboxRelease {
			warning |= WarningOrphanGeneratedEffect
		}
		if (group.OwnerKind == format.AdministrativePublicationCoordinate || group.OwnerKind == format.AdministrativePublicationMarker) && group.EffectEntryCeiling != 0 {
			warning |= WarningPublicationOrderValue
		}
		if group.OwnerKind == format.AdministrativeGeneratedDuty && group.DutyKind != contract.GeneratedDutyCreate {
			warning |= WarningLateDestructiveEffect
		}
	}
	if targetGroup.GroupID.IsZero() {
		t.Fatal("expected exit target absent")
	}
	store := env.Store.(*memoryStore)
	cas := store.cas
	public, private := env.Custody.Calls()
	windows, err := before.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		t.Fatal(err)
	}
	candidate, result := prepareTestEndSelectedWork(t, before, t.Context(), target, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		publicationExitPreparationFailure(t, before, target, result)
	}
	after, result := before.selectCandidate(t.Context(), candidate)
	if after == nil || result.Outcome != ObservedCurrent || store.cas != cas+1 {
		t.Fatal("joint exit real CAS", result, store.cas-cas)
	}
	if partial {
		after, result = openAdministrative(t.Context(), OpenContext{admission: &before.admission}, store)
	} else {
		after, result = Open(t.Context(), OpenContext{admission: &before.admission}, store)
	}
	if after == nil || result.Outcome != ObservedCurrent {
		t.Fatal("joint exit cold Open", result)
	}
	got, err := after.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Successes) != 256 || len(got.Failures) != 256 || !slices.Equal(got.Successes[:255], windows.Successes[1:]) || !slices.Equal(got.Failures, windows.Failures) || got.Successes[255].AdministrativeTargetID != publicationExitTarget(before, target) {
		t.Fatal("joint exit exact receipt windows")
	}
	if after.root.WarningBits != warning {
		t.Fatal("joint exit exact permanent warnings", after.root.WarningBits, warning)
	}
	last := got.Successes[255]
	if last.OperationKind != contract.OperationEndSelectedWork || last.StateResult != contract.ReceiptStateWorkEnded || last.EffectSummary != contract.ReceiptEffectNotApplicable || last.OutputSummary != contract.ReceiptOutputNotApplicable || last.EvidenceCeiling != contract.ReceiptEvidenceCanonical || last.CanonicalOutcome != contract.ReceiptCanonicalSelected || last.DomainID != before.root.Domain || last.PredecessorRevisionID != before.head.Core.Revision || last.RequestedRevisionID != after.head.Core.Revision || last.ObservedRevisionID != after.head.Core.Revision || last.AdministrativeTargetKind != targetGroup.OwnerKind || last.AdministrativeOriginalEvidence != targetGroup.SelectedEvidenceSummary || last.WarningBits != uint64(warning) || last.AdministrativeWarningChanges != warning&^before.root.WarningBits || last.AdministrativePageDelta != int16(after.root.ChildCount)-int16(before.root.ChildCount) || last.AdministrativeByteDelta != int64(after.root.ChildEncodedBytes)-int64(before.root.ChildEncodedBytes) {
		t.Fatal("joint exit exact administrative receipt fields")
	}
	if after.head.EndWork == nil || !reflect.DeepEqual(after.head.EndWork, candidate.head.EndWork) || last.OperationID != candidate.head.EndWork.OperationID || last.RequestIdentityDigest != candidate.head.EndWork.RequestCoreDigest || last.AdministrativeDisposition != candidate.head.EndWork.RequestCoreDigest {
		t.Fatal("joint exit receipt is not bound to selected candidate")
	}
	publicationJointPhysicalCharge(t, before, after, candidate)
	if !reflect.DeepEqual(before.currentEntryInputs(), after.currentEntryInputs()) || !reflect.DeepEqual(before.root.ValueEntryPages, after.root.ValueEntryPages) || !reflect.DeepEqual(before.root.Recipients, after.root.Recipients) || before.root.ValueEntryCount != after.root.ValueEntryCount || before.root.SecretCount != after.root.SecretCount || before.root.RawBytes != after.root.RawBytes || before.root.MembershipCount != after.root.MembershipCount || before.root.SecretOrdinaryWrapCount != after.root.SecretOrdinaryWrapCount || before.root.OutputConfiguration != after.root.OutputConfiguration {
		t.Fatal("joint exit changed current state")
	}
	publicationJointAccessPreserved(t, before, after, obsoleteSeed, expectedAccess)
	if partial {
		assertPublicationJointAdministrativePreserved(t, after, expected, expectedOrder, removed)
	} else {
		assertPublicationJointExitPreserved(t, after, expected, expectedOrder, removed)
	}
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("joint exit used custody", p-public, k-private)
	}
	if err := after.reserveFirstEndWork(t.Context()); err != nil {
		t.Fatal("joint remaining exit no longer fits", err)
	}
	return after
}

// full_only: false
func TestPublicationJointLifecycle(t *testing.T) {
	t.Run("small", func(t *testing.T) {
		env, f, _ := configuredSuccessionMemoryFixture(t, false)
		rows, order := publicationJointRows(t, env.Domain, 1)
		env, current := publicationJointSelectedImage(t, env, f.session, f.session, rows, order, 0, 0, "joint small seed")
		original := current
		relation, err := selectedPublicationRelation(current.selectedImage())
		if err != nil {
			t.Fatal(err)
		}
		coordinateID := order[0].CoordinateID
		coordinate, err := current.publicationCoordinateForAdmission(coordinateID, publicationJointID(env.Domain, "rolled", 0))
		if err != nil {
			t.Fatal(err)
		}
		create, err := contract.InspectPublicationMarker(rows[0].Body)
		if err != nil || create.CoordinateID != coordinateID || relation.markers[create.AttemptID] != create {
			t.Fatal("joint lifecycle selected uncertain create", err)
		}
		marker := publicationReservedDeleteMarker(t, create)
		marker.AttemptID, marker.OperationID = publicationJointID(env.Domain, "new-attempt", 0), publicationJointID(env.Domain, "new-operation", 0)
		marker.PublicationIncarnationID, marker.AdmissionOrdinal = coordinate.CurrentPublicationIncarnationID, coordinate.LastAdmissionOrdinal
		marker.State = contract.PublicationMayHaveEntered
		var blockers []contract.ID
		for id, m := range relation.markers {
			if m.CoordinateID == coordinateID {
				blockers = append(blockers, id)
			}
		}
		marker.BlockerCount = uint16(len(blockers))
		slices.SortFunc(blockers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		marker.BlockerDigest, err = contract.PublicationBlockerDigest(blockers)
		if err != nil {
			t.Fatal(err)
		}
		coordinate.LatestUnresolvedAttemptID = marker.AttemptID
		_, loaded, err := current.publicationLoadedRowsForDisposition()
		if err != nil {
			t.Fatal(err)
		}
		var reserved []contract.SupportRecord
		for key, record := range loaded {
			body, err := record.body()
			if err != nil {
				t.Fatal(err)
			}
			row := contract.SupportRecord{Kind: key.kind, RecordID: key.id, Body: body}
			if key.kind == contract.PublicationCoordinateSupportKind || key.kind == contract.PublicationMarkerSupportKind {
				if key.id == coordinateID {
					row.Body, err = contract.EncodePublicationCoordinate(coordinate)
					if err != nil {
						t.Fatal(err)
					}
				}
				reserved = append(reserved, row)
			}
		}
		body, err := contract.EncodePublicationMarker(marker)
		if err != nil {
			t.Fatal(err)
		}
		reserved = append(reserved, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body})
		current = publicationJointMaterialize(t, env, current, reserved, true, "joint small reserve")
		current = publicationJointMaterialize(t, env, current, publicationNoEffectRows(t, current), false, "joint small close")
		if current.root.OutputConfiguration != original.root.OutputConfiguration {
			t.Fatal("reserve/close lost configuration")
		}
		current = publicationJointExit(t, env, current, coordinateID)
		if slices.ContainsFunc(current.adminIndex.Groups, func(g format.AdministrativeGroup) bool { return g.OwnerID == coordinateID }) || slices.ContainsFunc(current.adminIndex.PublicationOrder, func(o format.PublicationCoordinateOrder) bool { return o.CoordinateID == coordinateID }) {
			t.Fatal("retired-coordinate exit left dependency or order")
		}
		t.Logf("real reserve/close/retired-coordinate exit preserved %d current entries and full windows", current.root.ValueEntryCount)
	})
}

// full_only: false
func TestPublicationReservedSlotExitClosure(t *testing.T) {
	t.Run("small", func(t *testing.T) {
		env, f, _ := configuredSuccessionMemoryFixture(t, false)
		rows, orders := publicationJointRows(t, env.Domain, 1)
		create, err := contract.InspectPublicationMarker(rows[0].Body)
		if err != nil {
			t.Fatal(err)
		}
		reserved, err := contract.InspectPublicationMarker(rows[1].Body)
		if err != nil {
			t.Fatal(err)
		}
		reserved.Projection.Action = contract.PublicationDeleteReservedSlot
		reserved.Projection.PolicyDigest = contract.ID{}
		reserved.Projection.UncertainCreateAttemptID = create.AttemptID
		reserved.Projection.ExclusiveNamespaceDigest = publicationJointID(env.Domain, "exclusive namespace", 0)
		reserved.BirthServiceContractID, reserved.BirthTargetContractID = "", ""
		reserved.ProjectionCommitment, err = contract.PublicationProjectionCommitment(reserved.Projection)
		if err != nil {
			t.Fatal(err)
		}
		rows[1].Body, err = contract.EncodePublicationMarker(reserved)
		if err != nil {
			t.Fatal(err)
		}
		env, before := publicationJointSelectedImage(t, env, f.session, f.session, rows, orders, 0, 0, "reserved delete seed")
		expected, err := capacityConfigurationPreservedFacts(t.Context(), before)
		if err != nil {
			t.Fatal(err)
		}
		removed := []generatedRecordKey{{contract.PublicationMarkerSupportKind, create.AttemptID}, {contract.PublicationMarkerSupportKind, reserved.AttemptID}}
		for _, key := range removed {
			if _, found := expected[key]; !found {
				t.Fatal("expected dependent row missing")
			}
			delete(expected, key)
		}
		coordinate, err := contract.InspectPublicationCoordinate(rows[2].Body)
		if err != nil {
			t.Fatal(err)
		}
		coordinate.OwnerState, coordinate.LatestUnresolvedAttemptID = contract.PublicationOwnerNone, contract.ID{}
		body, err := contract.EncodePublicationCoordinate(coordinate)
		if err != nil {
			t.Fatal(err)
		}
		key := generatedRecordKey{contract.PublicationCoordinateSupportKind, coordinate.CoordinateID}
		changed := expected[key]
		changed.row, err = contract.InspectSupportRecordDigest(env.Domain, contract.SupportRecord{Kind: key.kind, RecordID: key.id, Body: body})
		if err != nil {
			t.Fatal(err)
		}
		expected[key] = changed
		expectedOrder := clonePublicationWork(before.adminIndex).PublicationOrder
		for i := range expectedOrder {
			if expectedOrder[i].CoordinateID == coordinate.CoordinateID {
				expectedOrder[i].Incarnations = append(slices.Clone(orders[0].Incarnations[:3]), coordinate.CurrentPublicationIncarnationID)
			}
		}
		after := publicationJointExitWithExpected(t, env, before, create.AttemptID, expected, expectedOrder, removed, contract.ID{})
		selected, err := selectedPublicationRelation(after.selectedImage())
		if err != nil || !reflect.DeepEqual(selected.coordinates[coordinate.CoordinateID], coordinate) {
			t.Fatal("reserved delete closure changed frozen/ACK/risk facts", err)
		}
		if len(after.adminIndex.Groups) != len(before.adminIndex.Groups)-2 {
			t.Fatal("uncertain create did not end exact reserved-delete closure")
		}
	})
}

// full_only: false
func TestPublicationPartialExitDisposesFinalMatchingCreateProof(t *testing.T) {
	env, fixture, _ := configuredSuccessionMemoryFixture(t, false)
	for _, isolated := range []bool{false, true} {
		layout := "shared_coordinates"
		if isolated {
			layout = "isolated_coordinates"
		}
		t.Run(layout, func(t *testing.T) {
			rows, orders, nonproof := publicationJointConfiguredMarkers(t, fixture.session, false)
			var target, coordinateID contract.ID
			for i, row := range rows {
				if row.Kind != contract.PublicationMarkerSupportKind || row.RecordID != nonproof {
					continue
				}
				marker, err := contract.InspectPublicationMarker(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				coordinateID = marker.CoordinateID
				// This older entered create names a different historical entry.
				// It remains a blocker, but cannot prove ownership of the frozen
				// current binding/entry/target tuple. The later create is its last
				// exact proof and the selected unresolved pointer.
				marker.Projection.EntryIncarnationID = publicationJointID(env.Domain, "earlier nonproof entry", 0)
				marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
				if err != nil {
					t.Fatal(err)
				}
				rows[i].Body, err = contract.EncodePublicationMarker(marker)
				if err != nil {
					t.Fatal(err)
				}
			}
			for i, row := range rows {
				switch row.Kind {
				case contract.PublicationCoordinateSupportKind:
					coordinate, err := contract.InspectPublicationCoordinate(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if coordinate.CoordinateID != coordinateID {
						continue
					}
					coordinate.LateEffectRisk = 1
					rows[i].Body, err = contract.EncodePublicationCoordinate(coordinate)
					if err != nil {
						t.Fatal(err)
					}
				case contract.PublicationMarkerSupportKind:
					marker, err := contract.InspectPublicationMarker(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if marker.CoordinateID != coordinateID {
						continue
					}
					marker.LateEffectRisk = 1
					rows[i].Body, err = contract.EncodePublicationMarker(marker)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			copyEnv, complete := publicationJointSelectedImage(t, env, fixture.session, fixture.session, rows, orders, 1, 1, "final proof "+layout, isolated)
			selected, err := selectedPublicationRelation(complete.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			coordinate, found := selected.coordinates[coordinateID]
			if !found || coordinate.OwnerState != contract.PublicationOwnerUncertainCreate || coordinate.LatestUnresolvedAttemptID == nonproof || coordinate.PossibleRemoteObject != 1 || coordinate.LateEffectRisk != 1 {
				t.Fatal("final proof fixture lacks exact uncertain ownership")
			}
			target = coordinate.LatestUnresolvedAttemptID
			proof, found := selected.markers[target]
			older := selected.markers[nonproof]
			if !found || proof.Projection.Action != contract.PublicationCreateEmpty || proof.State != contract.PublicationUnknown ||
				proof.Projection.BindingIncarnationID != coordinate.LastBindingIncarnationID || proof.Projection.EntryIncarnationID != coordinate.LastEntryIncarnationID || proof.Projection.TargetRowDigest != coordinate.DeletionTargetRowDigest ||
				older.Projection.EntryIncarnationID == coordinate.LastEntryIncarnationID {
				t.Fatal("independent matching and nonmatching create facts")
			}
			var optional format.Ref
			for _, page := range complete.adminIndex.Pages {
				if slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool { return row.RecordID == target }) {
					if page.ReadRequired || slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
						t.Fatal("last proof body must be optional")
					}
					optional = page.Ref
				}
			}
			if optional.Length == 0 {
				t.Fatal("last proof optional page missing")
			}
			for _, group := range complete.adminIndex.Groups {
				if group.GroupID == target && group.UncertainCreateProof != 1 || group.GroupID == nonproof && group.UncertainCreateProof != 0 {
					t.Fatal("writer did not retain independently derived exact proof bit")
				}
			}
			expected, err := capacityConfigurationPreservedFacts(t.Context(), complete)
			if err != nil {
				t.Fatal(err)
			}
			removed := []generatedRecordKey{{contract.PublicationMarkerSupportKind, target}}
			delete(expected, removed[0])
			wantCoordinate := coordinate
			wantCoordinate.OwnerState, wantCoordinate.LatestUnresolvedAttemptID = contract.PublicationOwnerNone, contract.ID{}
			body, err := contract.EncodePublicationCoordinate(wantCoordinate)
			if err != nil {
				t.Fatal(err)
			}
			key := generatedRecordKey{contract.PublicationCoordinateSupportKind, coordinateID}
			fact := expected[key]
			fact.row, err = contract.InspectSupportRecordDigest(env.Domain, contract.SupportRecord{Kind: key.kind, RecordID: key.id, Body: body})
			if err != nil {
				t.Fatal(err)
			}
			expected[key] = fact
			store := copyEnv.Store.(*memoryStore)
			optionalKey := mustKey(t, store.desc.Prefix, optional)
			store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if key == optionalKey {
					return contract.ReadResult{Status: contract.ReadMissing}
				}
				return read
			}
			partial, result := openAdministrative(t.Context(), OpenContext{admission: &complete.admission}, store)
			if partial == nil || result.Outcome != ObservedCurrent || !reflect.DeepEqual(partial.adminIndex, complete.adminIndex) {
				t.Fatal("actual partial reader lost signed disposition facts", result)
			}
			optionalPosition := -1
			for i, page := range partial.supportFacts {
				if page.ref == optional {
					optionalPosition = i
				}
			}
			if optionalPosition < 0 || len(partial.supportFacts[optionalPosition].rows) != 0 {
				t.Fatal("partial reader loaded unavailable proof detail")
			}
			if normal, result := Open(t.Context(), OpenContext{admission: &complete.admission}, store); normal != nil || result.Outcome == ObservedCurrent {
				t.Fatal("complete reader accepted unavailable optional proof body", result)
			}
			// The same healthy predecessor index and mandatory coordinate bytes
			// govern both reservation and execution, without optional markers.
			creates, cas := store.creates, store.cas
			public, private := env.Custody.Calls()
			var expectedWork format.AdministrativeIndex
			var expectedEnded []format.AdministrativeGroup
			wantPages, wantIndexBytes := uint64(0), uint64(0)
			for i, state := range []*StateSession{complete, partial} {
				if err := state.reserveFirstEndWork(t.Context()); err != nil {
					t.Fatal("same-evidence first exit reservation", i, err)
				}
				work, ended, err := state.administrativeWorkClosure(target)
				if err != nil || len(ended) != 1 || ended[0].GroupID != target {
					t.Fatal("exact final proof closure", i, err)
				}
				pages, indexBytes, err := state.endWorkPublicationRewriteAllowance(work, ended)
				if err != nil || pages != wantPages || indexBytes != wantIndexBytes {
					t.Fatal("same-evidence physical coordinate reservation", i, pages, indexBytes, err)
				}
				if i == 0 {
					expectedWork, expectedEnded = work, ended
				} else if !reflect.DeepEqual(work, expectedWork) || !reflect.DeepEqual(ended, expectedEnded) {
					t.Fatal("complete and partial closure disagree on retained exact proof")
				}
			}
			if p, k := env.Custody.Calls(); p != public || k != private || store.creates != creates || store.cas != cas {
				t.Fatal("disposition reservation used effects or Store writes")
			}
			coordinateRefs := func(index format.AdministrativeIndex) map[format.Ref]bool {
				refs := make(map[format.Ref]bool)
				for _, page := range index.Pages {
					if slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool {
						return row.Kind == contract.PublicationCoordinateSupportKind
					}) {
						refs[page.Ref] = true
					}
				}
				return refs
			}
			beforeRefs := coordinateRefs(partial.adminIndex)
			wantBefore := 1
			if isolated {
				wantBefore = 4
			}
			if len(beforeRefs) != wantBefore {
				t.Fatal("actual coordinate page layout", len(beforeRefs), wantBefore)
			}
			priorBody, result := complete.readObjectBorrowedUncached(t.Context(), fact.ref)
			if result.Outcome != 0 {
				t.Fatal("original coordinate carrier read", result)
			}
			priorBody = bytes.Clone(priorBody)
			priorPage, err := format.InspectRequiredSupportPage(priorBody)
			if err != nil || int(fact.physical) >= len(priorPage.Records) {
				t.Fatal("original coordinate physical ordinal", err)
			}
			after := publicationJointExitWithExpected(t, copyEnv, partial, target, expected, orders, removed, contract.ID{}, true)
			afterRefs := coordinateRefs(after.adminIndex)
			if len(afterRefs)-len(beforeRefs) != int(wantPages) {
				t.Fatal("actual coordinate replacement disagrees with reserved physical delta", len(beforeRefs), len(afterRefs), wantPages)
			}
			if afterRefs[fact.ref] {
				t.Fatal("old coordinate carrier remained selected after whole-page replacement")
			}
			var replacement format.Ref
			for ref := range afterRefs {
				if ref.Index == fact.ref.Index {
					replacement = ref
				}
			}
			if replacement.Object.IsZero() || replacement.Object == fact.ref.Object || replacement.Length != fact.ref.Length {
				t.Fatal("coordinate replacement did not retain physical index and length")
			}
			replacementBody, result := after.readObjectBorrowedUncached(t.Context(), replacement)
			if result.Outcome != 0 {
				t.Fatal("replacement coordinate carrier read", result)
			}
			replacementPage, err := format.InspectRequiredSupportPage(replacementBody)
			if err != nil || len(replacementPage.Records) != len(priorPage.Records) {
				t.Fatal("coordinate replacement changed physical row count", err)
			}
			for i, row := range replacementPage.Records {
				prior := priorPage.Records[i]
				if row.Kind != prior.Kind || row.RecordID != prior.RecordID || len(row.Body) != len(prior.Body) {
					t.Fatal("coordinate replacement changed physical row identity or length", i)
				}
				if i == int(fact.physical) {
					changed, err := contract.InspectPublicationCoordinate(row.Body)
					if err != nil || row.Kind != contract.PublicationCoordinateSupportKind || row.RecordID != coordinateID || !reflect.DeepEqual(changed, wantCoordinate) {
						t.Fatal("coordinate replacement changed exact disposition or physical ordinal", err)
					}
				} else if !bytes.Equal(row.Body, prior.Body) {
					t.Fatal("coordinate replacement changed physical peer bytes", i)
				}
			}
			coordinates, err := after.publicationCoordinatesForDisposition()
			if err != nil || !reflect.DeepEqual(coordinates[coordinateID], wantCoordinate) {
				t.Fatal("partial final proof exit changed possible-object, deletion or unrelated coordinate facts", err)
			}
			if !slices.ContainsFunc(after.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
				return group.GroupID == nonproof && group.UncertainCreateProof == 0
			}) {
				t.Fatal("nonproof blocker was discarded or promoted to proof")
			}
			head, token := bytes.Clone(after.body), after.token
			store.readHook = nil
			restored, result := Open(t.Context(), OpenContext{admission: &after.admission}, store)
			if restored == nil || result.Outcome != ObservedCurrent || !bytes.Equal(restored.body, head) || restored.token != token {
				t.Fatal("full cold admission after final matching-proof exit", result)
			}
			actual, err := selectedPublicationRelation(restored.selectedImage())
			if err != nil || !reflect.DeepEqual(actual.coordinates[coordinateID], wantCoordinate) || actual.markers[nonproof] != older || len(actual.markers) != len(selected.markers)-1 {
				t.Fatal("restored exact surviving blocker and cleared proof relation", err)
			}
			wantBlockers := publicationBlockers(selected, coordinateID)
			wantBlockers = slices.DeleteFunc(wantBlockers, func(id contract.ID) bool { return id == target })
			if !slices.Equal(publicationBlockers(actual, coordinateID), wantBlockers) || !slices.Equal(wantBlockers, []contract.ID{nonproof}) {
				t.Fatal("final proof exit changed unrelated unresolved blockers")
			}
			assertPublicationJointExitPreserved(t, restored, expected, orders, removed)
			t.Logf("same-evidence first End coordinate layout=%s admitted-children=%d successor-children=%d coordinate-page-delta=%d coordinate-index-byte-delta=%d", layout, complete.root.ChildCount, restored.root.ChildCount, wantPages, wantIndexBytes)
		})
	}
}

// full_only: false
func TestPublicationPartialReadRequiresSignedUncertainProofFacts(t *testing.T) {
	for _, condition := range []string{"exact_proof", "missing_proof", "proof_on_nonuncertain_coordinate"} {
		t.Run(condition, func(t *testing.T) {
			env, baseFixture, coordinate, marker := signedPublicationReadFixture(t)
			coordinate.LatestUnresolvedAttemptID = contract.ID{}
			if condition == "proof_on_nonuncertain_coordinate" {
				coordinate.OwnerState = contract.PublicationOwnerNone
			}
			rows := publicationRelationRows(t, coordinate, marker)
			order := clonePublicationWork(baseFixture.session.adminIndex).PublicationOrder
			copyEnv, healthy := publicationJointSelectedImage(t, env, baseFixture.session, baseFixture.session, rows, order, 0, 0, "mandatory proof "+condition)
			store := copyEnv.Store.(*memoryStore)
			next := *healthy
			next.adminIndex = clonePublicationWork(healthy.adminIndex)
			position := slices.IndexFunc(next.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == marker.AttemptID })
			if position < 0 || next.adminIndex.Groups[position].OwnerKind != format.AdministrativePublicationMarker || next.adminIndex.Groups[position].OwnerID != coordinate.CoordinateID {
				t.Fatal("actual full writer omitted exact marker owner")
			}
			wantWriterProof := uint8(1)
			if condition == "proof_on_nonuncertain_coordinate" {
				wantWriterProof = 0
			}
			if next.adminIndex.Groups[position].UncertainCreateProof != wantWriterProof {
				t.Fatal("actual full writer did not derive qualified mandatory proof")
			}
			switch condition {
			case "missing_proof":
				next.adminIndex.Groups[position].UncertainCreateProof = 0
			case "proof_on_nonuncertain_coordinate":
				next.adminIndex.Groups[position].UncertainCreateProof = 1
			}
			// This models an authenticated but inconsistent mandatory fact.
			// Encode fresh immutable index/root objects and sign their actual
			// lifecycle HEAD bindings. A raw digest or signature corruption
			// would test a different boundary.
			next.root.Snapshot = publicationJointID(env.Domain, "proof fact snapshot "+condition, 0)
			next.root.Transition = publicationJointID(env.Domain, "proof fact transition "+condition, 0)
			next.adminIndex.Object = administrativeIndexObject(env.Domain, next.root.Snapshot)
			shards, err := format.EncodeAdministrativeIndexPages(next.adminIndex)
			if err != nil || len(shards) == 0 {
				t.Fatal("structural altered mandatory facts", err)
			}
			next.root.AdministrativeIndex, next.root.AdministrativeIndexShards = shards[0].Ref, nil
			for i, shard := range shards {
				if err := format.CheckReference(shard.Ref, shard.Body); err != nil {
					t.Fatal(err)
				}
				if err := store.putSelected(mustKey(t, store.desc.Prefix, shard.Ref), shard.Body); err != nil {
					t.Fatal("fresh signed proof index", err)
				}
				if i != 0 {
					next.root.AdministrativeIndexShards = append(next.root.AdministrativeIndexShards, shard.Ref)
				}
			}
			next.recountChildren()
			rootBody, err := format.EncodeRoot(next.root)
			if err != nil {
				t.Fatal(err)
			}
			rootRef, err := format.Reference(format.RootKind, env.Domain, next.root.Snapshot, 0, rootBody)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.putSelected(mustKey(t, store.desc.Prefix, rootRef), rootBody); err != nil {
				t.Fatal("fresh signed proof root", err)
			}
			head := healthy.head
			if head.AuthKind != format.LifecycleAuth {
				t.Fatal("mandatory proof fixture requires actual lifecycle signing")
			}
			head.Core.Root, head.Core.Revision = rootRef, publicationJointID(env.Domain, "proof fact revision "+condition, 0)
			head.Core.PreviousRevision, head.Core.PreviousDigest, head.Core.PreviousToken = healthy.head.Core.Revision, contract.Hash(healthy.body), healthy.token
			head.Subject.Operation = publicationJointID(env.Domain, "proof fact operation "+condition, 0)
			head.Subject.Normal.PublicState = next.publicState()
			head.Subject.Request = requestCommitment(head.Core, head.Subject)
			storeHead(t, &fixture{store: store, trust: copyEnv.Trust.(*fixtureTrust)}, head, true)
			storedHead, err := format.DecodeHead(store.objects[store.desc.HeadKey].Body)
			control, valid := healthy.selectedControl()
			if err != nil || !valid || !healthy.verifyHeadProofs(storedHead, control) {
				t.Fatal("altered mandatory facts lack valid pinned cryptographic authorization", err)
			}
			var markerRef format.Ref
			for _, page := range next.adminIndex.Pages {
				if slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool { return row.RecordID == marker.AttemptID }) {
					if page.ReadRequired || slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
						t.Fatal("proof detail must remain optional")
					}
					markerRef = page.Ref
				}
			}
			if markerRef.Length == 0 {
				t.Fatal("signed marker page absent")
			}
			markerKey := mustKey(t, store.desc.Prefix, markerRef)
			unavailableReads := 0
			store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if key == markerKey {
					unavailableReads++
					return contract.ReadResult{Status: contract.ReadMissing}
				}
				return read
			}
			creates, cas := store.creates, store.cas
			public, private := env.Custody.Calls()
			if complete, result := Open(t.Context(), OpenContext{admission: &healthy.admission}, store); complete != nil || result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject || unavailableReads == 0 {
				t.Fatal("full cold read did not establish unavailable selected marker detail", result)
			}
			beforePartialReads := unavailableReads
			opened, result := openAdministrative(t.Context(), OpenContext{admission: &healthy.admission}, store)
			if condition == "exact_proof" {
				if opened == nil || result.Outcome != ObservedCurrent || !reflect.DeepEqual(opened.adminIndex, next.adminIndex) {
					t.Fatal("signed exact proof with absent optional detail was refused", result)
				}
				coordinates, err := opened.publicationCoordinatesForDisposition()
				if err != nil || !reflect.DeepEqual(coordinates[coordinate.CoordinateID], coordinate) {
					t.Fatal("positive partial read lost zero-cache exact uncertainty", err)
				}
				for _, page := range opened.supportFacts {
					if page.ref == markerRef && len(page.rows) != 0 {
						t.Fatal("positive partial read fabricated optional proof detail")
					}
				}
			} else if opened != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
				t.Fatal("cryptographically signed inconsistent mandatory proof was admitted", condition, result)
			}
			if unavailableReads != beforePartialReads {
				t.Fatal("partial proof qualification fetched optional marker detail")
			}
			if p, k := env.Custody.Calls(); p != public || k != private || store.creates != creates || store.cas != cas {
				t.Fatal("mandatory proof cold admission used custody or Store effects")
			}
		})
	}
}

// Augment existing configured coordinates. Their identity/binding/entry relation
// remains selected; no second coordinate population or generated lifecycle is built.
func publicationJointConfiguredMarkers(t *testing.T, before *StateSession, full bool) ([]contract.SupportRecord, []format.PublicationCoordinateOrder, contract.ID) {
	t.Helper()
	configuration := capacityOutputConfiguration(t, before, full)
	image, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, _, err := contract.SplitOutputConfiguration(before.root.Domain, image)
	if err != nil || descriptor != before.root.OutputConfiguration {
		t.Fatal("marker source configuration changed", err)
	}
	selected, err := selectedPublicationRelation(before.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	var rows []contract.SupportRecord
	var orders []format.PublicationCoordinateOrder
	var target contract.ID
	count := 0
	for _, binding := range configuration.Bindings {
		for _, destination := range binding.Targets {
			id, err := contract.PublicationCoordinateID(before.root.Domain, destination.ServiceContractID, destination.CanonicalTarget)
			if err != nil {
				t.Fatal(err)
			}
			coordinate, found := selected.coordinates[id]
			if !found {
				t.Fatal("configured coordinate missing")
			}
			coordinate.OwnerState, coordinate.PossibleRemoteObject = contract.PublicationOwnerUncertainCreate, 1
			coordinate.LastAdmissionOrdinal = 2
			coordinate.DeletionDestinationID, coordinate.DeletionConsumerLocator = binding.DestinationID, destination.ConsumerLocator
			coordinate.DeletionTargetContractID, coordinate.DeletionConfigContractID = destination.TargetContractID, binding.Destination.ConfigContractID
			coordinate.DeletionCredentialRouteContractID, coordinate.DeletionPayloadEncoding = "fixture/route/v1", destination.PayloadEncoding
			coordinate.DeletionTargetData = bytes.Clone(destination.TargetData)
			coordinate.DeletionTargetRowDigest, err = contract.PublicationTargetRowDigest(before.root.Domain, binding.DestinationID, binding.IncarnationID, destination)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := contract.OutputPolicyDigest(before.root.Domain, destination.Policy)
			if err != nil {
				t.Fatal(err)
			}
			for ordinal := 0; ordinal < 2; ordinal++ {
				_, _, marker, _ := publicationRelationFixtureForDomain(t, before.root.Domain)
				marker.AttemptID, marker.OperationID = publicationJointID(before.root.Domain, fmt.Sprintf("configured-marker-%d", ordinal), count), publicationJointID(before.root.Domain, fmt.Sprintf("configured-operation-%d", ordinal), count)
				marker.CoordinateID, marker.PublicationIncarnationID, marker.AdmissionOrdinal = id, coordinate.CurrentPublicationIncarnationID, uint64(ordinal+1)
				marker.Projection.ConfigurationDigest = before.root.OutputConfiguration.ConfigurationDigest
				marker.Projection.CoordinateID, marker.Projection.BindingIncarnationID, marker.Projection.EntryIncarnationID = id, binding.IncarnationID, destination.EntryIncarnationID
				marker.Projection.TargetRowDigest, marker.Projection.PolicyDigest = coordinate.DeletionTargetRowDigest, policy
				marker.BirthServiceContractID, marker.BirthTargetContractID = destination.ServiceContractID, destination.TargetContractID
				marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
				if err != nil {
					t.Fatal(err)
				}
				body, err := contract.EncodePublicationMarker(marker)
				if err != nil {
					t.Fatal(err)
				}
				rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body})
				coordinate.LatestUnresolvedAttemptID = marker.AttemptID
				// Dispose the older marker so the later create pointer/uncertain owner
				// remains exact. The reserved-delete case separately checks pointer repair.
				if count == 0 && ordinal == 0 {
					target = marker.AttemptID
				}
			}
			body, err := contract.EncodePublicationCoordinate(coordinate)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, contract.SupportRecord{Kind: contract.PublicationCoordinateSupportKind, RecordID: id, Body: body})
			orders = append(orders, format.PublicationCoordinateOrder{CoordinateID: id, Incarnations: []contract.ID{coordinate.CurrentPublicationIncarnationID}})
			count++
		}
	}
	slices.SortFunc(orders, func(a, b format.PublicationCoordinateOrder) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	want := 4
	if full {
		want = 1024
	}
	if count != want || len(rows) != 3*want {
		t.Fatal("configured publication population", count, len(rows), want)
	}
	return rows, orders, target
}

func publicationJointExpectedAccess(t *testing.T, before *StateSession, obsoleteSeed contract.ID) []contract.AccessRecord {
	t.Helper()
	var rows []contract.AccessRecord
	removed := 0
	for _, page := range before.access {
		if page == nil {
			continue
		}
		for _, row := range page.Records {
			if !obsoleteSeed.IsZero() && row.MaterialKind == contract.OperationSeedMaterialKind && row.MaterialID == obsoleteSeed {
				removed++
				continue
			}
			rows = append(rows, row)
		}
	}
	if !obsoleteSeed.IsZero() && removed != 1 {
		t.Fatal("predecessor lacks exact exclusively owned obsolete Seed Access", removed)
	}
	return rows
}

// The sole generated owner in the mixed fixture owns one obsolete Seed.
// Its identity is supplied by the real predecessor attempt, never by EndWork.
func publicationJointAccessPreserved(t *testing.T, before, after *StateSession, obsoleteSeed contract.ID, expected []contract.AccessRecord) {
	t.Helper()
	if obsoleteSeed.IsZero() {
		if !reflect.DeepEqual(before.root.CurrentAccess, after.root.CurrentAccess) || !reflect.DeepEqual(before.access, after.access) {
			t.Fatal("publication exit changed exact current access")
		}
		return
	}
	removed := 0
	for _, ref := range before.root.CurrentAccess.Core.AccessPageRefs {
		page := before.access[ref.Index]
		var kept []contract.AccessRecord
		for _, row := range page.Records {
			if row.MaterialKind == contract.OperationSeedMaterialKind && row.MaterialID == obsoleteSeed {
				removed++
				continue
			}
			kept = append(kept, row)
		}
		actual := after.access[ref.Index]
		if len(kept) == 0 {
			if actual != nil {
				t.Fatal("generated exit retained obsolete Seed access page")
			}
			continue
		}
		if actual == nil || !reflect.DeepEqual(actual.Records, kept) {
			t.Fatal("generated exit changed unaffected exact material access", ref.Index)
		}
		if len(kept) == len(page.Records) && !slices.Contains(after.root.CurrentAccess.Core.AccessPageRefs, ref) {
			t.Fatal("generated exit replaced unaffected physical access page", ref.Index)
		}
	}
	if removed != 1 || after.root.AccessRecordCount != uint32(len(expected)) {
		t.Fatal("generated exit did not remove exactly one obsolete Seed", removed, after.root.AccessRecordCount, len(expected))
	}
	descriptor, err := contract.AccessRecordsDescriptor(before.root.Domain, expected)
	if err != nil || descriptor != after.root.CurrentAccess.Core.AccessRecordsDescriptor {
		t.Fatal("generated exit changed exact retained access descriptor", err)
	}
	control := before.root.CurrentAccess.Core
	if err := contract.AdvanceAccessGeneration(&control, after.root.Transition); err != nil {
		t.Fatal("expected generated access generation", err)
	}
	if !reflect.DeepEqual(control.CurrentControl, after.root.CurrentAccess.Core.CurrentControl) || before.root.CurrentAccess.Core.RecipientRefsDescriptor != after.root.CurrentAccess.Core.RecipientRefsDescriptor {
		t.Fatal("generated exit changed current control beyond exact access generation")
	}
}

func publicationJointPhysicalCharge(t *testing.T, before, after *StateSession, candidate *Candidate) {
	t.Helper()
	refs := func(selected *StateSession) map[format.Ref]bool {
		all := make(map[format.Ref]bool)
		add := func(ref format.Ref) {
			if ref.Length == 0 || all[ref] {
				t.Fatal("duplicate or empty selected physical reference")
			}
			all[ref] = true
		}
		for _, ref := range selected.root.ValueEntryPages {
			if ref != nil {
				add(*ref)
			}
		}
		for _, ref := range selected.root.Recipients {
			if ref != nil {
				add(*ref)
			}
		}
		for _, ref := range selected.root.CurrentAccess.Core.AccessPageRefs {
			add(ref)
		}
		for _, ref := range selected.root.RequiredSupport {
			add(ref)
		}
		add(selected.root.AdministrativeIndex)
		for _, ref := range selected.root.AdministrativeIndexShards {
			add(ref)
		}
		var bytes uint64
		for ref := range all {
			bytes += uint64(ref.Length)
		}
		if uint32(len(all)) != selected.root.ChildCount || bytes != selected.root.ChildEncodedBytes {
			t.Fatal("physical closure charge differs from selected root", len(all), bytes, selected.root.ChildCount, selected.root.ChildEncodedBytes)
		}
		return all
	}
	old, next := refs(before), refs(after)
	var predecessor, successor, shared uint64
	for ref := range old {
		predecessor += uint64(ref.Length)
		if next[ref] {
			shared += uint64(ref.Length)
		}
	}
	for ref := range next {
		successor += uint64(ref.Length)
	}
	q := after.head.EndWork
	if q == nil || q.BeforeChildBytes != predecessor || q.AfterChildBytes != successor || q.BeforeChildCount != uint16(len(old)) || q.AfterChildCount != uint16(len(next)) {
		t.Fatal("exit subject omitted physical predecessor/successor bytes")
	}
	for _, object := range candidate.objects {
		if err := format.CheckReference(object.ref, object.body); err != nil {
			t.Fatal("exit candidate physical bytes", err)
		}
	}
	owned := retainedByteCapacity(before, nil, candidate, after)
	// This observes byte backing only. The separately accepted administrative
	// ceiling also covers typed arrays, maps, views and transient workspaces.
	const administrativeWorkingCeiling = uint64(8105170160 + (1 << 30))
	if owned > administrativeWorkingCeiling {
		t.Fatal("exit retained byte backing exceeds administrative working ceiling", owned)
	}
	t.Logf("exit physical predecessor=%d successor=%d shared=%d replacement=%d overlap=%d retained-byte-backing=%d administrative-working-ceiling=%d", predecessor, successor, shared, successor-shared, predecessor+successor-shared, owned, administrativeWorkingCeiling)

}

// full_only: false
func TestPublicationJointMixedExits(t *testing.T) {
	t.Run("small", func(t *testing.T) {
		publicationJointMixedExits(t, t.Context(), newConfiguredSuccessionMemorySeed(t, false))
	})
}

// The maximum caller supplies its already-built immutable configured seed.
func publicationJointMixedExits(t *testing.T, operationCtx context.Context, configuredSeed configuredSuccessionMemorySeed) {
	t.Helper()
	full := configuredSeed.full
	env, f, _ := configuredSeed.openCase(t)
	rows, orders, marker := publicationJointConfiguredMarkers(t, f.session, full)
	env, configured := publicationJointSelectedImage(t, env, f.session, f.session, rows, orders, 0, 0, "configured marker history")
	// One actual failed create adds an independent retained owner. It uses
	// an existing supplied name; its nonselecting Final keeps all current
	// values and does not rebuild either completed generated origin.
	var name string
	var current *contract.ValueEntry
	for _, named := range configured.root.Names {
		entry := configured.valueEntry(named.Slot)
		if entry.ValueSource == contract.Supplied {
			name, current = named.Name, entry
			break
		}
	}
	if name == "" {
		t.Fatal("configured existing supplied name missing")
	}
	retiring := make(map[string]contract.ValueEntry)
	for _, named := range configured.root.Names {
		entry := configured.valueEntry(named.Slot)
		if entry.ValueSource == contract.Generated {
			retiring[named.Name] = *entry
		}
	}
	// The planned whole-set replacement needs exact old retirement
	// templates even though this failed aggregate will not select it.
	operation := fixtureID(env.Domain, "joint retained failed create")
	profile := defaultGeneratedFixtureProfile()
	input := generatedStatePlanInput(t, configured, operation, []string{name}, profile, 0, nil, retiring)
	bound := generatedReservationInputForMembershipStateIntent(t, configured, operation, slices.Clone(current.Recipients),
		[]string{name}, []byte(`{"name":"generated"}`), profile, 0, nil, retiring)
	input.graph, input.declaration = bound.graph, bound.declaration
	input.registry, input.recoveryPolicy = bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID
	input.requestBindings = slices.Clone(bound.requestBindings)
	creates, retirements := 0, 0
	for _, lineage := range input.graph.Lineages {
		switch lineage.Purpose {
		case contract.GeneratorLineageCreate:
			creates++
		case contract.GeneratorLineageRetirement:
			retirements++
		}
	}
	if creates != 1 || retirements != int(configured.root.Generated.GeneratedCurrent) || len(input.graph.ValueEntryPlans) != 1 {
		t.Fatal("joint planned failed create/retirement dimensions", creates, retirements, len(input.graph.ValueEntryPlans))
	}
	view, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil {
		t.Fatal("joint failed-create declaration", err)
	}
	declaration, err := view.Own()
	if err != nil || len(declaration.Entries) != 1 || !slices.Equal(declaration.Entries[0].Recipients, current.Recipients) ||
		input.graph.ValueEntryPlans[0].ChangeMask != contract.GeneratorValueChangeContent || input.graph.ValueEntryPlans[0].EntryIncarnationID == current.Incarnation {
		t.Fatal("joint failed-create conversion changed selected recipients or omitted fresh content-only incarnation", err)
	}
	input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	if _, err := configured.generatedPlanRequest(t.Context(), input); err != nil {
		t.Fatalf("joint failed-create public plan: current=%d generated=%d intended=%d create-names=1 retirement-templates=%d: %v", configured.root.ValueEntryCount, configured.root.Generated.GeneratedCurrent, len(input.graph.ValueEntryPlans), len(retiring), err)
	}
	retained, original := selectPrivateOwnedUnusableAggregateFromInput(t, env, configured, []string{name}, input, nil)
	retained = generatedLifecycleReopen(t, operationCtx, retained, env.Store)
	if retained.root.ValueEntryCount != configured.root.ValueEntryCount || retained.root.Generated.GeneratedCurrent != configured.root.Generated.GeneratedCurrent || !reflect.DeepEqual(retained.currentEntryInputs(), configured.currentEntryInputs()) || retained.root.Generated.Hazards != 1 || retained.root.Generated.Duties != 0 || retained.root.RawBytes != configured.root.RawBytes || retained.root.MembershipCount != configured.root.MembershipCount || retained.root.SecretOrdinaryWrapCount != configured.root.SecretOrdinaryWrapCount || retained.root.SecretCount != configured.root.SecretCount || retained.root.OutputConfiguration != configured.root.OutputConfiguration {
		t.Fatal("real retained-work setup changed current dimensions")
	}
	assertCapacityConfigurationPreserved(t, configured, retained)
	seed := retained
	generated := original.expected.Template.HazardID
	if !slices.ContainsFunc(seed.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
		return group.GroupID == generated && group.OwnerKind == format.AdministrativeGeneratedHazard && group.OwnerID == original.record.OwnerID
	}) {
		t.Fatal("selected real generated Hazard exit missing")
	}
	// Keep all logical records, but place existing current evidence on more
	// retained peer pages. Publication-page expansion alone is credited away
	// by the ordinary reserve and therefore cannot establish its endpoint.
	unpartitioned := seed
	currentEvidence := make(map[contract.ID]bool)
	for _, named := range seed.root.Names {
		entry := seed.valueEntry(named.Slot)
		if entry.ValueSource == contract.Generated {
			currentEvidence[entry.Generated.CreateResultID] = true
		}
	}
	pubKeys := make(map[generatedRecordKey]bool)
	var framed, maximumWidth uint64
	for _, row := range rows {
		pubKeys[generatedRecordKey{row.Kind, row.RecordID}] = true
		width := uint64(contract.SupportRecordOverhead + len(row.Body))
		if row.Kind == contract.PublicationMarkerSupportKind {
			// PublicationEvidence/v3 adds SafeRequestID, SafeResourceID and
			// ConsumerLocator, each bounded at 1024 bytes.
			width += 3 * 1024
		}
		framed += width
		maximumWidth = max(maximumWidth, width)
	}
	payload := uint64(contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength)
	publicationPages := int(min(uint64(len(rows)), 2+(framed-1)/(payload-maximumWidth+1)))
	markerPages := publicationPages - 1 // Existing coordinates fit one real page.
	peerPages, oldEvidencePages := 0, 0
	for _, page := range seed.adminIndex.Pages {
		// ReadRequired Slice carrier pages intentionally have no row summaries.
		hasPeer, hasEvidence := page.ReadRequired, false
		for _, row := range page.Rows {
			if row.Kind == contract.GeneratedCreateEvidenceSupportKind && currentEvidence[row.RecordID] {
				hasEvidence = true
			} else if !pubKeys[generatedRecordKey{row.Kind, row.RecordID}] {
				hasPeer = true
			}
		}
		if hasEvidence {
			// In this configured fixture all current create proofs are mandatory
			// and ownerless, so one span is added for each new evidence page.
			if hasPeer || len(page.Spans) != 1 || !page.Spans[0].Mandatory || len(page.Spans[0].GroupIndexes) != 0 {
				t.Fatal("configured current evidence is not a pure mandatory peer")
			}
			oldEvidencePages++
		}
		if hasPeer {
			peerPages++
		}
	}
	oldIndexBytes, err := format.AdministrativeIndexEncodedLength(seed.adminIndex)
	if err != nil || len(seed.adminIndex.Pages) != len(seed.root.RequiredSupport) {
		t.Fatal("partition predecessor index/page facts", err)
	}
	oldSupportPages := len(seed.root.RequiredSupport)
	oldIndexChildren := 1 + len(seed.root.AdministrativeIndexShards)
	nonSupportOrIndex := int(seed.root.ChildCount) - len(seed.root.RequiredSupport) - oldIndexChildren
	counts := func(evidencePages int) (uint32, uint64) {
		supportPages := peerPages + evidencePages + publicationPages
		// Formats encodes each page in108 bytes and an ownerless span in7.
		// Row/group/order counts and their widths remain unchanged.
		indexBytes := int64(oldIndexBytes) + 108*int64(supportPages-oldSupportPages) + 7*int64(evidencePages-oldEvidencePages)
		if indexBytes < 0 {
			t.Fatal("negative independent partition index length")
		}
		shards, err := format.AdministrativeIndexShardCount(uint64(indexBytes))
		if err != nil {
			t.Fatal(err)
		}
		return uint32(nonSupportOrIndex + supportPages + int(shards)), uint64(indexBytes)
	}
	evidencePages := 1
	if full {
		evidencePages = 0
		for n := 1; n < len(currentEvidence); n++ {
			children, _ := counts(n)
			if children == ordinaryChildPageLimit {
				evidencePages = n
				break
			}
		}
		if evidencePages == 0 {
			t.Fatal("existing current evidence cannot establish independent ordinary252")
		}
	}
	expectedChildren, expectedIndexBytes := counts(evidencePages)
	expectedNextChildren, expectedNextIndexBytes := counts(evidencePages + 1)
	if expectedNextChildren != expectedChildren+1 {
		t.Fatal("next evidence partition crosses an index shard boundary", expectedChildren, expectedNextChildren)
	}
	selectedFacts := func(selected *StateSession) map[generatedRecordKey]contract.SupportRecordDigest {
		facts := make(map[generatedRecordKey]contract.SupportRecordDigest)
		for _, page := range selected.supportFacts {
			for _, row := range page.rows {
				facts[generatedRecordKey{row.Kind(), row.RecordID()}] = row
			}
		}
		return facts
	}
	expectedLogical := selectedFacts(seed)
	expectedWindows, err := seed.receiptWindows(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	checkPartition := func(partitioned *StateSession, children uint32, indexBytes uint64) {
		actualIndexBytes, err := format.AdministrativeIndexEncodedLength(partitioned.adminIndex)
		windows, receiptErr := partitioned.receiptWindows(t.Context())
		if err != nil || receiptErr != nil || actualIndexBytes != indexBytes || partitioned.root.ChildCount != children || !reflect.DeepEqual(selectedFacts(partitioned), expectedLogical) || !reflect.DeepEqual(partitioned.root.Generated, unpartitioned.root.Generated) || !reflect.DeepEqual(partitioned.currentEntryInputs(), unpartitioned.currentEntryInputs()) || !reflect.DeepEqual(partitioned.root.CurrentAccess, unpartitioned.root.CurrentAccess) || !reflect.DeepEqual(partitioned.access, unpartitioned.access) || !reflect.DeepEqual(windows, expectedWindows) || partitioned.root.WarningBits != unpartitioned.root.WarningBits {
			t.Fatalf("partition facts: children=%d expected=%d index-bytes=%d expected=%d index-error=%v receipt-error=%v", partitioned.root.ChildCount, children, actualIndexBytes, indexBytes, err, receiptErr)
		}
		assertCapacityConfigurationPreserved(t, unpartitioned, partitioned)
	}
	env, seed = publicationJointSelectedImage(t, env, f.session, unpartitioned, rows, orders, evidencePages, markerPages, "joint retained capacity partition")
	checkPartition(seed, expectedChildren, expectedIndexBytes)
	if _, err := seed.reservePublicationRewrite(t.Context(), seed.adminIndex, expectedChildren); err != nil {
		t.Fatal("exact independent projected child endpoint refused", expectedChildren, err)
	}
	if err := seed.reserveOrdinaryPublicationRewrite(t.Context()); err != nil {
		t.Fatal("joint ordinary reserve refused", expectedChildren, err)
	}
	t.Logf("joint selected/projected children=%d evidence-pages=%d marker-pages=%d worst-publication-pages=%d index-bytes=%d", expectedChildren, evidencePages, markerPages, publicationPages, expectedIndexBytes)
	t.Run("partition_next_refusal", func(t *testing.T) {
		nextEnv := env
		nextEnv.Store = unpartitioned.store
		_, next := publicationJointSelectedImage(t, nextEnv, f.session, unpartitioned, rows, orders, evidencePages+1, markerPages, "joint next capacity partition")
		checkPartition(next, expectedNextChildren, expectedNextIndexBytes)
		rootBefore, err := format.EncodeRoot(next.root)
		if err != nil {
			t.Fatal(err)
		}
		indexBefore, err := format.EncodeAdministrativeIndexPages(next.adminIndex)
		if err != nil {
			t.Fatal(err)
		}
		store := next.store.(*memoryStore)
		creates, cas := store.creates, store.cas
		public, private := env.Custody.Calls()
		if _, err := next.reservePublicationRewrite(t.Context(), next.adminIndex, expectedChildren); err != contract.ErrRecordCapacity {
			t.Fatal("next physical partition did not refuse exact child budget", expectedNextChildren, expectedChildren, err)
		}
		rootAfter, err := format.EncodeRoot(next.root)
		if err != nil || !bytes.Equal(rootAfter, rootBefore) {
			t.Fatal("capacity refusal changed independent encoded predecessor root", err)
		}
		indexAfter, err := format.EncodeAdministrativeIndexPages(next.adminIndex)
		if err != nil || len(indexAfter) != len(indexBefore) {
			t.Fatal("capacity refusal changed index shard count", err)
		}
		for i := range indexBefore {
			if indexBefore[i].Ref != indexAfter[i].Ref || !bytes.Equal(indexBefore[i].Body, indexAfter[i].Body) {
				t.Fatal("capacity refusal changed independent encoded predecessor index", i)
			}
		}
		if p, k := env.Custody.Calls(); p != public || k != private || store.creates != creates || store.cas != cas || !reflect.DeepEqual(selectedFacts(next), expectedLogical) {
			t.Fatal("capacity refusal changed selected facts or called custody/Store writes")
		}
	})
	if !full {
		t.Run("retained_reframe", func(t *testing.T) {
			expected, err := capacityConfigurationPreservedFacts(t.Context(), seed)
			if err != nil {
				t.Fatal(err)
			}
			windows, err := seed.receiptWindows(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			_, reframed := publicationJointSelectedImage(t, env, f.session, seed, nil, nil, 0, 0, "retained closure reframe")
			assertPublicationJointExitPreserved(t, reframed, expected, seed.adminIndex.PublicationOrder, nil)
			got, err := reframed.receiptWindows(t.Context())
			if err != nil || !reflect.DeepEqual(got, windows) || !reflect.DeepEqual(reframed.currentEntryInputs(), seed.currentEntryInputs()) || !reflect.DeepEqual(reframed.root.CurrentAccess, seed.root.CurrentAccess) || !reflect.DeepEqual(reframed.access, seed.access) || !reflect.DeepEqual(reframed.root.Generated, seed.root.Generated) || reframed.root.WarningBits != seed.root.WarningBits {
				t.Fatal("retained reframe changed exact values/access/generated closure/windows/warnings", err)
			}
		})
		t.Run("delete_reservation", func(t *testing.T) {
			publicationJointDeleteReservation(t, env, seed, generated)
		})
	}
	for _, publicationFirst := range []bool{true, false} {
		orderName := "publication_first"
		if !publicationFirst {
			orderName = "generated_first"
		}
		t.Run(orderName, func(t *testing.T) {
			copyEnv := env
			copyEnv.Store = selectedMemoryStoreCopy(env.Store.(*memoryStore))
			current, result := Open(t.Context(), OpenContext{admission: &seed.admission}, copyEnv.Store)
			if current == nil || result.Outcome != ObservedCurrent {
				t.Fatal("mixed independent cold seed", result)
			}
			order := []contract.ID{marker, generated}
			if !publicationFirst {
				order = []contract.ID{generated, marker}
			}
			for _, target := range order {
				expected, err := capacityConfigurationPreservedFacts(t.Context(), current)
				if err != nil {
					t.Fatal(err)
				}
				var removed []generatedRecordKey
				if target == marker {
					key := generatedRecordKey{contract.PublicationMarkerSupportKind, marker}
					if _, found := expected[key]; !found {
						t.Fatal("expected marker missing")
					}
					delete(expected, key)
					removed = []generatedRecordKey{key}
				}
				expectedOrder := clonePublicationWork(current.adminIndex).PublicationOrder
				before := current
				obsoleteSeed := contract.ID{}
				if target == generated {
					obsoleteSeed = original.material.Core.OperationMaterialID
				}
				current = publicationJointExitWithExpected(t, copyEnv, before, target, expected, expectedOrder, removed, obsoleteSeed)
				if len(current.adminIndex.Groups) != len(before.adminIndex.Groups)-1 || slices.ContainsFunc(current.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == target }) {
					t.Fatal("mixed exit removed wrong owner")
				}
				if target == generated {
					if current.root.Generated.Hazards != 0 || current.root.Generated.Retiring != 0 || current.root.Generated.Graphs.Count != 0 || current.root.Generated.LiveOwners.Count != 0 || current.root.Generated.Attempts != 0 || current.root.Generated.Materials != 0 || current.root.Generated.Duties != 0 || current.root.Generated.PendingReleases != 0 || current.root.Generated.Results != 0 || current.root.Generated.Slices.Count != configured.root.Generated.GeneratedCurrent || !current.root.Generated.ActiveOwner.IsZero() || current.root.Generated.GeneratedCurrent != before.root.Generated.GeneratedCurrent {
						t.Fatalf("generated exit counters: hazards=%d retiring=%d graphs=%d live-owners=%d attempts=%d materials=%d duties=%d pending-releases=%d results=%d slices=%d expected-current-slices=%d active-owner-zero=%t generated-current=%d expected-generated-current=%d", current.root.Generated.Hazards, current.root.Generated.Retiring, current.root.Generated.Graphs.Count, current.root.Generated.LiveOwners.Count, current.root.Generated.Attempts, current.root.Generated.Materials, current.root.Generated.Duties, current.root.Generated.PendingReleases, current.root.Generated.Results, current.root.Generated.Slices.Count, configured.root.Generated.GeneratedCurrent, current.root.Generated.ActiveOwner.IsZero(), current.root.Generated.GeneratedCurrent, before.root.Generated.GeneratedCurrent)
					}
					assertCapacityCurrentIntents(t, current, int(configured.root.Generated.GeneratedCurrent))
				}
			}
		})
	}
	publicationJointUnreadableExits(t, env, seed, marker, generated, original.material.Core.OperationMaterialID, full)
	publicationJointMandatoryLoss(t, env, seed)
}

// This distinct preparation uses the same retained Hazard and publication rows.
// It never claims, selects or sends the prepared delete.
func publicationJointDeleteReservation(t *testing.T, env fixtureEnvironment, seed *StateSession, hazardID contract.ID) {
	t.Helper()
	store := selectedMemoryStoreCopy(env.Store.(*memoryStore))
	env.Store = store
	before, result := Open(t.Context(), OpenContext{admission: &seed.admission}, store)
	if before == nil || result.Outcome != ObservedCurrent {
		t.Fatal("delete reservation cold seed", result)
	}
	work := mustSelectedGeneratedWork(t, before)
	row, found := work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, hazardID}]
	hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
	if !found || err != nil {
		t.Fatal("delete reservation predecessor Hazard", err)
	}
	target, err := work.generatedCleanupTarget(row.Kind, hazardID, hazard.Target)
	if err != nil {
		t.Fatal("delete reservation predecessor target", err)
	}
	input, canonical := generatedDeletePlanInputForSource(t, before, fixtureID(env.Domain, "joint retained cleanup reserve"), row, target)
	view, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil || contract.ValidateGeneratorDeclarationGraph(view, input.graph) != nil {
		t.Fatal("delete reservation complete unchanged declaration", err)
	}
	if view.EntryCount() != len(before.root.Names) || len(input.graph.ValueEntryPlans) != len(before.root.Names) {
		t.Fatal("delete reservation omitted current declaration or plan entries", view.EntryCount(), len(input.graph.ValueEntryPlans), len(before.root.Names))
	}
	canonicalBySlot := make(map[uint16]contract.GeneratedCanonicalSelection, len(canonical))
	for _, source := range canonical {
		current := before.valueEntry(source.Record.OriginalSlot)
		_, duplicate := canonicalBySlot[source.Record.OriginalSlot]
		if duplicate || current == nil || current.ValueSource != contract.Supplied || current.ConfidentialityClass != contract.Secret ||
			!reflect.DeepEqual(source.Record.Entry, *current) || source.Selection.Slot != source.Record.OriginalSlot ||
			!reflect.DeepEqual(source.Selection.Entry, *current) || source.Selection.Root != before.head.Core.Root ||
			source.Selection.HEADRevision != before.head.Core.Revision || source.Selection.HEADToken != before.token ||
			source.Selection.HEADDigest != contract.Hash(before.body) || source.Selection.SnapshotID != before.root.Snapshot ||
			source.Selection.DomainID != before.root.Domain || source.Selection.AccessRoot != before.root.CurrentAccess.AccessRoot {
			t.Fatal("delete reservation canonical source differs from exact current entry", source.Record.OriginalSlot)
		}
		canonicalBySlot[source.Record.OriginalSlot] = source
	}
	suppliedSecrets, generatedEntries := 0, 0
	for i, named := range before.root.Names {
		current := before.valueEntry(named.Slot)
		declaration, _, err := view.Entry(i)
		plan := input.graph.ValueEntryPlans[i]
		if err != nil || current == nil || string(declaration.Name) != named.Name || declaration.ValueSource() != current.ValueSource ||
			declaration.ConfidentialityClass() != current.ConfidentialityClass || len(declaration.RecipientIDs) != 32*len(current.Recipients) ||
			plan.Name != named.Name || plan.Slot != named.Slot || plan.ValueSource != current.ValueSource ||
			plan.ConfidentialityClass != current.ConfidentialityClass || plan.EntryIncarnationID != current.Incarnation {
			t.Fatal("delete reservation current declaration or plan identity differs", named.Name, err)
		}
		for j, recipient := range current.Recipients {
			if !bytes.Equal(declaration.RecipientIDs[j*32:(j+1)*32], recipient[:]) {
				t.Fatal("delete reservation current declaration membership differs", named.Name)
			}
		}
		membership, err := contract.GeneratorIntendedMembershipDescriptor(current.Recipients)
		if err != nil || plan.IntendedMembership != membership {
			t.Fatal("delete reservation current plan membership differs", named.Name, err)
		}
		if current.ValueSource == contract.Supplied {
			retained, err := contract.InspectRetainedCanonicalRecord(declaration.Payload)
			if err != nil || declaration.Kind != contract.GeneratorDeclarationRetained {
				t.Fatal("delete reservation supplied secret is not retained", named.Name, err)
			}
			owned, err := retained.Own()
			canonicalSource, present := canonicalBySlot[named.Slot]
			if err != nil || !present || !reflect.DeepEqual(owned, canonicalSource.Record) || owned.OriginalSlot != named.Slot ||
				!reflect.DeepEqual(owned.Entry, *current) {
				t.Fatal("delete reservation supplied secret lost its exact canonical tuple", named.Name, err)
			}
			suppliedSecrets++
			continue
		}
		location, present := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, current.Generated.IntentDigest}]
		reference, err := contract.InspectGeneratorDeclaredGenerationReference(declaration.Payload)
		g := current.Generated
		want := contract.GeneratorDeclaredGenerationReference{Epoch: g.Epoch, RetirementMode: g.RetirementMode,
			Schema: contract.GeneratorDeclaredReferenceSchema, ConfigContractID: g.ConfigContractID, ResourceContractID: g.ResourceContractID, LifecycleMode: g.LifecycleMode, CompletionClass: g.CompletionClass,
			Intent: location.Logical()}
		if err != nil || !present || declaration.Kind != contract.GeneratorDeclarationGeneratedReference || reference != want ||
			plan.Epoch != g.Epoch || plan.IntentDigest != g.IntentDigest || plan.RetirementMode != g.RetirementMode || plan.ChangeMask != 0 {
			t.Fatal("delete reservation generated entry changed its selected intent or metadata", named.Name, err)
		}
		generatedEntries++
	}
	if suppliedSecrets != 4 || generatedEntries != 2 || len(canonical) != suppliedSecrets ||
		before.root.Generated.GeneratedCurrent != uint32(generatedEntries) {
		t.Fatal("small delete reservation lost its complete mixed current set", suppliedSecrets, generatedEntries, len(canonical))
	}
	input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	head, token := bytes.Clone(before.body), before.token
	root, err := format.EncodeRoot(before.root)
	if err != nil {
		t.Fatal(err)
	}
	creates, cas := store.creates, store.cas
	prepared, _ := prepareUnclaimedGeneratedReservation(t, env, before, input, canonical)
	after := prepared.reservation.state
	if prepared.producerPhase == nil || prepared.producerPhase.TransitionKind != contract.GeneratorAuthorityCleanupReserve || prepared.claimed {
		t.Fatal("delete reservation did not retain the unclaimed cleanup phase")
	}
	if !reflect.DeepEqual(before.currentEntryInputs(), after.currentEntryInputs()) || !reflect.DeepEqual(before.root.ValueEntryPages, after.root.ValueEntryPages) || !reflect.DeepEqual(before.root.Recipients, after.root.Recipients) || before.root.ValueEntryCount != after.root.ValueEntryCount || before.root.SecretCount != after.root.SecretCount || before.root.RawBytes != after.root.RawBytes || before.root.MembershipCount != after.root.MembershipCount || before.root.SecretOrdinaryWrapCount != after.root.SecretOrdinaryWrapCount || before.root.OutputConfiguration != after.root.OutputConfiguration {
		t.Fatal("delete reservation changed exact current values or configuration")
	}
	// The unselected candidate owns new fragment bodies. Supply those exact
	// objects to a readback-only Store copy; the selected Store stays untouched.
	readback := selectedMemoryStoreCopy(store)
	for _, object := range prepared.reservation.candidate.objects {
		if err := format.CheckReference(object.ref, object.body); err != nil {
			t.Fatal("delete reservation candidate object", err)
		}
		if err := readback.putSelected(mustKey(t, readback.desc.Prefix, object.ref), object.body); err != nil {
			t.Fatal(err)
		}
	}
	afterStore := after.store
	after.store = readback
	assertCapacityConfigurationFactsPreserved(t, before, after)
	after.store = afterStore
	for _, page := range before.access {
		if page == nil {
			continue
		}
		for _, record := range page.Records {
			got, present := after.materialAccess(record.MaterialKind, record.MaterialID)
			if !present || !reflect.DeepEqual(got, record) {
				t.Fatal("delete reservation changed an existing access record", record.MaterialKind, record.MaterialID)
			}
		}
	}
	seedAccess, present := after.materialAccess(contract.OperationSeedMaterialKind, input.graph.Header.MaterialID)
	if !present || seedAccess.MaterialID != input.graph.Header.MaterialID || after.root.AccessRecordCount != before.root.AccessRecordCount+1 {
		t.Fatal("delete reservation did not add exactly its new operation Seed Access")
	}
	env.Custody.RetireGenerated()
	if code := env.Custody.BindGeneratedCandidate(env.operationContext(), prepared.operation.context.AdmissionID, generatedPrivateCandidate(t, prepared)); code != contract.CryptoInvalidAdmission {
		t.Fatal("retired delete preparation retained private admission", code)
	}
	gotRoot, err := format.EncodeRoot(before.root)
	if err != nil || !bytes.Equal(gotRoot, root) || !bytes.Equal(before.body, head) || before.token != token || store.creates != creates || store.cas != cas {
		t.Fatal("unclaimed delete reservation changed the selected predecessor or Store", err)
	}
	reopened, result := Open(t.Context(), OpenContext{admission: &seed.admission}, store)
	if reopened == nil || result.Outcome != ObservedCurrent || !bytes.Equal(reopened.body, head) || reopened.token != token {
		t.Fatal("retired unclaimed delete did not cold-open exact predecessor", result)
	}
}

func assertPublicationJointAdministrativePreserved(t *testing.T, after *StateSession, expected map[generatedRecordKey]selectedFragmentFact, order []format.PublicationCoordinateOrder, removed []generatedRecordKey) {
	t.Helper()
	seen := make(map[generatedRecordKey]bool)
	for i, page := range after.adminIndex.Pages {
		logical := 0
		for _, span := range page.Spans {
			for offset := uint16(0); offset < span.Count; offset++ {
				physical := span.First + offset
				var summary format.AdministrativeRowSummary
				if page.ReadRequired {
					row := after.support[i].Records[logical]
					summary = format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))}
				} else {
					summary = page.Rows[logical]
				}
				key := generatedRecordKey{summary.Kind, summary.RecordID}
				if summary.Kind == contract.OutputConfigurationSliceSupportKind || summary.Kind == contract.PublicationCoordinateSupportKind || summary.Kind == contract.PublicationMarkerSupportKind {
					want, present := expected[key]
					if !present || seen[key] || summary.BodyLength != want.row.BodyLength() {
						t.Fatal("partial exit selected row summary", key.kind, key.id)
					}
					seen[key] = true
					if page.Ref == want.ref && physical != want.physical {
						t.Fatal("partial exit retained physical ordinal", key.kind, key.id, physical, want.physical)
					}
					facts := after.supportFacts[i]
					if len(facts.rows) != 0 {
						if facts.rows[logical] != want.row || facts.ordinals[logical] != physical {
							t.Fatalf("partial exit readable fact: kind=%d id=%x digest-equal=%t fact-equal=%t length=%d expected-length=%d physical=%d expected-physical=%d fact-physical=%d ref-equal=%t logical=%d", key.kind, key.id, facts.rows[logical].BodyDigest() == want.row.BodyDigest(), facts.rows[logical] == want.row, facts.rows[logical].BodyLength(), want.row.BodyLength(), physical, want.physical, facts.ordinals[logical], page.Ref == want.ref, logical)
						}
					} else if page.Ref != want.ref || page.ReadRequired || span.Mandatory {
						t.Fatal("partial exit did not retain exact optional immutable reference", key.kind, key.id)
					}
				}
				logical++
			}
		}
	}
	if len(seen) != len(expected) || !reflect.DeepEqual(after.adminIndex.PublicationOrder, order) {
		t.Fatal("partial exit complete selected row set or ordering", len(seen), len(expected))
	}
	for _, key := range removed {
		if seen[key] || slices.ContainsFunc(after.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == key.id }) {
			t.Fatal("partial exit retained disposed owner", key.kind, key.id)
		}
	}
}

type publicationJointOpaqueSpan struct {
	first, count uint16
	owners       []contract.ID
	rows         []format.AdministrativeRowSummary
}

type publicationJointOpaquePage struct {
	ref   format.Ref
	spans []publicationJointOpaqueSpan
}

func publicationJointOpaqueExpected(t *testing.T, seed *StateSession, ref format.Ref) publicationJointOpaquePage {
	t.Helper()
	out := publicationJointOpaquePage{ref: ref}
	for _, page := range seed.adminIndex.Pages {
		if page.Ref != ref {
			continue
		}
		if page.ReadRequired {
			t.Fatal("opaque page is read-required")
		}
		logical := 0
		for _, span := range page.Spans {
			if span.Mandatory {
				t.Fatal("opaque page has mandatory span")
			}
			saved := publicationJointOpaqueSpan{first: span.First, count: span.Count, rows: slices.Clone(page.Rows[logical : logical+int(span.Count)])}
			for _, index := range span.GroupIndexes {
				saved.owners = append(saved.owners, seed.adminIndex.Groups[index].GroupID)
			}
			if len(saved.owners) == 0 {
				t.Fatal("optional opaque span has no owner")
			}
			out.spans = append(out.spans, saved)
			logical += int(span.Count)
		}
		return out
	}
	t.Fatal("opaque reference not selected")
	return out
}

func publicationJointOpaqueAfterExit(t *testing.T, expected publicationJointOpaquePage, target contract.ID, after *StateSession) publicationJointOpaquePage {
	t.Helper()
	var spans []publicationJointOpaqueSpan
	for _, span := range expected.spans {
		var owners []contract.ID
		for _, owner := range span.owners {
			if owner != target {
				owners = append(owners, owner)
			}
		}
		if len(owners) == 0 {
			continue
		}
		span.owners = owners
		spans = append(spans, span)
	}
	expected.spans = spans
	position := slices.IndexFunc(after.adminIndex.Pages, func(page format.AdministrativePage) bool { return page.Ref == expected.ref })
	if len(spans) == 0 {
		if position >= 0 || slices.Contains(after.root.RequiredSupport, expected.ref) {
			t.Fatal("opaque page retained after last owner ended")
		}
		return expected
	}
	if position < 0 || !slices.Contains(after.root.RequiredSupport, expected.ref) {
		t.Fatal("opaque shared page lost surviving owner")
	}
	page := after.adminIndex.Pages[position]
	if page.ReadRequired || len(page.Spans) != len(spans) {
		t.Fatal("opaque selected span count or required state")
	}
	var rows []format.AdministrativeRowSummary
	logical := uint16(0)
	for i, want := range spans {
		got := page.Spans[i]
		var owners []contract.ID
		for _, index := range got.GroupIndexes {
			owners = append(owners, after.adminIndex.Groups[index].GroupID)
		}
		if got.First != want.first || got.Count != want.count || got.Mandatory || !slices.Equal(owners, want.owners) {
			t.Fatal("opaque physical span or remapped owners changed", i)
		}
		for offset := uint16(0); offset < want.count; offset++ {
			slot, present := administrativeSelectedOrdinal(page, want.first+offset)
			if !present || slot != logical {
				t.Fatal("opaque physical-to-logical ordinal changed")
			}
			logical++
		}
		rows = append(rows, want.rows...)
	}
	if !slices.Equal(page.Rows, rows) || after.supportFacts[position].ref != expected.ref || len(after.supportFacts[position].rows) != 0 {
		t.Fatal("opaque authenticated summaries or physical reference changed")
	}
	return expected
}

func publicationJointUnreadableExits(t *testing.T, env fixtureEnvironment, seed *StateSession, marker, generated, obsoleteSeed contract.ID, full bool) {
	t.Helper()
	var markerRef, generatedRef format.Ref
	for _, page := range seed.adminIndex.Pages {
		optional := !page.ReadRequired && !slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory })
		if !optional {
			continue
		}
		targetPresent := slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool { return row.RecordID == marker })
		if targetPresent {
			peer := false
			for _, span := range page.Spans {
				for _, index := range span.GroupIndexes {
					peer = peer || seed.adminIndex.Groups[index].GroupID != marker
				}
			}
			if peer {
				markerRef = page.Ref
			}
		}
		if slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool {
			return row.Kind == contract.GeneratedFragmentSupportKind
		}) && slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool {
			return slices.ContainsFunc(span.GroupIndexes, func(index uint16) bool { return seed.adminIndex.Groups[index].GroupID == generated })
		}) {
			generatedRef = page.Ref
		}
	}
	if markerRef.Length == 0 || generatedRef.Length == 0 || markerRef == generatedRef {
		t.Fatal("joint fixture lacks shared optional marker and independent generated auxiliary pages")
	}
	expectedRows, err := capacityConfigurationPreservedFacts(t.Context(), seed)
	if err != nil {
		t.Fatal(err)
	}
	expectedOrder := clonePublicationWork(seed.adminIndex).PublicationOrder
	selected, err := selectedPublicationRelation(seed.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	markerCoordinate := selected.markers[marker].CoordinateID
	changedCoordinate := selected.coordinates[markerCoordinate]
	if changedCoordinate.OwnerState != contract.PublicationOwnerUncertainCreate || changedCoordinate.LatestUnresolvedAttemptID == marker || changedCoordinate.PossibleRemoteObject != 1 {
		t.Fatal("partial exit requires a retained later uncertain create")
	}
	markerPage, generatedPage := publicationJointOpaqueExpected(t, seed, markerRef), publicationJointOpaqueExpected(t, seed, generatedRef)
	faults := []string{"missing", "denied", "changed"}
	if full {
		faults = faults[:1]
	}
	for _, fault := range faults {
		for _, publicationFirst := range []bool{true, false} {
			orderName := "publication_first"
			if !publicationFirst {
				orderName = "generated_first"
			}
			t.Run("unreadable_"+fault+"_"+orderName, func(t *testing.T) {
				copyEnv := env
				store := selectedMemoryStoreCopy(env.Store.(*memoryStore))
				copyEnv.Store = store
				keys := map[string]bool{mustKey(t, store.desc.Prefix, markerRef): true, mustKey(t, store.desc.Prefix, generatedRef): true}
				rows := make(map[generatedRecordKey]selectedFragmentFact, len(expectedRows))
				for key, fact := range expectedRows {
					rows[key] = fact
				}
				opaque := []publicationJointOpaquePage{markerPage, generatedPage}
				expectedGroups := clonePublicationWork(seed.adminIndex).Groups
				store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
					if !keys[key] {
						return read
					}
					switch fault {
					case "missing":
						return contract.ReadResult{Status: contract.ReadMissing}
					case "denied":
						return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
					default:
						read.Body = bytes.Clone(read.Body)
						read.Body[len(read.Body)-1] ^= 1
						return read
					}
				}
				creates, cas := store.creates, store.cas
				current, result := openAdministrative(t.Context(), OpenContext{admission: &seed.admission}, store)
				if current == nil || result.Outcome != ObservedCurrent || store.creates != creates || store.cas != cas {
					t.Fatal("joint unreadable administrative Open", result)
				}
				if normal, result := Open(t.Context(), OpenContext{admission: &seed.admission}, store); normal != nil || result.Outcome == ObservedCurrent {
					t.Fatal("complete Open accepted unreadable selected auxiliary", result)
				}
				targets := []contract.ID{marker, generated}
				if !publicationFirst {
					targets = []contract.ID{generated, marker}
				}
				for _, target := range targets {
					var removed []generatedRecordKey
					seedID := contract.ID{}
					if target == marker {
						key := generatedRecordKey{contract.PublicationMarkerSupportKind, marker}
						delete(rows, key)
						removed = []generatedRecordKey{key}
					} else {
						seedID = obsoleteSeed
					}
					before := current
					current = publicationJointExitWithExpected(t, copyEnv, before, target, rows, expectedOrder, removed, seedID, true)
					if len(current.adminIndex.Groups) != len(before.adminIndex.Groups)-1 || slices.ContainsFunc(current.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == target }) {
						t.Fatal("unreadable exit removed wrong owner")
					}
					for i, page := range opaque {
						opaque[i] = publicationJointOpaqueAfterExit(t, page, target, current)
					}
					expectedGroups = publicationJointExpectedGroupsAfterExit(t, expectedGroups, target, current)
				}
				head, token, creates, cas := bytes.Clone(current.body), current.token, store.creates, store.cas
				store.readHook = nil
				complete, result := Open(t.Context(), OpenContext{admission: &seed.admission}, store)
				if complete == nil || result.Outcome != ObservedCurrent || !bytes.Equal(complete.body, head) || complete.token != token || store.creates != creates || store.cas != cas {
					t.Fatal("restored read availability changed selected successor", result)
				}
				assertPublicationJointExitPreserved(t, complete, rows, expectedOrder, []generatedRecordKey{{contract.PublicationMarkerSupportKind, marker}})
				if !reflect.DeepEqual(complete.root, current.root) || !reflect.DeepEqual(complete.currentEntryInputs(), seed.currentEntryInputs()) || !reflect.DeepEqual(complete.accessRecords(), current.accessRecords()) || complete.root.Generated.Hazards != 0 || complete.root.Generated.Graphs.Count != 0 || complete.root.Generated.LiveOwners.Count != 0 || complete.root.Generated.GeneratedCurrent != seed.root.Generated.GeneratedCurrent {
					t.Fatal("restored complete joint current state or generated closure")
				}
			})
		}
	}
}

func publicationJointMandatoryLoss(t *testing.T, env fixtureEnvironment, seed *StateSession) {
	t.Helper()
	refs := map[string]format.Ref{"index": seed.root.AdministrativeIndex}
	for _, page := range seed.adminIndex.Pages {
		if page.ReadRequired {
			refs["Slice_carrier"] = page.Ref
		}
		for _, row := range page.Rows {
			if row.Kind == contract.OutputConfigurationSliceSupportKind {
				refs["configuration"] = page.Ref
			}
			if row.Kind == contract.PublicationCoordinateSupportKind {
				refs["coordinate"] = page.Ref
			}
		}
	}
	if len(seed.root.AdministrativeIndexShards) != 0 {
		refs["index_shard"] = seed.root.AdministrativeIndexShards[0]
	}
	for _, name := range []string{"configuration", "coordinate", "Slice_carrier", "index", "index_shard"} {
		ref, present := refs[name]
		if !present {
			if name == "index_shard" {
				continue
			}
			t.Fatal("joint mandatory fixture lacks required page", name)
		}
		t.Run("mandatory_missing_"+name, func(t *testing.T) {
			store := selectedMemoryStoreCopy(env.Store.(*memoryStore))
			key := mustKey(t, store.desc.Prefix, ref)
			head, token := bytes.Clone(seed.body), seed.token
			index, err := format.EncodeAdministrativeIndexPages(seed.adminIndex)
			if err != nil {
				t.Fatal(err)
			}
			store.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
				if actual == key {
					return contract.ReadResult{Status: contract.ReadMissing}
				}
				return read
			}
			creates, cas := store.creates, store.cas
			public, private := env.Custody.Calls()
			if current, result := openAdministrative(t.Context(), OpenContext{admission: &seed.admission}, store); current != nil || result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject {
				t.Fatal("joint mandatory loss was not refused before admission", result)
			}
			if p, k := env.Custody.Calls(); p != public || k != private || store.creates != creates || store.cas != cas {
				t.Fatal("joint mandatory loss called custody or Store writes")
			}
			store.readHook = nil
			current, result := Open(t.Context(), OpenContext{admission: &seed.admission}, store)
			if current == nil || result.Outcome != ObservedCurrent || !bytes.Equal(current.body, head) || current.token != token {
				t.Fatal("mandatory read restoration changed HEAD/token", result)
			}
			got, err := format.EncodeAdministrativeIndexPages(current.adminIndex)
			if err != nil || len(got) != len(index) {
				t.Fatal("mandatory read restoration changed index", err)
			}
			for i := range index {
				if got[i].Ref != index[i].Ref || !bytes.Equal(got[i].Body, index[i].Body) {
					t.Fatal("mandatory read restoration changed exact index shard", i)
				}
			}
		})
	}
}

func publicationJointExpectedGroupsAfterExit(t *testing.T, before []format.AdministrativeGroup, target contract.ID, after *StateSession) []format.AdministrativeGroup {
	t.Helper()
	expected := make([]format.AdministrativeGroup, 0, len(before)-1)
	positions := make(map[uint16]uint16, len(before)-1)
	for i, group := range before {
		if group.GroupID == target {
			continue
		}
		positions[uint16(i)] = uint16(len(expected))
		expected = append(expected, group)
	}
	for i := range expected {
		expected[i].RelatedGroupIndexes = slices.Clone(expected[i].RelatedGroupIndexes)
		for j, old := range expected[i].RelatedGroupIndexes {
			fresh, present := positions[old]
			if !present {
				t.Fatal("independent exit has a retained dependent owner")
			}
			expected[i].RelatedGroupIndexes[j] = fresh
		}
	}
	if len(after.adminIndex.Groups) != len(expected) {
		t.Fatal("opaque exit selected owner set", len(after.adminIndex.Groups), len(expected))
	}
	for i, want := range expected {
		if !reflect.DeepEqual(after.adminIndex.Groups[i], want) {
			t.Fatalf("opaque exit changed surviving owner: id=%x kind=%d pages=%d bytes=%d got-pages=%d got-bytes=%d", want.GroupID, want.OwnerKind, want.ChargedPages, want.ChargedBytes, after.adminIndex.Groups[i].ChargedPages, after.adminIndex.Groups[i].ChargedBytes)
		}
	}
	return expected
}
