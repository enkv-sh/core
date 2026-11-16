package core

import (
	"bytes"
	"errors"
	"maps"
	"math"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type publicationBoundsRefusalFacts struct {
	root, index []byte
	support     []format.RequiredSupportPageView
	pages       []selectedSupportPageFacts
	fragments   map[format.FragmentLocation]selectedFragmentFact
}

func publicationBoundsCaptureRefusalFacts(t *testing.T, state *StateSession) publicationBoundsRefusalFacts {
	t.Helper()
	root, err := format.EncodeRoot(state.root)
	if err != nil {
		t.Fatal("refusal Root facts", err)
	}
	index, err := format.EncodeAdministrativeIndex(state.adminIndex)
	if err != nil {
		t.Fatal("refusal index facts", err)
	}
	facts := publicationBoundsRefusalFacts{root: root, index: index,
		support: slices.Clone(state.support), pages: slices.Clone(state.supportFacts), fragments: maps.Clone(state.fragmentFacts)}
	for i := range facts.support {
		facts.support[i].Records = slices.Clone(facts.support[i].Records)
		for j := range facts.support[i].Records {
			facts.support[i].Records[j].Body = slices.Clone(facts.support[i].Records[j].Body)
		}
	}
	for i := range facts.pages {
		facts.pages[i].rows = slices.Clone(facts.pages[i].rows)
		facts.pages[i].ordinals = slices.Clone(facts.pages[i].ordinals)
	}
	return facts
}

func publicationBoundsPredecessor(t *testing.T, count int) *StateSession {
	t.Helper()
	state := generatedEmptyPredecessor(t)
	rows, order := publicationJointRows(t, state.root.Domain, count)
	state.adminIndex.PublicationOrder = order
	state.root.WarningBits = WarningPublicationOrderValue | WarningDiscardedExactEvidence
	publicationBoundsInstallRows(t, state, rows)
	state.admission.composition = publicationRelationID(87)
	state.admission.expires = time.Now().Add(time.Minute)
	state.admission.store.HeadKey = state.admission.store.Prefix + "/HEAD"
	state.store.(*generatedFixtureSupportStore).descriptor = state.admission.store
	return state
}

func publicationBoundsInstallRows(t *testing.T, state *StateSession, rows []contract.SupportRecord) {
	t.Helper()
	var mandatory administrativeMandatorySupport
	if _, err := mandatory.selectedPublication(state.root.Domain, rows, state.adminIndex.PublicationOrder); err != nil {
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
	// Keep the existing configuration carrier and discard only fixture publication pages.
	state.support = slices.DeleteFunc(slices.Clone(state.support), func(page format.RequiredSupportPageView) bool {
		return slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool {
			return row.Kind == contract.PublicationMarkerSupportKind || row.Kind == contract.PublicationCoordinateSupportKind
		})
	})
	packed, err := format.PackRequiredSupportRows(state.root.Domain, groups, uint32(len(state.support)))
	if err != nil {
		t.Fatal(err)
	}
	for i, page := range packed {
		physical := generatedFixtureFreeSupportIndex(t, state)
		view := format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationJointID(state.root.Domain, "bounds-source-page", i), Index: physical}
		for _, row := range page {
			view.Records = append(view.Records, contract.SupportRecordView(row))
		}
		state.support = append(state.support, view)
	}
	generatedRefreshSupport(t, state)
}

func publicationBoundsRows(t *testing.T, state *StateSession) []contract.SupportRecord {
	t.Helper()
	var rows []contract.SupportRecord
	for _, page := range state.support {
		for _, row := range page.Records {
			if row.Kind == contract.PublicationMarkerSupportKind || row.Kind == contract.PublicationCoordinateSupportKind {
				rows = append(rows, contract.SupportRecord(row))
			}
		}
	}
	return rows
}

func publicationBoundsPages(t *testing.T, state *StateSession, rows []contract.SupportRecord, label string) []contract.ID {
	t.Helper()
	order, err := publicationOrderForRows(state.root.Domain, rows, state.adminIndex.PublicationOrder)
	if err != nil {
		t.Fatal(err)
	}
	var mandatory administrativeMandatorySupport
	if _, err := mandatory.selectedPublication(state.root.Domain, rows, order); err != nil {
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
	packed, err := format.PackRequiredSupportRows(state.root.Domain, groups, 0)
	if err != nil {
		t.Fatal(err)
	}
	return publicationJointPageIDs(state.root.Domain, label, len(packed))
}

// full_only: false
func TestPublicationCloseOrdersBirthAcrossIncarnations(t *testing.T) {
	for _, name := range []string{"newer_ack_replaces_birth", "older_ack_preserves_birth", "older_ack_cannot_replace_birth"} {
		t.Run(name, func(t *testing.T) {
			state, rows := publicationCreateACKCloseFixture(t, name != "newer_ack_replaces_birth")
			oldIncarnation, newIncarnation := publicationRelationID(85), publicationRelationID(86)
			// The older incarnation has a larger ordinal. Only authenticated table order
			// can establish which admission is newer across the counter rollover.
			rewrite := func(row contract.SupportRecord) contract.SupportRecord {
				var err error
				if row.Kind == contract.PublicationMarkerSupportKind {
					marker, e := contract.InspectPublicationMarker(row.Body)
					if e != nil {
						t.Fatal(e)
					}
					if marker.AttemptID == rows[1].RecordID {
						marker.PublicationIncarnationID, marker.AdmissionOrdinal = oldIncarnation, math.MaxUint64
					} else {
						marker.PublicationIncarnationID, marker.AdmissionOrdinal = newIncarnation, 1
					}
					row.Body, err = contract.EncodePublicationMarker(marker)
				} else {
					coordinate, e := contract.InspectPublicationCoordinate(row.Body)
					if e != nil {
						t.Fatal(e)
					}
					coordinate.CurrentPublicationIncarnationID, coordinate.LastAdmissionOrdinal = newIncarnation, 1
					if coordinate.LastPolicyAckAttemptID == rows[1].RecordID {
						coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = oldIncarnation, math.MaxUint64
					} else {
						coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = newIncarnation, 1
					}
					row.Body, err = contract.EncodePublicationCoordinate(coordinate)
				}
				if err != nil {
					t.Fatal(err)
				}
				return row
			}
			predecessorRows := publicationBoundsRows(t, state)
			for i := range predecessorRows {
				predecessorRows[i] = rewrite(predecessorRows[i])
			}
			coordinate, err := contract.InspectPublicationCoordinate(rows[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			state.adminIndex.PublicationOrder = []format.PublicationCoordinateOrder{{CoordinateID: coordinate.CoordinateID, Incarnations: []contract.ID{oldIncarnation, newIncarnation}}}
			publicationBoundsInstallRows(t, state, predecessorRows)
			for i := range rows {
				rows[i] = rewrite(rows[i])
			}
			if name == "older_ack_cannot_replace_birth" {
				older, err := contract.InspectPublicationMarker(rows[1].Body)
				if err != nil {
					t.Fatal(err)
				}
				coordinate, err = contract.InspectPublicationCoordinate(rows[0].Body)
				if err != nil {
					t.Fatal(err)
				}
				coordinate.OwnedBirthAttemptID = older.AttemptID
				coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(coordinate.DomainID, coordinate.CoordinateID, older.Projection.BindingIncarnationID, older.Projection.EntryIncarnationID, older.Projection.TargetRowDigest, older.AttemptID, older.Evidence.SafeResourceID)
				if err != nil {
					t.Fatal(err)
				}
				rows[0].Body, err = contract.EncodePublicationCoordinate(coordinate)
				if err != nil {
					t.Fatal(err)
				}
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			initial := next
			predecessorInitial := *state
			predecessorFacts := publicationBoundsCaptureRefusalFacts(t, state)
			candidateFacts := publicationBoundsCaptureRefusalFacts(t, &next)
			candidate := Candidate{session: state}
			construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
			if constructionErr == nil {
				constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, publicationBoundsPages(t, state, rows, "cross-incarnation-close"))
			}
			err = constructionErr
			if name == "older_ack_cannot_replace_birth" {
				if !errors.Is(err, contract.ErrRecord) || len(candidate.objects) != 0 || candidate.session != state ||
					!reflect.DeepEqual(next, initial) || !reflect.DeepEqual(*state, predecessorInitial) {
					t.Fatal("older result changed refused candidate", err)
				}
				if !reflect.DeepEqual(predecessorFacts, publicationBoundsCaptureRefusalFacts(t, state)) ||
					!reflect.DeepEqual(candidateFacts, publicationBoundsCaptureRefusalFacts(t, &next)) {
					t.Fatal("older result changed refused selected facts")
				}
				return
			}
			if err != nil {
				t.Fatal("cross-incarnation close", err)
			}
			after, err := selectedPublicationRelation(next.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if row.Kind == contract.PublicationCoordinateSupportKind {
					expected, err := contract.InspectPublicationCoordinate(row.Body)
					if err != nil || !after.coordinates[row.RecordID].Equal(expected) {
						t.Fatal("qualified coordinate changed", err)
					}
				} else {
					expected, err := contract.InspectPublicationMarker(row.Body)
					if err != nil || after.markers[row.RecordID] != expected {
						t.Fatal("retained result changed", err)
					}
				}
			}
			if !reflect.DeepEqual(next.adminIndex.PublicationOrder, state.adminIndex.PublicationOrder) || next.root.WarningBits != state.root.WarningBits {
				t.Fatal("close changed retained order/warnings")
			}
		})
	}
}

// full_only: false
func TestPublicationRolloverAtRetainedMarkerLimit(t *testing.T) {
	for _, count := range []int{2, 1024} {
		name := "small"
		if count == 1024 {
			name = "maximum"
		}
		t.Run(name, func(t *testing.T) {
			state := publicationBoundsPredecessor(t, count)
			before, err := selectedPublicationRelation(state.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			coordinateID := state.adminIndex.PublicationOrder[0].CoordinateID
			beforeCoordinate := before.coordinates[coordinateID]
			fresh := publicationJointID(state.root.Domain, "rollover-incarnation", 0)
			advanced, err := state.publicationCoordinateForAdmission(coordinateID, fresh)
			if err != nil {
				t.Fatal(err)
			}
			var blockers []contract.ID
			for _, retained := range before.markers {
				if retained.CoordinateID == coordinateID {
					blockers = append(blockers, retained.AttemptID)
				}
			}
			slices.SortFunc(blockers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			if len(blockers) != 2 {
				t.Fatal("rollover fixture does not retain two uncertain creates")
			}
			oldMarker, remaining := before.markers[blockers[0]], before.markers[blockers[1]]
			marker := publicationReservedDeleteMarker(t, remaining)
			marker.AttemptID, marker.OperationID = publicationJointID(state.root.Domain, "rollover-attempt", 0), publicationJointID(state.root.Domain, "rollover-operation", 0)
			marker.PublicationIncarnationID, marker.AdmissionOrdinal = fresh, 1
			marker.State = contract.PublicationMayHaveEntered
			marker.BlockerCount = 2
			marker.BlockerDigest, err = contract.PublicationBlockerDigest(blockers)
			if err != nil {
				t.Fatal(err)
			}
			advanced.LatestUnresolvedAttemptID = marker.AttemptID
			admissionRows := func(basis []contract.SupportRecord, coordinate contract.PublicationCoordinate) []contract.SupportRecord {
				result := slices.Clone(basis)
				body, err := contract.EncodePublicationCoordinate(coordinate)
				if err != nil {
					t.Fatal(err)
				}
				for i := range result {
					if result[i].RecordID == coordinate.CoordinateID && result[i].Kind == contract.PublicationCoordinateSupportKind {
						result[i].Body = body
					}
				}
				body, err = contract.EncodePublicationMarker(marker)
				if err != nil {
					t.Fatal(err)
				}
				return append(result, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body})
			}
			if count == 1024 {
				rows := admissionRows(publicationBoundsRows(t, state), advanced)
				next := *state
				next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
				initial := next
				predecessorInitial := *state
				predecessorFacts := publicationBoundsCaptureRefusalFacts(t, state)
				candidateFacts := publicationBoundsCaptureRefusalFacts(t, &next)
				candidate := Candidate{session: state}
				// With empty result evidence,1024*743 mandatory bytes and2049*859
				// optional bytes each fit one real2MiB support page. Valid fresh page
				// identities ensure the refusal cannot come from missing writer inputs.
				pageIDs := publicationJointPageIDs(state.root.Domain, "full-marker-refused-page", 2)
				construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
				if constructionErr == nil {
					constructionErr = state.materializePublicationReservationConstruction(t.Context(), &next, &candidate, construction, pageIDs)
				}
				err := constructionErr
				if !errors.Is(err, contract.ErrRecordCapacity) {
					t.Fatalf("2049th marker must refuse at capacity before mutation: %v", err)
				}
				if len(candidate.objects) != 0 || candidate.session != state ||
					!reflect.DeepEqual(next, initial) || !reflect.DeepEqual(*state, predecessorInitial) {
					t.Fatalf("2049th marker refusal changed candidate objects=%d", len(candidate.objects))
				}
				if !reflect.DeepEqual(predecessorFacts, publicationBoundsCaptureRefusalFacts(t, state)) ||
					!reflect.DeepEqual(candidateFacts, publicationBoundsCaptureRefusalFacts(t, &next)) {
					t.Fatal("2049th marker admission changed refused selected facts")
				}
			}
			// Build the independently bounded 2047-marker predecessor. The omitted
			// marker incarnation has no remaining reference. This fixture does not
			// claim an exit or terminal-compaction execution.
			rows := publicationBoundsRows(t, state)
			rows = slices.DeleteFunc(rows, func(row contract.SupportRecord) bool {
				return row.Kind == contract.PublicationMarkerSupportKind && row.RecordID == oldMarker.AttemptID
			})
			beforeCoordinate.LatestUnresolvedAttemptID = remaining.AttemptID
			coordinateBody, err := contract.EncodePublicationCoordinate(beforeCoordinate)
			if err != nil {
				t.Fatal(err)
			}
			for i := range rows {
				if rows[i].Kind == contract.PublicationCoordinateSupportKind && rows[i].RecordID == coordinateID {
					rows[i].Body = coordinateBody
				}
			}
			for i := range state.adminIndex.PublicationOrder {
				if state.adminIndex.PublicationOrder[i].CoordinateID == coordinateID {
					state.adminIndex.PublicationOrder[i].Incarnations = slices.DeleteFunc(slices.Clone(state.adminIndex.PublicationOrder[i].Incarnations), func(id contract.ID) bool { return id == oldMarker.PublicationIncarnationID })
				}
			}
			publicationBoundsInstallRows(t, state, rows)
			predecessor, err := selectedPublicationRelation(state.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			advanced, err = state.publicationCoordinateForAdmission(coordinateID, fresh)
			if err != nil {
				t.Fatal(err)
			}
			expectedCoordinate := beforeCoordinate
			expectedCoordinate.CurrentPublicationIncarnationID, expectedCoordinate.LastAdmissionOrdinal, expectedCoordinate.LatestUnresolvedAttemptID = fresh, 1, marker.AttemptID
			expectedAdmission := expectedCoordinate
			expectedAdmission.LatestUnresolvedAttemptID = beforeCoordinate.LatestUnresolvedAttemptID
			if !advanced.Equal(expectedAdmission) {
				t.Fatal("rollover changed non-ordering coordinate fields")
			}
			advanced.LatestUnresolvedAttemptID = marker.AttemptID
			marker.BlockerCount = 1
			marker.BlockerDigest, err = contract.PublicationBlockerDigest([]contract.ID{remaining.AttemptID})
			if err != nil {
				t.Fatal(err)
			}
			rows = admissionRows(rows, advanced)
			expectedOrder := clonePublicationWork(state.adminIndex).PublicationOrder
			for i := range expectedOrder {
				if expectedOrder[i].CoordinateID == coordinateID {
					expectedOrder[i].Incarnations = slices.DeleteFunc(expectedOrder[i].Incarnations, func(id contract.ID) bool { return id == beforeCoordinate.CurrentPublicationIncarnationID })
					expectedOrder[i].Incarnations = append(expectedOrder[i].Incarnations, fresh)
				}
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			candidate := Candidate{session: state}
			if !state.admission.valid(state.store) {
				t.Fatal("rollover fixture admission invalid")
			}
			reservePlan, err := state.planPublicationRewrite(t.Context(), state.adminIndex)
			if err != nil {
				t.Fatal("rollover predecessor plan", err)
			}
			if err := state.publicationReservationRows(rows, reservePlan); err != nil {
				t.Fatal("rollover reservation row relation", err)
			}
			construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
			if constructionErr == nil {
				constructionErr = state.materializePublicationReservationConstruction(t.Context(), &next, &candidate, construction, publicationBoundsPages(t, state, rows, "rollover-successor-page"))
			}
			if err := constructionErr; err != nil {
				t.Fatal("real rollover reservation", err)
			}
			after, err := selectedPublicationRelation(next.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			if len(after.coordinates) != count || len(after.markers) != 2*count || !after.coordinates[coordinateID].Equal(expectedCoordinate) ||
				!reflect.DeepEqual(next.adminIndex.PublicationOrder, expectedOrder) || next.root.WarningBits != state.root.WarningBits {
				t.Fatalf("rollover counts/order/history coordinates=%d markers=%d", len(after.coordinates), len(after.markers))
			}
			for id, coordinate := range predecessor.coordinates {
				if id != coordinateID && !after.coordinates[id].Equal(coordinate) {
					t.Fatal("rollover changed unrelated coordinate")
				}
			}
			for id, marker := range predecessor.markers {
				if after.markers[id] != marker {
					t.Fatal("rollover changed retained marker")
				}
			}
			total := 0
			for _, row := range next.adminIndex.PublicationOrder {
				total += len(row.Incarnations)
			}
			if total != 6*count-1 {
				t.Fatalf("deduplicated rollover union=%d expected=%d", total, 6*count-1)
			}
			for _, object := range candidate.objects {
				if err := format.CheckReference(object.ref, object.body); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// Retained receipts can occupy separate immutable carriers after earlier
// selections. Their complete ordered window remains authenticated; empty or
// padded pages are never used to reach a child endpoint.
func publicationBoundsReceiptPeers(t *testing.T, state *StateSession, count int) {
	t.Helper()
	_, receipt, _ := receiptStateFixtureForDomain(t, state.root.Domain)
	windows := contract.MutationReceiptWindows{DomainID: state.root.Domain}
	for i := 0; i < count; i++ {
		row := receipt
		row.OperationID = publicationJointID(state.root.Domain, "bounds-receipt", i)
		windows.Successes = append(windows.Successes, row)
		windows.Order = append(windows.Order, row.OperationID)
	}
	rows, err := windows.SupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	indexes, err := windows.Indexes()
	if err != nil {
		t.Fatal(err)
	}
	successes, failures, order, err := indexes.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	state.root.Generated.SuccessWindow, state.root.Generated.FailureWindow, state.root.Generated.ReceiptOrder = successes, failures, order
	indexID, err := contract.MutationReceiptIndexBlobID(state.root.Domain, successes, failures, order)
	if err != nil {
		t.Fatal(err)
	}
	indexBody, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		t.Fatal(err)
	}
	fragmentBody, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: indexID, Count: 1, TotalLength: uint64(len(indexBody)), WholeDigest: contract.Hash(indexBody), Payload: indexBody})
	if err != nil {
		t.Fatal(err)
	}
	fragmentID, err := contract.GeneratorFragmentID(indexID, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: fragmentBody})
	for i, row := range rows {
		physical := generatedFixtureFreeSupportIndex(t, state)
		state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationJointID(state.root.Domain, "bounds-receipt-page", i), Index: physical, Records: []contract.SupportRecordView{contract.SupportRecordView(row)}})
		if row.Kind == contract.GeneratedFragmentSupportKind {
			state.root.Generated.Fragments = []format.FragmentLocation{{BlobID: indexID, SupportPageIndex: physical}}
		}
	}
	// Filling a sparse physical index does not append at the end of the Root's
	// reference order. Keep every immutable page identity and fragment coordinate.
	slices.SortFunc(state.support, func(a, b format.RequiredSupportPageView) int {
		return int(a.Index) - int(b.Index)
	})
	generatedRefreshSupport(t, state)
	// Refresh invalidates the selected Root proofs. Verify the final retained
	// image after all carrier changes, before any selected-source consumer.
	generatedVerifySelectedFixtureSlices(t, state)
	proof, result, err := validateSelectedPublicationConfiguration(t.Context(), state.selectedImage(), state)
	if err != nil || result.Outcome != 0 || proof == nil || !state.selectedOutputComplete() {
		t.Fatal("endpoint predecessor publication/configuration proof", result, err)
	}
	state.publicationProof = proof
	actual, err := state.receiptWindows(t.Context())
	if err != nil || !slices.Equal(actual.Successes, windows.Successes) || !slices.Equal(actual.Order, windows.Order) || len(actual.Failures) != 0 {
		t.Fatal("sparse receipt window changed", err)
	}
}

// full_only: false
func TestPublicationWriterChildEndpoints(t *testing.T) {
	for _, test := range []struct {
		name            string
		children, limit uint32
		refuse, writer  bool
	}{
		{"small", 8, 252, false, true},
		{"ordinary_252", 251, 252, false, true},
		{"ordinary_253_refused", 252, 252, true, true},
		{"administrative_256", 255, 256, false, false},
		{"administrative_257_refused", 256, 256, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := publicationBoundsPredecessor(t, 2)
			generatedMaterializeFixtureSupport(t, state)
			// Configuration shares the immutable mandatory coordinate carrier. Its
			// successor retains the complete old physical page while publication is
			// repacked into two new carriers. This charges one additional child.
			var configuration, coordinates int
			for i, page := range state.support {
				for _, row := range page.Records {
					if row.Kind == contract.OutputConfigurationSliceSupportKind {
						configuration = i
					}
					if row.Kind == contract.PublicationCoordinateSupportKind {
						coordinates = i
					}
				}
			}
			if configuration == coordinates || len(state.support[configuration].Records) != 1 || len(state.support[coordinates].Records) != 2 {
				t.Fatalf("shared source carriers config_index=%d coordinate_index=%d config_rows=%d coordinate_rows=%d", configuration, coordinates, len(state.support[configuration].Records), len(state.support[coordinates].Records))
			}
			state.support[configuration].Records = append(slices.Clone(state.support[configuration].Records), state.support[coordinates].Records...)
			slices.SortFunc(state.support[configuration].Records, func(a, b contract.SupportRecordView) int {
				if a.Kind != b.Kind {
					return int(a.Kind) - int(b.Kind)
				}
				return bytes.Compare(a.RecordID[:], b.RecordID[:])
			})
			state.support = slices.Delete(state.support, coordinates, coordinates+1)
			generatedRefreshSupport(t, state)
			// Base has recipient, shared mandatory carrier, marker carrier and index.
			// Receipt peers add their single authenticated window fragment.
			publicationBoundsReceiptPeers(t, state, int(test.children)-5)
			if state.root.ChildCount != test.children {
				t.Fatalf("actual predecessor children=%d expected=%d", state.root.ChildCount, test.children)
			}
			capacity, err := state.reservePublicationRewrite(t.Context(), state.adminIndex, test.limit)
			if test.refuse {
				if !errors.Is(err, contract.ErrRecordCapacity) {
					t.Fatal("next child admitted", err)
				}
			} else if err != nil {
				t.Fatal("child endpoint refused", err)
			}
			if !test.writer {
				return
			}
			rows := publicationNoEffectRows(t, state)
			plan, err := state.planPublicationRewrite(t.Context(), state.adminIndex)
			if err != nil {
				t.Fatal(err)
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			initial := next
			predecessorInitial := *state
			predecessorFacts := publicationBoundsCaptureRefusalFacts(t, state)
			candidateFacts := publicationBoundsCaptureRefusalFacts(t, &next)
			candidate := Candidate{session: state}
			construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
			if constructionErr == nil {
				constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, publicationBoundsPages(t, state, rows, "child-endpoint-close"))
			}
			err = constructionErr
			if test.refuse {
				if !errors.Is(err, contract.ErrRecordCapacity) || len(candidate.objects) != 0 || candidate.session != state ||
					!reflect.DeepEqual(next, initial) || !reflect.DeepEqual(*state, predecessorInitial) {
					t.Fatalf("next ordinary writer changed candidate objects=%d err=%v", len(candidate.objects), err)
				}
				if !reflect.DeepEqual(predecessorFacts, publicationBoundsCaptureRefusalFacts(t, state)) ||
					!reflect.DeepEqual(candidateFacts, publicationBoundsCaptureRefusalFacts(t, &next)) {
					t.Fatal("next ordinary writer changed refused selected facts")
				}
				return
			}
			if err != nil || next.root.ChildCount != test.children+1 {
				t.Fatalf("writer endpoint children=%d expected=%d err=%v", next.root.ChildCount, test.children+1, err)
			}
			var supportBytes uint64
			for _, ref := range next.root.RequiredSupport {
				supportBytes += uint64(ref.Length)
			}
			// Four no-effect markers use two result strings each. Their four
			// reserved 1024-byte consumer locators remain unused; page counts match.
			if supportBytes+4*1024 != capacity.physicalBytes {
				t.Fatalf("physical support=%d reserve=%d", supportBytes, capacity.physicalBytes)
			}
			for _, peer := range plan.peers {
				i := slices.IndexFunc(next.adminIndex.Pages, func(page format.AdministrativePage) bool { return page.Ref == peer.Ref })
				if i < 0 || !samePublicationPage(peer, next.adminIndex.Pages[i]) {
					t.Fatal("writer changed retained physical peer")
				}
			}
			actual, err := next.receiptWindows(t.Context())
			before, beforeErr := state.receiptWindows(t.Context())
			if err != nil || beforeErr != nil || !slices.Equal(actual.Successes, before.Successes) || !slices.Equal(actual.Failures, before.Failures) || !slices.Equal(actual.Order, before.Order) {
				t.Fatal("writer changed receipt window", err, beforeErr)
			}
		})
	}
}
