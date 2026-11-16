package core

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func publicationNoEffectRows(t *testing.T, s *StateSession) []contract.SupportRecord {
	t.Helper()
	_, loaded, err := s.publicationLoadedRowsForDisposition()
	if err != nil {
		t.Fatal(err)
	}
	var rows []contract.SupportRecord
	for _, page := range s.adminIndex.Pages {
		for _, summary := range page.Rows {
			if summary.Kind != contract.PublicationCoordinateSupportKind && summary.Kind != contract.PublicationMarkerSupportKind {
				continue
			}
			body, err := loaded[generatedRecordKey{summary.Kind, summary.RecordID}].body()
			if err != nil {
				t.Fatal(err)
			}
			row := contract.SupportRecord{Kind: summary.Kind, RecordID: summary.RecordID, Body: body}
			if row.Kind == contract.PublicationMarkerSupportKind {
				marker, err := contract.InspectPublicationMarker(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				marker.State = contract.PublicationQualifiedNoEffectState
				marker.Evidence.Class = contract.PublicationQualifiedNoEffect
				marker.Evidence.SafeRequestID = strings.Repeat("r", 1024)
				marker.Evidence.SafeResourceID = strings.Repeat("s", 1024)
				row.Body, err = contract.EncodePublicationMarker(marker)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				coordinate, err := contract.InspectPublicationCoordinate(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				coordinate.OwnerState = contract.PublicationOwnerNone
				coordinate.LatestUnresolvedAttemptID = contract.ID{}
				row.Body, err = contract.EncodePublicationCoordinate(coordinate)
				if err != nil {
					t.Fatal(err)
				}
			}
			rows = append(rows, row)
		}
	}
	return rows
}

// full_only: false
func TestPublicationRewriteUsesActualEvidenceAndPacking(t *testing.T) {
	state := publicationCapacityState(t)
	plan, err := state.planPublicationRewrite(t.Context(), state.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	rows := publicationNoEffectRows(t, state)
	next := *state
	next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
	candidate := Candidate{session: state}
	construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
	if constructionErr == nil {
		constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
	}
	if err := constructionErr; err != nil {
		t.Fatal("actual rewrite", err)
	}
	if next.publicationProof == nil || !next.publicationProof.validFor(next.selectedImage()) {
		t.Fatal("no complete successor proof")
	}
	if next.root.OutputConfiguration != state.root.OutputConfiguration || next.root.WarningBits != state.root.WarningBits {
		t.Fatal("rewrite changed preserved state")
	}
	for _, peer := range plan.peers {
		i := slices.IndexFunc(next.adminIndex.Pages, func(page format.AdministrativePage) bool { return page.Ref == peer.Ref })
		if i < 0 || !samePublicationPage(peer, next.adminIndex.Pages[i]) {
			t.Fatal("physical peer changed")
		}
	}
	for _, image := range candidate.objects {
		if err := format.CheckReference(image.ref, image.body); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range rows {
		found := false
		for _, view := range next.support {
			for _, actual := range view.Records {
				if actual.Kind == row.Kind && actual.RecordID == row.RecordID {
					found = bytes.Equal(actual.Body, row.Body)
				}
			}
		}
		if !found {
			t.Fatal("actual output row missing", row.Kind)
		}
	}
}

// full_only: false
func TestPublicationRewriteRejectsChangedReservationAndStalePlan(t *testing.T) {
	for _, damage := range []string{"stamp", "projection", "missing_marker", "stale_plan", "occupied_owner", "reused_page"} {
		t.Run(damage, func(t *testing.T) {
			state := publicationCapacityState(t)
			rows := publicationNoEffectRows(t, state)
			ids := []contract.ID{publicationRelationID(92), publicationRelationID(93)}
			switch damage {
			case "stamp", "projection":
				for i, row := range rows {
					if row.Kind == contract.PublicationMarkerSupportKind {
						marker, err := contract.InspectPublicationMarker(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						if damage == "stamp" {
							marker.AdmissionOrdinal++
						} else {
							marker.Projection.PolicyDigest = publicationRelationID(99)
							marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
							if err != nil {
								t.Fatal(err)
							}
						}
						rows[i].Body, err = contract.EncodePublicationMarker(marker)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
			case "missing_marker":
				rows = rows[:1]
			case "reused_page":
				ids[0] = state.root.Snapshot
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			candidate := Candidate{session: state}
			construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
			if (damage == "stale_plan" || damage == "occupied_owner") && constructionErr != nil {
				t.Fatal("healthy construction before source mutation", constructionErr)
			}
			if constructionErr == nil {
				// These sources change after the owned construction is checked.
				// No caller-supplied old plan is available to perform this guard.
				if damage == "stale_plan" {
					state.body = []byte("different selected HEAD")
				}
				if damage == "occupied_owner" {
					state.root.Generated.ActiveOwner = publicationRelationID(89)
				}
				constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, ids)
			}
			if err := constructionErr; !errors.Is(err, contract.ErrRecord) {
				t.Fatalf("invalid rewrite accepted: %v", err)
			}
			if len(candidate.objects) != 0 {
				t.Fatal("failed rewrite leaked candidate writes")
			}
		})
	}
}

func publicationMixedPeerState(t *testing.T) *StateSession {
	t.Helper()
	state, _, _ := generatedDetachedRetirementState(t, "generated", 0)
	_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	coordinate.BindingState = contract.PublicationBindingRetired
	coordinate.ActiveBindingIncarnationID = contract.ID{}
	rows := publicationRelationRows(t, coordinate, marker)
	index := generatedFixtureFreeSupportIndex(t, state)
	state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(20), Index: index,
		Records: []contract.SupportRecordView{contract.SupportRecordView(rows[0]), contract.SupportRecordView(rows[1])}})
	generatedRefreshSupport(t, state)
	all := state.supportRecords()
	generatedRepackSupport(t, state, all, generatedFixtureBundles(t, state))
	return state
}

// full_only: false
func TestPublicationRewriteKeepsGeneratedPhysicalPeers(t *testing.T) {
	state := publicationMixedPeerState(t)
	oldSnapshot := state.adminIndex.SliceSnapshot
	var mixed format.Ref
	for _, page := range state.adminIndex.Pages {
		pub, peer := false, false
		for _, row := range page.Rows {
			if row.Kind == contract.PublicationMarkerSupportKind {
				pub = true
			} else {
				peer = true
			}
		}
		if pub && peer {
			mixed = page.Ref
		}
	}
	if mixed.Object.IsZero() {
		t.Fatal("real packer did not create mixed OwnerSupport fixture")
	}
	plan, err := state.planPublicationRewrite(t.Context(), state.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	next := *state
	next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
	candidate := Candidate{session: state}
	construction, constructionErr := state.preparePublicationConstruction(t.Context(), publicationNoEffectRows(t, state))
	if constructionErr == nil {
		constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
	}
	if err := constructionErr; err != nil {
		t.Fatal(err)
	}
	if next.adminIndex.SliceSnapshot != oldSnapshot {
		t.Fatal("publication rewrite changed retained slice owner", oldSnapshot, next.adminIndex.SliceSnapshot)
	}
	if !slices.Contains(next.root.RequiredSupport, mixed) {
		t.Fatal("mixed physical peer page was released")
	}
	for _, peer := range plan.peers {
		i := slices.IndexFunc(next.adminIndex.Pages, func(page format.AdministrativePage) bool { return page.Ref == peer.Ref })
		if i < 0 || !samePublicationPage(peer, next.adminIndex.Pages[i]) {
			t.Fatal("peer ref/span/ordinal changed")
		}
	}
	if !reflect.DeepEqual(next.root.Generated, state.root.Generated) {
		t.Fatal("publication close changed generated facts")
	}
}

// full_only: false
func TestPublicationConstructionRejectsReusedSuccessorIdentities(t *testing.T) {
	for _, reservation := range []bool{false, true} {
		name := "close"
		if reservation {
			name = "reserve"
		}
		t.Run(name, func(t *testing.T) {
			for _, damage := range []string{"snapshot", "transition", "same_identity", "zero_snapshot", "zero_transition"} {
				t.Run(damage, func(t *testing.T) {
					state := publicationCapacityState(t)
					rows := publicationNoEffectRows(t, state)
					if reservation {
						state, rows = publicationReservationFixture(t, false)
					}
					next := *state
					next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
					switch damage {
					case "snapshot":
						next.root.Snapshot = state.root.Snapshot
					case "transition":
						next.root.Transition = state.root.Transition
					case "same_identity":
						next.root.Transition = next.root.Snapshot
					case "zero_snapshot":
						next.root.Snapshot = contract.ID{}
					case "zero_transition":
						next.root.Transition = contract.ID{}
					}
					candidate := Candidate{session: state}
					var err error
					if reservation {
						construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
						if constructionErr == nil {
							constructionErr = state.materializePublicationReservationConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
						}
						err = constructionErr
					} else {
						construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
						if constructionErr == nil {
							constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
						}
						err = constructionErr
					}
					if !errors.Is(err, contract.ErrRecord) {
						t.Fatalf("reused successor accepted: %v", err)
					}
					if len(candidate.objects) != 0 {
						t.Fatal("invalid successor emitted objects")
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicationClosePreservesFrozenCoordinateFields(t *testing.T) {
	for _, damage := range []string{"binding", "deletion_locator", "deletion_profile"} {
		t.Run(damage, func(t *testing.T) {
			state := publicationCapacityState(t)
			rows := publicationNoEffectRows(t, state)
			for i := range rows {
				if rows[i].Kind != contract.PublicationCoordinateSupportKind {
					continue
				}
				coordinate, err := contract.InspectPublicationCoordinate(rows[i].Body)
				if err != nil {
					t.Fatal(err)
				}
				switch damage {
				case "binding":
					coordinate.LastBindingIncarnationID = publicationRelationID(78)
				case "deletion_locator":
					coordinate.DeletionConsumerLocator = "changed"
				case "deletion_profile":
					coordinate.DeletionTargetContractID = "changed"
				}
				rows[i].Body, err = contract.EncodePublicationCoordinate(coordinate)
				if err != nil {
					t.Fatal(err)
				}
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			candidate := Candidate{session: state}
			construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
			if constructionErr == nil {
				constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
			}
			if err := constructionErr; !errors.Is(err, contract.ErrRecord) {
				t.Fatalf("frozen coordinate changed: %v", err)
			}
			if len(candidate.objects) != 0 {
				t.Fatal("changed coordinate emitted objects")
			}
		})
	}
}

// full_only: false
func TestPublicationClosePreservesCompactedACKHistory(t *testing.T) {
	for _, damage := range []string{"digest", "stamp", "erase", "older_ack", "value_digest", "delete_stamp"} {
		t.Run(damage, func(t *testing.T) {
			state, _ := publicationReservationFixture(t, true)
			if damage == "value_digest" || damage == "delete_stamp" {
				for i := range state.support {
					for j, row := range state.support[i].Records {
						if row.Kind != contract.PublicationCoordinateSupportKind {
							continue
						}
						c, err := contract.InspectPublicationCoordinate(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						if damage == "value_digest" {
							c.LastValueAckAttemptID, c.LastValueDigest = publicationRelationID(72), publicationRelationID(73)
							c.LastValueAckIncarnationID, c.LastValueAckOrdinal = c.CurrentPublicationIncarnationID, math.MaxUint64-1
						} else {
							c.LastDeleteAckAttemptID = publicationRelationID(74)
							c.LastDeleteAckIncarnationID, c.LastDeleteAckOrdinal = c.CurrentPublicationIncarnationID, math.MaxUint64-1
						}
						state.support[i].Records[j].Body, err = contract.EncodePublicationCoordinate(c)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				generatedRefreshSupport(t, state)
			}
			rows := publicationNoEffectRows(t, state)
			var err error
			var closed contract.PublicationMarker
			if damage == "older_ack" {
				for i := range rows {
					if rows[i].Kind != contract.PublicationMarkerSupportKind {
						continue
					}
					closed, err = contract.InspectPublicationMarker(rows[i].Body)
					if err != nil {
						t.Fatal(err)
					}
					closed.State, closed.Evidence.Class = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged
					closed.Evidence.NormalizedStatus, closed.Evidence.SafeResourceID = 201, "exact-resource"
					closed.Evidence.ConsumerLocator = "locator"
					rows[i].Body, err = contract.EncodePublicationMarker(closed)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			for i := range rows {
				if rows[i].Kind != contract.PublicationCoordinateSupportKind {
					continue
				}
				coordinate, err := contract.InspectPublicationCoordinate(rows[i].Body)
				if err != nil {
					t.Fatal(err)
				}
				switch damage {
				case "digest":
					coordinate.LastPolicyDigest = publicationRelationID(77)
				case "value_digest":
					coordinate.LastValueDigest = publicationRelationID(77)
				case "delete_stamp":
					coordinate.LastDeleteAckOrdinal--
				case "stamp":
					coordinate.LastPolicyAckOrdinal--
				case "erase":
					coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyDigest, coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = contract.ID{}, contract.ID{}, contract.ID{}, 0
				case "older_ack":
					coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyDigest, coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = closed.AttemptID, closed.Projection.PolicyDigest, closed.PublicationIncarnationID, closed.AdmissionOrdinal
				}
				rows[i].Body, err = contract.EncodePublicationCoordinate(coordinate)
				if err != nil {
					t.Fatal(err)
				}
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			candidate := Candidate{session: state}
			construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
			if constructionErr == nil {
				constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
			}
			if err := constructionErr; !errors.Is(err, contract.ErrRecord) {
				t.Fatal("close replaced compacted ACK history", err)
			}
			if len(candidate.objects) != 0 {
				t.Fatal("ACK damage emitted objects")
			}
		})
	}
}

// full_only: false
func TestPublicationCloseKeepsUnrelatedCoordinateExact(t *testing.T) {
	state := publicationCapacityState(t)
	_, c, _, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	c.CanonicalTarget = "account/other"
	var err error
	c.CoordinateID, err = contract.PublicationCoordinateID(c.DomainID, c.ServiceContractID, c.CanonicalTarget)
	if err != nil {
		t.Fatal(err)
	}
	c.BindingState, c.ActiveBindingIncarnationID, c.OwnerState = contract.PublicationBindingRetired, contract.ID{}, contract.PublicationOwnerNone
	c.CurrentPublicationIncarnationID, c.LatestUnresolvedAttemptID = publicationRelationID(75), contract.ID{}
	c.PossibleRemoteObject = 0
	c.LastPolicyAckAttemptID, c.LastPolicyDigest = publicationRelationID(76), publicationRelationID(77)
	c.LastPolicyAckIncarnationID, c.LastPolicyAckOrdinal = c.CurrentPublicationIncarnationID, 1
	body, err := contract.EncodePublicationCoordinate(c)
	if err != nil {
		t.Fatal(err)
	}
	state.support = append(state.support, format.RequiredSupportPageView{Domain: c.DomainID, Object: publicationRelationID(78), Index: 3, Records: []contract.SupportRecordView{{Kind: contract.PublicationCoordinateSupportKind, RecordID: c.CoordinateID, Body: body}}})
	generatedRefreshSupport(t, state)
	rows := publicationNoEffectRows(t, state)
	for i := range rows {
		if rows[i].RecordID == c.CoordinateID {
			c.LastPolicyDigest = publicationRelationID(79)
			rows[i].Body, err = contract.EncodePublicationCoordinate(c)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	next := *state
	next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
	candidate := Candidate{session: state}
	construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
	if constructionErr == nil {
		constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
	}
	if err := constructionErr; !errors.Is(err, contract.ErrRecord) {
		t.Fatal("close altered unrelated coordinate", err)
	}
	if len(candidate.objects) != 0 {
		t.Fatal("unrelated coordinate emitted writes")
	}
}

// full_only: false
func TestPublicationCloseInstallsQualifiedACKWitness(t *testing.T) {
	state := publicationCapacityState(t)
	_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
	marker.State, marker.Evidence.Class = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged
	marker.Evidence.NormalizedStatus, marker.Evidence.SafeResourceID = 201, "exact-resource"
	marker.Evidence.ConsumerLocator = "locator"
	coordinate.OwnerState, coordinate.LatestUnresolvedAttemptID, coordinate.OwnedBirthAttemptID = contract.PublicationOwnerQualified, contract.ID{}, marker.AttemptID
	var err error
	coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(coordinate.DomainID, coordinate.CoordinateID, marker.Projection.BindingIncarnationID, marker.Projection.EntryIncarnationID, marker.Projection.TargetRowDigest, marker.AttemptID, marker.Evidence.SafeResourceID)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyDigest = marker.AttemptID, marker.Projection.PolicyDigest
	coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = marker.PublicationIncarnationID, marker.AdmissionOrdinal
	rows := publicationRelationRows(t, coordinate, marker)
	next := *state
	next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
	candidate := Candidate{session: state}
	construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
	if constructionErr == nil {
		constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92)})
	}
	if err := constructionErr; err != nil {
		t.Fatal("qualified ACK close", err)
	}
	selected, err := selectedPublicationRelation(next.selectedImage())
	if err != nil || !selected.coordinates[coordinate.CoordinateID].Equal(coordinate) || selected.markers[marker.AttemptID] != marker {
		t.Fatal("qualified ACK not selected exactly", err)
	}
}

// full_only: false
func TestPublicationCloseCannotLowerCoordinateLateEffectRisk(t *testing.T) {
	state := publicationCapacityState(t)
	for i := range state.support {
		for j, row := range state.support[i].Records {
			if row.Kind != contract.PublicationCoordinateSupportKind {
				continue
			}
			c, err := contract.InspectPublicationCoordinate(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			c.LateEffectRisk = 1
			state.support[i].Records[j].Body, err = contract.EncodePublicationCoordinate(c)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	generatedRefreshSupport(t, state)
	rows := publicationNoEffectRows(t, state)
	for i := range rows {
		if rows[i].Kind != contract.PublicationCoordinateSupportKind {
			continue
		}
		c, err := contract.InspectPublicationCoordinate(rows[i].Body)
		if err != nil {
			t.Fatal(err)
		}
		c.LateEffectRisk = 0
		rows[i].Body, err = contract.EncodePublicationCoordinate(c)
		if err != nil {
			t.Fatal(err)
		}
	}
	next := *state
	next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
	candidate := Candidate{session: state}
	construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
	if constructionErr == nil {
		constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
	}
	if err := constructionErr; !errors.Is(err, contract.ErrRecord) {
		t.Fatal("close lowered retained late-effect risk", err)
	}
	if len(candidate.objects) != 0 {
		t.Fatal("lowered risk emitted writes")
	}
}

func publicationOwnedActionCloseFixture(t *testing.T, action, outcome uint8) (*StateSession, []contract.SupportRecord) {
	t.Helper()
	state := generatedEmptyPredecessor(t)
	_, coordinate, birth, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
	birth.State, birth.Evidence.Class, birth.Evidence.NormalizedStatus, birth.Evidence.SafeResourceID = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged, 201, "exact-resource"
	birth.Evidence.ConsumerLocator = "locator"
	coordinate.OwnerState, coordinate.OwnedBirthAttemptID = contract.PublicationOwnerQualified, birth.AttemptID
	var err error
	coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(coordinate.DomainID, coordinate.CoordinateID, birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
	if err != nil {
		t.Fatal(err)
	}
	marker := birth
	marker.AttemptID, marker.OperationID, marker.AdmissionOrdinal = publicationRelationID(60), publicationRelationID(61), 2
	marker.Projection.Action, marker.Projection.OwnedBirthAttemptID = action, birth.AttemptID
	if action == contract.PublicationWriteValue {
		marker.Projection.ValueBasisDigest = publicationRelationID(62)
	}
	if action == contract.PublicationDeleteOwned {
		marker.Projection.PolicyDigest = contract.ID{}
	}
	marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
	if err != nil {
		t.Fatal(err)
	}
	marker.State, marker.Evidence.Class, marker.Evidence.NormalizedStatus, marker.Evidence.SafeResourceID = contract.PublicationMayHaveEntered, contract.PublicationUnproved, 0, ""
	marker.Evidence.ConsumerLocator = ""
	marker.BirthServiceContractID, marker.BirthTargetContractID = "", ""
	marker.Evidence.ConsumerLocator = ""
	coordinate.LastAdmissionOrdinal, coordinate.LatestUnresolvedAttemptID = 2, marker.AttemptID
	rows := publicationRelationRows(t, coordinate, birth)
	body, err := contract.EncodePublicationMarker(marker)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body})
	state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(20), Index: 1})
	for _, row := range rows {
		state.support[len(state.support)-1].Records = append(state.support[len(state.support)-1].Records, contract.SupportRecordView(row))
	}
	generatedRefreshSupport(t, state)
	if _, err := selectedPublicationRelation(state.selectedImage()); err != nil {
		t.Fatal("owned action source", err)
	}
	marker.State = outcome
	switch outcome {
	case contract.PublicationQualifiedNoEffectState:
		marker.Evidence.Class = contract.PublicationQualifiedNoEffect
	case contract.PublicationAcknowledged:
		marker.Evidence.Class, marker.Evidence.NormalizedStatus = contract.PublicationRequestAcknowledged, 200
	}
	rows[2].Body, err = contract.EncodePublicationMarker(marker)
	if err != nil {
		t.Fatal(err)
	}
	if outcome == contract.PublicationAcknowledged || outcome == contract.PublicationQualifiedNoEffectState {
		coordinate.LatestUnresolvedAttemptID = contract.ID{}
	}
	rows[0].Body, err = contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	return state, rows
}

// full_only: false
func TestPublicationCloseRequiresExactOwnershipResult(t *testing.T) {
	for _, action := range []uint8{contract.PublicationUpdatePolicy, contract.PublicationWriteValue} {
		for _, outcome := range []uint8{contract.PublicationQualifiedNoEffectState, contract.PublicationUnknown} {
			name := "policy_no_effect"
			if action == contract.PublicationWriteValue {
				name = "value_no_effect"
			}
			if outcome == contract.PublicationUnknown {
				name += "_unknown"
			}
			t.Run(name, func(t *testing.T) {
				state, rows := publicationOwnedActionCloseFixture(t, action, outcome)
				coordinate, err := contract.InspectPublicationCoordinate(rows[0].Body)
				if err != nil {
					t.Fatal(err)
				}
				coordinate.OwnerState, coordinate.OwnedBirthAttemptID, coordinate.OwnedInstanceDigest = contract.PublicationOwnerNone, contract.ID{}, contract.ID{}
				rows[0].Body, err = contract.EncodePublicationCoordinate(coordinate)
				if err != nil {
					t.Fatal(err)
				}
				next := *state
				next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
				initial := next
				candidate := Candidate{session: state}
				construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
				if constructionErr == nil {
					constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
				}
				if err := constructionErr; !errors.Is(err, contract.ErrRecord) {
					t.Fatal("unrelated result erased qualified ownership", err)
				}
				if len(candidate.objects) != 0 || !reflect.DeepEqual(next, initial) {
					t.Fatal("ownership refusal changed candidate/state")
				}
			})
		}
	}
}

func publicationTwoCreateCloseFixture(t *testing.T, closeNewer bool, owner uint8) (*StateSession, []contract.SupportRecord) {
	t.Helper()
	state := generatedEmptyPredecessor(t)
	_, coordinate, older, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	coordinate.BindingState, coordinate.ActiveBindingIncarnationID, coordinate.OwnerState = contract.PublicationBindingRetired, contract.ID{}, owner
	newer := older
	newer.AttemptID, newer.OperationID, newer.AdmissionOrdinal = publicationRelationID(60), publicationRelationID(61), 2
	var err error
	newer.BlockerCount = 1
	newer.BlockerDigest, err = contract.PublicationBlockerDigest([]contract.ID{older.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	coordinate.LastAdmissionOrdinal, coordinate.LatestUnresolvedAttemptID = 2, newer.AttemptID
	rows := publicationRelationRows(t, coordinate, older)
	body, err := contract.EncodePublicationMarker(newer)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: newer.AttemptID, Body: body})
	state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(20), Index: 1})
	for _, row := range rows {
		state.support[len(state.support)-1].Records = append(state.support[len(state.support)-1].Records, contract.SupportRecordView(row))
	}
	generatedRefreshSupport(t, state)
	if _, err := selectedPublicationRelation(state.selectedImage()); err != nil {
		t.Fatal("two-create source", err)
	}
	closed := &older
	index := 1
	if closeNewer {
		closed, index = &newer, 2
		coordinate.LatestUnresolvedAttemptID = older.AttemptID
	}
	closed.State, closed.Evidence.Class = contract.PublicationQualifiedNoEffectState, contract.PublicationQualifiedNoEffect
	rows[index].Body, err = contract.EncodePublicationMarker(*closed)
	if err != nil {
		t.Fatal(err)
	}
	rows[0].Body, err = contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	return state, rows
}

// full_only: false
func TestPublicationClosePreservesRemainingCreateObligations(t *testing.T) {
	for _, damage := range []string{"possible_object", "latest_pointer", "uncertain_owner"} {
		t.Run(damage, func(t *testing.T) {
			owner := uint8(contract.PublicationOwnerNone)
			if damage == "uncertain_owner" {
				owner = contract.PublicationOwnerUncertainCreate
			}
			state, rows := publicationTwoCreateCloseFixture(t, false, owner)
			coordinate, err := contract.InspectPublicationCoordinate(rows[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "possible_object":
				coordinate.PossibleRemoteObject = 0
			case "latest_pointer":
				coordinate.LatestUnresolvedAttemptID = contract.ID{}
			default:
				coordinate.OwnerState = contract.PublicationOwnerNone
			}
			rows[0].Body, err = contract.EncodePublicationCoordinate(coordinate)
			if err != nil {
				t.Fatal(err)
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			initial := next
			candidate := Candidate{session: state}
			construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
			if constructionErr == nil {
				constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
			}
			if err := constructionErr; !errors.Is(err, contract.ErrRecord) {
				t.Fatal("older close erased remaining create obligation", err)
			}
			if len(candidate.objects) != 0 || !reflect.DeepEqual(next, initial) {
				t.Fatal("remaining obligation refusal changed candidate/state")
			}
		})
	}
}

// full_only: false
func TestPublicationClosePreservesActionOwnedFacts(t *testing.T) {
	check := func(t *testing.T, state *StateSession, rows []contract.SupportRecord) {
		t.Helper()
		next := *state
		next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
		candidate := Candidate{session: state}
		construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
		if constructionErr == nil {
			constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
		}
		if err := constructionErr; err != nil {
			t.Fatal("legitimate action close", err)
		}
		selected, err := selectedPublicationRelation(next.selectedImage())
		if err != nil {
			t.Fatal("legitimate successor relation", err)
		}
		for _, row := range rows {
			if row.Kind == contract.PublicationCoordinateSupportKind {
				want, err := contract.InspectPublicationCoordinate(row.Body)
				if err != nil || !selected.coordinates[row.RecordID].Equal(want) {
					t.Fatal("coordinate changed after close", err)
				}
			} else {
				want, err := contract.InspectPublicationMarker(row.Body)
				if err != nil || selected.markers[row.RecordID] != want {
					t.Fatal("marker changed after close", err)
				}
			}
		}
	}
	for _, action := range []uint8{contract.PublicationUpdatePolicy, contract.PublicationWriteValue, contract.PublicationDeleteOwned} {
		for _, outcome := range []uint8{contract.PublicationQualifiedNoEffectState, contract.PublicationUnknown, contract.PublicationAcknowledged} {
			if outcome == contract.PublicationAcknowledged && action != contract.PublicationDeleteOwned {
				continue // Exact value/policy ACK cache updates have separate checks.
			}
			name := map[uint8]string{contract.PublicationUpdatePolicy: "policy", contract.PublicationWriteValue: "value", contract.PublicationDeleteOwned: "delete"}[action]
			name += map[uint8]string{contract.PublicationQualifiedNoEffectState: "_no_effect", contract.PublicationUnknown: "_unknown", contract.PublicationAcknowledged: "_ack"}[outcome]
			t.Run(name, func(t *testing.T) {
				state, rows := publicationOwnedActionCloseFixture(t, action, outcome)
				if action == contract.PublicationDeleteOwned && outcome == contract.PublicationAcknowledged {
					// The delete does not prove lasting absence. Keep the exact birth,
					// possible object and prior late-effect risk for a fresh delete.
					for i := range state.support {
						for j, row := range state.support[i].Records {
							if row.Kind != contract.PublicationCoordinateSupportKind {
								continue
							}
							coordinate, err := contract.InspectPublicationCoordinate(row.Body)
							if err != nil {
								t.Fatal(err)
							}
							coordinate.LateEffectRisk = 1
							state.support[i].Records[j].Body, err = contract.EncodePublicationCoordinate(coordinate)
							if err != nil {
								t.Fatal(err)
							}
						}
					}
					generatedRefreshSupport(t, state)
					coordinate, err := contract.InspectPublicationCoordinate(rows[0].Body)
					if err != nil {
						t.Fatal(err)
					}
					coordinate.LateEffectRisk = 1
					coordinate.LastDeleteAckAttemptID, coordinate.LastDeleteAckIncarnationID, coordinate.LastDeleteAckOrdinal = publicationRelationID(60), coordinate.CurrentPublicationIncarnationID, 2
					rows[0].Body, err = contract.EncodePublicationCoordinate(coordinate)
					if err != nil {
						t.Fatal(err)
					}
				}
				check(t, state, rows)
			})
		}
	}
	for _, owner := range []uint8{contract.PublicationOwnerNone, contract.PublicationOwnerUncertainCreate} {
		for _, closeNewer := range []bool{false, true} {
			name := "none_older"
			if owner == contract.PublicationOwnerUncertainCreate {
				name = "uncertain_older"
			}
			if closeNewer {
				name += "_newer"
			}
			t.Run(name, func(t *testing.T) {
				state, rows := publicationTwoCreateCloseFixture(t, closeNewer, owner)
				check(t, state, rows)
			})
		}
	}
	t.Run("sole_no_effect_create", func(t *testing.T) {
		state := publicationCapacityState(t)
		rows := publicationNoEffectRows(t, state)
		for i := range rows {
			if rows[i].Kind != contract.PublicationCoordinateSupportKind {
				continue
			}
			coordinate, err := contract.InspectPublicationCoordinate(rows[i].Body)
			if err != nil {
				t.Fatal(err)
			}
			coordinate.PossibleRemoteObject = 0
			rows[i].Body, err = contract.EncodePublicationCoordinate(coordinate)
			if err != nil {
				t.Fatal(err)
			}
		}
		check(t, state, rows)
	})
}

// full_only: false
func TestPublicationCloseReleasesOnlyMatchingCreateObligation(t *testing.T) {
	state, rows := publicationTwoCreateCloseFixture(t, false, contract.PublicationOwnerUncertainCreate)
	newer, err := contract.InspectPublicationMarker(rows[2].Body)
	if err != nil {
		t.Fatal(err)
	}
	newer.Projection.BindingIncarnationID, newer.Projection.EntryIncarnationID, newer.Projection.TargetRowDigest = publicationRelationID(113), publicationRelationID(114), publicationRelationID(115)
	newer.ProjectionCommitment, err = contract.PublicationProjectionCommitment(newer.Projection)
	if err != nil {
		t.Fatal(err)
	}
	rows[2].Body, err = contract.EncodePublicationMarker(newer)
	if err != nil {
		t.Fatal(err)
	}
	for i := range state.support {
		for j, row := range state.support[i].Records {
			if row.Kind == contract.PublicationMarkerSupportKind && row.RecordID == newer.AttemptID {
				state.support[i].Records[j].Body = slices.Clone(rows[2].Body)
			}
		}
	}
	generatedRefreshSupport(t, state)
	if _, err := selectedPublicationRelation(state.selectedImage()); err != nil {
		t.Fatal("different-obligation predecessor", err)
	}
	coordinate, err := contract.InspectPublicationCoordinate(rows[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.OwnerState = contract.PublicationOwnerNone
	rows[0].Body, err = contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	next := *state
	next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
	candidate := Candidate{session: state}
	construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
	if constructionErr == nil {
		constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
	}
	if err := constructionErr; err != nil {
		t.Fatal("matching no-effect close with unrelated create retained", err)
	}
	selected, err := selectedPublicationRelation(next.selectedImage())
	older, oldErr := contract.InspectPublicationMarker(rows[1].Body)
	if err != nil || oldErr != nil || !selected.coordinates[coordinate.CoordinateID].Equal(coordinate) || selected.markers[newer.AttemptID] != newer || selected.markers[older.AttemptID] != older {
		t.Fatal("different-obligation close changed retained facts", err, oldErr)
	}
}

func publicationCreateACKCloseFixture(t *testing.T, closeOlder bool) (*StateSession, []contract.SupportRecord) {
	t.Helper()
	state, rows := publicationTwoCreateCloseFixture(t, false, contract.PublicationOwnerNone)
	coordinate, err := contract.InspectPublicationCoordinate(rows[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	var markers [2]contract.PublicationMarker
	for i := range markers {
		markers[i], err = contract.InspectPublicationMarker(rows[i+1].Body)
		if err != nil {
			t.Fatal(err)
		}
		markers[i].State, markers[i].Evidence.Class = contract.PublicationUnknown, contract.PublicationUnproved
		markers[i].Evidence.NormalizedStatus, markers[i].Evidence.SafeResourceID = 0, ""
		markers[i].Evidence.ConsumerLocator = ""
	}
	prior, closed := 0, 1
	if closeOlder {
		prior, closed = 1, 0
	}
	markers[prior].State, markers[prior].Evidence.Class, markers[prior].Evidence.NormalizedStatus = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged, 201
	markers[prior].Evidence.SafeResourceID = []string{"older-resource", "newer-resource"}[prior]
	markers[prior].Evidence.ConsumerLocator = "locator"
	coordinate.OwnerState, coordinate.OwnedBirthAttemptID = contract.PublicationOwnerQualified, markers[prior].AttemptID
	coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(coordinate.DomainID, coordinate.CoordinateID, markers[prior].Projection.BindingIncarnationID, markers[prior].Projection.EntryIncarnationID, markers[prior].Projection.TargetRowDigest, markers[prior].AttemptID, markers[prior].Evidence.SafeResourceID)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyDigest = markers[prior].AttemptID, markers[prior].Projection.PolicyDigest
	coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = markers[prior].PublicationIncarnationID, markers[prior].AdmissionOrdinal
	coordinate.LatestUnresolvedAttemptID = markers[closed].AttemptID
	rows[0].Body, err = contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	for i := range markers {
		rows[i+1].Body, err = contract.EncodePublicationMarker(markers[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range state.support {
		for j, retained := range state.support[i].Records {
			for _, row := range rows {
				if retained.Kind == row.Kind && retained.RecordID == row.RecordID {
					state.support[i].Records[j].Body = slices.Clone(row.Body)
				}
			}
		}
	}
	generatedRefreshSupport(t, state)
	if _, err := selectedPublicationRelation(state.selectedImage()); err != nil {
		t.Fatal("qualified two-create predecessor", err)
	}
	markers[closed].State, markers[closed].Evidence.Class, markers[closed].Evidence.NormalizedStatus = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged, 201
	markers[closed].Evidence.SafeResourceID = []string{"older-resource", "newer-resource"}[closed]
	markers[closed].Evidence.ConsumerLocator = "locator"
	if !closeOlder {
		coordinate.OwnedBirthAttemptID = markers[closed].AttemptID
		coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(coordinate.DomainID, coordinate.CoordinateID, markers[closed].Projection.BindingIncarnationID, markers[closed].Projection.EntryIncarnationID, markers[closed].Projection.TargetRowDigest, markers[closed].AttemptID, markers[closed].Evidence.SafeResourceID)
		if err != nil {
			t.Fatal(err)
		}
		coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyDigest = markers[closed].AttemptID, markers[closed].Projection.PolicyDigest
		coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = markers[closed].PublicationIncarnationID, markers[closed].AdmissionOrdinal
	}
	coordinate.LatestUnresolvedAttemptID = contract.ID{}
	rows[0].Body, err = contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	rows[closed+1].Body, err = contract.EncodePublicationMarker(markers[closed])
	if err != nil {
		t.Fatal(err)
	}
	return state, rows
}

// full_only: false
func TestPublicationCloseOrdersQualifiedBirthByAdmission(t *testing.T) {
	for _, name := range []string{"newer_ack_installs_birth", "older_ack_preserves_birth", "older_ack_cannot_replace_birth"} {
		t.Run(name, func(t *testing.T) {
			state, rows := publicationCreateACKCloseFixture(t, name != "newer_ack_installs_birth")
			coordinate, err := contract.InspectPublicationCoordinate(rows[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			if name == "older_ack_cannot_replace_birth" {
				older, err := contract.InspectPublicationMarker(rows[1].Body)
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
			candidate := Candidate{session: state}
			construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
			if constructionErr == nil {
				constructionErr = state.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
			}
			err = constructionErr
			if name == "older_ack_cannot_replace_birth" {
				if !errors.Is(err, contract.ErrRecord) || len(candidate.objects) != 0 || !reflect.DeepEqual(next, initial) {
					t.Fatal("older ACK rolled back qualified birth or changed refused candidate", err)
				}
				return
			}
			if err != nil {
				t.Fatal("qualified create ACK close", err)
			}
			selected, err := selectedPublicationRelation(next.selectedImage())
			if err != nil || !selected.coordinates[coordinate.CoordinateID].Equal(coordinate) {
				t.Fatal("qualified birth successor changed coordinate", err)
			}
			for _, row := range rows[1:] {
				marker, err := contract.InspectPublicationMarker(row.Body)
				if err != nil || selected.markers[marker.AttemptID] != marker {
					t.Fatal("qualified birth successor changed retained marker", err)
				}
			}
		})
	}
}
