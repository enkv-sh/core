package core

import (
	"bytes"
	"context"
	"errors"
	"math"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func publicationReservationFixture(t *testing.T, rollover bool) (*StateSession, []contract.SupportRecord) {
	t.Helper()
	state := publicationCapacityState(t)
	var coordinate contract.PublicationCoordinate
	var marker contract.PublicationMarker
	for i := range state.support {
		for j, row := range state.support[i].Records {
			if row.Kind == contract.PublicationCoordinateSupportKind {
				var err error
				coordinate, err = contract.InspectPublicationCoordinate(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if rollover {
					coordinate.LastAdmissionOrdinal = math.MaxUint64
					coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyDigest = publicationRelationID(70), publicationRelationID(71)
					coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = coordinate.CurrentPublicationIncarnationID, math.MaxUint64-1
					state.support[i].Records[j].Body, err = contract.EncodePublicationCoordinate(coordinate)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if row.Kind == contract.PublicationMarkerSupportKind {
				var err error
				marker, err = contract.InspectPublicationMarker(row.Body)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if rollover {
		generatedRefreshSupport(t, state)
	}
	state.admission.composition = publicationRelationID(87)
	state.admission.expires = time.Now().Add(time.Minute)
	state.admission.store.HeadKey = state.admission.store.Prefix + "/HEAD"
	state.store.(*generatedFixtureSupportStore).descriptor = state.admission.store
	state.root.WarningBits = WarningPublicationOrderValue | WarningDiscardedExactEvidence
	var fresh contract.ID
	if rollover {
		fresh = publicationRelationID(88)
	}
	after, err := state.publicationCoordinateForAdmission(coordinate.CoordinateID, fresh)
	if err != nil {
		t.Fatal(err)
	}
	oldMarker := marker
	marker = publicationReservedDeleteMarker(t, oldMarker)
	marker.AttemptID, marker.OperationID = publicationRelationID(80), publicationRelationID(81)
	marker.PublicationIncarnationID, marker.AdmissionOrdinal = after.CurrentPublicationIncarnationID, after.LastAdmissionOrdinal
	marker.State = contract.PublicationMayHaveEntered
	marker.BlockerCount = 1
	marker.BlockerDigest, err = contract.PublicationBlockerDigest([]contract.ID{oldMarker.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	after.LatestUnresolvedAttemptID = marker.AttemptID
	rows := publicationRelationRows(t, after, oldMarker)
	body, err := contract.EncodePublicationMarker(marker)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body})
	return state, rows
}

func publicationReservedDeleteMarker(t *testing.T, create contract.PublicationMarker) contract.PublicationMarker {
	t.Helper()
	marker := create
	marker.Projection.Action = contract.PublicationDeleteReservedSlot
	marker.Projection.PolicyDigest = contract.ID{}
	marker.Projection.UncertainCreateAttemptID = create.AttemptID
	marker.Projection.ExclusiveNamespaceDigest = publicationRelationID(122)
	marker.Projection.RequestContractDigest = publicationRelationID(123)
	marker.AuthoritySubjectDigest = publicationRelationID(124)
	marker.Evidence.ResponseContractDigest = publicationRelationID(125)
	marker.BirthServiceContractID, marker.BirthTargetContractID = "", ""
	marker.Evidence.ConsumerLocator = ""
	var err error
	marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
	if err != nil {
		t.Fatal("retained reserved-delete projection", err)
	}
	return marker
}

// full_only: false
func TestPublicationReservationAndRolloverPreserveSelectedHistory(t *testing.T) {
	for _, rollover := range []bool{false, true} {
		name := "next_ordinal"
		if rollover {
			name = "fresh_incarnation"
		}
		t.Run(name, func(t *testing.T) {
			state, rows := publicationReservationFixture(t, rollover)
			before, err := selectedPublicationRelation(state.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			candidate := Candidate{session: state}
			construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
			if constructionErr == nil {
				constructionErr = state.materializePublicationReservationConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
			}
			if err := constructionErr; err != nil {
				t.Fatal(err)
			}
			after, err := selectedPublicationRelation(next.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			if len(after.markers) != len(before.markers)+1 || next.root.WarningBits != state.root.WarningBits {
				t.Fatal("reservation lost old blockers/warnings")
			}
			for id, marker := range before.markers {
				if after.markers[id] != marker {
					t.Fatal("old selected marker changed")
				}
			}
			for id, coordinate := range before.coordinates {
				selected := after.coordinates[id]
				if selected.LastPolicyAckIncarnationID != coordinate.LastPolicyAckIncarnationID || selected.LastPolicyAckOrdinal != coordinate.LastPolicyAckOrdinal ||
					selected.LastPolicyAckAttemptID != coordinate.LastPolicyAckAttemptID || selected.LastPolicyDigest != coordinate.LastPolicyDigest ||
					selected.OwnerState != coordinate.OwnerState {
					t.Fatal("rollover lost ACK/ownership")
				}
				order := next.adminIndex.PublicationOrder[0].Incarnations
				if rollover {
					if selected.LastAdmissionOrdinal != 1 || !slices.Equal(order, []contract.ID{coordinate.CurrentPublicationIncarnationID, publicationRelationID(88)}) {
						t.Fatal("incorrect rollover", order)
					}
				} else if selected.LastAdmissionOrdinal != coordinate.LastAdmissionOrdinal+1 {
					t.Fatal("ordinal not advanced")
				}
			}
			for _, image := range candidate.objects {
				if err := format.CheckReference(image.ref, image.body); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// full_only: false
func TestPublicationReservationRefusesReintroductionAndInvalidStamp(t *testing.T) {
	for _, damage := range []string{"terminal_new", "reused_attempt", "wrong_ordinal", "reused_incarnation", "changed_old_marker", "missing_old_marker", "missing_authority"} {
		t.Run(damage, func(t *testing.T) {
			state, rows := publicationReservationFixture(t, true)
			switch damage {
			case "missing_authority":
				state.admission.expires = time.Time{}
			case "missing_old_marker":
				rows = append(rows[:1], rows[2:]...)
			case "changed_old_marker":
				rows[1].Body = bytes.Clone(rows[1].Body)
				rows[1].Body[len(rows[1].Body)-1] ^= 1
			case "reused_incarnation":
				coordinate, err := contract.InspectPublicationCoordinate(rows[0].Body)
				if err != nil {
					t.Fatal(err)
				}
				coordinate.CurrentPublicationIncarnationID = state.adminIndex.PublicationOrder[0].Incarnations[0]
				coordinate.LastAdmissionOrdinal = math.MaxUint64
				rows[0].Body, err = contract.EncodePublicationCoordinate(coordinate)
				if err != nil {
					t.Fatal(err)
				}
			default:
				marker, err := contract.InspectPublicationMarker(rows[2].Body)
				if err != nil {
					t.Fatal(err)
				}
				switch damage {
				case "terminal_new":
					marker.State = contract.PublicationQualifiedNoEffectState
					marker.Evidence.Class = contract.PublicationQualifiedNoEffect
				case "reused_attempt":
					marker.AttemptID = rows[1].RecordID
					rows[2].RecordID = marker.AttemptID
				case "wrong_ordinal":
					marker.AdmissionOrdinal = 2
				}
				rows[2].Body, err = contract.EncodePublicationMarker(marker)
				if err != nil {
					t.Fatal(err)
				}
			}
			next := *state
			next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
			candidate := Candidate{session: state}
			construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
			if constructionErr == nil {
				constructionErr = state.materializePublicationReservationConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
			}
			if err := constructionErr; !errors.Is(err, contract.ErrRecord) {
				t.Fatalf("invalid reservation accepted: %v", err)
			}
			if len(candidate.objects) != 0 {
				t.Fatal("refusal leaked candidate writes")
			}
		})
	}
}

// full_only: false
func TestPublicationFirstCreateInstallsFrozenDeletionInputs(t *testing.T) {
	binding, entry := publicationRelationID(2), publicationRelationID(3)
	state, _ := publicationConfiguredImage(t, binding, entry, binding)
	var frozen contract.PublicationCoordinate
	var marker contract.PublicationMarker
	for i := range state.support {
		kept := state.support[i].Records[:0]
		for _, row := range state.support[i].Records {
			if row.Kind == contract.PublicationMarkerSupportKind {
				var err error
				marker, err = contract.InspectPublicationMarker(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				continue
			}
			if row.Kind == contract.PublicationCoordinateSupportKind {
				var err error
				frozen, err = contract.InspectPublicationCoordinate(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				coordinate := frozen
				coordinate.OwnerState, coordinate.PossibleRemoteObject, coordinate.LateEffectRisk = contract.PublicationOwnerNone, 0, 0
				coordinate.LastAdmissionOrdinal, coordinate.LatestUnresolvedAttemptID = 0, contract.ID{}
				coordinate.DeletionDestinationID, coordinate.DeletionConsumerLocator = "", ""
				coordinate.DeletionTargetContractID, coordinate.DeletionConfigContractID = "", ""
				coordinate.DeletionCredentialRouteContractID, coordinate.DeletionPayloadEncoding, coordinate.DeletionTargetRowDigest = "", 0, contract.ID{}
				row.Body, err = contract.EncodePublicationCoordinate(coordinate)
				if err != nil {
					t.Fatal(err)
				}
			}
			kept = append(kept, row)
		}
		state.support[i].Records = kept
	}
	generatedRefreshSupport(t, state)
	state.publicationProof = nil
	if !state.indexSelectedMaterials() {
		t.Fatal("first-create source material")
	}
	state.admission.composition, state.admission.expires = publicationRelationID(87), time.Now().Add(time.Minute)
	state.admission.store.HeadKey = state.admission.store.Prefix + "/HEAD"
	state.store.(*generatedFixtureSupportStore).descriptor = state.admission.store
	after, err := state.publicationCoordinateForAdmission(frozen.CoordinateID, contract.ID{})
	if err != nil {
		t.Fatal(err)
	}
	marker.AttemptID, marker.OperationID, marker.State = publicationRelationID(112), publicationRelationID(113), contract.PublicationMayHaveEntered
	marker.PublicationIncarnationID, marker.AdmissionOrdinal = after.CurrentPublicationIncarnationID, after.LastAdmissionOrdinal
	after.LatestUnresolvedAttemptID, after.OwnerState, after.PossibleRemoteObject = marker.AttemptID, contract.PublicationOwnerUncertainCreate, 1
	after.DeletionDestinationID, after.DeletionConsumerLocator = frozen.DeletionDestinationID, frozen.DeletionConsumerLocator
	after.DeletionTargetContractID, after.DeletionConfigContractID = frozen.DeletionTargetContractID, frozen.DeletionConfigContractID
	after.DeletionCredentialRouteContractID, after.DeletionPayloadEncoding, after.DeletionTargetRowDigest = frozen.DeletionCredentialRouteContractID, frozen.DeletionPayloadEncoding, frozen.DeletionTargetRowDigest
	rows := publicationRelationRows(t, after, marker)
	next := *state
	next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
	candidate := Candidate{session: state}
	construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
	if constructionErr == nil {
		constructionErr = state.materializePublicationReservationConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
	}
	if err := constructionErr; err != nil {
		t.Fatal("first-create actual materializer", err)
	}
	selected, err := selectedPublicationRelation(next.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	if !selected.coordinates[after.CoordinateID].Equal(after) || selected.markers[marker.AttemptID] != marker {
		t.Fatal("first create lost frozen fields or selected marker")
	}
}

// full_only: false
func TestPublicationReservationCannotReplaceFrozenHistory(t *testing.T) {
	state, rows := publicationReservationFixture(t, false)
	coordinate, err := contract.InspectPublicationCoordinate(rows[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.DeletionConsumerLocator = "changed"
	rows[0].Body, err = contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	next := *state
	next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
	candidate := Candidate{session: state}
	construction, constructionErr := state.preparePublicationConstruction(t.Context(), rows)
	if constructionErr == nil {
		constructionErr = state.materializePublicationReservationConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
	}
	if err := constructionErr; !errors.Is(err, contract.ErrRecord) {
		t.Fatal("reservation replaced selected deletion history", err)
	}
	if len(candidate.objects) != 0 {
		t.Fatal("history rewrite emitted objects")
	}
}

// full_only: false
func TestReservedSlotReservationRequiresSelectedCreateWitness(t *testing.T) {
	for _, field := range []string{"unchanged", "attempt", "binding", "entry", "target"} {
		t.Run(field, func(t *testing.T) {
			state, rows := publicationReservationFixture(t, false)
			last := &rows[len(rows)-1]
			row, err := contract.InspectPublicationMarker(last.Body)
			if err != nil {
				t.Fatal(err)
			}
			other := publicationRelationID(127)
			switch field {
			case "attempt":
				row.Projection.UncertainCreateAttemptID = other
			case "binding":
				row.Projection.BindingIncarnationID = other
			case "entry":
				row.Projection.EntryIncarnationID = other
			case "target":
				row.Projection.TargetRowDigest = other
			}
			row.ProjectionCommitment, err = contract.PublicationProjectionCommitment(row.Projection)
			if err != nil {
				t.Fatal(err)
			}
			last.Body, err = contract.EncodePublicationMarker(row)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := state.planPublicationRewrite(t.Context(), state.adminIndex)
			if err != nil {
				t.Fatal(err)
			}
			err = state.publicationReservationRows(rows, plan)
			if field == "unchanged" && err != nil || field != "unchanged" && !errors.Is(err, contract.ErrRecord) {
				t.Fatal("reservation witness", field, err)
			}
		})
	}
}

// full_only: false
func TestReservedSlotDeleteRechecksRetiredOwner(t *testing.T) {
	state, rows := publicationReservationFixture(t, false)
	original, err := selectedPublicationRelation(state.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := contract.InspectPublicationMarker(rows[2].Body)
	if err != nil {
		t.Fatal(err)
	}
	create := original.markers[proposal.Projection.UncertainCreateAttemptID]
	pin := original.coordinates[create.CoordinateID]
	if !publicationReservedSlotEligible(pin, create) || !publicationDeletionWitnessMatches(pin, pin) {
		t.Fatal("unchanged retired owner lost its cleanup witness")
	}
	// This boundary has no private owner, signing or provider implementation.
	target := publicationDeletionTarget(pin)
	premise := proposal.Projection.ExclusiveNamespaceDigest
	state.admission.publicationNamespaces = []publicationNamespace{{domain: pin.DomainID, service: pin.ServiceContractID, physical: pin.CanonicalTarget, premise: premise}}
	plan := publicationPlan{input: publicationInput{deadline: time.Now().Add(5 * time.Second)}}
	pinned := publicationTargetPlan{coordinate: pin.CoordinateID, retained: pin, target: target, exclusive: premise, blockers: []contract.ID{create.AttemptID}, uncertain: &create}
	checked := false
	stop := publicationPrivate{Check: func(_ context.Context, input publicationActionCheckInput) (publicationActionCheckFacts, error) {
		checked = input.UncertainCreate != nil && *input.UncertainCreate == create && input.Birth == nil
		return publicationActionCheckFacts{}, contract.ErrRecord
	}}
	candidate, prepared, result := plan.preparePublicationReservation(t.Context(), state, pinned, contract.PublicationDeleteReservedSlot, stop)
	if !checked || candidate != nil || prepared != nil || result.Reason != InvalidIntent {
		t.Fatal("unchanged witness did not reach private admission", result)
	}
	birth := create
	birth.AttemptID, birth.OperationID = publicationRelationID(128), publicationRelationID(129)
	birth.AdmissionOrdinal++
	birth.State, birth.Evidence.Class = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged
	birth.Evidence.NormalizedStatus, birth.Evidence.SafeResourceID, birth.Evidence.ConsumerLocator = 201, "current-resource", pin.DeletionConsumerLocator
	current := pin
	current.OwnerState, current.OwnedBirthAttemptID, current.LastAdmissionOrdinal = contract.PublicationOwnerQualified, birth.AttemptID, birth.AdmissionOrdinal
	current.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(current.DomainID, current.CoordinateID, current.LastBindingIncarnationID, current.LastEntryIncarnationID, current.DeletionTargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
	if err != nil {
		t.Fatal(err)
	}
	selectedRows := publicationRelationRows(t, current, birth)
	selectedRows = append(selectedRows, rows[1])
	publicationBoundsInstallRows(t, state, selectedRows)
	selected, err := selectedPublicationRelation(state.selectedImage())
	if err != nil || selected.markers[create.AttemptID] != create || !publicationQualifiedBirthValid(state.root.Domain, selected.coordinates[current.CoordinateID], selected.markers[birth.AttemptID]) {
		t.Fatal("selected owner and retained uncertainty", err)
	}
	if publicationReservedSlotEligible(current, create) || publicationDeletionWitnessMatches(current, pin) {
		t.Fatal("earlier uncertainty authorized cleanup for a qualified owner")
	}

	before := publicationBoundsCaptureRefusalFacts(t, state)
	head := state.head.Core
	check := publicationPrivate{Check: func(context.Context, publicationActionCheckInput) (publicationActionCheckFacts, error) {
		t.Fatal("stale owner reached private admission")
		return publicationActionCheckFacts{}, contract.ErrRecord
	}}
	candidate, prepared, result = plan.preparePublicationReservation(t.Context(), state, pinned, contract.PublicationDeleteReservedSlot, check)
	if candidate != nil || prepared != nil || result.Reason != DifferentSelection {
		t.Fatal("fresh reservation did not refuse the stale owner", result)
	}
	proposal.AdmissionOrdinal = current.LastAdmissionOrdinal + 1
	next := current
	next.LastAdmissionOrdinal, next.LatestUnresolvedAttemptID = proposal.AdmissionOrdinal, proposal.AttemptID
	projected := publicationRelationRows(t, next, proposal)
	projected = append(projected, selectedRows[1:]...)
	rewrite, err := state.planPublicationRewrite(t.Context(), state.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.publicationReservationRows(projected, rewrite); !errors.Is(err, contract.ErrRecord) {
		t.Fatal("row admission accepted obsolete cleanup", err)
	}
	if !reflect.DeepEqual(before, publicationBoundsCaptureRefusalFacts(t, state)) || !reflect.DeepEqual(head, state.head.Core) {
		t.Fatal("refusal changed the selected HEAD or support records")
	}
}

// full_only: false
func TestOwnedDeleteReservationKeepsPlannedBirth(t *testing.T) {
	state, _ := publicationReservationFixture(t, false)
	domain, coordinate, original, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
	coordinate.OwnerState, coordinate.LatestUnresolvedAttemptID = contract.PublicationOwnerQualified, contract.ID{}
	original.State, original.Evidence.Class, original.Evidence.NormalizedStatus = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged, 201
	original.Evidence.SafeResourceID, original.Evidence.ConsumerLocator = "first-instance", coordinate.DeletionConsumerLocator
	current := original
	current.AttemptID, current.OperationID, current.AdmissionOrdinal = publicationRelationID(130), publicationRelationID(131), original.AdmissionOrdinal+1
	current.Evidence.SafeResourceID = "second-instance"

	selectedOwner := func(marker contract.PublicationMarker) contract.PublicationCoordinate {
		t.Helper()
		c := coordinate
		c.LastAdmissionOrdinal, c.OwnedBirthAttemptID = marker.AdmissionOrdinal, marker.AttemptID
		var err error
		c.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(domain, c.CoordinateID, c.LastBindingIncarnationID, c.LastEntryIncarnationID, c.DeletionTargetRowDigest, marker.AttemptID, marker.Evidence.SafeResourceID)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	old, fresh := selectedOwner(original), selectedOwner(current)
	oldRows := publicationRelationRows(t, old, original)
	selectedRows := append(publicationRelationRows(t, fresh, current), oldRows[1])
	publicationBoundsInstallRows(t, state, selectedRows)
	selected, err := selectedPublicationRelation(state.selectedImage())
	if err != nil || !publicationQualifiedBirthValid(domain, fresh, selected.markers[current.AttemptID]) || selected.markers[original.AttemptID] != original {
		t.Fatal("selected and historical births", err)
	}

	plan := publicationPlan{input: publicationInput{deadline: time.Now().Add(5 * time.Second)}}
	before := publicationBoundsCaptureRefusalFacts(t, state)
	head := state.head.Core
	deletion := current
	deletion.AttemptID, deletion.OperationID, deletion.AdmissionOrdinal = publicationRelationID(132), publicationRelationID(133), fresh.LastAdmissionOrdinal+1
	deletion.Projection.Action, deletion.Projection.PolicyDigest = contract.PublicationDeleteOwned, contract.ID{}
	deletion.BirthServiceContractID, deletion.BirthTargetContractID = "", ""
	deletion.State = contract.PublicationMayHaveEntered
	deletion.Evidence = contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationUnproved, ResponseContractDigest: publicationRelationID(125)}
	next := fresh
	next.LastAdmissionOrdinal, next.LatestUnresolvedAttemptID = deletion.AdmissionOrdinal, deletion.AttemptID
	rewrite, err := state.planPublicationRewrite(t.Context(), state.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	for _, planned := range []contract.PublicationMarker{current, original} {
		pinned := publicationTargetPlan{coordinate: fresh.CoordinateID, retained: selectedOwner(planned), birth: &planned}
		calls := 0
		private := publicationPrivate{Check: func(_ context.Context, in publicationActionCheckInput) (publicationActionCheckFacts, error) {
			calls++
			if in.Birth == nil || *in.Birth != planned {
				t.Fatal("private admission received a different birth")
			}
			return publicationActionCheckFacts{}, contract.ErrRecord
		}}
		candidate, prepared, result := plan.preparePublicationReservation(t.Context(), state, pinned, contract.PublicationDeleteOwned, private)
		if candidate != nil || prepared != nil || planned == current && (calls != 1 || result.Reason != InvalidIntent) || planned == original && (calls != 0 || result.Reason != DifferentSelection) {
			t.Fatal("owned delete admission", planned.Evidence.SafeResourceID, calls, result)
		}
		deletion.Projection.OwnedBirthAttemptID = planned.AttemptID
		deletion.ProjectionCommitment, err = contract.PublicationProjectionCommitment(deletion.Projection)
		if err != nil {
			t.Fatal(err)
		}
		proposal := append(publicationRelationRows(t, next, deletion), selectedRows[1:]...)
		err = state.publicationReservationRows(proposal, rewrite)
		if planned == current && err != nil || planned == original && !errors.Is(err, contract.ErrRecord) {
			t.Errorf("owned reservation for %s: %v", planned.Evidence.SafeResourceID, err)
		}
	}
	if !reflect.DeepEqual(before, publicationBoundsCaptureRefusalFacts(t, state)) || !reflect.DeepEqual(head, state.head.Core) {
		t.Fatal("read-only admission changed HEAD or selected ownership")
	}
}
