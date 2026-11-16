package core

import (
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// A provably later birth needs only the selected incarnation sequence. A birth
// at or before a compacted delete needs the missing marker's exact relation.
func publicationHistorySession(t *testing.T, mode string, rollover bool) (*fixture, publicationInput, *publicationControlledPrivate) {
	t.Helper()
	f, input, p := publicationEngineFixture(t)
	first := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	if first.summary != contract.PublicationSummaryComplete {
		t.Fatal("initial ACK", first.state)
	}
	publicationEngineReopen(t, f)
	if mode != "no_delete" {
		publicationHistoryDelete(t, f, mode, rollover)
	}
	return f, input, p
}

func publicationHistoryDelete(t *testing.T, f *fixture, mode string, rollover bool) {
	t.Helper()
	selected, err := selectedPublicationRelation(f.session.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	var coordinate contract.PublicationCoordinate
	for _, row := range selected.coordinates {
		coordinate = row
	}
	birth := selected.markers[coordinate.OwnedBirthAttemptID]
	if rollover {
		birth.AdmissionOrdinal = 17
		coordinate.LastValueAckOrdinal = 17
		coordinate.LastPolicyAckOrdinal = 17
	}
	historicalBirth := birth
	deletionIncarnation := birth.PublicationIncarnationID
	deletionOrdinal := birth.AdmissionOrdinal + 1
	if rollover {
		deletionIncarnation = contract.Hash([]byte("later publication incarnation"))
		deletionOrdinal = 1
		for i := range f.session.adminIndex.PublicationOrder {
			order := &f.session.adminIndex.PublicationOrder[i]
			if order.CoordinateID == coordinate.CoordinateID {
				order.Incarnations = append(slices.Clone(order.Incarnations), deletionIncarnation)
			}
		}
	}
	coordinate.CurrentPublicationIncarnationID, coordinate.LastAdmissionOrdinal = deletionIncarnation, deletionOrdinal
	coordinate.LastDeleteAckAttemptID = contract.Hash([]byte("compacted delete ACK"))
	coordinate.LastDeleteAckIncarnationID, coordinate.LastDeleteAckOrdinal = deletionIncarnation, deletionOrdinal
	if mode == "new_birth" || mode == "new_birth_old_policy" {
		oldBirth := birth.AttemptID
		birth.AttemptID = contract.Hash([]byte("new qualified birth"))
		birth.Evidence.SafeResourceID = "new-created-instance"
		birth.PublicationIncarnationID, birth.AdmissionOrdinal = deletionIncarnation, deletionOrdinal+1
		coordinate.LastAdmissionOrdinal = birth.AdmissionOrdinal
		coordinate.OwnedBirthAttemptID = birth.AttemptID
		var err error
		coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(f.session.root.Domain, coordinate.CoordinateID, birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
		if err != nil {
			t.Fatal(err)
		}
		coordinate.LastValueDigest, err = contract.PublicationSelectedValueDigest(f.session.root.Domain, birth.Projection.ValueBasisDigest, birth.AttemptID, coordinate.OwnedInstanceDigest)
		if err != nil {
			t.Fatal(err)
		}
		coordinate.LastValueAckAttemptID, coordinate.LastValueAckIncarnationID, coordinate.LastValueAckOrdinal = birth.AttemptID, birth.PublicationIncarnationID, birth.AdmissionOrdinal
		if coordinate.LastPolicyAckAttemptID == oldBirth && mode != "new_birth_old_policy" {
			coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = birth.AttemptID, birth.PublicationIncarnationID, birth.AdmissionOrdinal
		}
	}
	for i := range f.session.support {
		for j, row := range f.session.support[i].Records {
			var err error
			switch {
			case row.Kind == contract.PublicationCoordinateSupportKind && row.RecordID == coordinate.CoordinateID:
				row.Body, err = contract.EncodePublicationCoordinate(coordinate)
			case row.Kind == contract.PublicationMarkerSupportKind && row.RecordID == historicalBirth.AttemptID:
				row.Body, err = contract.EncodePublicationMarker(historicalBirth)
			}
			if err != nil {
				t.Fatal(err)
			}
			f.session.support[i].Records[j] = row
		}
	}
	if mode == "new_birth" || mode == "new_birth_old_policy" {
		body, err := contract.EncodePublicationMarker(birth)
		if err != nil {
			t.Fatal(err)
		}
		f.session.support[0].Records = append(f.session.support[0].Records, contract.SupportRecordView{Kind: contract.PublicationMarkerSupportKind, RecordID: birth.AttemptID, Body: body})
	}
	generatedRefreshSupport(t, f.session)
	generatedVerifySelectedFixtureSlices(t, f.session)
	proof, result, err := validateSelectedPublicationConfiguration(t.Context(), f.session.selectedImage(), nil)
	if err != nil || result.Outcome != 0 || proof == nil {
		t.Fatal("ordered historical fixture", result, err)
	}
	f.session.publicationProof = proof
}

// full_only: false
func TestPublicationPlanningOrdersDeleteACKBeforeEquality(t *testing.T) {
	for _, rollover := range []bool{false, true} {
		for _, mode := range []string{"no_delete", "later_delete", "new_birth", "new_birth_old_policy"} {
			if rollover && mode == "no_delete" {
				continue
			}
			name := mode + "/same_incarnation"
			if rollover {
				name = mode + "/rollover"
			}
			t.Run(name, func(t *testing.T) {
				f, input, p := publicationHistorySession(t, mode, rollover)
				before, err := selectedPublicationRelation(f.session.selectedImage())
				if err != nil {
					t.Fatal(err)
				}
				checks, owners := p.checks, len(p.owners)
				plan, result := f.session.planPublication(t.Context(), input, p.callbacks())
				if mode == "later_delete" {
					if plan != nil || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable {
						t.Fatal("missing required deletion evidence did not remain unavailable", result)
					}
				} else if mode == "new_birth_old_policy" {
					if plan == nil || len(plan.targets) != 1 || !slices.Equal(plan.targets[0].actions, []uint8{contract.PublicationUpdatePolicy}) {
						t.Fatal("new birth inherited a policy ACK before delete", result)
					}
					checks++
				} else if plan == nil || len(plan.vector.Entries) != 1 || plan.vector.Entries[0].Actions[0].Disposition != contract.PublicationNoOp {
					t.Fatal("current birth lost no-op", result)
				}
				after, err := selectedPublicationRelation(f.session.selectedImage())
				if err != nil || !reflect.DeepEqual(before, after) || p.checks != checks || len(p.owners) != owners {
					t.Fatal("planning changed historical evidence or prepared private work", err)
				}
			})
		}
	}
}

// full_only: false
func TestPublicationOwnedAdmissionOrdersDeleteACKBeforeBirth(t *testing.T) {
	for _, rollover := range []bool{false, true} {
		for _, mode := range []string{"no_delete", "later_delete", "new_birth"} {
			if rollover && mode == "no_delete" {
				continue
			}
			name := mode + "/same_incarnation"
			if rollover {
				name = mode + "/rollover"
			}
			t.Run(name, func(t *testing.T) {
				// Capture the action before the refreshed predecessor obtains a delete ACK.
				f, input, p := publicationHistorySession(t, "no_delete", false)
				valueCandidate := prepare(t, f, changed(t, f.session, 0))
				if result := f.session.Select(t.Context(), valueCandidate); result.Outcome != ObservedCurrent {
					t.Fatal("changed value selection", result)
				}
				publicationEngineReopen(t, f)
				plan := publicationEnginePlan(t, f, input, p)
				if len(plan.targets) != 1 || !slices.Equal(plan.targets[0].actions, []uint8{contract.PublicationWriteValue}) ||
					len(plan.targets[0].attempts) != 1 || plan.targets[0].attempts[0].IsZero() {
					t.Fatal("changed value lacks one fresh planned write")
				}
				target := plan.targets[0]
				if mode != "no_delete" {
					publicationHistoryDelete(t, f, mode, rollover)
				}
				checks, owners := p.checks, len(p.owners)
				candidate, preparation, result := plan.reserveCandidate(t.Context(), f.session, target, contract.PublicationWriteValue, p.callbacks())
				if mode == "later_delete" {
					if candidate != nil || preparation != nil || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable || p.checks != checks || len(p.owners) != owners {
						t.Fatal("missing required deletion evidence reached private work or lost its unavailable result", result)
					}
					return
				}
				if candidate == nil || preparation == nil {
					t.Fatal("current birth admission refused", result)
				}
				if err := preparation.retire(t.Context()); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
