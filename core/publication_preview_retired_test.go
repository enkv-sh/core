package core

import (
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPublicationPreviewRetiredNeverSentCoordinateNeedsNoDeletionFacts(t *testing.T) {
	for _, warning := range []bool{false, true} {
		name := "never-sent"
		if warning {
			name = "domain-warning"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			state := generatedEmptyPredecessor(t)
			id, err := contract.PublicationCoordinateID(state.root.Domain, "provider", "never-sent-slot")
			if err != nil {
				t.Fatal(err)
			}
			coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: state.root.Domain, CoordinateID: id,
				ServiceContractID: "provider", CanonicalTarget: "never-sent-slot", BindingState: contract.PublicationBindingRetired,
				LastBindingIncarnationID: publicationRelationID(80), LastEntryIncarnationID: publicationRelationID(81), CurrentPublicationIncarnationID: publicationRelationID(82)}
			body, err := contract.EncodePublicationCoordinate(coordinate)
			if err != nil {
				t.Fatal("valid never-sent coordinate refused", err)
			}
			page := format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(83), Index: generatedFixtureFreeSupportIndex(t, state),
				Records: []contract.SupportRecordView{{Kind: contract.PublicationCoordinateSupportKind, RecordID: id, Body: body}}}
			state.support = append(state.support, page)
			state.adminIndex.PublicationOrder = []format.PublicationCoordinateOrder{{CoordinateID: id, Incarnations: []contract.ID{coordinate.CurrentPublicationIncarnationID}}}
			if warning {
				state.root.WarningBits = WarningDiscardedExactEvidence
			}
			generatedRefreshSupport(t, state)
			selected := publicSelection{complete: true, image: *state.selectedImage(), authorityID: state.root.CurrentAccess.Core.AuthorityRecipientID,
				basis: publicReadBasis{reader: selectedObjectReader{domain: state.root.Domain, descriptor: state.admission.store, source: state.store}}}
			facts, failed := readPublicationPreviewFacts(ctx, &selected)
			if failed.Outcome != 0 || len(facts.coordinates) != 1 || !facts.coordinates[id].Equal(coordinate) || len(facts.markers) != 0 {
				t.Fatal("authenticated never-sent premise unavailable", failed)
			}
			reader := ReaderEngine{}
			empty := PublicConfigurationValidation{Valid: true, Complete: true}
			preview, _, failed := reader.projectPublicationPreview(ctx, &selected, empty, empty)
			if failed.Outcome != 0 || !preview.Complete || preview.ReasonCode != 0 || len(preview.Entries) != 1 || preview.DomainWideWarning != warning {
				t.Fatal("never-sent retirement requires nonexistent deletion facts", preview, failed)
			}
			row := preview.Entries[0]
			basis := "acknowledged-equal"
			if warning {
				basis = "warning"
			}
			if row.Origin != "observed" || row.CoordinateID != id || row.BindingID != coordinate.LastBindingIncarnationID || row.ServiceContractID != "provider" || row.PhysicalTarget != "never-sent-slot" || row.TargetContractID != "" || row.DestinationID != nil || row.EntryName != nil || row.Basis != basis || row.ReasonCode != 0 || row.Conditional || len(row.Actions) != 0 || len(row.BlockerIDs) != 0 || row.RemoteValueMayRemain || row.LateWriteRisk {
				t.Fatal("preview invented deletion work or target evidence", row)
			}
		})
	}
}

// full_only: false
func TestPublicationPreviewRetiredDeleteRequiresCurrentBirthAndOrder(t *testing.T) {
	for _, rollover := range []bool{false, true} {
		for _, condition := range []string{"exact-delete", "later-birth", "other-birth", "other-binding", "other-entry", "other-target", "compacted-delete", "later-birth-compacted-delete"} {
			name := condition + "/same-incarnation"
			if rollover {
				name = condition + "/rollover"
			}
			t.Run(name, func(t *testing.T) {
				s := generatedEmptyPredecessor(t)
				_, coordinate, original, _ := publicationRelationFixtureForDomain(t, s.root.Domain)
				coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
				coordinate.OwnerState, coordinate.LatestUnresolvedAttemptID = contract.PublicationOwnerQualified, contract.ID{}
				original.State, original.Evidence.Class, original.Evidence.NormalizedStatus, original.Evidence.SafeResourceID = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged, 201, "original-instance"
				original.Evidence.ConsumerLocator = "locator"
				var err error
				current := original
				deletion := original
				deletion.AttemptID, deletion.AdmissionOrdinal = publicationRelationID(70), 3
				deletion.Projection.Action, deletion.Projection.OwnedBirthAttemptID = contract.PublicationDeleteOwned, original.AttemptID
				deletion.Projection.PolicyDigest = contract.ID{}
				deletion.BirthServiceContractID, deletion.BirthTargetContractID = "", ""
				deletion.Evidence.ConsumerLocator = ""
				order := []contract.ID{original.PublicationIncarnationID}
				if rollover {
					deletion.PublicationIncarnationID, deletion.AdmissionOrdinal = publicationRelationID(71), 1
					order = append(order, deletion.PublicationIncarnationID)
				}
				laterBirth := condition == "later-birth" || condition == "later-birth-compacted-delete"
				if laterBirth || condition == "other-birth" || condition == "other-binding" || condition == "other-entry" {
					current.AttemptID, current.Evidence.SafeResourceID = publicationRelationID(72), "current-instance"
					current.Evidence.ConsumerLocator = "locator"
					current.AdmissionOrdinal = 2
					if laterBirth {
						current.PublicationIncarnationID, current.AdmissionOrdinal = deletion.PublicationIncarnationID, deletion.AdmissionOrdinal+1
					}
				}
				if condition == "other-binding" {
					original.Projection.BindingIncarnationID, deletion.Projection.BindingIncarnationID = publicationRelationID(75), publicationRelationID(75)
				}
				if condition == "other-entry" {
					original.Projection.EntryIncarnationID, deletion.Projection.EntryIncarnationID = publicationRelationID(76), publicationRelationID(76)
				}
				if condition == "other-target" {
					deletion.Projection.TargetRowDigest = publicationRelationID(73)
				}
				original.ProjectionCommitment, err = contract.PublicationProjectionCommitment(original.Projection)
				if err != nil {
					t.Fatal(err)
				}
				coordinate.OwnedBirthAttemptID = current.AttemptID
				coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(s.root.Domain, coordinate.CoordinateID, current.Projection.BindingIncarnationID, current.Projection.EntryIncarnationID, current.Projection.TargetRowDigest, current.AttemptID, current.Evidence.SafeResourceID)
				if err != nil {
					t.Fatal(err)
				}
				coordinate.CurrentPublicationIncarnationID, coordinate.LastAdmissionOrdinal = deletion.PublicationIncarnationID, deletion.AdmissionOrdinal
				if laterBirth {
					coordinate.LastAdmissionOrdinal = current.AdmissionOrdinal
				}
				coordinate.LastDeleteAckAttemptID, coordinate.LastDeleteAckIncarnationID, coordinate.LastDeleteAckOrdinal = deletion.AttemptID, deletion.PublicationIncarnationID, deletion.AdmissionOrdinal
				rows := publicationRelationRows(t, coordinate, original)
				markers := []contract.PublicationMarker{deletion}
				if current.AttemptID != original.AttemptID {
					markers = append(markers, current)
				}
				for _, marker := range markers {
					if (condition == "compacted-delete" || condition == "later-birth-compacted-delete") && marker.AttemptID == deletion.AttemptID {
						continue
					}
					marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
					if err != nil {
						t.Fatal(err)
					}
					body, err := contract.EncodePublicationMarker(marker)
					if err != nil {
						t.Fatal(err)
					}
					rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body})
				}
				page := format.RequiredSupportPageView{Domain: s.root.Domain, Object: publicationRelationID(74), Index: 1}
				for _, row := range rows {
					page.Records = append(page.Records, contract.SupportRecordView(row))
				}
				s.support = append(s.support, page)
				s.adminIndex.PublicationOrder = []format.PublicationCoordinateOrder{{CoordinateID: coordinate.CoordinateID, Incarnations: order}}
				generatedRefreshSupport(t, s)
				selected := publicSelection{complete: true, image: *s.selectedImage(), basis: publicReadBasis{reader: selectedObjectReader{domain: s.root.Domain, descriptor: s.admission.store, source: s.store}}}
				facts, failed := readPublicationPreviewFacts(t.Context(), &selected)
				if failed.Outcome != 0 || !facts.coordinates[coordinate.CoordinateID].Equal(coordinate) {
					t.Fatal("fixture failed before retired preview gate", failed)
				}
				reader := ReaderEngine{}
				declaration := PublicConfigurationValidation{Valid: true, Complete: true}
				preview, _, failed := reader.projectPublicationPreview(t.Context(), &selected, declaration, declaration)
				if condition == "compacted-delete" || condition == "other-target" {
					if failed.Reason != InvalidRelation || preview.Complete || preview.ReasonCode != uint8(InvalidRelation) {
						t.Fatal("unrelated or unavailable delete became current no-action proof", preview, failed)
					}
					return
				}
				if failed.Outcome != 0 || !preview.Complete || preview.ReasonCode != 0 || len(preview.Entries) != 1 {
					t.Fatal("valid ordered retired preview incomplete", preview, failed)
				}
				row := preview.Entries[0]
				wantBasis, wantActions := "warning", []uint8(nil)
				if condition != "exact-delete" {
					wantBasis, wantActions = "retained-deletion", []uint8{contract.PublicationDeleteOwned}
				}
				if row.Origin != "observed" || row.CoordinateID != coordinate.CoordinateID || row.BindingID != coordinate.LastBindingIncarnationID || row.Basis != wantBasis || !reflect.DeepEqual(row.Actions, wantActions) || row.Conditional || !row.RemoteValueMayRemain || row.LateWriteRisk || len(row.BlockerIDs) != 0 {
					t.Fatal("retired preview inherited another birth's delete or lost retained facts", row)
				}
			})
		}
	}
}
