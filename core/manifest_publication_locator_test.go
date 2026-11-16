package core

import (
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestManifestAssignedLocatorRequiresCurrentBirthBinding(t *testing.T) {
	for _, stale := range []bool{false, true} {
		name := "current-binding"
		if stale {
			name = "removed-and-readded-binding"
		}
		t.Run(name, func(t *testing.T) {
			state := generatedEmptyPredecessor(t)
			_, coordinate, birth, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
			coordinate.OwnerState, coordinate.LatestUnresolvedAttemptID = contract.PublicationOwnerQualified, contract.ID{}
			coordinate.OwnedBirthAttemptID, coordinate.LocatorRequiresCreation = birth.AttemptID, true
			birth.State = contract.PublicationAcknowledged
			birth.Evidence.Class, birth.Evidence.NormalizedStatus = contract.PublicationRequestAcknowledged, 201
			birth.Evidence.SafeResourceID, birth.Evidence.ConsumerLocator = "created-instance", "service/created-instance"
			coordinate.DeletionConsumerLocator = "service/created-instance"
			var err error
			coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(state.root.Domain, coordinate.CoordinateID, coordinate.LastBindingIncarnationID, coordinate.LastEntryIncarnationID, coordinate.DeletionTargetRowDigest, birth.AttemptID, "created-instance")
			if err != nil {
				t.Fatal(err)
			}
			if stale {
				coordinate.ActiveBindingIncarnationID = publicationRelationID(94)
			}
			rows := publicationRelationRows(t, coordinate, birth)
			page := format.RequiredSupportPageView{Domain: state.root.Domain, Object: publicationRelationID(95), Index: generatedFixtureFreeSupportIndex(t, state)}
			for _, row := range rows {
				page.Records = append(page.Records, contract.SupportRecordView(row))
			}
			state.support = append(state.support, page)
			generatedRefreshSupport(t, state)
			image := state.selectedImage()
			proofRows, err := publicationSelectedRowProofs(image)
			if err != nil {
				t.Fatal("authenticated fixture row locations", err)
			}
			digest, err := publicationRootDigest(image.root)
			if err != nil {
				t.Fatal(err)
			}
			image.publicationProof = &selectedPublicationProof{rootDigest: digest, indexRef: image.root.AdministrativeIndex, rows: proofRows}
			selected := publicSelection{complete: true, image: *image, basis: publicReadBasis{reader: selectedObjectReader{domain: state.root.Domain, descriptor: state.admission.store, source: state.store}}}
			requests := []manifestLocatorRequest{
				{target: contract.OutputTarget{ConsumerLocator: "static/first"}},
				{binding: coordinate.ActiveBindingIncarnationID, destination: "destination", target: contract.OutputTarget{EntryIncarnationID: coordinate.LastEntryIncarnationID, ServiceContractID: "provider", TargetContractID: "profile", CanonicalTarget: "account/slot", LocatorRequiresCreation: true}},
			}
			locators, failed := manifestConsumerLocators(t.Context(), selected, requests)
			if stale {
				if failed.Outcome != AdmissionRefused || failed.Reason != InvalidIntent || failed.diagnostic != contract.ReasonLocatorUnusable || locators != nil {
					t.Fatal("old binding locator did not refuse complete selection", locators, failed)
				}
				return
			}
			if failed.Outcome != 0 || !reflect.DeepEqual(locators, []string{"static/first", "service/created-instance"}) {
				t.Fatal("current binding lost its exact locators", locators, failed)
			}
		})
	}
}
