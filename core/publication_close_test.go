package core

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationUnknownResultRetainsExactDispatch(t *testing.T) {
	_, _, marker, _ := publicationRelationFixture(t)
	dispatch := contract.PublicationDispatch{Schema: 5, DomainID: marker.DomainID,
		OperationID: marker.OperationID, AttemptID: marker.AttemptID, CoordinateID: marker.CoordinateID,
		Projection: marker.Projection, ProjectionCommitment: marker.ProjectionCommitment,
		AuthoritySubjectDigest: marker.AuthoritySubjectDigest, ExecutorID: marker.ExecutorID,
		CredentialRouteID: marker.CredentialRouteID, ResponseContractDigest: marker.Evidence.ResponseContractDigest}
	digest, err := contract.PublicationDispatchContextDigest(dispatch)
	if err != nil {
		t.Fatal(err)
	}
	original := publicationOriginalResultOwner{dispatch: dispatch,
		reserve: contract.OutputReserveSubject{DispatchContextDigest: digest}}
	result := publicationUnknownResult(original)
	if err := contract.ValidatePublicationResult(dispatch, result); err != nil {
		t.Fatal("unknown result cannot close its exact dispatch", err)
	}
	want := contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry,
		Class: contract.PublicationUnproved, ResponseContractDigest: dispatch.ResponseContractDigest}
	if result.Schema != 2 || result.Evidence != want {
		t.Fatal("unknown result acquired acknowledgement facts or changed schema")
	}
	dispatch.AttemptID[0] ^= 1
	if contract.ValidatePublicationResult(dispatch, result) == nil {
		t.Fatal("unknown result closed another attempt")
	}
}
