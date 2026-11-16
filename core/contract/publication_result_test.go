package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func publicationDispatchFixture(t *testing.T) PublicationDispatch {
	t.Helper()
	_, marker := publicationRecordFixture(t)
	return PublicationDispatch{Schema: 5, DomainID: marker.DomainID, OperationID: marker.OperationID,
		AttemptID: marker.AttemptID, CoordinateID: marker.CoordinateID, Projection: marker.Projection,
		ProjectionCommitment:   marker.ProjectionCommitment,
		AuthoritySubjectDigest: marker.AuthoritySubjectDigest,
		ExecutorID:             marker.ExecutorID, CredentialRouteID: marker.CredentialRouteID,
		ResponseContractDigest: marker.Evidence.ResponseContractDigest}
}

// full_only: false
func TestPublicationResultV2RequiresClosedDispatch(t *testing.T) {
	dispatch := publicationDispatchFixture(t)
	body, err := EncodePublicationDispatch(dispatch)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := InspectPublicationDispatch(body); err != nil || got != dispatch {
		t.Fatalf("dispatch=%#v err=%v", got, err)
	}
	// The complete canonical dispatch, rather than an action or payload label, is hashed.
	input := append([]byte("ENKV/PUBLICATION/DISPATCH/v4\x00"), body...)
	want := sha256.Sum256(input)
	if got, err := PublicationDispatchContextDigest(dispatch); err != nil || got != want {
		t.Fatalf("context digest=%x want=%x err=%v", got, want, err)
	}
	if _, err := InspectPublicationDispatch(body[:len(body)-1]); err == nil {
		t.Fatal("truncated dispatch accepted")
	}
	dispatch.Schema = 2
	if _, err := EncodePublicationDispatch(dispatch); err == nil {
		t.Fatal("superseded dispatch accepted")
	}
}

// full_only: false
func TestPublicationResultV2ExactContext(t *testing.T) {
	dispatch := publicationDispatchFixture(t)
	contextDigest, err := PublicationDispatchContextDigest(dispatch)
	if err != nil {
		t.Fatal(err)
	}
	result := PublicationResult{Schema: 2, DomainID: dispatch.DomainID, OperationID: dispatch.OperationID,
		AttemptID: dispatch.AttemptID, CoordinateID: dispatch.CoordinateID, ProjectionCommitment: dispatch.ProjectionCommitment,
		DispatchContextDigest: contextDigest, Evidence: PublicationEvidence{Schema: 3,
			Entry: PublicationMayHaveEnteredEntry, Class: PublicationRequestAcknowledged,
			ResponseContractDigest: dispatch.ResponseContractDigest, NormalizedStatus: 201, SafeResourceID: "created-resource", ConsumerLocator: "locator"}}
	body, err := EncodePublicationResult(result)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := InspectPublicationResult(body); err != nil || got != result {
		t.Fatalf("result=%#v err=%v", got, err)
	}
	if err := ValidatePublicationResult(dispatch, result); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*PublicationResult){
		func(v *PublicationResult) { v.AttemptID = publicationTestID(99) },
		func(v *PublicationResult) { v.DispatchContextDigest = publicationTestID(99) },
		func(v *PublicationResult) { v.Evidence.ResponseContractDigest = publicationTestID(99) },
	} {
		bad := result
		mutate(&bad)
		if err := ValidatePublicationResult(dispatch, bad); err == nil {
			t.Fatal("mismatched result accepted")
		}
	}
}

// full_only: false
func TestPublicationOutcomeV2OrderedActionsAndNoAction(t *testing.T) {
	dispatch := publicationDispatchFixture(t)
	evidence := PublicationEvidence{Schema: 3, Entry: PublicationMayHaveEnteredEntry,
		Class: PublicationRequestAcknowledged, ResponseContractDigest: dispatch.ResponseContractDigest, NormalizedStatus: 201, SafeResourceID: "created-resource", ConsumerLocator: "locator"}
	vector := PublicationOutcomeVector{Schema: 2, DomainID: dispatch.DomainID, OperationID: dispatch.OperationID,
		SnapshotID: publicationTestID(12), SelectionDigest: publicationTestID(13), Entries: []PublicationTargetOutcome{
			{CoordinateID: publicationTestID(20), Actions: []PublicationOutcome{{Disposition: PublicationNoOp}}},
			{CoordinateID: publicationTestID(30), Actions: []PublicationOutcome{
				{Action: PublicationCreateEmpty, ProjectionCommitment: publicationTestID(21), AttemptID: publicationTestID(22),
					Disposition: PublicationOutcomeAcknowledged, Evidence: evidence},
				{Action: PublicationUpdatePolicy, ProjectionCommitment: publicationTestID(23),
					Disposition: PublicationNotSent, CoreReason: 1},
			}},
		}}
	body, err := EncodePublicationOutcomeVector(vector)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := InspectPublicationOutcomeVector(body); err != nil || len(got.Entries) != 2 ||
		len(got.Entries[1].Actions) != 2 || got.Entries[1].Actions[0].Action != PublicationCreateEmpty {
		t.Fatalf("decoded vector=%#v err=%v", got, err)
	}
	if got := SummarizePublication(vector.Entries); got != PublicationSummaryMixedTerminal {
		t.Fatalf("summary=%d", got)
	}
	vector.Entries[1].Actions[1].Disposition = PublicationOutcomeUnknown
	vector.Entries[1].Actions[1].AttemptID = publicationTestID(24)
	vector.Entries[1].Actions[1].CoreReason = 0
	vector.Entries[1].Actions[1].Evidence = PublicationEvidence{Schema: 3, Entry: PublicationMayHaveEnteredEntry,
		Class: PublicationUnproved, ResponseContractDigest: dispatch.ResponseContractDigest}
	if got := SummarizePublication(vector.Entries); got != PublicationSummaryUnknown {
		t.Fatalf("unknown summary=%d", got)
	}
	if _, err := EncodePublicationOutcomeVector(vector); err != nil {
		t.Fatal(err)
	}
	vector.Entries[1].Actions[1].Action = PublicationCreateEmpty
	if _, err := EncodePublicationOutcomeVector(vector); err == nil {
		t.Fatal("duplicate action accepted")
	}
	vector.Entries[1].Actions[1].Action = PublicationUpdatePolicy
	vector.Entries[0].Actions = append(vector.Entries[0].Actions, PublicationOutcome{Disposition: PublicationNoOp})
	if _, err := EncodePublicationOutcomeVector(vector); err == nil {
		t.Fatal("no-action mixed with action accepted")
	}
}

// full_only: false
func TestPublicationOutcomeV2DistinctActionAttempts(t *testing.T) {
	for _, differentTarget := range []bool{false, true} {
		name := "same_target"
		if differentTarget {
			name = "different_targets"
		}
		t.Run(name, func(t *testing.T) {
			evidence := PublicationEvidence{Schema: 3, Entry: PublicationMayHaveEnteredEntry,
				Class: PublicationRequestAcknowledged, ResponseContractDigest: publicationTestID(10), NormalizedStatus: 201, SafeResourceID: "created-resource", ConsumerLocator: "locator"}
			first := PublicationOutcome{Action: PublicationCreateEmpty, ProjectionCommitment: publicationTestID(11),
				AttemptID: publicationTestID(12), Disposition: PublicationOutcomeAcknowledged, Evidence: evidence}
			second := PublicationOutcome{Action: PublicationUpdatePolicy, ProjectionCommitment: publicationTestID(13),
				AttemptID: publicationTestID(14), Disposition: PublicationOutcomeAcknowledged, Evidence: evidence}
			second.Evidence.ConsumerLocator = ""
			v := PublicationOutcomeVector{Schema: 2, DomainID: publicationTestID(1), OperationID: publicationTestID(2),
				SnapshotID: publicationTestID(3), SelectionDigest: publicationTestID(4), Entries: []PublicationTargetOutcome{
					{CoordinateID: publicationTestID(5), Actions: []PublicationOutcome{first, second}},
				}}
			if differentTarget {
				v.Entries[0].Actions = []PublicationOutcome{first}
				v.Entries = append(v.Entries, PublicationTargetOutcome{CoordinateID: publicationTestID(6), Actions: []PublicationOutcome{second}})
			}
			body, err := EncodePublicationOutcomeVector(v)
			if err != nil {
				t.Fatal("distinct action attempts refused", err)
			}
			if _, err := InspectPublicationOutcomeVector(body); err != nil {
				t.Fatal("distinct action attempts failed inspection", err)
			}
			if bytes.Count(body, second.AttemptID[:]) != 1 {
				t.Fatal("second AttemptID does not identify one encoded field")
			}
			damaged := bytes.Replace(body, second.AttemptID[:], first.AttemptID[:], 1)
			if _, err := InspectPublicationOutcomeVector(damaged); err == nil {
				t.Error("inspection accepted one AttemptID for two actions")
			}
			last := &v.Entries[len(v.Entries)-1]
			last.Actions[len(last.Actions)-1].AttemptID = first.AttemptID
			if _, err := EncodePublicationOutcomeVector(v); err == nil {
				t.Error("encoder accepted one AttemptID for two actions")
			}
		})
	}
	t.Run("shared_blockers_and_unadmitted_actions", func(t *testing.T) {
		blocker := publicationTestID(8)
		v := PublicationOutcomeVector{Schema: 2, DomainID: publicationTestID(1), OperationID: publicationTestID(2),
			SnapshotID: publicationTestID(3), SelectionDigest: publicationTestID(4), Entries: []PublicationTargetOutcome{
				{CoordinateID: publicationTestID(5), Actions: []PublicationOutcome{
					{Action: PublicationUpdatePolicy, ProjectionCommitment: publicationTestID(6), Disposition: PublicationNotSent,
						CoreReason: 1, BlockerIDs: []ID{blocker}},
					{Action: PublicationWriteValue, ProjectionCommitment: publicationTestID(7), Disposition: PublicationNotSent,
						CoreReason: 1, BlockerIDs: []ID{blocker}},
				}},
			}}
		body, err := EncodePublicationOutcomeVector(v)
		if err != nil {
			t.Fatal("shared blocker or absent unadmitted AttemptID refused", err)
		}
		got, err := InspectPublicationOutcomeVector(body)
		if err != nil || len(got.Entries) != 1 || len(got.Entries[0].Actions) != 2 {
			t.Fatal("shared blocker vector failed inspection", err)
		}
		for _, action := range got.Entries[0].Actions {
			if !action.AttemptID.IsZero() || len(action.BlockerIDs) != 1 || action.BlockerIDs[0] != blocker {
				t.Fatal("unadmitted action identity or blocker changed")
			}
		}
	})
}

// full_only: false
func TestPublicationOutcomeV2IndependentNoActionFraming(t *testing.T) {
	v := PublicationOutcomeVector{Schema: 2, DomainID: publicationTestID(1), OperationID: publicationTestID(2),
		SnapshotID: publicationTestID(3), SelectionDigest: publicationTestID(4), Entries: []PublicationTargetOutcome{
			{CoordinateID: publicationTestID(5), Actions: []PublicationOutcome{{Disposition: PublicationNoOp}}},
		}}
	body, err := EncodePublicationOutcomeVector(v)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 0, 242)
	want = append(want, 0, 2)
	for i := byte(1); i <= 4; i++ {
		id := publicationTestID(i)
		want = append(want, id[:]...)
	}
	want = append(want, 0, 0, 1) // warning, target count
	id := publicationTestID(5)
	want = append(want, id[:]...)
	want = append(want, 1, 0) // action count, no-action tag
	want = append(want, make([]byte, 64)...)
	want = append(want, PublicationNoOp, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) // result through empty B(Evidence)
	if !bytes.Equal(body, want) {
		t.Fatalf("framing length=%d want=%d", len(body), len(want))
	}
	if _, err := InspectPublicationOutcomeVector(body); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectPublicationOutcomeVector(append(append([]byte{}, body...), 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
}

// full_only: false
func TestPublicationOutcomeV2WholeTargetIncludesCoordinateAndCount(t *testing.T) {
	blockers := make([]ID, 2048)
	for i := range blockers {
		binary.BigEndian.PutUint16(blockers[i][:2], uint16(i+1))
	}
	base := PublicationOutcomeVector{Schema: 2, DomainID: publicationTestID(1), OperationID: publicationTestID(2),
		SnapshotID: publicationTestID(3), SelectionDigest: publicationTestID(4), Entries: []PublicationTargetOutcome{{
			CoordinateID: publicationTestID(5), Actions: []PublicationOutcome{
				{Action: PublicationCreateEmpty, ProjectionCommitment: publicationTestID(6),
					Disposition: PublicationNotSent, CoreReason: 1, BlockerIDs: blockers},
				{Action: PublicationUpdatePolicy, ProjectionCommitment: publicationTestID(7),
					Disposition: PublicationNotSent, CoreReason: 1, BlockerIDs: blockers[:506]},
			},
		}}}
	// 33 target-framing bytes + two 76-byte action bodies + 2,554 IDs.
	// This is 81,913 bytes, seven below the 80 KiB target ceiling.
	if _, err := EncodePublicationOutcomeVector(base); err != nil {
		t.Fatalf("below-bound target refused: %v", err)
	}
	base.Entries[0].Actions[1].BlockerIDs = blockers[:507]
	// One more blocker makes 81,945 bytes. Its ID already occurs in the
	// first action, so the distinct-blocker limit still stays at 2,048.
	if _, err := EncodePublicationOutcomeVector(base); err != ErrRecordCapacity {
		t.Fatalf("whole-target over-bound accepted: %v", err)
	}
}
