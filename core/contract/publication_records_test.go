package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func publicationRecordFixture(t *testing.T) (PublicationCoordinate, PublicationMarker) {
	t.Helper()
	domain := publicationTestID(1)
	coordinateID, err := PublicationCoordinateID(domain, "provider", "account/resource")
	if err != nil {
		t.Fatal(err)
	}
	binding, attempt := publicationTestID(3), publicationTestID(4)
	coordinate := PublicationCoordinate{Schema: 5, CurrentPublicationIncarnationID: publicationTestID(40), DomainID: domain, CoordinateID: coordinateID,
		ServiceContractID: "provider", CanonicalTarget: "account/resource", BindingState: PublicationBindingActive,
		OwnerState: PublicationOwnerUncertainCreate, ActiveBindingIncarnationID: binding,
		LastBindingIncarnationID: binding, LastEntryIncarnationID: publicationTestID(12), LastAdmissionOrdinal: 1,
		LatestUnresolvedAttemptID: attempt, PossibleRemoteObject: 1,
		DeletionDestinationID: "dest", DeletionConsumerLocator: "locator", DeletionTargetContractID: "profile",
		DeletionConfigContractID: "config", DeletionCredentialRouteContractID: "2", DeletionTargetData: []byte("public"), DeletionPayloadEncoding: OutputEncodingRaw,
		DeletionTargetRowDigest: publicationTestID(14)}
	projection := PublicationProjection{Schema: 4, DomainID: domain, ConfigurationDigest: publicationTestID(13),
		CoordinateID: coordinateID, BindingIncarnationID: binding, EntryIncarnationID: coordinate.LastEntryIncarnationID,
		TargetRowDigest: publicationTestID(14), Action: PublicationCreateEmpty, PolicyDigest: publicationTestID(15),
		RequestContractDigest: publicationTestID(16), ActingRecipientID: publicationTestID(5)}
	commitment, err := PublicationProjectionCommitment(projection)
	if err != nil {
		t.Fatal(err)
	}
	marker := PublicationMarker{Schema: 5, PublicationIncarnationID: publicationTestID(40), DomainID: domain, OperationID: publicationTestID(8), AttemptID: attempt,
		CoordinateID: coordinateID, AdmissionOrdinal: 1, Projection: projection, ProjectionCommitment: commitment,
		AuthoritySubjectDigest: publicationTestID(10),
		ExecutorID:             "executor", CredentialRouteID: "route", State: PublicationMayHaveEntered,
		Evidence: PublicationEvidence{Schema: 3, Entry: PublicationMayHaveEnteredEntry, Class: PublicationUnproved,
			ResponseContractDigest: publicationTestID(11)}, BirthServiceContractID: "profile", BirthTargetContractID: "2"}
	return coordinate, marker
}

// full_only: false
func TestAcknowledgedCreateEvidenceRequiresResourceIdentity(t *testing.T) {
	for _, action := range []uint8{PublicationCreateEmpty, PublicationCreateWithValue} {
		evidence := PublicationEvidence{Schema: 3, Entry: PublicationMayHaveEnteredEntry, Class: PublicationRequestAcknowledged, ResponseContractDigest: publicationTestID(11), NormalizedStatus: 201, ConsumerLocator: "service/created-instance"}
		if validatePublicationEvidence(evidence) != nil {
			t.Fatal("fixture failed before action-correlated admission")
		}
		if validatePublicationActionLocator(action, evidence) == nil {
			t.Errorf("create action %d accepted empty resource identity", action)
		}
		evidence.SafeResourceID = strings.Repeat("r", 1024)
		if validatePublicationActionLocator(action, evidence) != nil || validatePublicationEvidence(evidence) != nil {
			t.Fatal("maximum resource identity refused")
		}
		evidence.SafeResourceID += "r"
		if validatePublicationEvidence(evidence) == nil {
			t.Fatal("one-over resource identity accepted")
		}
	}
	for _, action := range []uint8{PublicationWriteValue, PublicationUpdatePolicy, PublicationDeleteOwned, PublicationDeleteReservedSlot} {
		evidence := PublicationEvidence{Schema: 3, Entry: PublicationMayHaveEnteredEntry, Class: PublicationRequestAcknowledged, ResponseContractDigest: publicationTestID(11), NormalizedStatus: 204}
		if validatePublicationActionLocator(action, evidence) != nil || validatePublicationEvidence(evidence) != nil {
			t.Fatal("non-create acknowledgement requires unnecessary resource identity", action)
		}
	}
}

// full_only: false
func TestPublicationRecordsClosedAndBounded(t *testing.T) {
	t.Run("V5RawVector", func(t *testing.T) {
		// Build the selected record from specified fields, independently of
		// the coordinate codec.
		var body []byte
		putID := func(b byte) { body = append(body, bytes.Repeat([]byte{b}, 32)...) }
		putString := func(s string) {
			body = binary.BigEndian.AppendUint32(body, uint32(len(s)))
			body = append(body, s...)
		}
		domain := publicationTestID(1)
		coordinateInput := append([]byte("ENKV/PUBLICATION/COORDINATE/v3\x00"), domain[:]...)
		coordinateInput = binary.BigEndian.AppendUint32(coordinateInput, 1)
		coordinateInput = append(coordinateInput, 'p')
		coordinateInput = binary.BigEndian.AppendUint32(coordinateInput, 4)
		coordinateInput = append(coordinateInput, "slot"...)
		coordinate := sha256.Sum256(coordinateInput)
		body = binary.BigEndian.AppendUint16(body, 5)
		putID(1)
		body = append(body, coordinate[:]...)
		putString("p")
		putString("slot")
		body = append(body, 1, 1)
		for _, b := range []byte{3, 3, 12, 0, 0, 40} {
			putID(b)
		}
		body = binary.BigEndian.AppendUint64(body, 1)
		for _, b := range []byte{4, 0, 0} {
			putID(b)
		}
		putID(0)
		body = binary.BigEndian.AppendUint64(body, 0)
		putID(0)
		putID(0)
		putID(0)
		body = binary.BigEndian.AppendUint64(body, 0)
		putID(0)
		putID(0)
		body = binary.BigEndian.AppendUint64(body, 0)
		body = append(body, 1, 0)
		for _, s := range []string{"dest", "locator", "profile", "public", "config", "2"} {
			putString(s)
		}
		body = append(body, OutputEncodingRaw, 0)
		putID(14)
		if len(body) != 684 {
			t.Fatalf("independent vector length=%d", len(body))
		}
		decoded, err := InspectPublicationCoordinate(body)
		if err != nil {
			t.Fatalf("valid schema-5 coordinate refused: %v", err)
		}
		if decoded.Schema != 5 || decoded.CoordinateID != coordinate || decoded.DeletionDestinationID != "dest" ||
			decoded.DeletionConsumerLocator != "locator" || decoded.DeletionTargetContractID != "profile" ||
			decoded.DeletionConfigContractID != "config" || decoded.DeletionCredentialRouteContractID != "2" || !bytes.Equal(decoded.DeletionTargetData, []byte("public")) ||
			decoded.DeletionPayloadEncoding != OutputEncodingRaw || decoded.DeletionTargetRowDigest != publicationTestID(14) {
			t.Fatalf("wrong retained delete inputs: %#v", decoded)
		}
		encoded, err := EncodePublicationCoordinate(decoded)
		if err != nil || !bytes.Equal(encoded, body) {
			t.Fatalf("coordinate roundtrip error=%v", err)
		}
		obsolete := bytes.Clone(body)
		obsolete[1] = 2
		if _, err := InspectPublicationCoordinate(obsolete); err == nil {
			t.Fatal("obsolete coordinate schema accepted by decoder")
		}
	})
	coordinate, marker := publicationRecordFixture(t)
	body, err := EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := InspectPublicationCoordinate(body); err != nil || !reflect.DeepEqual(got, coordinate) {
		t.Fatalf("coordinate=%#v err=%v", got, err)
	}
	for _, bad := range [][]byte{body[:len(body)-1], append(bytes.Clone(body), 0)} {
		if _, err := InspectPublicationCoordinate(bad); err == nil {
			t.Fatal("malformed coordinate accepted")
		}
	}
	coordinate.Schema = 2
	if _, err := EncodePublicationCoordinate(coordinate); err == nil {
		t.Fatal("obsolete coordinate schema accepted")
	}
	body, err = EncodePublicationMarker(marker)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := InspectPublicationMarker(body); err != nil || got != marker {
		t.Fatalf("marker=%#v err=%v", got, err)
	}
	for _, bad := range [][]byte{body[:len(body)-1], append(append([]byte{}, body...), 0)} {
		if _, err := InspectPublicationMarker(bad); err == nil {
			t.Fatal("malformed marker accepted")
		}
	}
	marker.State = PublicationAcknowledged
	if _, err := EncodePublicationMarker(marker); err == nil {
		t.Fatal("ACK without evidence accepted")
	}
	marker.Evidence.Class = PublicationRequestAcknowledged
	marker.Evidence.NormalizedStatus = 201
	marker.Evidence.SafeResourceID = "exact-instance"
	marker.Evidence.ConsumerLocator = "locator"
	if _, err := EncodePublicationMarker(marker); err != nil {
		t.Fatal(err)
	}
	marker.BirthServiceContractID = ""
	if _, err := EncodePublicationMarker(marker); err == nil {
		t.Fatal("create without birth semantic contract accepted")
	}
}

// full_only: false
func TestPublicationRecordMaximumWidths(t *testing.T) {
	coordinate, marker := publicationRecordFixture(t)
	coordinate.ServiceContractID = strings.Repeat("p", 256)
	coordinate.CanonicalTarget = strings.Repeat("s", 1024)
	coordinate.DeletionDestinationID = strings.Repeat("d", 256)
	coordinate.DeletionConsumerLocator = strings.Repeat("l", 1024)
	coordinate.DeletionTargetContractID = strings.Repeat("p", 256)
	coordinate.DeletionConfigContractID = strings.Repeat("c", 256)
	coordinate.DeletionCredentialRouteContractID = strings.Repeat("v", 256)
	coordinate.DeletionTargetData = bytes.Repeat([]byte{255}, 4096)
	coordinate.DeletionPayloadEncoding = OutputEncodingRaw
	coordinate.CoordinateID, _ = PublicationCoordinateID(coordinate.DomainID, coordinate.ServiceContractID, coordinate.CanonicalTarget)
	body, err := EncodePublicationCoordinate(coordinate)
	if err != nil || len(body) != 8072 || len(body)+SupportRecordOverhead != 8109 {
		t.Fatalf("coordinate bytes=%d err=%v", len(body), err)
	}
	if _, err := InspectPublicationCoordinate(body); err != nil {
		t.Fatal(err)
	}
	if _, err := AppendSupportRecord(nil, SupportRecord{Kind: PublicationCoordinateSupportKind,
		RecordID: coordinate.CoordinateID, Body: body}); err != nil {
		t.Fatal(err)
	}
	coordinate.DeletionConsumerLocator += "x"
	if _, err := EncodePublicationCoordinate(coordinate); err == nil {
		t.Fatal("delete locator max+1 accepted")
	}
	marker.ExecutorID = strings.Repeat("e", 256)
	marker.CredentialRouteID = strings.Repeat("r", 256)
	marker.BirthServiceContractID = strings.Repeat("p", 256)
	marker.BirthTargetContractID = strings.Repeat("v", 256)
	marker.State = PublicationAcknowledged
	marker.Evidence.Class = PublicationRequestAcknowledged
	marker.Evidence.NormalizedStatus = 201
	marker.Evidence.SafeRequestID = strings.Repeat("q", 1024)
	marker.Evidence.SafeResourceID = strings.Repeat("s", 1024)
	marker.Evidence.ConsumerLocator = strings.Repeat("l", 1024)
	body, err = EncodePublicationMarker(marker)
	if err != nil || len(body) != 4859 || len(body)+SupportRecordOverhead != 4896 {
		t.Fatalf("marker bytes=%d err=%v", len(body), err)
	}
	if _, err := InspectPublicationMarker(body); err != nil {
		t.Fatal(err)
	}
	marker.Evidence.SafeResourceID += "s"
	if _, err := EncodePublicationMarker(marker); err == nil {
		t.Fatal("safe ID max+1 accepted")
	}
}

// full_only: false
func TestPublicationCoordinateOwnerStates(t *testing.T) {
	coordinate, marker := publicationRecordFixture(t)
	for name, change := range map[string]func(*PublicationCoordinate){
		"destination":               func(v *PublicationCoordinate) { v.DeletionDestinationID = "" },
		"locator":                   func(v *PublicationCoordinate) { v.DeletionConsumerLocator = "" },
		"target contract":           func(v *PublicationCoordinate) { v.DeletionTargetContractID = "" },
		"config contract":           func(v *PublicationCoordinate) { v.DeletionConfigContractID = "" },
		"credential route contract": func(v *PublicationCoordinate) { v.DeletionCredentialRouteContractID = "" },
		"encoding":                  func(v *PublicationCoordinate) { v.DeletionPayloadEncoding = 0 },
		"digest":                    func(v *PublicationCoordinate) { v.DeletionTargetRowDigest = ID{} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := coordinate
			change(&bad)
			if _, err := EncodePublicationCoordinate(bad); err == nil {
				t.Fatal("partial retained deletion inputs accepted")
			}
		})
	}
	coordinate.OwnerState = PublicationOwnerNone
	coordinate.LatestUnresolvedAttemptID = ID{}
	coordinate.PossibleRemoteObject = 0
	if _, err := EncodePublicationCoordinate(coordinate); err != nil {
		t.Fatal(err)
	}
	coordinate.DeletionDestinationID, coordinate.DeletionConsumerLocator = "", ""
	coordinate.DeletionTargetContractID, coordinate.DeletionConfigContractID, coordinate.DeletionCredentialRouteContractID = "", "", ""
	coordinate.DeletionTargetData, coordinate.DeletionPayloadEncoding = nil, 0
	coordinate.DeletionTargetRowDigest = ID{}
	body, err := EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal("no-owner discharged coordinate refused: ", err)
	}
	decoded, err := InspectPublicationCoordinate(body)
	if err != nil || !reflect.DeepEqual(decoded, coordinate) {
		t.Fatalf("no-owner coordinate did not round-trip: decoded=%+v err=%v", decoded, err)
	}
	coordinate.PossibleRemoteObject = 1
	if _, err := EncodePublicationCoordinate(coordinate); err == nil {
		t.Fatal("possible remote object without delete inputs accepted")
	}
	coordinate.PossibleRemoteObject = 0
	coordinate.LatestUnresolvedAttemptID = marker.AttemptID
	if _, err := EncodePublicationCoordinate(coordinate); err == nil {
		t.Fatal("unresolved attempt without delete inputs accepted")
	}
	coordinate.LatestUnresolvedAttemptID = ID{}
	coordinate.LateEffectRisk = 1
	if _, err := EncodePublicationCoordinate(coordinate); err == nil {
		t.Fatal("late effect without delete inputs accepted")
	}
	coordinate.LateEffectRisk = 0
	coordinate.DeletionDestinationID, coordinate.DeletionConsumerLocator = "dest", "locator"
	coordinate.DeletionTargetContractID, coordinate.DeletionConfigContractID, coordinate.DeletionCredentialRouteContractID = "profile", "config", "2"
	coordinate.DeletionTargetData, coordinate.DeletionPayloadEncoding = []byte("public"), OutputEncodingRaw
	coordinate.DeletionTargetRowDigest = publicationTestID(14)
	coordinate.OwnerState = PublicationOwnerQualified
	if _, err := EncodePublicationCoordinate(coordinate); err == nil {
		t.Fatal("qualified owner without birth accepted")
	}
	coordinate.OwnedBirthAttemptID = marker.AttemptID
	coordinate.OwnedInstanceDigest = publicationTestID(20)
	coordinate.DeletionDestinationID, coordinate.DeletionConsumerLocator = "", ""
	coordinate.DeletionTargetContractID, coordinate.DeletionConfigContractID, coordinate.DeletionCredentialRouteContractID = "", "", ""
	coordinate.DeletionTargetData, coordinate.DeletionPayloadEncoding = nil, 0
	coordinate.DeletionTargetRowDigest = ID{}
	if _, err := EncodePublicationCoordinate(coordinate); err == nil {
		t.Fatal("qualified owner without delete inputs accepted")
	}
	coordinate.DeletionDestinationID, coordinate.DeletionConsumerLocator = "dest", "locator"
	coordinate.DeletionTargetContractID, coordinate.DeletionConfigContractID, coordinate.DeletionCredentialRouteContractID = "profile", "config", "2"
	coordinate.DeletionTargetData, coordinate.DeletionPayloadEncoding = []byte("public"), OutputEncodingRaw
	coordinate.DeletionTargetRowDigest = publicationTestID(14)
	if _, err := EncodePublicationCoordinate(coordinate); err != nil {
		t.Fatal(err)
	}
	coordinate.OwnerState = PublicationOwnerUncertainCreate
	if _, err := EncodePublicationCoordinate(coordinate); err == nil {
		t.Fatal("uncertain create with owned digest accepted")
	}
}

// full_only: false
func TestPublicationBlockerDigestClosed(t *testing.T) {
	if digest, err := PublicationBlockerDigest(nil); err != nil || !digest.IsZero() {
		t.Fatalf("empty blockers digest=%x err=%v", digest, err)
	}
	if _, err := PublicationBlockerDigest([]ID{publicationTestID(2), publicationTestID(1)}); err == nil {
		t.Fatal("unsorted blockers accepted")
	}
	if _, err := PublicationBlockerDigest([]ID{publicationTestID(1), publicationTestID(1)}); err == nil {
		t.Fatal("duplicate blockers accepted")
	}
}

// full_only: false
func TestPublicationRecordIdentityCollection(t *testing.T) {
	coordinate, marker := publicationRecordFixture(t)
	coordinate.LastValueAckAttemptID, coordinate.LastValueDigest, coordinate.LastValueAckIncarnationID, coordinate.LastValueAckOrdinal = publicationTestID(51), publicationTestID(52), publicationTestID(53), 1
	coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyDigest, coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = publicationTestID(54), publicationTestID(55), publicationTestID(56), 1
	coordinate.LastDeleteAckAttemptID, coordinate.LastDeleteAckIncarnationID, coordinate.LastDeleteAckOrdinal = publicationTestID(57), publicationTestID(58), 1
	body, err := EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	used := map[ID]bool{publicationTestID(90): true}
	if err := CollectPublicationRecordIdentities(SupportRecord{Kind: PublicationCoordinateSupportKind, RecordID: coordinate.CoordinateID, Body: body}, used); err != nil {
		t.Fatal(err)
	}
	body, err = EncodePublicationMarker(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := CollectPublicationRecordIdentities(SupportRecord{Kind: PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body}, used); err != nil {
		t.Fatal(err)
	}
	// Fixed fixture identities, independent of the collector's field list.
	want := []ID{publicationTestID(3), publicationTestID(12), publicationTestID(40), publicationTestID(53), publicationTestID(56), publicationTestID(58), publicationTestID(8), publicationTestID(90)}
	if len(used) != len(want) {
		t.Fatal("wrong retained identity set", len(used))
	}
	for _, id := range want {
		if !used[id] {
			t.Fatal("retained identity omitted", id)
		}
	}
	if used[ID{}] || used[coordinate.CoordinateID] || used[marker.AttemptID] {
		t.Fatal("collector added zero or caller-owned record identity")
	}
	for _, kind := range []uint8{PublicationCoordinateSupportKind, PublicationMarkerSupportKind} {
		if err := CollectPublicationRecordIdentities(SupportRecord{Kind: kind, Body: []byte{0}}, used); err == nil {
			t.Fatal("damaged publication row admitted", kind)
		}
	}
	if err := CollectPublicationRecordIdentities(SupportRecord{Kind: OutputConfigurationSliceSupportKind, Body: []byte{0}}, used); err != nil || len(used) != len(want) {
		t.Fatal("unrelated kind changed collection", err)
	}
}

// full_only: false
func TestPublicationUncertainOwnerCodecAllowsZeroLatestCache(t *testing.T) {
	coordinate, _ := publicationRecordFixture(t)
	original := coordinate
	coordinate.LatestUnresolvedAttemptID = ID{}
	t.Run("encode-roundtrip", func(t *testing.T) {
		body, err := EncodePublicationCoordinate(coordinate)
		if err != nil {
			t.Fatal("uncertain owner with zero latest cache refused", err)
		}
		decoded, err := InspectPublicationCoordinate(body)
		if err != nil || !reflect.DeepEqual(decoded, coordinate) {
			t.Fatalf("zero latest cache changed ownership facts: %+v %v", decoded, err)
		}
	})
	t.Run("decode-independent-zero-field", func(t *testing.T) {
		body, err := EncodePublicationCoordinate(original)
		if err != nil {
			t.Fatal(err)
		}
		// V5 offset: schema2, domain/coordinate64, two u32 strings, state2,
		// six IDs192 and ordinal8 precede the32-byte latest-unresolved cache.
		offset := 2 + 64 + 4 + len(original.ServiceContractID) + 4 + len(original.CanonicalTarget) + 2 + 6*32 + 8
		if !bytes.Equal(body[offset:offset+32], original.LatestUnresolvedAttemptID[:]) {
			t.Fatal("independent cache offset disagrees with V5 layout")
		}
		clear(body[offset : offset+32])
		decoded, err := InspectPublicationCoordinate(body)
		if err != nil || !reflect.DeepEqual(decoded, coordinate) {
			t.Fatalf("valid zero cache wire refused: %+v %v", decoded, err)
		}
	})
	t.Run("preserve-owner-invariants", func(t *testing.T) {
		for name, damage := range map[string]func(*PublicationCoordinate){
			"owned-birth":             func(v *PublicationCoordinate) { v.OwnedBirthAttemptID = publicationTestID(90) },
			"owned-instance":          func(v *PublicationCoordinate) { v.OwnedInstanceDigest = publicationTestID(91) },
			"missing-possible-object": func(v *PublicationCoordinate) { v.PossibleRemoteObject = 0 },
			"missing-deletion-inputs": func(v *PublicationCoordinate) { v.DeletionTargetRowDigest = ID{} },
		} {
			t.Run(name, func(t *testing.T) {
				bad := coordinate
				damage(&bad)
				if _, err := EncodePublicationCoordinate(bad); err == nil {
					t.Fatal("zero cache weakened owner invariants")
				}
			})
		}
	})
}

// full_only: false
func TestPublicationEvidenceAndResultCompleteMaxima(t *testing.T) {
	dispatch := publicationDispatchFixture(t)
	context, err := PublicationDispatchContextDigest(dispatch)
	if err != nil {
		t.Fatal(err)
	}
	evidence := PublicationEvidence{Schema: 3, Entry: PublicationMayHaveEnteredEntry, Class: PublicationRequestAcknowledged, ResponseContractDigest: dispatch.ResponseContractDigest, NormalizedStatus: 201, SafeRequestID: strings.Repeat("q", 1024), SafeResourceID: strings.Repeat("r", 1024), ConsumerLocator: strings.Repeat("l", 1024)}
	body, err := EncodePublicationEvidence(evidence)
	if err != nil || len(body) != 2+1+1+32+2+3*(4+1024) {
		t.Fatal("complete evidence maximum", len(body), err)
	}
	result := PublicationResult{Schema: 2, DomainID: dispatch.DomainID, OperationID: dispatch.OperationID, AttemptID: dispatch.AttemptID, CoordinateID: dispatch.CoordinateID, ProjectionCommitment: dispatch.ProjectionCommitment, DispatchContextDigest: context, Evidence: evidence}
	body, err = EncodePublicationResult(result)
	if err != nil || len(body) != 2+6*32+4+3122 {
		t.Fatal("complete Core result maximum", len(body), err)
	}
	if err := ValidatePublicationResult(dispatch, result); err != nil {
		t.Fatal(err)
	}
	result.Evidence.ConsumerLocator += "l"
	if _, err := EncodePublicationResult(result); err == nil {
		t.Fatal("locator max+1 accepted")
	}
	result.Evidence = evidence
	result.Evidence.ConsumerLocator = ""
	if err := ValidatePublicationResult(dispatch, result); err == nil {
		t.Fatal("create ACK without complete locator accepted")
	}
	result.Evidence = evidence
	dispatch.Projection.Action = PublicationDeleteReservedSlot
	dispatch.Projection.UncertainCreateAttemptID = publicationTestID(91)
	dispatch.Projection.ExclusiveNamespaceDigest = publicationTestID(92)
	dispatch.Projection.PolicyDigest = ID{}
	dispatch.ProjectionCommitment, _ = PublicationProjectionCommitment(dispatch.Projection)
	result.ProjectionCommitment = dispatch.ProjectionCommitment
	result.DispatchContextDigest, _ = PublicationDispatchContextDigest(dispatch)
	if err := ValidatePublicationResult(dispatch, result); err == nil {
		t.Fatal("non-create locator accepted")
	}
}

// full_only: false
func TestPublicationCoordinateOwnsCompleteDeletionFacts(t *testing.T) {
	coordinate, _ := publicationRecordFixture(t)
	backing := make([]byte, len(coordinate.DeletionTargetData), 1<<20)
	copy(backing, coordinate.DeletionTargetData)
	coordinate.DeletionTargetData = backing
	owned, err := coordinate.Clone()
	if err != nil || !owned.Equal(coordinate) || cap(owned.DeletionTargetData) != len(backing) {
		t.Fatal("bounded complete coordinate clone", err)
	}
	backing[0]++
	if owned.Equal(coordinate) {
		t.Fatal("coordinate retained caller target bytes")
	}
	changed := owned
	changed.DeletionConfigContractID = "different-config"
	if owned.Equal(changed) {
		t.Fatal("config contract absent from coordinate equality")
	}
	invalid := owned
	invalid.DeletionTargetData = make([]byte, MaxOutputTargetDataBytes+1)
	if _, err := invalid.Clone(); err == nil {
		t.Fatal("unbounded coordinate cloned")
	}
	if invalid.Equal(invalid) {
		t.Fatal("invalid coordinate has no canonical equality")
	}
	body, err := EncodePublicationCoordinate(owned)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := InspectPublicationCoordinate(body)
	if err != nil {
		t.Fatal(err)
	}
	clear(body)
	if !decoded.Equal(owned) {
		t.Fatal("decoded target bytes borrow caller record")
	}
}
