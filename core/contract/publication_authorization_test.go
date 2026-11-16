package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func outputVectorDigest(t *testing.T, literal string) ID {
	t.Helper()
	decoded, err := hex.DecodeString(literal)
	if err != nil || len(decoded) != 32 {
		t.Fatal("invalid independent digest literal", err)
	}
	var id ID
	copy(id[:], decoded)
	return id
}

func outputReserveSubjectFixture() OutputReserveSubject {
	id := publicationTestID
	return OutputReserveSubject{Schema: 5, PublicationIncarnationID: publicationTestID(23), AdmissionOrdinal: 1, Action: PublicationWriteValue,
		DomainID: id(1), OperationID: id(2), AttemptID: id(3),
		PredecessorRevisionID: id(6), PredecessorFullHEADDigest: id(7), PredecessorToken: Token{Family: GCP, Value: "1"},
		CurrentAccessRoot: id(8), ConfigurationDigest: id(9), CoordinateID: id(10),
		BindingIncarnationID: id(11), EntryIncarnationID: id(12), TargetRowDigest: id(13),
		BirthTargetRowDigest: id(22),
		OwnedBirthAttemptID:  id(14), ValueBasisDigest: id(15), PolicyDigest: id(16),
		RequestContractDigest: id(17), DispatchContextDigest: id(18),
		BlockerCount: 1, BlockerDigest: id(19), HeadCoreDigest: id(20),
		HeadCoreLength: SuccessorHeadCoreMinLength, ConditionalPlanDigest: id(21)}
}

func outputReserveMarkerFixture(t *testing.T, s OutputReserveSubject) PublicationMarker {
	t.Helper()
	p := PublicationProjection{Schema: 4, DomainID: s.DomainID, ConfigurationDigest: s.ConfigurationDigest, CoordinateID: s.CoordinateID,
		BindingIncarnationID: s.BindingIncarnationID, EntryIncarnationID: s.EntryIncarnationID, TargetRowDigest: s.TargetRowDigest,
		Action: s.Action, OwnedBirthAttemptID: s.OwnedBirthAttemptID, UncertainCreateAttemptID: s.UncertainCreateAttemptID,
		ExclusiveNamespaceDigest: s.ExclusiveNamespaceDigest, ValueBasisDigest: s.ValueBasisDigest, PolicyDigest: s.PolicyDigest,
		RequestContractDigest: s.RequestContractDigest, ActingRecipientID: publicationTestID(24)}
	commitment, err := PublicationProjectionCommitment(p)
	if err != nil {
		t.Fatal(err)
	}
	return PublicationMarker{Schema: 5, DomainID: s.DomainID, OperationID: s.OperationID, AttemptID: s.AttemptID, CoordinateID: s.CoordinateID,
		PublicationIncarnationID: s.PublicationIncarnationID, AdmissionOrdinal: s.AdmissionOrdinal, Projection: p, ProjectionCommitment: commitment,
		ExecutorID: "executor", CredentialRouteID: "route",
		BlockerCount: s.BlockerCount, BlockerDigest: s.BlockerDigest, Evidence: PublicationEvidence{ResponseContractDigest: publicationTestID(26)}}
}

func outputCloseSubjectFixture() OutputCloseSubject {
	id := publicationTestID
	return OutputCloseSubject{Schema: 4, Action: PublicationWriteValue,
		DomainID: id(1), OperationID: id(2), AttemptID: id(3),
		ReservationAdmissionDigest: id(6), PredecessorRevisionID: id(7), PredecessorFullHEADDigest: id(8),
		PredecessorToken: Token{Family: GCP, Value: "1"}, CurrentAccessRoot: id(9),
		ConfigurationDigest: id(10), CoordinateID: id(11), BindingIncarnationID: id(12),
		EntryIncarnationID: id(13), TargetRowDigest: id(14), OwnedBirthAttemptID: id(15),
		ActionProjectionCommitment: id(16), EntryClass: PublicationMayHaveEnteredEntry,
		ResultClass: PublicationRequestAcknowledged, LateRisk: 1,
		ResultEvidenceDigest: id(17), HeadCoreDigest: id(18),
		HeadCoreLength: SuccessorHeadCoreMinLength, ConditionalPlanDigest: id(19)}
}

// full_only: false
func TestOutputReserveSubjectIndependentBytesAndAdmissionDigest(t *testing.T) {
	s := outputReserveSubjectFixture()
	marker := outputReserveMarkerFixture(t, s)
	body, err := EncodeOutputReserveSubject(s)
	if err != nil {
		t.Fatal(err)
	}
	// Independent Python hashlib/struct derivation; fixed one-byte ID patterns make the field order visible. This expected
	// preimage uses only the frozen field list and ordinary byte primitives.
	id := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	var admission []byte
	// The two absent optional IDs sit between owned birth and value basis.
	// Assemble that segment explicitly instead of accepting a production offset.
	admission = append(admission, 0, 5, PublicationWriteValue)
	for _, b := range []byte{1, 2, 3, 6, 7} {
		admission = append(admission, id(b)...)
	}
	admission = append(admission, byte(GCP), 0, 0, 0, 1, '1')
	for b := byte(8); b <= 10; b++ {
		admission = append(admission, id(b)...)
	}
	admission = append(admission, id(23)...)
	admission = binary.BigEndian.AppendUint64(admission, 1)
	for b := byte(11); b <= 13; b++ {
		admission = append(admission, id(b)...)
	}
	admission = append(admission, id(22)...)
	admission = append(admission, id(14)...)
	admission = append(admission, make([]byte, 64)...)
	for b := byte(15); b <= 17; b++ {
		admission = append(admission, id(b)...)
	}
	want := append([]byte("ENKV/K2-OUTPUT-RESERVE/v5\x00"), admission...)
	want = append(want, id(18)...)
	want = binary.BigEndian.AppendUint16(want, 1)
	want = append(want, id(19)...)
	want = append(want, id(20)...)
	want = binary.BigEndian.AppendUint32(want, SuccessorHeadCoreMinLength)
	want = append(want, id(21)...)
	if !bytes.Equal(body, want) {
		t.Fatal("reserve subject bytes differ from independent field preimage")
	}
	reserveDigest := outputVectorDigest(t, "1ab6910578b8e571166ffe1bd6512feb20a69ea466cb503a254da64c60b6213f")
	if sha256.Sum256(body) != reserveDigest {
		t.Fatal("reserve subject digest differs from independent literal")
	}
	admissionPreimage := append([]byte("ENKV/K2-OUTPUT-RESERVE-ADMISSION/v5\x00"), admission...)
	admissionPreimage = binary.BigEndian.AppendUint16(admissionPreimage, 1)
	admissionPreimage = append(admissionPreimage, id(19)...)
	// Immutable marker context is framed independently; the projection's fixed
	// scalar preimage has the expected commitment below.
	projectionCommitment := outputVectorDigest(t, "9cdd6f92bd1fa3afdf9a160fbc2a79f9d7d38c744800d93bf9398907955029e5")
	admissionPreimage = append(admissionPreimage, projectionCommitment[:]...)
	appendBlob := func(value string) {
		admissionPreimage = binary.BigEndian.AppendUint32(admissionPreimage, uint32(len(value)))
		admissionPreimage = append(admissionPreimage, value...)
	}
	appendBlob("executor")
	appendBlob("route")
	admissionPreimage = append(admissionPreimage, id(26)...)
	appendBlob("")
	appendBlob("")
	admissionDigest := outputVectorDigest(t, "14adb4a3014416973ec2d989b50455ca2f0d8b5f0e2bdc5c2289c20d5b4de5af")
	if got, err := OutputReserveAdmissionDigest(s, marker); err != nil || got != admissionDigest || sha256.Sum256(admissionPreimage) != admissionDigest {
		t.Fatal("reservation admission digest includes wrong fields", err)
	}
	if request, err := NewOutputReserveRequest(s); err != nil || request.Purpose() != OutputReservePurpose || request.Digest() != reserveDigest || !request.Valid() {
		t.Fatal("reserve signing request differs from exact subject", err)
	}
	if decoded, err := DecodeOutputReserveSubject(want); err != nil || decoded != s {
		t.Fatal("reserve subject did not round-trip", err)
	}
	t.Run("distinct birth target row", func(t *testing.T) {
		// The frozen reserve order places the immutable birth target after the
		// current target. Change only those bytes in the independent field vector.
		const beforeBirth = len("ENKV/K2-OUTPUT-RESERVE/v5\x00") + 2 + 1 + 5*32 + 1 + 4 + 1 + 7*32 + 8
		decoded, err := DecodeOutputReserveSubject(want)
		if err != nil {
			t.Fatal("canonical reserve with distinct birth target refused", err)
		}
		encoded, err := EncodeOutputReserveSubject(decoded)
		if err != nil || !bytes.Equal(encoded, want) {
			t.Fatal("birth target bytes changed on round-trip", err)
		}
		other := bytes.Clone(want)
		copy(other[beforeBirth:beforeBirth+32], id(23))
		changed, err := DecodeOutputReserveSubject(other)
		if err != nil {
			t.Fatal("alternate birth target refused", err)
		}
		before, beforeErr := OutputReserveAdmissionDigest(decoded, outputReserveMarkerFixture(t, decoded))
		after, afterErr := OutputReserveAdmissionDigest(changed, outputReserveMarkerFixture(t, changed))
		if beforeErr != nil || afterErr != nil || before == after {
			t.Fatal("birth target omitted from reservation admission", beforeErr, afterErr)
		}
		firstRequest, firstErr := NewOutputReserveRequest(decoded)
		secondRequest, secondErr := NewOutputReserveRequest(changed)
		if firstErr != nil || secondErr != nil || firstRequest.Digest() == secondRequest.Digest() {
			t.Fatal("birth target omitted from full reserve signature", firstErr, secondErr)
		}
	})
	before, _ := OutputReserveAdmissionDigest(s, marker)
	requestBefore, _ := NewOutputReserveRequest(s)
	s.DispatchContextDigest = publicationTestID(77)
	s.HeadCoreDigest = publicationTestID(78)
	s.ConditionalPlanDigest = publicationTestID(79)
	if after, err := OutputReserveAdmissionDigest(s, marker); err != nil || after != before {
		t.Fatal("later dispatch or HEAD field entered admission digest", err)
	}
	if requestAfter, err := NewOutputReserveRequest(s); err != nil || requestAfter.Digest() == requestBefore.Digest() {
		t.Fatal("full reserve signature omitted later fields", err)
	}
	s.RequestContractDigest = publicationTestID(80)
	if after, err := OutputReserveAdmissionDigest(s, outputReserveMarkerFixture(t, s)); err != nil || after == before {
		t.Fatal("request contract missing from admission digest", err)
	}
}

// full_only: false
func TestOutputCloseSubjectIndependentBytesAndCurrentPredecessor(t *testing.T) {
	s := outputCloseSubjectFixture()
	body, err := EncodeOutputCloseSubject(s)
	if err != nil {
		t.Fatal(err)
	}
	id := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	want := append([]byte("ENKV/K2-OUTPUT-CLOSE/v4\x00"), 0, 4, PublicationWriteValue)
	for _, b := range []byte{1, 2, 3, 6, 7, 8} {
		want = append(want, id(b)...)
	}
	want = append(want, byte(GCP), 0, 0, 0, 1, '1')
	for b := byte(9); b <= 15; b++ {
		want = append(want, id(b)...)
	}
	want = append(want, make([]byte, 64)...)
	want = append(want, id(16)...)
	want = append(want, PublicationMayHaveEnteredEntry, PublicationRequestAcknowledged, 1)
	want = append(want, id(17)...)
	want = append(want, id(18)...)
	want = binary.BigEndian.AppendUint32(want, SuccessorHeadCoreMinLength)
	want = append(want, id(19)...)
	if !bytes.Equal(body, want) {
		t.Fatal("close subject bytes differ from independent field preimage")
	}
	closeDigest := outputVectorDigest(t, "7a2057fe301bbd233010c65b7e4a2675becad288afeb5e15936ecbcf459193a1")
	if sha256.Sum256(body) != closeDigest {
		t.Fatal("close subject digest differs from independent literal")
	}
	if request, err := NewOutputCloseRequest(s); err != nil || request.Purpose() != OutputClosePurpose || request.Digest() != closeDigest || !request.Valid() {
		t.Fatal("close signing request differs from exact subject", err)
	}
	if decoded, err := DecodeOutputCloseSubject(want); err != nil || decoded != s {
		t.Fatal("close subject did not round-trip", err)
	}
	// Closing after an unrelated transition uses a new current predecessor,
	// while the original retained admission identity remains exact.
	requestBefore, _ := NewOutputCloseRequest(s)
	s.PredecessorRevisionID = publicationTestID(81)
	s.PredecessorFullHEADDigest = publicationTestID(82)
	s.ConfigurationDigest = publicationTestID(83)
	requestAfter, err := NewOutputCloseRequest(s)
	if err != nil || requestAfter.Digest() == requestBefore.Digest() || s.ReservationAdmissionDigest != publicationTestID(6) {
		t.Fatal("later current predecessor invalidated original reservation", err)
	}
}

// full_only: false
func TestOutputSigningSubjectsClosedBoundsAndRoles(t *testing.T) {
	reserve := outputReserveSubjectFixture()
	close := outputCloseSubjectFixture()
	reserve.PredecessorToken = Token{Family: AWS, Value: `"` + strings.Repeat("a", 254) + `"`}
	close.PredecessorToken = reserve.PredecessorToken
	if b, err := EncodeOutputReserveSubject(reserve); err != nil || len(b) != 1040 || OutputReserveSubjectMaxLength != 1040 {
		t.Fatal("maximum reserve subject length", len(b), err)
	}
	if b, err := EncodeOutputCloseSubject(close); err != nil || len(b) != 903 || OutputCloseSubjectMaxLength != 903 {
		t.Fatal("maximum close subject length", len(b), err)
	}
	for _, purpose := range []Purpose{OutputReservePurpose, OutputClosePurpose} {
		if !SigningPurposeAllowed(NormalSigningRole, purpose) || SigningPurposeAllowed(RecoverySigningRole, purpose) {
			t.Fatal("output purpose escaped normal authority")
		}
	}
	reserve.PredecessorToken.Value += "a"
	if _, err := EncodeOutputReserveSubject(reserve); err == nil {
		t.Fatal("overlong predecessor token accepted")
	}
	close.Action = 0
	if _, err := EncodeOutputCloseSubject(close); err == nil {
		t.Fatal("unknown close action accepted")
	}
}

// full_only: false
func TestOutputSigningSubjectsRejectMalformedWireAndRelations(t *testing.T) {
	reserve := outputReserveSubjectFixture()
	close := outputCloseSubjectFixture()
	reserveBody, _ := EncodeOutputReserveSubject(reserve)
	closeBody, _ := EncodeOutputCloseSubject(close)
	for i := 0; i < len(reserveBody); i++ {
		if _, err := DecodeOutputReserveSubject(reserveBody[:i]); err == nil {
			t.Fatal("truncated reserve subject accepted", i)
		}
	}
	for i := 0; i < len(closeBody); i++ {
		if _, err := DecodeOutputCloseSubject(closeBody[:i]); err == nil {
			t.Fatal("truncated close subject accepted", i)
		}
	}
	reserve.BlockerCount = 0
	if _, err := EncodeOutputReserveSubject(reserve); err == nil {
		t.Fatal("nonzero blocker digest with zero count accepted")
	}
	reserve = outputReserveSubjectFixture()
	reserve.DispatchContextDigest = ID{}
	if _, err := EncodeOutputReserveSubject(reserve); err == nil {
		t.Fatal("missing dispatch digest accepted")
	}
	reserve = outputReserveSubjectFixture()
	reserve.BirthTargetRowDigest = ID{}
	if _, err := EncodeOutputReserveSubject(reserve); err == nil {
		t.Fatal("owned action without birth target accepted")
	}
	reserve = outputReserveSubjectFixture()
	reserve.Action = PublicationCreateWithValue
	reserve.OwnedBirthAttemptID = ID{}
	if _, err := EncodeOutputReserveSubject(reserve); err == nil {
		t.Fatal("create action with birth target accepted")
	}
	reserve.BirthTargetRowDigest = ID{}
	if _, err := EncodeOutputReserveSubject(reserve); err != nil {
		t.Fatal("create action with zero birth target refused", err)
	}
	reserve.Action = PublicationDeleteReservedSlot
	reserve.UncertainCreateAttemptID = publicationTestID(81)
	reserve.ExclusiveNamespaceDigest = publicationTestID(82)
	reserve.ValueBasisDigest = ID{}
	reserve.PolicyDigest = ID{}
	if _, err := EncodeOutputReserveSubject(reserve); err != nil {
		t.Fatal("reserved-slot delete with zero birth target refused", err)
	}
	reserve.BirthTargetRowDigest = publicationTestID(83)
	if _, err := EncodeOutputReserveSubject(reserve); err == nil {
		t.Fatal("reserved-slot delete with birth target accepted")
	}
	close.EntryClass = PublicationNotEntered
	if _, err := EncodeOutputCloseSubject(close); err == nil {
		t.Fatal("acknowledgement with no entry accepted")
	}
}

// full_only: false
func TestOutputReserveAdmissionBindsEveryFieldAndExcludesLaterCommitments(t *testing.T) {
	base := outputReserveSubjectFixture()
	baseMarker := outputReserveMarkerFixture(t, base)
	before, err := OutputReserveAdmissionDigest(base, baseMarker)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*OutputReserveSubject){
		"domain":                  func(s *OutputReserveSubject) { s.DomainID = publicationTestID(99) },
		"operation":               func(s *OutputReserveSubject) { s.OperationID = publicationTestID(99) },
		"attempt":                 func(s *OutputReserveSubject) { s.AttemptID = publicationTestID(99) },
		"predecessor revision":    func(s *OutputReserveSubject) { s.PredecessorRevisionID = publicationTestID(99) },
		"predecessor HEAD digest": func(s *OutputReserveSubject) { s.PredecessorFullHEADDigest = publicationTestID(99) },
		"predecessor token":       func(s *OutputReserveSubject) { s.PredecessorToken.Value = "2" },
		"predecessor provider":    func(s *OutputReserveSubject) { s.PredecessorToken = Token{Family: AWS, Value: `"etag"`} },
		"access root":             func(s *OutputReserveSubject) { s.CurrentAccessRoot = publicationTestID(99) },
		"configuration":           func(s *OutputReserveSubject) { s.ConfigurationDigest = publicationTestID(99) },
		"coordinate":              func(s *OutputReserveSubject) { s.CoordinateID = publicationTestID(99) },
		"incarnation":             func(s *OutputReserveSubject) { s.PublicationIncarnationID = publicationTestID(99) },
		"ordinal":                 func(s *OutputReserveSubject) { s.AdmissionOrdinal++ },
		"binding":                 func(s *OutputReserveSubject) { s.BindingIncarnationID = publicationTestID(99) },
		"entry":                   func(s *OutputReserveSubject) { s.EntryIncarnationID = publicationTestID(99) },
		"target":                  func(s *OutputReserveSubject) { s.TargetRowDigest = publicationTestID(99) },
		"birth target":            func(s *OutputReserveSubject) { s.BirthTargetRowDigest = publicationTestID(99) },
		"owned birth":             func(s *OutputReserveSubject) { s.OwnedBirthAttemptID = publicationTestID(99) },
		"value basis":             func(s *OutputReserveSubject) { s.ValueBasisDigest = publicationTestID(99) },
		"policy":                  func(s *OutputReserveSubject) { s.PolicyDigest = publicationTestID(99) },
		"request contract":        func(s *OutputReserveSubject) { s.RequestContractDigest = publicationTestID(99) },
		"blocker count":           func(s *OutputReserveSubject) { s.BlockerCount++ },
		"blocker digest":          func(s *OutputReserveSubject) { s.BlockerDigest = publicationTestID(99) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			change(&changed)
			after, err := OutputReserveAdmissionDigest(changed, outputReserveMarkerFixture(t, changed))
			if err != nil || after == before {
				t.Fatal("admission omitted field", err)
			}
		})
	}
	for name, change := range map[string]func(*OutputReserveSubject){
		"dispatch":         func(s *OutputReserveSubject) { s.DispatchContextDigest = publicationTestID(99) },
		"HEAD digest":      func(s *OutputReserveSubject) { s.HeadCoreDigest = publicationTestID(99) },
		"HEAD length":      func(s *OutputReserveSubject) { s.HeadCoreLength++ },
		"conditional plan": func(s *OutputReserveSubject) { s.ConditionalPlanDigest = publicationTestID(99) },
	} {
		t.Run("excluded "+name, func(t *testing.T) {
			changed := base
			change(&changed)
			after, err := OutputReserveAdmissionDigest(changed, baseMarker)
			first, e1 := NewOutputReserveRequest(base)
			second, e2 := NewOutputReserveRequest(changed)
			if err != nil || after != before || e1 != nil || e2 != nil || first.Digest() == second.Digest() {
				t.Fatal("later field admission/full subject boundary changed", err, e1, e2)
			}
		})
	}
	for name, change := range map[string]func(*PublicationMarker){
		"executor":          func(m *PublicationMarker) { m.ExecutorID = "other" },
		"credential route":  func(m *PublicationMarker) { m.CredentialRouteID = "other" },
		"response contract": func(m *PublicationMarker) { m.Evidence.ResponseContractDigest = publicationTestID(99) },
		"acting recipient": func(m *PublicationMarker) {
			m.Projection.ActingRecipientID = publicationTestID(99)
			m.ProjectionCommitment, _ = PublicationProjectionCommitment(m.Projection)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := baseMarker
			change(&changed)
			if after, err := OutputReserveAdmissionDigest(base, changed); err != nil || after == before {
				t.Fatal("admission omitted retained marker field", err)
			}
		})
	}
	for name, change := range map[string]func(*PublicationMarker){
		"authority digest": func(m *PublicationMarker) { m.AuthoritySubjectDigest = publicationTestID(99) },
		"result state":     func(m *PublicationMarker) { m.State = PublicationAcknowledged },
		"result status":    func(m *PublicationMarker) { m.Evidence.NormalizedStatus = 201 },
		"result resource":  func(m *PublicationMarker) { m.Evidence.SafeResourceID = "exact-resource" },
	} {
		t.Run("excluded "+name, func(t *testing.T) {
			changed := baseMarker
			change(&changed)
			if after, err := OutputReserveAdmissionDigest(base, changed); err != nil || after != before {
				t.Fatal("later result field entered admission", err)
			}
		})
	}

	t.Run("reserved deletion optional fields", func(t *testing.T) {
		reserved := base
		reserved.Action = PublicationDeleteReservedSlot
		reserved.OwnedBirthAttemptID, reserved.BirthTargetRowDigest, reserved.ValueBasisDigest, reserved.PolicyDigest = ID{}, ID{}, ID{}, ID{}
		reserved.UncertainCreateAttemptID, reserved.ExclusiveNamespaceDigest = publicationTestID(90), publicationTestID(91)
		before, err := OutputReserveAdmissionDigest(reserved, outputReserveMarkerFixture(t, reserved))
		if err != nil {
			t.Fatal(err)
		}
		for name, change := range map[string]func(*OutputReserveSubject){
			"uncertain create":    func(s *OutputReserveSubject) { s.UncertainCreateAttemptID = publicationTestID(99) },
			"exclusive namespace": func(s *OutputReserveSubject) { s.ExclusiveNamespaceDigest = publicationTestID(99) },
		} {
			t.Run(name, func(t *testing.T) {
				changed := reserved
				change(&changed)
				if after, err := OutputReserveAdmissionDigest(changed, outputReserveMarkerFixture(t, changed)); err != nil || after == before {
					t.Fatal("admission omitted reserved deletion field", err)
				}
			})
		}
	})
	t.Run("creation action and birth profile", func(t *testing.T) {
		creation := base
		creation.Action = PublicationCreateWithValue
		creation.OwnedBirthAttemptID, creation.BirthTargetRowDigest = ID{}, ID{}
		marker := outputReserveMarkerFixture(t, creation)
		marker.BirthServiceContractID, marker.BirthTargetContractID = "profile", "2"
		before, err := OutputReserveAdmissionDigest(creation, marker)
		if err != nil {
			t.Fatal(err)
		}
		baseDigest, err := OutputReserveAdmissionDigest(base, baseMarker)
		if err != nil || before == baseDigest {
			t.Fatal("admission omitted legal action change")
		}
		for name, change := range map[string]func(*PublicationMarker){
			"birth service":         func(m *PublicationMarker) { m.BirthServiceContractID = "other" },
			"birth target contract": func(m *PublicationMarker) { m.BirthTargetContractID = "3" },
		} {
			t.Run(name, func(t *testing.T) {
				changed := marker
				change(&changed)
				if after, err := OutputReserveAdmissionDigest(creation, changed); err != nil || after == before {
					t.Fatal("admission omitted birth profile field", err)
				}
			})
		}
	})
}
