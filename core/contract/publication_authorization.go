package contract

import "bytes"

const (
	outputReserveSubjectPrefix    = "ENKV/K2-OUTPUT-RESERVE/v5\x00"
	outputReserveAdmissionPrefix  = "ENKV/K2-OUTPUT-RESERVE-ADMISSION/v5\x00"
	outputCloseSubjectPrefix      = "ENKV/K2-OUTPUT-CLOSE/v4\x00"
	OutputReserveSubjectMaxLength = 1040
	OutputCloseSubjectMaxLength   = 903
)

// OutputReserveSubject binds one selected, may-have-entered publication
// reservation. The admission fields precede the dispatch and HEAD commitments.
type OutputReserveSubject struct {
	Schema                                                                          uint16
	Action                                                                          uint8
	DomainID, OperationID, AttemptID                                                ID
	PredecessorRevisionID, PredecessorFullHEADDigest                                ID
	PredecessorToken                                                                Token
	CurrentAccessRoot, ConfigurationDigest, CoordinateID                            ID
	PublicationIncarnationID                                                        ID
	AdmissionOrdinal                                                                uint64
	BindingIncarnationID, EntryIncarnationID, TargetRowDigest, BirthTargetRowDigest ID
	OwnedBirthAttemptID, UncertainCreateAttemptID, ExclusiveNamespaceDigest         ID
	ValueBasisDigest, PolicyDigest, RequestContractDigest, DispatchContextDigest    ID
	BlockerCount                                                                    uint16
	BlockerDigest, HeadCoreDigest                                                   ID
	HeadCoreLength                                                                  uint32
	ConditionalPlanDigest                                                           ID
}

// OutputCloseSubject binds a result to the retained reservation admission and
// to the then-current predecessor. It does not require the reserve HEAD to be
// the current HEAD.
type OutputCloseSubject struct {
	Schema                                                                  uint16
	Action                                                                  uint8
	DomainID, OperationID, AttemptID                                        ID
	ReservationAdmissionDigest                                              ID
	PredecessorRevisionID, PredecessorFullHEADDigest                        ID
	PredecessorToken                                                        Token
	CurrentAccessRoot, ConfigurationDigest, CoordinateID                    ID
	BindingIncarnationID, EntryIncarnationID, TargetRowDigest               ID
	OwnedBirthAttemptID, UncertainCreateAttemptID, ExclusiveNamespaceDigest ID
	ActionProjectionCommitment                                              ID
	EntryClass, ResultClass, LateRisk                                       uint8
	ResultEvidenceDigest, HeadCoreDigest                                    ID
	HeadCoreLength                                                          uint32
	ConditionalPlanDigest                                                   ID
}

func outputAuthorizationActionValid(action uint8, owned, uncertain, exclusive ID) bool {
	switch action {
	case PublicationCreateEmpty, PublicationCreateWithValue:
		return owned.IsZero() && uncertain.IsZero() && exclusive.IsZero()
	case PublicationWriteValue, PublicationUpdatePolicy, PublicationDeleteOwned:
		return !owned.IsZero() && uncertain.IsZero() && exclusive.IsZero()
	case PublicationDeleteReservedSlot:
		return owned.IsZero() && !uncertain.IsZero() && !exclusive.IsZero()
	default:
		return false
	}
}

func outputReserveAdmissionValid(s OutputReserveSubject) bool {
	if s.Schema != 5 || s.AdmissionOrdinal == 0 || !publicIDsValid(s.DomainID, s.OperationID, s.AttemptID, s.PredecessorRevisionID, s.PredecessorFullHEADDigest,
		s.CurrentAccessRoot, s.ConfigurationDigest, s.CoordinateID, s.PublicationIncarnationID,
		s.BindingIncarnationID, s.EntryIncarnationID, s.TargetRowDigest,
		s.RequestContractDigest) || !s.PredecessorToken.Valid() ||
		!outputAuthorizationActionValid(s.Action, s.OwnedBirthAttemptID,
			s.UncertainCreateAttemptID, s.ExclusiveNamespaceDigest) ||
		(s.Action == PublicationCreateEmpty || s.Action == PublicationCreateWithValue ||
			s.Action == PublicationDeleteReservedSlot) != s.BirthTargetRowDigest.IsZero() ||
		s.BlockerCount > MaxPublicationMarkers ||
		(s.BlockerCount == 0) != s.BlockerDigest.IsZero() {
		return false
	}
	switch s.Action {
	case PublicationCreateEmpty:
		return s.ValueBasisDigest.IsZero()
	case PublicationCreateWithValue, PublicationWriteValue:
		return !s.ValueBasisDigest.IsZero()
	case PublicationUpdatePolicy:
		return s.ValueBasisDigest.IsZero() && !s.PolicyDigest.IsZero()
	case PublicationDeleteOwned, PublicationDeleteReservedSlot:
		return s.ValueBasisDigest.IsZero() && s.PolicyDigest.IsZero()
	}
	return false
}

func outputReserveSubjectValid(s OutputReserveSubject) bool {
	return outputReserveAdmissionValid(s) &&
		publicIDsValid(s.DispatchContextDigest, s.HeadCoreDigest, s.ConditionalPlanDigest) &&
		s.HeadCoreLength >= SuccessorHeadCoreMinLength && s.HeadCoreLength <= SuccessorHeadCoreMaxLength
}

func writeOutputReserveAdmission(w *cryptoWriter, s OutputReserveSubject) {
	w.u16(s.Schema)
	w.u8(s.Action)
	for _, id := range [...]ID{s.DomainID, s.OperationID, s.AttemptID, s.PredecessorRevisionID, s.PredecessorFullHEADDigest} {
		w.id(id)
	}
	writeToken(w, s.PredecessorToken)
	for _, id := range [...]ID{s.CurrentAccessRoot, s.ConfigurationDigest, s.CoordinateID, s.PublicationIncarnationID} {
		w.id(id)
	}
	w.u64(s.AdmissionOrdinal)
	for _, id := range [...]ID{s.BindingIncarnationID, s.EntryIncarnationID, s.TargetRowDigest, s.BirthTargetRowDigest,
		s.OwnedBirthAttemptID, s.UncertainCreateAttemptID, s.ExclusiveNamespaceDigest, s.ValueBasisDigest, s.PolicyDigest, s.RequestContractDigest} {
		w.id(id)
	}
}

// OutputReserveAdmissionDigest is the selected marker's AuthoritySubjectDigest.
// DispatchContextDigest and the final HEAD fields are deliberately excluded.
func OutputReserveAdmissionDigest(s OutputReserveSubject, marker PublicationMarker) (ID, error) {
	projection := marker.Projection
	if !outputReserveAdmissionValid(s) || marker.Schema != 5 || marker.DomainID != s.DomainID || marker.OperationID != s.OperationID ||
		marker.AttemptID != s.AttemptID || marker.CoordinateID != s.CoordinateID || marker.PublicationIncarnationID != s.PublicationIncarnationID || marker.AdmissionOrdinal != s.AdmissionOrdinal ||
		marker.BlockerCount != s.BlockerCount || marker.BlockerDigest != s.BlockerDigest ||
		projection.DomainID != s.DomainID || projection.ConfigurationDigest != s.ConfigurationDigest || projection.CoordinateID != s.CoordinateID ||
		projection.BindingIncarnationID != s.BindingIncarnationID || projection.EntryIncarnationID != s.EntryIncarnationID || projection.TargetRowDigest != s.TargetRowDigest ||
		projection.Action != s.Action || projection.OwnedBirthAttemptID != s.OwnedBirthAttemptID || projection.UncertainCreateAttemptID != s.UncertainCreateAttemptID ||
		projection.ExclusiveNamespaceDigest != s.ExclusiveNamespaceDigest || projection.ValueBasisDigest != s.ValueBasisDigest || projection.PolicyDigest != s.PolicyDigest || projection.RequestContractDigest != s.RequestContractDigest ||
		!outputIdentifierValid(marker.ExecutorID) || !outputIdentifierValid(marker.CredentialRouteID) || marker.Evidence.ResponseContractDigest.IsZero() {
		return ID{}, ErrSubject
	}
	w := cryptoHashWriter(outputReserveAdmissionPrefix)
	writeOutputReserveAdmission(&w, s)
	w.u16(s.BlockerCount)
	w.id(s.BlockerDigest)
	commitment, err := PublicationProjectionCommitment(projection)
	if err != nil || commitment != marker.ProjectionCommitment {
		return ID{}, ErrSubject
	}
	create := s.Action == PublicationCreateEmpty || s.Action == PublicationCreateWithValue
	if create != (outputIdentifierValid(marker.BirthServiceContractID) && outputIdentifierValid(marker.BirthTargetContractID)) || !create && (marker.BirthServiceContractID != "" || marker.BirthTargetContractID != "") {
		return ID{}, ErrSubject
	}
	w.id(marker.ProjectionCommitment)
	w.blob([]byte(marker.ExecutorID))
	w.blob([]byte(marker.CredentialRouteID))
	w.id(marker.Evidence.ResponseContractDigest)
	w.blob([]byte(marker.BirthServiceContractID))
	w.blob([]byte(marker.BirthTargetContractID))
	return w.result(0).Digest, nil
}

func writeOutputReserveSubject(w *cryptoWriter, s OutputReserveSubject) {
	w.raw([]byte(outputReserveSubjectPrefix))
	writeOutputReserveAdmission(w, s)
	w.id(s.DispatchContextDigest)
	w.u16(s.BlockerCount)
	w.id(s.BlockerDigest)
	w.id(s.HeadCoreDigest)
	w.u32(s.HeadCoreLength)
	w.id(s.ConditionalPlanDigest)
}

func EncodeOutputReserveSubject(s OutputReserveSubject) ([]byte, error) {
	if !outputReserveSubjectValid(s) {
		return nil, ErrSubject
	}
	w := cryptoWriter{b: make([]byte, 0, OutputReserveSubjectMaxLength)}
	writeOutputReserveSubject(&w, s)
	if len(w.b) > OutputReserveSubjectMaxLength {
		return nil, ErrSubject
	}
	return w.b, nil
}

func DecodeOutputReserveSubject(b []byte) (OutputReserveSubject, error) {
	if len(b) > OutputReserveSubjectMaxLength {
		return OutputReserveSubject{}, ErrSubject
	}
	r := cryptoReader{b: b}
	if !bytes.Equal(r.take(len(outputReserveSubjectPrefix)), []byte(outputReserveSubjectPrefix)) {
		return OutputReserveSubject{}, ErrSubject
	}
	s := OutputReserveSubject{Schema: r.u16(), Action: r.u8(), DomainID: r.id(), OperationID: r.id(),
		AttemptID:             r.id(),
		PredecessorRevisionID: r.id(), PredecessorFullHEADDigest: r.id()}
	token := readToken(&r)
	s.PredecessorToken = Token{Family: token.Family, Value: string(token.Value)}
	s.CurrentAccessRoot, s.ConfigurationDigest, s.CoordinateID = r.id(), r.id(), r.id()
	s.PublicationIncarnationID, s.AdmissionOrdinal = r.id(), r.u64()
	s.BindingIncarnationID, s.EntryIncarnationID, s.TargetRowDigest = r.id(), r.id(), r.id()
	s.BirthTargetRowDigest = r.id()
	s.OwnedBirthAttemptID, s.UncertainCreateAttemptID, s.ExclusiveNamespaceDigest = r.id(), r.id(), r.id()
	s.ValueBasisDigest, s.PolicyDigest, s.RequestContractDigest, s.DispatchContextDigest = r.id(), r.id(), r.id(), r.id()
	s.BlockerCount, s.BlockerDigest = r.u16(), r.id()
	s.HeadCoreDigest, s.HeadCoreLength, s.ConditionalPlanDigest = r.id(), r.u32(), r.id()
	if r.end() != nil || !outputReserveSubjectValid(s) {
		return OutputReserveSubject{}, ErrSubject
	}
	return s, nil
}

func NewOutputReserveRequest(s OutputReserveSubject) (SignRequest, error) {
	if !outputReserveSubjectValid(s) {
		return SignRequest{}, ErrSubject
	}
	w := cryptoHashWriter("")
	writeOutputReserveSubject(&w, s)
	return SignRequest{purpose: OutputReservePurpose, digest: w.result(0).Digest}, nil
}

func outputCloseSubjectValid(s OutputCloseSubject) bool {
	return s.Schema == 4 && publicIDsValid(s.DomainID, s.OperationID, s.AttemptID,
		s.ReservationAdmissionDigest,
		s.PredecessorRevisionID, s.PredecessorFullHEADDigest, s.CurrentAccessRoot,
		s.ConfigurationDigest, s.CoordinateID, s.BindingIncarnationID,
		s.EntryIncarnationID, s.TargetRowDigest, s.ActionProjectionCommitment,
		s.ResultEvidenceDigest, s.HeadCoreDigest, s.ConditionalPlanDigest) &&
		s.PredecessorToken.Valid() &&
		outputAuthorizationActionValid(s.Action, s.OwnedBirthAttemptID,
			s.UncertainCreateAttemptID, s.ExclusiveNamespaceDigest) &&
		s.EntryClass >= PublicationNotEntered && s.EntryClass <= PublicationMayHaveEnteredEntry &&
		s.ResultClass <= PublicationQualifiedNoEffect && s.LateRisk <= 1 &&
		(s.ResultClass != PublicationRequestAcknowledged || s.EntryClass == PublicationMayHaveEnteredEntry) &&
		s.HeadCoreLength >= SuccessorHeadCoreMinLength && s.HeadCoreLength <= SuccessorHeadCoreMaxLength
}

func writeOutputCloseSubject(w *cryptoWriter, s OutputCloseSubject) {
	w.raw([]byte(outputCloseSubjectPrefix))
	w.u16(s.Schema)
	w.u8(s.Action)
	for _, id := range [...]ID{s.DomainID, s.OperationID, s.AttemptID, s.ReservationAdmissionDigest, s.PredecessorRevisionID,
		s.PredecessorFullHEADDigest} {
		w.id(id)
	}
	writeToken(w, s.PredecessorToken)
	for _, id := range [...]ID{s.CurrentAccessRoot, s.ConfigurationDigest, s.CoordinateID,
		s.BindingIncarnationID, s.EntryIncarnationID, s.TargetRowDigest,
		s.OwnedBirthAttemptID, s.UncertainCreateAttemptID, s.ExclusiveNamespaceDigest,
		s.ActionProjectionCommitment} {
		w.id(id)
	}
	w.u8(s.EntryClass)
	w.u8(s.ResultClass)
	w.u8(s.LateRisk)
	w.id(s.ResultEvidenceDigest)
	w.id(s.HeadCoreDigest)
	w.u32(s.HeadCoreLength)
	w.id(s.ConditionalPlanDigest)
}

func EncodeOutputCloseSubject(s OutputCloseSubject) ([]byte, error) {
	if !outputCloseSubjectValid(s) {
		return nil, ErrSubject
	}
	w := cryptoWriter{b: make([]byte, 0, OutputCloseSubjectMaxLength)}
	writeOutputCloseSubject(&w, s)
	if len(w.b) > OutputCloseSubjectMaxLength {
		return nil, ErrSubject
	}
	return w.b, nil
}

func DecodeOutputCloseSubject(b []byte) (OutputCloseSubject, error) {
	if len(b) > OutputCloseSubjectMaxLength {
		return OutputCloseSubject{}, ErrSubject
	}
	r := cryptoReader{b: b}
	if !bytes.Equal(r.take(len(outputCloseSubjectPrefix)), []byte(outputCloseSubjectPrefix)) {
		return OutputCloseSubject{}, ErrSubject
	}
	s := OutputCloseSubject{Schema: r.u16(), Action: r.u8(), DomainID: r.id(), OperationID: r.id(),
		AttemptID:                  r.id(),
		ReservationAdmissionDigest: r.id(), PredecessorRevisionID: r.id(),
		PredecessorFullHEADDigest: r.id()}
	token := readToken(&r)
	s.PredecessorToken = Token{Family: token.Family, Value: string(token.Value)}
	s.CurrentAccessRoot, s.ConfigurationDigest, s.CoordinateID = r.id(), r.id(), r.id()
	s.BindingIncarnationID, s.EntryIncarnationID, s.TargetRowDigest = r.id(), r.id(), r.id()
	s.OwnedBirthAttemptID, s.UncertainCreateAttemptID, s.ExclusiveNamespaceDigest = r.id(), r.id(), r.id()
	s.ActionProjectionCommitment = r.id()
	s.EntryClass, s.ResultClass, s.LateRisk = r.u8(), r.u8(), r.u8()
	s.ResultEvidenceDigest, s.HeadCoreDigest, s.HeadCoreLength, s.ConditionalPlanDigest = r.id(), r.id(), r.u32(), r.id()
	if r.end() != nil || !outputCloseSubjectValid(s) {
		return OutputCloseSubject{}, ErrSubject
	}
	return s, nil
}

func NewOutputCloseRequest(s OutputCloseSubject) (SignRequest, error) {
	if !outputCloseSubjectValid(s) {
		return SignRequest{}, ErrSubject
	}
	w := cryptoHashWriter("")
	writeOutputCloseSubject(&w, s)
	return SignRequest{purpose: OutputClosePurpose, digest: w.result(0).Digest}, nil
}
