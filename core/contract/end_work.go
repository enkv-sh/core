package contract

import "bytes"

const (
	endWorkSubjectPrefix    = "ENKV/K2-END-WORK/v8\x00"
	EndWorkSubjectMaxLength = 1024
)

// EndWorkSubject binds one effect-free administrative successor to its exact
// predecessor and selected owner. It carries commitments, not discarded work.
type EndWorkSubject struct {
	Schema                                                uint16
	DomainID, OperationID, AdmissionID, RequestCoreDigest ID
	PredecessorRevisionID, PredecessorFullHEADDigest      ID
	PredecessorToken                                      Token
	TargetGroupID, TargetOwnerID, TargetID                ID
	TargetKind, DutyKind                                  uint8
	SelectedEvidenceSummary                               uint16
	DependentGroups, RemovedSupport                       GeneratorDescriptor
	PreservedCurrent                                      DigestLength
	BeforeAccessRoot, AfterAccessRoot                     ID
	BeforeAccessIncarnationID, AfterAccessIncarnationID   ID
	BeforeAccessGeneration, AfterAccessGeneration         uint64
	BeforeWarningBits, AfterWarningBits                   uint8
	BeforeChildCount, AfterChildCount                     uint16
	BeforeChildBytes, AfterChildBytes                     uint64
	ReceiptDeltaDigest, HeadCoreDigest                    ID
	HeadCoreLength                                        uint32
	ConditionalPlanDigest                                 ID
}

func endWorkCoreValid(s EndWorkSubject) bool {
	if s.Schema != CanonicalSchema || !publicIDsValid(s.DomainID, s.OperationID, s.AdmissionID,
		s.PredecessorRevisionID, s.PredecessorFullHEADDigest,
		s.TargetGroupID, s.TargetOwnerID, s.TargetID, s.PreservedCurrent.Digest,
		s.BeforeAccessRoot, s.AfterAccessRoot, s.BeforeAccessIncarnationID, s.AfterAccessIncarnationID) ||
		!s.PredecessorToken.Valid() || s.TargetKind < AdministrativeGeneratedParent || s.TargetKind > AdministrativeGC ||
		!AdministrativeEvidenceValid(s.SelectedEvidenceSummary) ||
		(s.TargetKind == AdministrativeGeneratedDuty && (s.DutyKind < GeneratedDutyCreate || s.DutyKind > GeneratedDutyUnselectedCleanup) ||
			s.TargetKind != AdministrativeGeneratedDuty && s.DutyKind != 0) ||
		!s.DependentGroups.Valid() || s.DependentGroups.Count == 0 ||
		!s.RemovedSupport.Valid() || s.RemovedSupport.Count == 0 ||
		s.PreservedCurrent.Length == 0 ||
		s.BeforeAccessGeneration == 0 || s.AfterAccessGeneration == 0 ||
		(s.BeforeAccessRoot == s.AfterAccessRoot &&
			(s.BeforeAccessIncarnationID != s.AfterAccessIncarnationID || s.BeforeAccessGeneration != s.AfterAccessGeneration)) ||
		(s.BeforeAccessRoot != s.AfterAccessRoot &&
			!IncarnationCounterStep(s.BeforeAccessIncarnationID, s.BeforeAccessGeneration,
				s.AfterAccessIncarnationID, s.AfterAccessGeneration)) ||
		s.BeforeWarningBits&^uint8(0x1f) != 0 || s.AfterWarningBits&^uint8(0x1f) != 0 ||
		s.AfterWarningBits&s.BeforeWarningBits != s.BeforeWarningBits ||
		s.BeforeChildCount == 0 || s.AfterChildCount == 0 ||
		s.BeforeChildCount > MaxChildPages || s.AfterChildCount > MaxChildPages ||
		s.BeforeChildBytes == 0 || s.AfterChildBytes == 0 ||
		s.BeforeChildBytes > MaxChildPages*MaxRequiredSupportPageLength ||
		s.AfterChildBytes > MaxChildPages*MaxRequiredSupportPageLength {
		return false
	}
	return true
}

// EndWorkRequestCoreDigest has no receipt or successor root input. It is the
// one request identity used by the receipt and the complete signed subject.
func EndWorkRequestCoreDigest(s EndWorkSubject) (ID, error) {
	if !endWorkCoreValid(s) {
		return ID{}, ErrSubject
	}
	w := cryptoHashWriter("ENKV/K2-END-WORK/core/v6\x00")
	w.u16(s.Schema)
	for _, id := range []ID{s.DomainID, s.OperationID, s.AdmissionID,
		s.PredecessorRevisionID, s.PredecessorFullHEADDigest} {
		w.id(id)
	}
	writeToken(&w, s.PredecessorToken)
	for _, id := range []ID{s.TargetGroupID, s.TargetOwnerID, s.TargetID} {
		w.id(id)
	}
	w.u8(s.TargetKind)
	w.u8(s.DutyKind)
	w.u16(s.SelectedEvidenceSummary)
	writeGeneratorDescriptor(&w, s.DependentGroups)
	writeGeneratorDescriptor(&w, s.RemovedSupport)
	w.digestLength(s.PreservedCurrent)
	w.id(s.BeforeAccessRoot)
	w.id(s.AfterAccessRoot)
	w.id(s.BeforeAccessIncarnationID)
	w.id(s.AfterAccessIncarnationID)
	w.u64(s.BeforeAccessGeneration)
	w.u64(s.AfterAccessGeneration)
	w.u8(s.BeforeWarningBits)
	w.u8(s.AfterWarningBits)
	w.u16(s.BeforeChildCount)
	w.u16(s.AfterChildCount)
	w.u64(s.BeforeChildBytes)
	w.u64(s.AfterChildBytes)
	return w.result(0).Digest, nil
}

func endWorkSubjectValid(s EndWorkSubject) bool {
	core, err := EndWorkRequestCoreDigest(s)
	return err == nil && s.RequestCoreDigest == core &&
		publicIDsValid(s.ReceiptDeltaDigest, s.HeadCoreDigest, s.ConditionalPlanDigest) &&
		s.HeadCoreLength >= SuccessorHeadCoreMinLength && s.HeadCoreLength <= SuccessorHeadCoreMaxLength
}

func writeEndWorkSubject(w *cryptoWriter, s EndWorkSubject) {
	w.raw([]byte(endWorkSubjectPrefix))
	w.u16(s.Schema)
	for _, id := range []ID{s.DomainID, s.OperationID, s.AdmissionID, s.RequestCoreDigest,
		s.PredecessorRevisionID, s.PredecessorFullHEADDigest} {
		w.id(id)
	}
	writeToken(w, s.PredecessorToken)
	for _, id := range []ID{s.TargetGroupID, s.TargetOwnerID, s.TargetID} {
		w.id(id)
	}
	w.u8(s.TargetKind)
	w.u8(s.DutyKind)
	w.u16(s.SelectedEvidenceSummary)
	writeGeneratorDescriptor(w, s.DependentGroups)
	writeGeneratorDescriptor(w, s.RemovedSupport)
	w.digestLength(s.PreservedCurrent)
	w.id(s.BeforeAccessRoot)
	w.id(s.AfterAccessRoot)
	w.id(s.BeforeAccessIncarnationID)
	w.id(s.AfterAccessIncarnationID)
	w.u64(s.BeforeAccessGeneration)
	w.u64(s.AfterAccessGeneration)
	w.u8(s.BeforeWarningBits)
	w.u8(s.AfterWarningBits)
	w.u16(s.BeforeChildCount)
	w.u16(s.AfterChildCount)
	w.u64(s.BeforeChildBytes)
	w.u64(s.AfterChildBytes)
	w.id(s.ReceiptDeltaDigest)
	w.id(s.HeadCoreDigest)
	w.u32(s.HeadCoreLength)
	w.id(s.ConditionalPlanDigest)
}

func EncodeEndWorkSubject(s EndWorkSubject) ([]byte, error) {
	if !endWorkSubjectValid(s) {
		return nil, ErrSubject
	}
	w := cryptoWriter{b: make([]byte, 0, EndWorkSubjectMaxLength)}
	writeEndWorkSubject(&w, s)
	if len(w.b) > EndWorkSubjectMaxLength {
		return nil, ErrSubject
	}
	return w.b, nil
}

func DecodeEndWorkSubject(b []byte) (EndWorkSubject, error) {
	if len(b) > EndWorkSubjectMaxLength {
		return EndWorkSubject{}, ErrSubject
	}
	r := cryptoReader{b: b}
	if !bytes.Equal(r.take(len(endWorkSubjectPrefix)), []byte(endWorkSubjectPrefix)) {
		return EndWorkSubject{}, ErrSubject
	}
	s := EndWorkSubject{Schema: r.u16(), DomainID: r.id(), OperationID: r.id(),
		AdmissionID: r.id(), RequestCoreDigest: r.id(), PredecessorRevisionID: r.id(), PredecessorFullHEADDigest: r.id()}
	token := readToken(&r)
	s.PredecessorToken = Token{Family: token.Family, Value: string(token.Value)}
	s.TargetGroupID, s.TargetOwnerID, s.TargetID = r.id(), r.id(), r.id()
	s.TargetKind, s.DutyKind = r.u8(), r.u8()
	s.SelectedEvidenceSummary = r.u16()
	s.DependentGroups, s.RemovedSupport = readGeneratorDescriptor(&r), readGeneratorDescriptor(&r)
	s.PreservedCurrent = r.digestLength()
	s.BeforeAccessRoot, s.AfterAccessRoot = r.id(), r.id()
	s.BeforeAccessIncarnationID, s.AfterAccessIncarnationID = r.id(), r.id()
	s.BeforeAccessGeneration, s.AfterAccessGeneration = r.u64(), r.u64()
	s.BeforeWarningBits, s.AfterWarningBits = r.u8(), r.u8()
	s.BeforeChildCount, s.AfterChildCount = r.u16(), r.u16()
	s.BeforeChildBytes, s.AfterChildBytes = r.u64(), r.u64()
	s.ReceiptDeltaDigest, s.HeadCoreDigest = r.id(), r.id()
	s.HeadCoreLength = r.u32()
	s.ConditionalPlanDigest = r.id()
	if r.end() != nil || !endWorkSubjectValid(s) {
		return EndWorkSubject{}, ErrSubject
	}
	return s, nil
}

func NewEndWorkRequest(s EndWorkSubject) (SignRequest, error) {
	if !endWorkSubjectValid(s) {
		return SignRequest{}, ErrSubject
	}
	w := cryptoHashWriter("")
	writeEndWorkSubject(&w, s)
	return SignRequest{purpose: EndWorkPurpose, digest: w.result(0).Digest}, nil
}
