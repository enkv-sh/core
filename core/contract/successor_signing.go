package contract

const (
	SuccessorProbeSchema     uint16 = 1
	SuccessorSignerEvidence  uint8  = 1
	SuccessorKEKEvidence     uint8  = 2
	SuccessorNormalSigner    uint8  = 1
	SuccessorAuthorityKEK    uint8  = 2
	SuccessorRecoverySigner  uint8  = 3
	SuccessorRecoveryKEK     uint8  = 4
	SuccessorProbeCoreLength        = 228
	signerProbePrefix               = cryptoPurposePrefix + "successor-signer-probe\x00"
)

// SuccessorProbeCore proves a requested signing route, never its authority.
// The caller matches TargetRole and binding to the exact admitted signer;
// the common runtime purpose alone does not establish that relation.
type SuccessorProbeCore struct {
	Schema                                                         uint16
	EvidenceKind, TargetRole                                       uint8
	DomainID, CoordinateID, AdmissionID, PredecessorFullHEADDigest ID
	RequestCoreDigest, SuccessorBindingDigest, ProbeAttemptID      ID
}

func (v SuccessorProbeCore) valid() bool {
	return v.Schema == SuccessorProbeSchema && v.EvidenceKind == SuccessorSignerEvidence &&
		(v.TargetRole == SuccessorNormalSigner || v.TargetRole == SuccessorRecoverySigner) &&
		publicIDsValid(v.DomainID, v.CoordinateID, v.AdmissionID, v.PredecessorFullHEADDigest,
			v.RequestCoreDigest, v.SuccessorBindingDigest, v.ProbeAttemptID)
}

func writeSuccessorProbeCore(w *cryptoWriter, v SuccessorProbeCore) {
	w.u16(v.Schema)
	w.u8(v.EvidenceKind)
	w.u8(v.TargetRole)
	for _, id := range []ID{v.DomainID, v.CoordinateID, v.AdmissionID, v.PredecessorFullHEADDigest,
		v.RequestCoreDigest, v.SuccessorBindingDigest, v.ProbeAttemptID} {
		w.id(id)
	}
}

func EncodeSuccessorProbeCore(v SuccessorProbeCore) ([]byte, error) {
	if !v.valid() {
		return nil, ErrSubject
	}
	w := cryptoWriter{b: make([]byte, 0, SuccessorProbeCoreLength)}
	writeSuccessorProbeCore(&w, v)
	return w.b, nil
}

func NewSuccessorSignerProbeRequest(v SuccessorProbeCore) (SignRequest, error) {
	if !v.valid() {
		return SignRequest{}, ErrSubject
	}
	w := cryptoHashWriter(signerProbePrefix)
	w.u32(SuccessorProbeCoreLength)
	writeSuccessorProbeCore(&w, v)
	return SignRequest{purpose: SuccessorSignerProbePurpose, digest: w.result(0).Digest}, nil
}
