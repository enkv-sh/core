package contract

// SuccessorKEKProbeCore binds a private diagnostic to the admitted replacement
// context. It grants no access and contains no private challenge material.
type SuccessorKEKProbeCore struct {
	Schema, Profile                   uint16
	ProbeID                           ID
	Context                           ApplyContext
	SubjectKind                       uint8
	SubjectID, SuccessorBindingDigest ID
}

const SuccessorKEKProbeCoreLength = 2 + 2 + 32 + cryptoContextBlobLength + 1 + 2*32

func (v SuccessorKEKProbeCore) valid() bool {
	return v.Schema == CanonicalSchema && v.Profile == MaterialCryptoProfile &&
		publicIDsValid(v.ProbeID, v.SubjectID, v.SuccessorBindingDigest) && (v.SubjectKind == OrdinaryWrapSubject || v.SubjectKind == RecoveryWrapSubject) &&
		v.Context.OperationClass == CryptoAccessReplacementClass && cryptoContextError(v.Context) == nil
}
func writeSuccessorKEKProbe(w *cryptoWriter, v SuccessorKEKProbeCore) {
	w.u16(v.Schema)
	w.u16(v.Profile)
	w.id(v.ProbeID)
	w.context(v.Context)
	w.u8(v.SubjectKind)
	w.id(v.SubjectID)
	w.id(v.SuccessorBindingDigest)
}
func EncodeSuccessorKEKProbeCore(v SuccessorKEKProbeCore) ([]byte, error) {
	if !v.valid() {
		return nil, ErrCryptoMessage
	}
	w := cryptoWriter{b: make([]byte, 0, SuccessorKEKProbeCoreLength)}
	writeSuccessorKEKProbe(&w, v)
	return w.b, nil
}
func SuccessorKEKProbeMaterialContextDigest(v SuccessorKEKProbeCore) (ID, error) {
	if !v.valid() {
		return ID{}, ErrCryptoMessage
	}
	w := cryptoHashWriter(valueMaterialDigestPrefix)
	w.u32(SuccessorKEKProbeCoreLength)
	writeSuccessorKEKProbe(&w, v)
	return w.result(0).Digest, nil
}
