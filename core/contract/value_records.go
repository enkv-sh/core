package contract

import "unicode/utf8"

const (
	valueCoreFixedLength        = 322
	valueCoreMaxLength          = valueCoreFixedLength + CryptoMaxName + 32
	CanonicalPayloadOverhead    = 215
	canonicalPayloadMaxLength   = CanonicalPayloadOverhead + CryptoMaxRetainedValue
	valueMaterialDigestPrefix   = cryptoPurposePrefix + "material\x00"
	immutableMaterialBodyPrefix = cryptoPurposePrefix + "immutable-material-body-v1\x00"
	storedMaterialSchema        = CanonicalSchema
	MaterialCryptoProfile       = 2
	canonicalCiphertextTagSize  = 16
)

// ValueCore fixes immutable public value context. It excludes current access
// and the ciphertext and checks derived from this context.
type ValueCore struct {
	Schema                 uint16
	Profile                uint16
	CompatibilityID        ID
	CryptoSupportID        ID
	DomainID               ID
	Name                   string
	EntryIncarnationID     ID
	ValueStateID           ID
	OriginSnapshotID       ID
	OriginTransitionID     ID
	DataKeyID              ID
	DataKeyEpoch           uint64
	CommitmentKeyID        ID
	CommitmentKeyEpoch     uint64
	ContentLength          uint32
	InputEncoding          uint8
	RetainedLength         uint32
	ValueSource            uint8
	GeneratedBindingDigest ID
}

// ValueCoreView borrows Name. Keep the input unchanged until inspection ends
// or Own copies the retained name.
type ValueCoreView struct {
	Schema                 uint16
	Profile                uint16
	CompatibilityID        ID
	CryptoSupportID        ID
	DomainID               ID
	Name                   []byte
	EntryIncarnationID     ID
	ValueStateID           ID
	OriginSnapshotID       ID
	OriginTransitionID     ID
	DataKeyID              ID
	DataKeyEpoch           uint64
	CommitmentKeyID        ID
	CommitmentKeyEpoch     uint64
	ContentLength          uint32
	InputEncoding          uint8
	RetainedLength         uint32
	ValueSource            uint8
	GeneratedBindingDigest ID
}

func (v ValueCoreView) shapeError() error {
	if len(v.Name) > CryptoMaxName {
		return ErrRecordCapacity
	}
	if !utf8.Valid(v.Name) {
		return ErrRecord
	}
	_, err := ValueCoreLength(v.fields())
	return err
}

func (v ValueCoreView) fields() ValueCore {
	return ValueCore{Schema: v.Schema, Profile: v.Profile, CompatibilityID: v.CompatibilityID,
		CryptoSupportID: v.CryptoSupportID, DomainID: v.DomainID,
		EntryIncarnationID: v.EntryIncarnationID, ValueStateID: v.ValueStateID,
		OriginSnapshotID: v.OriginSnapshotID, OriginTransitionID: v.OriginTransitionID,
		DataKeyID: v.DataKeyID, DataKeyEpoch: v.DataKeyEpoch, CommitmentKeyID: v.CommitmentKeyID,
		CommitmentKeyEpoch: v.CommitmentKeyEpoch, ContentLength: v.ContentLength, InputEncoding: v.InputEncoding, RetainedLength: v.RetainedLength,
		ValueSource: v.ValueSource, GeneratedBindingDigest: v.GeneratedBindingDigest}
}

func (v ValueCoreView) Own() (ValueCore, error) {
	if err := v.shapeError(); err != nil {
		return ValueCore{}, err
	}
	out := v.fields()
	out.Name = string(v.Name)
	return out, nil
}

func valueKeyEpochsValid(profile uint16, dataEpoch, commitmentEpoch uint64) bool {
	return profile == MaterialCryptoProfile && dataEpoch != 0 && commitmentEpoch != 0
}

func ValueCoreLength(v ValueCore) (int, error) {
	if len(v.Name) > CryptoMaxName || v.ContentLength > CryptoMaxRawValue || v.RetainedLength > CryptoMaxRetainedValue {
		return 0, ErrRecordCapacity
	}
	if InputLengths(v.InputEncoding, v.ContentLength, v.RetainedLength) != nil || v.Schema != storedMaterialSchema || !valueKeyEpochsValid(v.Profile, v.DataKeyEpoch, v.CommitmentKeyEpoch) ||
		(v.ValueSource != Supplied && v.ValueSource != Generated) || (v.ValueSource == Supplied) != v.GeneratedBindingDigest.IsZero() ||
		!utf8.ValidString(v.Name) || !publicIDsValid(v.CompatibilityID, v.CryptoSupportID, v.DomainID,
		v.EntryIncarnationID, v.ValueStateID, v.OriginSnapshotID, v.OriginTransitionID, v.DataKeyID, v.CommitmentKeyID) {
		return 0, ErrRecord
	}
	return valueCoreEncodedLength(v), nil
}

func valueCoreEncodedLength(v ValueCore) int {
	n := valueCoreFixedLength + len(v.Name)
	if v.ValueSource == Generated {
		n += 32
	}
	return n
}

func writeValueCore(w *cryptoWriter, v ValueCore) {
	writeValueCoreWithName(w, v, []byte(v.Name))
}

func writeValueCoreWithName(w *cryptoWriter, v ValueCore, name []byte) {
	w.u16(v.Schema)
	w.u16(v.Profile)
	w.id(v.CompatibilityID)
	w.id(v.CryptoSupportID)
	w.id(v.DomainID)
	w.blob(name)
	w.id(v.EntryIncarnationID)
	w.id(v.ValueStateID)
	w.id(v.OriginSnapshotID)
	w.id(v.OriginTransitionID)
	w.id(v.DataKeyID)
	w.u64(v.DataKeyEpoch)
	w.id(v.CommitmentKeyID)
	w.u64(v.CommitmentKeyEpoch)
	w.u32(v.ContentLength)
	w.u8(v.InputEncoding)
	w.u32(v.RetainedLength)
	w.u8(v.ValueSource)
	if v.ValueSource == Generated {
		w.id(v.GeneratedBindingDigest)
	}
}

func writeValueCoreBlob(w *cryptoWriter, v ValueCore) {
	w.u32(uint32(valueCoreEncodedLength(v)))
	writeValueCore(w, v)
}

func readValueCore(r *cryptoReader) ValueCoreView {
	v := ValueCoreView{Schema: r.u16(), Profile: r.u16(), CompatibilityID: r.requiredID(),
		CryptoSupportID: r.requiredID(), DomainID: r.requiredID(), Name: r.name(),
		EntryIncarnationID: r.requiredID(), ValueStateID: r.requiredID(), OriginSnapshotID: r.requiredID(),
		OriginTransitionID: r.requiredID(), DataKeyID: r.requiredID(), DataKeyEpoch: r.u64(),
		CommitmentKeyID: r.requiredID(), CommitmentKeyEpoch: r.u64(), ContentLength: r.u32(), InputEncoding: r.u8(), RetainedLength: r.u32(), ValueSource: r.u8()}
	if r.err != nil {
		return v
	}
	if v.ValueSource == Generated {
		v.GeneratedBindingDigest = r.requiredID()
	}
	if r.err == nil {
		r.err = v.shapeError()
	}
	return v
}

func AppendValueCore(dst []byte, v ValueCore) ([]byte, error) {
	if _, err := ValueCoreLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeValueCore(&w, v)
	return w.b, nil
}

func EncodeValueCore(v ValueCore) ([]byte, error) {
	n, err := ValueCoreLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeValueCore(&w, v)
	return w.b, nil
}

func ParseValueCore(b []byte) (ValueCoreView, int, error) {
	r := newRecordReader(b)
	v := readValueCore(&r)
	if r.err != nil {
		return ValueCoreView{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectValueCore(b []byte) (ValueCoreView, error) {
	if len(b) > valueCoreMaxLength {
		return ValueCoreView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readValueCore(&r)
	if err := r.end(); err != nil {
		return ValueCoreView{}, err
	}
	return v, nil
}

func DecodeValueCore(b []byte) (ValueCore, error) {
	v, err := InspectValueCore(b)
	if err != nil {
		return ValueCore{}, err
	}
	return v.Own()
}

func ValueMaterialContextDigest(v ValueCore) (ID, error) {
	if _, err := ValueCoreLength(v); err != nil {
		return ID{}, err
	}
	return valueMaterialContextDigest(v, []byte(v.Name)), nil
}

func valueMaterialContextDigest(v ValueCore, name []byte) ID {
	w := cryptoHashWriter(valueMaterialDigestPrefix)
	w.u32(uint32(valueCoreEncodedLength(v) - len(v.Name) + len(name)))
	writeValueCoreWithName(&w, v, name)
	return w.result(0).Digest
}

func ValueCoreDigest(v ValueCore) (ID, error) {
	if _, err := ValueCoreLength(v); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("")
	writeValueCore(&w, v)
	return w.result(0).Digest, nil
}

// CanonicalPayload contains public encrypted bytes and opaque checks. Parsing
// does not authenticate the ciphertext or verify either check.
type CanonicalPayload struct {
	Profile            uint16
	CryptoSupportID    ID
	DataKeyID          ID
	DataKeyEpoch       uint64
	CommitmentKeyID    ID
	CommitmentKeyEpoch uint64
	ContentLength      uint32
	InputEncoding      uint8
	RetainedLength     uint32
	Nonce              [12]byte
	SemanticCommitment ID
	PackageCheck       ID
	Ciphertext         []byte
}

// CanonicalPayloadView borrows Ciphertext until inspection ends or Own copies it.
type CanonicalPayloadView CanonicalPayload

func (v CanonicalPayloadView) Own() (CanonicalPayload, error) {
	out := CanonicalPayload(v)
	if _, err := CanonicalPayloadLength(out); err != nil {
		return CanonicalPayload{}, err
	}
	out.Ciphertext = ownedBytes(out.Ciphertext)
	return out, nil
}

func CanonicalPayloadLength(v CanonicalPayload) (int, error) {
	if v.ContentLength > CryptoMaxRawValue || v.RetainedLength > CryptoMaxRetainedValue || len(v.Ciphertext) > CryptoMaxRetainedValue+canonicalCiphertextTagSize {
		return 0, ErrRecordCapacity
	}
	if InputLengths(v.InputEncoding, v.ContentLength, v.RetainedLength) != nil || !valueKeyEpochsValid(v.Profile, v.DataKeyEpoch, v.CommitmentKeyEpoch) ||
		!publicIDsValid(v.CryptoSupportID, v.DataKeyID, v.CommitmentKeyID) || len(v.Ciphertext) != int(v.RetainedLength)+canonicalCiphertextTagSize {
		return 0, ErrRecord
	}
	return CanonicalPayloadOverhead + int(v.RetainedLength), nil
}

func writeCanonicalPayload(w *cryptoWriter, v CanonicalPayload) {
	w.u16(v.Profile)
	w.id(v.CryptoSupportID)
	w.id(v.DataKeyID)
	w.u64(v.DataKeyEpoch)
	w.id(v.CommitmentKeyID)
	w.u64(v.CommitmentKeyEpoch)
	w.u32(v.ContentLength)
	w.u8(v.InputEncoding)
	w.u32(v.RetainedLength)
	w.raw(v.Nonce[:])
	w.id(v.SemanticCommitment)
	w.id(v.PackageCheck)
	w.raw(v.Ciphertext)
}

func readCanonicalPayload(r *cryptoReader) CanonicalPayloadView {
	v := CanonicalPayloadView{Profile: r.u16(), CryptoSupportID: r.requiredID(), DataKeyID: r.requiredID(),
		DataKeyEpoch: r.u64(), CommitmentKeyID: r.requiredID(), CommitmentKeyEpoch: r.u64(), ContentLength: r.u32(), InputEncoding: r.u8(), RetainedLength: r.u32()}
	if r.err != nil {
		return v
	}
	if v.ContentLength > CryptoMaxRawValue || v.RetainedLength > CryptoMaxRetainedValue {
		r.err = ErrRecordCapacity
		return v
	}
	if InputLengths(v.InputEncoding, v.ContentLength, v.RetainedLength) != nil || !valueKeyEpochsValid(v.Profile, v.DataKeyEpoch, v.CommitmentKeyEpoch) {
		r.err = ErrRecord
		return v
	}
	copy(v.Nonce[:], r.take(len(v.Nonce)))
	v.SemanticCommitment = r.id()
	v.PackageCheck = r.id()
	v.Ciphertext = r.take(int(v.RetainedLength) + canonicalCiphertextTagSize)
	return v
}

func AppendCanonicalPayload(dst []byte, v CanonicalPayload) ([]byte, error) {
	if _, err := CanonicalPayloadLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeCanonicalPayload(&w, v)
	return w.b, nil
}

func EncodeCanonicalPayload(v CanonicalPayload) ([]byte, error) {
	n, err := CanonicalPayloadLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeCanonicalPayload(&w, v)
	return w.b, nil
}

func ParseCanonicalPayload(b []byte) (CanonicalPayloadView, int, error) {
	r := newRecordReader(b)
	v := readCanonicalPayload(&r)
	if r.err != nil {
		return CanonicalPayloadView{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectCanonicalPayload(b []byte) (CanonicalPayloadView, error) {
	if len(b) > canonicalPayloadMaxLength {
		return CanonicalPayloadView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readCanonicalPayload(&r)
	if err := r.end(); err != nil {
		return CanonicalPayloadView{}, err
	}
	return v, nil
}

func DecodeCanonicalPayload(b []byte) (CanonicalPayload, error) {
	v, err := InspectCanonicalPayload(b)
	if err != nil {
		return CanonicalPayload{}, err
	}
	return v.Own()
}

// ValueImmutableBodyDigest binds complete public value bytes. It does not
// authenticate the ciphertext, semantic commitment or package check.
func ValueImmutableBodyDigest(core ValueCore, payload CanonicalPayload) (ID, error) {
	if _, err := ValueCoreLength(core); err != nil {
		return ID{}, err
	}
	n, err := CanonicalPayloadLength(payload)
	if err != nil {
		return ID{}, err
	}
	if core.Profile != payload.Profile || core.CryptoSupportID != payload.CryptoSupportID ||
		core.DataKeyID != payload.DataKeyID || core.DataKeyEpoch != payload.DataKeyEpoch ||
		core.CommitmentKeyID != payload.CommitmentKeyID || core.CommitmentKeyEpoch != payload.CommitmentKeyEpoch ||
		core.ContentLength != payload.ContentLength || core.InputEncoding != payload.InputEncoding || core.RetainedLength != payload.RetainedLength {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter(immutableMaterialBodyPrefix)
	w.u16(uint16(ValueMaterialKind))
	writeValueCoreBlob(&w, core)
	w.u32(uint32(n))
	writeCanonicalPayload(&w, payload)
	return w.result(0).Digest, nil
}
