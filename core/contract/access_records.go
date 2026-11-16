package contract

import "bytes"

const (
	ValueMaterialPacketLength     = 100
	SingleKeyMaterialPacketLength = 68
)

const (
	OrdinaryWrapSubject uint8 = 1
	RecoveryWrapSubject uint8 = 2
)

const (
	WrapRowWireLength       = 489
	wrapCoreWireLength      = 278
	RSACiphertextLength     = 384
	AccessRecordFixedLength = 102
	valueAccessWrapLimit    = CryptoMaxRecipients + 1
	ordinaryValueWrapLimit  = CryptoMaxRecipients
	accessRecordMaxLength   = AccessRecordFixedLength + valueAccessWrapLimit*WrapRowWireLength
	rsaPacketDigestPrefix   = cryptoPurposePrefix + "rsa-packet\x00"
	seedAccessWrapLimit     = 2
)

type MaterialKind = uint16

const (
	ValueMaterialKind         MaterialKind = 1
	SourceMaterialKind        MaterialKind = 2
	OperationSeedMaterialKind MaterialKind = 3
	ProofMaterialKind         MaterialKind = 4
)

// WrapRow is public access protection. Its RSA ciphertext remains opaque here.
type WrapRow struct {
	SubjectKind         uint8
	SubjectID           ID
	BindingID           ID
	BindingSerial       uint64
	PublicBindingDigest ID
	RSACiphertext       []byte
}

// WrapRowView borrows RSACiphertext until inspection ends or Own copies it.
type WrapRowView WrapRow

func (v WrapRowView) own() WrapRow {
	out := WrapRow(v)
	out.RSACiphertext = ownedBytes(out.RSACiphertext)
	return out
}

func (v WrapRowView) Own() (WrapRow, error) {
	if _, err := WrapRowLength(WrapRow(v)); err != nil {
		return WrapRow{}, err
	}
	return v.own(), nil
}

func wrapSubjectValid(kind uint8, subject, binding ID, serial uint64) bool {
	return (kind == OrdinaryWrapSubject || kind == RecoveryWrapSubject) && !subject.IsZero() && !binding.IsZero() && serial != 0
}

func WrapRowLength(v WrapRow) (int, error) {
	if len(v.RSACiphertext) > RSACiphertextLength {
		return 0, ErrRecordCapacity
	}
	if len(v.RSACiphertext) != RSACiphertextLength || !wrapSubjectValid(v.SubjectKind, v.SubjectID, v.BindingID, v.BindingSerial) {
		return 0, ErrRecord
	}
	return WrapRowWireLength, nil
}

func writeWrapRow(w *cryptoWriter, v WrapRow) {
	w.u8(v.SubjectKind)
	w.id(v.SubjectID)
	w.id(v.BindingID)
	w.u64(v.BindingSerial)
	w.id(v.PublicBindingDigest)
	w.raw(v.RSACiphertext)
}

func readWrapRow(r *cryptoReader) WrapRowView {
	v := WrapRowView{SubjectKind: r.u8(), SubjectID: r.requiredID(), BindingID: r.requiredID(),
		BindingSerial: r.u64(), PublicBindingDigest: r.id(), RSACiphertext: r.take(RSACiphertextLength)}
	if r.err == nil && !wrapSubjectValid(v.SubjectKind, v.SubjectID, v.BindingID, v.BindingSerial) {
		r.err = ErrRecord
	}
	return v
}

func AppendWrapRow(dst []byte, v WrapRow) ([]byte, error) {
	if _, err := WrapRowLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeWrapRow(&w, v)
	return w.b, nil
}

func EncodeWrapRow(v WrapRow) ([]byte, error) {
	n, err := WrapRowLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeWrapRow(&w, v)
	return w.b, nil
}

func ParseWrapRow(b []byte) (WrapRowView, int, error) {
	r := newRecordReader(b)
	v := readWrapRow(&r)
	if r.err != nil {
		return WrapRowView{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectWrapRow(b []byte) (WrapRowView, error) {
	if len(b) > WrapRowWireLength {
		return WrapRowView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readWrapRow(&r)
	if err := r.end(); err != nil {
		return WrapRowView{}, err
	}
	return v, nil
}

func DecodeWrapRow(b []byte) (WrapRow, error) {
	v, err := InspectWrapRow(b)
	if err != nil {
		return WrapRow{}, err
	}
	return v.own(), nil
}

// WrapCore binds one closed RSA packet purpose to public material and its exact
// subject and binding. It contains no private packet or key bytes.
type WrapCore struct {
	Schema                uint16
	Profile               uint16
	DomainID              ID
	CompatibilityID       ID
	CryptoSupportID       ID
	MaterialKind          MaterialKind
	MaterialID            ID
	MaterialContextDigest ID
	SubjectKind           uint8
	SubjectID             ID
	BindingID             ID
	BindingSerial         uint64
	PublicBindingDigest   ID
	Provider              Family
	WrapProfile           uint16
	PacketKind            uint16
	PacketLength          uint16
}

func wrapCoreValid(v WrapCore) bool {
	if v.Schema != storedMaterialSchema || v.Profile != MaterialCryptoProfile || !v.Provider.Valid() ||
		v.WrapProfile != RSAOAEPWrapProfile || !publicIDsValid(v.DomainID, v.CompatibilityID, v.CryptoSupportID, v.MaterialID) ||
		!wrapSubjectValid(v.SubjectKind, v.SubjectID, v.BindingID, v.BindingSerial) {
		return false
	}
	switch v.MaterialKind {
	case ValueMaterialKind:
		return v.PacketKind == 1 && v.PacketLength == ValueMaterialPacketLength
	case SourceMaterialKind:
		return v.PacketKind == 2 && v.PacketLength == SingleKeyMaterialPacketLength
	case OperationSeedMaterialKind:
		return v.PacketKind == 3 && v.PacketLength == SingleKeyMaterialPacketLength
	case ProofMaterialKind:
		return v.PacketKind == 4 && v.PacketLength == SingleKeyMaterialPacketLength
	default:
		return false
	}
}

func WrapCoreLength(v WrapCore) (int, error) {
	if !wrapCoreValid(v) {
		return 0, ErrRecord
	}
	return wrapCoreWireLength, nil
}

func writeWrapCore(w *cryptoWriter, v WrapCore) {
	w.u16(v.Schema)
	w.u16(v.Profile)
	w.id(v.DomainID)
	w.id(v.CompatibilityID)
	w.id(v.CryptoSupportID)
	w.u16(uint16(v.MaterialKind))
	w.id(v.MaterialID)
	w.id(v.MaterialContextDigest)
	w.u8(v.SubjectKind)
	w.id(v.SubjectID)
	w.id(v.BindingID)
	w.u64(v.BindingSerial)
	w.id(v.PublicBindingDigest)
	w.u8(uint8(v.Provider))
	w.u16(v.WrapProfile)
	w.u16(v.PacketKind)
	w.u16(v.PacketLength)
}

func readWrapCore(r *cryptoReader) WrapCore {
	v := WrapCore{Schema: r.u16(), Profile: r.u16(), DomainID: r.requiredID(), CompatibilityID: r.requiredID(),
		CryptoSupportID: r.requiredID(), MaterialKind: MaterialKind(r.u16()), MaterialID: r.requiredID(), MaterialContextDigest: r.id(),
		SubjectKind: r.u8(), SubjectID: r.requiredID(), BindingID: r.requiredID(), BindingSerial: r.u64(),
		PublicBindingDigest: r.id(), Provider: Family(r.u8()), WrapProfile: r.u16(), PacketKind: r.u16(), PacketLength: r.u16()}
	if r.err == nil && !wrapCoreValid(v) {
		r.err = ErrRecord
	}
	return v
}

func AppendWrapCore(dst []byte, v WrapCore) ([]byte, error) {
	if _, err := WrapCoreLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeWrapCore(&w, v)
	return w.b, nil
}

func EncodeWrapCore(v WrapCore) ([]byte, error) {
	n, err := WrapCoreLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeWrapCore(&w, v)
	return w.b, nil
}

func ParseWrapCore(b []byte) (WrapCore, int, error) {
	r := newRecordReader(b)
	v := readWrapCore(&r)
	if r.err != nil {
		return WrapCore{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectWrapCore(b []byte) (WrapCore, error) {
	if len(b) > wrapCoreWireLength {
		return WrapCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readWrapCore(&r)
	if err := r.end(); err != nil {
		return WrapCore{}, err
	}
	return v, nil
}

func DecodeWrapCore(b []byte) (WrapCore, error) {
	return InspectWrapCore(b)
}

func RSAPacketContextDigest(v WrapCore) (ID, error) {
	n, err := WrapCoreLength(v)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(rsaPacketDigestPrefix)
	w.u32(uint32(n))
	writeWrapCore(&w, v)
	return w.result(0).Digest, nil
}

// AccessRecord describes current protection for value or operation-seed
// material. Core must separately authenticate the complete selected relation.
type AccessRecord struct {
	Schema                uint16
	MaterialKind          MaterialKind
	MaterialID            ID
	MaterialContextDigest ID
	PackageCheck          ID
	Wraps                 []WrapRow
}

// AccessRecordView borrows the complete ordered wrap span. Keep its input
// unchanged until inspection ends or Own finishes copying it.
type AccessRecordView struct {
	Schema                uint16
	MaterialKind          MaterialKind
	MaterialID            ID
	MaterialContextDigest ID
	PackageCheck          ID
	Wraps                 []byte
}

func (v AccessRecordView) WrapCount() int {
	return len(v.Wraps) / WrapRowWireLength
}

func (v AccessRecordView) Wrap(index int) (WrapRowView, bool) {
	if index < 0 || index >= v.WrapCount() {
		return WrapRowView{}, false
	}
	row, err := InspectWrapRow(v.Wraps[index*WrapRowWireLength : (index+1)*WrapRowWireLength])
	return row, err == nil
}

func accessRecordHeaderError(schema uint16, kind MaterialKind, material ID, count int) error {
	if count > valueAccessWrapLimit || kind == OperationSeedMaterialKind && count > seedAccessWrapLimit {
		return ErrRecordCapacity
	}
	if schema != storedMaterialSchema || (kind != ValueMaterialKind && kind != OperationSeedMaterialKind) || material.IsZero() || count <= 0 {
		return ErrRecord
	}
	return nil
}

type accessWrapSubjects struct {
	ordinary, recovery int
	previousKind       uint8
	previousID         ID
}

func (s *accessWrapSubjects) add(kind uint8, id ID) error {
	if s.previousKind > kind || s.previousKind == kind && bytes.Compare(s.previousID[:], id[:]) >= 0 {
		return ErrRecord
	}
	s.previousKind, s.previousID = kind, id
	if kind == OrdinaryWrapSubject {
		s.ordinary++
	} else {
		s.recovery++
	}
	return nil
}

func (s accessWrapSubjects) end(kind MaterialKind) error {
	if s.ordinary > ordinaryValueWrapLimit {
		return ErrRecordCapacity
	}
	if s.ordinary < 1 || s.recovery > 1 || kind == OperationSeedMaterialKind && s.ordinary != 1 {
		return ErrRecord
	}
	return nil
}

func accessWrapSpanError(kind MaterialKind, span []byte) error {
	r := newRecordReader(span)
	var subjects accessWrapSubjects
	for r.i < len(span) {
		row := readWrapRow(&r)
		if r.err != nil {
			return r.failure()
		}
		if err := subjects.add(row.SubjectKind, row.SubjectID); err != nil {
			return err
		}
	}
	return subjects.end(kind)
}

// Own validates the complete view before allocating retained rows. Borrowed
// input must remain unchanged through validation and copying.
func (v AccessRecordView) Own() (AccessRecord, error) {
	if err := v.shapeError(); err != nil {
		return AccessRecord{}, err
	}
	return v.own()
}

func (v AccessRecordView) own() (AccessRecord, error) {
	count := v.WrapCount()
	out := AccessRecord{Schema: v.Schema, MaterialKind: v.MaterialKind, MaterialID: v.MaterialID,
		MaterialContextDigest: v.MaterialContextDigest, PackageCheck: v.PackageCheck}
	if count != 0 {
		out.Wraps = make([]WrapRow, count)
	}
	r := newRecordReader(v.Wraps)
	for i := range out.Wraps {
		row := readWrapRow(&r)
		if r.err != nil {
			return AccessRecord{}, r.failure()
		}
		out.Wraps[i] = row.own()
	}
	return out, nil
}

func (v AccessRecordView) shapeError() error {
	count := v.WrapCount()
	if err := accessRecordHeaderError(v.Schema, v.MaterialKind, v.MaterialID, count); err != nil {
		return err
	}
	if len(v.Wraps) != count*WrapRowWireLength {
		return ErrRecord
	}
	return accessWrapSpanError(v.MaterialKind, v.Wraps)
}

func AccessRecordLength(v AccessRecord) (int, error) {
	if err := accessRecordHeaderError(v.Schema, v.MaterialKind, v.MaterialID, len(v.Wraps)); err != nil {
		return 0, err
	}
	var subjects accessWrapSubjects
	for _, row := range v.Wraps {
		if _, err := WrapRowLength(row); err != nil {
			return 0, err
		}
		if err := subjects.add(row.SubjectKind, row.SubjectID); err != nil {
			return 0, err
		}
	}
	if err := subjects.end(v.MaterialKind); err != nil {
		return 0, err
	}
	return accessRecordEncodedLength(v), nil
}

func accessRecordEncodedLength(v AccessRecord) int {
	return AccessRecordFixedLength + WrapRowWireLength*len(v.Wraps)
}

func writeAccessRecord(w *cryptoWriter, v AccessRecord) {
	w.u16(v.Schema)
	w.u16(uint16(v.MaterialKind))
	w.id(v.MaterialID)
	w.id(v.MaterialContextDigest)
	w.id(v.PackageCheck)
	w.u16(uint16(len(v.Wraps)))
	for _, row := range v.Wraps {
		writeWrapRow(w, row)
	}
}

func writeAccessRecordBlob(w *cryptoWriter, v AccessRecord) {
	w.u32(uint32(accessRecordEncodedLength(v)))
	writeAccessRecord(w, v)
}

func readAccessRecord(r *cryptoReader) AccessRecordView {
	v := AccessRecordView{Schema: r.u16(), MaterialKind: MaterialKind(r.u16()), MaterialID: r.requiredID(),
		MaterialContextDigest: r.id(), PackageCheck: r.id()}
	count := int(r.u16())
	if r.err != nil {
		return v
	}
	if err := accessRecordHeaderError(v.Schema, v.MaterialKind, v.MaterialID, count); err != nil {
		r.err = err
		return v
	}
	v.Wraps = r.take(count * WrapRowWireLength)
	if r.err == nil {
		r.err = accessWrapSpanError(v.MaterialKind, v.Wraps)
	}
	return v
}

func AppendAccessRecord(dst []byte, v AccessRecord) ([]byte, error) {
	if _, err := AccessRecordLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeAccessRecord(&w, v)
	return w.b, nil
}

func EncodeAccessRecord(v AccessRecord) ([]byte, error) {
	n, err := AccessRecordLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeAccessRecord(&w, v)
	return w.b, nil
}

func ParseAccessRecord(b []byte) (AccessRecordView, int, error) {
	r := newRecordReader(b)
	v := readAccessRecord(&r)
	if r.err != nil {
		return AccessRecordView{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectAccessRecord(b []byte) (AccessRecordView, error) {
	if len(b) > accessRecordMaxLength {
		return AccessRecordView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readAccessRecord(&r)
	if err := r.end(); err != nil {
		return AccessRecordView{}, err
	}
	return v, nil
}

func DecodeAccessRecord(b []byte) (AccessRecord, error) {
	v, err := InspectAccessRecord(b)
	if err != nil {
		return AccessRecord{}, err
	}
	return v.Own()
}

func AccessRecordDigest(v AccessRecord) (ID, error) {
	if _, err := AccessRecordLength(v); err != nil {
		return ID{}, err
	}
	return accessRecordDigest(v), nil
}

func accessRecordDigest(v AccessRecord) ID {
	w := cryptoHashWriter("")
	writeAccessRecord(&w, v)
	return w.result(0).Digest
}

// AccessRecordBefore supplies the canonical order across pages and batches.
func AccessRecordBefore(a, b AccessRecord) bool {
	if a.MaterialKind != b.MaterialKind {
		return a.MaterialKind < b.MaterialKind
	}
	return bytes.Compare(a.MaterialID[:], b.MaterialID[:]) < 0
}
