package contract

import (
	"bytes"
	"unicode/utf8"
)

const (
	SealedInputCoreFixedLength            = 281
	SealedInputEnvelopeFixedLength        = len(sealedInputPrefix) + SealedInputCoreFixedLength + 12 + 4 + canonicalCiphertextTagSize + 2 + WrapRowWireLength
	SealedInputSchema              uint16 = 4
	sealedInputPrefix                     = "ENKV/SOURCE/v4\x00"
)

// SealedInputCoreFields are the fixed public facts shared by an owned SealedInputCore
// and its borrowed view.
type SealedInputCoreFields struct {
	Schema, Profile                                                uint16
	CompatibilityID, DomainID, FileIdentity, FilePredecessorDigest ID
	SourceID                                                       ID
	CryptoSupportID, DataKeyID                                     ID
	DataKeyEpoch                                                   uint64
	ContentLength                                                  uint32
	InputEncoding                                                  uint8
	RetainedLength                                                 uint32
	IntendedRecipientBindingSetDigest                              ID
}

type SealedInputCore struct {
	SealedInputCoreFields
	Name string
}

// SealedInputCoreView borrows Name. Keep the input unchanged until inspection ends
// or Own copies the retained name.
type SealedInputCoreView struct {
	SealedInputCoreFields
	Name []byte
}

func (v SealedInputCoreFields) valid() bool {
	return v.Schema == SealedInputSchema && v.Profile == MaterialCryptoProfile && v.DataKeyEpoch != 0 && InputLengths(v.InputEncoding, v.ContentLength, v.RetainedLength) == nil &&
		publicIDsValid(v.CompatibilityID, v.DomainID, v.FileIdentity, v.SourceID,
			v.CryptoSupportID, v.DataKeyID)
}

func (v SealedInputCore) Valid() bool {
	_, err := SealedInputCoreLength(v)
	return err == nil
}

func (v SealedInputCoreView) own() SealedInputCore {
	return SealedInputCore{SealedInputCoreFields: v.SealedInputCoreFields, Name: string(v.Name)}
}

func sealedInputCoreViewError(v SealedInputCoreView) error {
	if len(v.Name) > CryptoMaxName || v.ContentLength > CryptoMaxRawValue || v.RetainedLength > CryptoMaxRetainedValue {
		return ErrRecordCapacity
	}
	if !v.valid() || !utf8.Valid(v.Name) {
		return ErrRecord
	}
	return nil
}

func (v SealedInputCoreView) Own() (SealedInputCore, error) {
	if err := sealedInputCoreViewError(v); err != nil {
		return SealedInputCore{}, err
	}
	return v.own(), nil
}

func SealedInputCoreLength(v SealedInputCore) (int, error) {
	if len(v.Name) > CryptoMaxName || v.ContentLength > CryptoMaxRawValue || v.RetainedLength > CryptoMaxRetainedValue {
		return 0, ErrRecordCapacity
	}
	if !v.valid() || !utf8.ValidString(v.Name) {
		return 0, ErrRecord
	}
	return SealedInputCoreFixedLength + len(v.Name), nil
}

func writeSealedInputCore(w *cryptoWriter, v SealedInputCore) {
	writeSealedInputCoreFields(w, v.SealedInputCoreFields, []byte(v.Name))
}

func writeSealedInputCoreFields(w *cryptoWriter, v SealedInputCoreFields, name []byte) {
	w.u16(v.Schema)
	w.u16(v.Profile)
	w.id(v.CompatibilityID)
	w.id(v.DomainID)
	w.id(v.FileIdentity)
	w.id(v.FilePredecessorDigest)
	w.id(v.SourceID)

	w.blob(name)
	w.id(v.CryptoSupportID)
	w.id(v.DataKeyID)
	w.u64(v.DataKeyEpoch)
	w.u32(v.ContentLength)
	w.u8(v.InputEncoding)
	w.u32(v.RetainedLength)
	w.id(v.IntendedRecipientBindingSetDigest)
}

func readSealedInputCore(r *cryptoReader) SealedInputCoreView {
	v := SealedInputCoreView{SealedInputCoreFields: SealedInputCoreFields{Schema: r.u16(), Profile: r.u16(),
		CompatibilityID: r.requiredID(), DomainID: r.requiredID(), FileIdentity: r.requiredID(),
		FilePredecessorDigest: r.id(), SourceID: r.requiredID(),
	}, Name: r.name()}
	v.CryptoSupportID = r.requiredID()
	v.DataKeyID = r.requiredID()
	v.DataKeyEpoch = r.u64()
	v.ContentLength = r.u32()
	v.InputEncoding = r.u8()
	v.RetainedLength = r.u32()
	v.IntendedRecipientBindingSetDigest = r.id()
	if r.err != nil {
		return v
	}
	if v.ContentLength > CryptoMaxRawValue || v.RetainedLength > CryptoMaxRetainedValue {
		r.err = ErrRecordCapacity
		return v
	}
	if !v.valid() {
		r.err = ErrRecord
	}
	return v
}

func AppendSealedInputCore(dst []byte, v SealedInputCore) ([]byte, error) {
	if _, err := SealedInputCoreLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeSealedInputCore(&w, v)
	return w.b, nil
}

func EncodeSealedInputCore(v SealedInputCore) ([]byte, error) {
	n, err := SealedInputCoreLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeSealedInputCore(&w, v)
	return w.b, nil
}

func ParseSealedInputCore(b []byte) (SealedInputCoreView, int, error) {
	r := newRecordReader(b)
	v := readSealedInputCore(&r)
	if r.err != nil {
		return SealedInputCoreView{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectSealedInputCore(b []byte) (SealedInputCoreView, error) {
	if len(b) > SealedInputCoreFixedLength+CryptoMaxName {
		return SealedInputCoreView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readSealedInputCore(&r)
	if err := r.end(); err != nil {
		return SealedInputCoreView{}, err
	}
	return v, nil
}

func DecodeSealedInputCore(b []byte) (SealedInputCore, error) {
	v, err := InspectSealedInputCore(b)
	if err != nil {
		return SealedInputCore{}, err
	}
	return v.own(), nil
}

// SealedInputEnvelope carries encrypted source bytes and the claimed authority wrap.
// Structural decoding does not authenticate source provenance or key access.
type SealedInputEnvelope struct {
	Core          SealedInputCore
	Nonce         [12]byte
	Ciphertext    []byte
	AuthorityWrap WrapRow
}

// SealedInputEnvelopeView borrows the name, payload ciphertext and RSA ciphertext.
// Keep the input unchanged until inspection ends or Own copies the view.
type SealedInputEnvelopeView struct {
	Core          SealedInputCoreView
	Nonce         [12]byte
	Ciphertext    []byte
	AuthorityWrap WrapRowView
}

func (v SealedInputEnvelopeView) Own() (SealedInputEnvelope, error) {
	if err := sealedInputCoreViewError(v.Core); err != nil {
		return SealedInputEnvelope{}, err
	}
	out := SealedInputEnvelope{Core: SealedInputCore{SealedInputCoreFields: v.Core.SealedInputCoreFields},
		Nonce: v.Nonce, Ciphertext: v.Ciphertext, AuthorityWrap: WrapRow(v.AuthorityWrap)}
	if _, err := SealedInputEnvelopeLength(out); err != nil {
		return SealedInputEnvelope{}, err
	}
	out.Core.Name = string(v.Core.Name)
	out.Ciphertext = ownedBytes(v.Ciphertext)
	out.AuthorityWrap = v.AuthorityWrap.own()
	return out, nil
}

func SealedInputEnvelopeLength(v SealedInputEnvelope) (int, error) {
	if len(v.Ciphertext) > CryptoMaxRetainedValue+canonicalCiphertextTagSize {
		return 0, ErrRecordCapacity
	}
	n, err := SealedInputCoreLength(v.Core)
	if err != nil {
		return 0, err
	}
	wrapLength, err := WrapRowLength(v.AuthorityWrap)
	if err != nil {
		return 0, err
	}
	if len(v.Ciphertext) != int(v.Core.RetainedLength)+canonicalCiphertextTagSize || v.AuthorityWrap.SubjectKind != OrdinaryWrapSubject {
		return 0, ErrRecord
	}
	return len(sealedInputPrefix) + n + len(v.Nonce) + 4 + len(v.Ciphertext) + 2 + wrapLength, nil
}

func writeSealedInputEnvelope(w *cryptoWriter, v SealedInputEnvelope) {
	w.raw([]byte(sealedInputPrefix))
	writeSealedInputCore(w, v.Core)
	w.raw(v.Nonce[:])
	w.blob(v.Ciphertext)
	w.u16(1)
	writeWrapRow(w, v.AuthorityWrap)
}

func readSealedInputEnvelope(r *cryptoReader) SealedInputEnvelopeView {
	if !bytes.Equal(r.take(len(sealedInputPrefix)), []byte(sealedInputPrefix)) {
		if r.err == nil {
			r.err = ErrRecord
		}
		return SealedInputEnvelopeView{}
	}
	v := SealedInputEnvelopeView{Core: readSealedInputCore(r)}
	if r.err != nil {
		return v
	}
	copy(v.Nonce[:], r.take(len(v.Nonce)))
	v.Ciphertext = r.blob(CryptoMaxRetainedValue + canonicalCiphertextTagSize)
	if r.err != nil {
		return v
	}
	if len(v.Ciphertext) != int(v.Core.RetainedLength)+canonicalCiphertextTagSize {
		r.err = ErrRecord
		return v
	}
	count := r.u16()
	if r.err != nil {
		return v
	}
	if count != 1 {
		r.err = ErrRecord
		return v
	}
	v.AuthorityWrap = readWrapRow(r)
	if r.err == nil && v.AuthorityWrap.SubjectKind != OrdinaryWrapSubject {
		r.err = ErrRecord
	}
	return v
}

func AppendSealedInputEnvelope(dst []byte, v SealedInputEnvelope) ([]byte, error) {
	if _, err := SealedInputEnvelopeLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeSealedInputEnvelope(&w, v)
	return w.b, nil
}

func EncodeSealedInputEnvelope(v SealedInputEnvelope) ([]byte, error) {
	n, err := SealedInputEnvelopeLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeSealedInputEnvelope(&w, v)
	return w.b, nil
}

func ParseSealedInputEnvelope(b []byte) (SealedInputEnvelopeView, int, error) {
	r := newRecordReader(b)
	v := readSealedInputEnvelope(&r)
	if r.err != nil {
		return SealedInputEnvelopeView{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectSealedInputEnvelope(b []byte) (SealedInputEnvelopeView, error) {
	if len(b) > CryptoMaxSealedInputLength {
		return SealedInputEnvelopeView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readSealedInputEnvelope(&r)
	if err := r.end(); err != nil {
		return SealedInputEnvelopeView{}, err
	}
	return v, nil
}

func DecodeSealedInputEnvelope(b []byte) (SealedInputEnvelope, error) {
	v, err := InspectSealedInputEnvelope(b)
	if err != nil {
		return SealedInputEnvelope{}, err
	}
	return v.Own()
}
