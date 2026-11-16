package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"unicode/utf8"
)

const (
	cryptoRequestHeader     = 71
	cryptoResponseHeader    = 75
	cryptoContextBlobLength = 4 + CryptoApplyContextLength
)

type cryptoReader struct {
	b      []byte
	i      int
	err    error
	record bool
}

func newRecordReader(b []byte) cryptoReader {
	return cryptoReader{b: b, record: true}
}

func (r *cryptoReader) child(b []byte) cryptoReader {
	return cryptoReader{b: b, record: r.record}
}

func (r *cryptoReader) invalidError() error {
	if r.record {
		return ErrRecord
	}
	return ErrCryptoMessage
}

func (r *cryptoReader) capacityError() error {
	if r.record {
		return ErrRecordCapacity
	}
	return ErrCryptoCapacity
}

// Structural child errors belong to the enclosing reader. Other causes keep
// their identity; neither validation nor error ownership grants authority.
func (r *cryptoReader) failure() error {
	switch r.err {
	case ErrRecord, ErrCryptoMessage:
		return r.invalidError()
	case ErrRecordCapacity, ErrCryptoCapacity:
		return r.capacityError()
	default:
		return r.err
	}
}

func (r *cryptoReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b)-r.i {
		r.err = r.invalidError()
		return nil
	}
	b := r.b[r.i : r.i+n : r.i+n]
	r.i += n
	return b
}
func (r *cryptoReader) u8() uint8 {
	b := r.take(1)
	if len(b) != 1 {
		return 0
	}
	return b[0]
}
func (r *cryptoReader) u16() uint16 {
	b := r.take(2)
	if len(b) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *cryptoReader) u32() uint32 {
	b := r.take(4)
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *cryptoReader) u64() uint64 {
	b := r.take(8)
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *cryptoReader) id() ID { var id ID; copy(id[:], r.take(32)); return id }
func (r *cryptoReader) requiredID() ID {
	id := r.id()
	if id.IsZero() && r.err == nil {
		r.err = r.invalidError()
	}
	return id
}
func (r *cryptoReader) blob(limit int) []byte {
	n := r.u32()
	if r.err != nil {
		return nil
	}
	if uint64(n) > uint64(limit) {
		r.err = r.capacityError()
		return nil
	}
	return r.take(int(n))
}
func (r *cryptoReader) name() []byte {
	b := r.blob(CryptoMaxName)
	if !utf8.Valid(b) && r.err == nil {
		r.err = r.invalidError()
	}
	return b
}
func (r *cryptoReader) count(limit, minimumRow int) int {
	n := r.u32()
	if r.err != nil {
		return 0
	}
	if uint64(n) > uint64(limit) {
		r.err = r.capacityError()
		return 0
	}
	if uint64(n) > uint64((len(r.b)-r.i)/minimumRow) {
		r.err = r.invalidError()
		return 0
	}
	return int(n)
}
func (r *cryptoReader) digestLength() DigestLength {
	return DigestLength{Digest: r.id(), Length: r.u64()}
}
func (r *cryptoReader) descriptor() DescriptorVector {
	d := r.digestLength()
	return DescriptorVector{Digest: d.Digest, Length: d.Length, Count: r.u32()}
}
func (r *cryptoReader) end() error {
	if r.err != nil {
		return r.failure()
	}
	if r.i != len(r.b) {
		return r.invalidError()
	}
	return nil
}

type cryptoWriter struct {
	b          []byte
	h          hash.Hash
	n          int
	hashBuffer *[sha256.BlockSize]byte
	hashUsed   int
}

func (w *cryptoWriter) raw(b []byte) {
	w.n += len(b)
	if w.h == nil {
		w.b = append(w.b, b...)
		return
	}
	// Copy fields through one fixed block so the hash interface cannot make
	// each integer or ID escape to a separate heap allocation.
	for len(b) > 0 {
		n := copy(w.hashBuffer[w.hashUsed:], b)
		w.hashUsed += n
		b = b[n:]
		if w.hashUsed == len(w.hashBuffer) {
			w.flushHash()
		}
	}
}

func (w *cryptoWriter) flushHash() {
	if w.hashUsed != 0 {
		w.h.Write(w.hashBuffer[:w.hashUsed])
		w.hashUsed = 0
	}
}
func (w *cryptoWriter) u8(n uint8)    { w.raw([]byte{n}) }
func (w *cryptoWriter) u16(n uint16)  { var b [2]byte; binary.BigEndian.PutUint16(b[:], n); w.raw(b[:]) }
func (w *cryptoWriter) u32(n uint32)  { var b [4]byte; binary.BigEndian.PutUint32(b[:], n); w.raw(b[:]) }
func (w *cryptoWriter) u64(n uint64)  { var b [8]byte; binary.BigEndian.PutUint64(b[:], n); w.raw(b[:]) }
func (w *cryptoWriter) id(id ID)      { w.raw(id[:]) }
func (w *cryptoWriter) blob(b []byte) { w.u32(uint32(len(b))); w.raw(b) }
func cryptoDigestLengthBytes(d DigestLength) (b [digestLengthSize]byte) {
	n := copy(b[:], d.Digest[:])
	binary.BigEndian.PutUint64(b[n:], d.Length)
	return b
}

func cryptoDescriptorBytes(d DescriptorVector) (b [descriptorSize]byte) {
	prefix := cryptoDigestLengthBytes(DigestLength{Digest: d.Digest, Length: d.Length})
	n := copy(b[:], prefix[:])
	binary.BigEndian.PutUint32(b[n:], d.Count)
	return b
}

func (w *cryptoWriter) digestLength(d DigestLength) {
	b := cryptoDigestLengthBytes(d)
	w.raw(b[:])
}
func (w *cryptoWriter) descriptor(d DescriptorVector) {
	b := cryptoDescriptorBytes(d)
	w.raw(b[:])
}
func (w *cryptoWriter) result(count int) DescriptorVector {
	w.flushHash()
	var id ID
	copy(id[:], w.h.Sum(w.hashBuffer[:0]))
	return DescriptorVector{Digest: id, Length: uint64(w.n), Count: uint32(count)}
}
func cryptoHashWriter(prefix string) cryptoWriter {
	w := cryptoWriter{h: sha256.New(), hashBuffer: new([sha256.BlockSize]byte)}
	w.raw([]byte(prefix))
	return w
}

func cryptoNamesValid(previous, name []byte, first bool) bool {
	return len(name) <= CryptoMaxName && utf8.Valid(name) && (first || bytes.Compare(previous, name) < 0)
}

func cryptoRefValid(b []byte, kind byte, domain ID) bool {
	v, err := DecodeRef(b, CanonicalSchema)
	return err == nil && v.Kind == Kind(kind) && v.Domain == domain
}

func CryptoConditionDigest(condition HeadCondition) (ID, error) {
	if _, err := HeadConditionLength(condition); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("ENKV/CRYPTO-CONDITION/v1\x00")
	writeHeadCondition(&w, condition)
	return w.result(0).Digest, nil
}

func EncodeCryptoRequest(q CryptoRequest) ([]byte, error) {
	size, err := cryptoRequestSize(q)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, size)}
	writeCryptoRequest(&w, q)
	return w.b, nil
}

// InspectCryptoRequest borrows Body until the complete input is reused or changed.
func InspectCryptoRequest(b []byte) (CryptoRequestView, error) {
	if len(b) > CryptoRequestLimit {
		return CryptoRequestView{}, ErrCryptoCapacity
	}
	if len(b) < cryptoRequestHeader {
		return CryptoRequestView{}, ErrCryptoMessage
	}
	r := cryptoReader{b: b}
	v := readCryptoRequest(&r)
	if err := r.end(); err != nil {
		return CryptoRequestView{}, err
	}
	return v, nil
}
func EncodeCryptoResponse(q CryptoResponse) ([]byte, error) {
	size, err := cryptoResponseSize(q)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, size)}
	writeCryptoResponse(&w, q)
	return w.b, nil
}

// InspectCryptoResponse borrows body and key-use bytes from unchanged input.
func InspectCryptoResponse(b []byte) (CryptoResponseView, error) {
	if len(b) > CryptoResponseLimit {
		return CryptoResponseView{}, ErrCryptoCapacity
	}
	if len(b) < cryptoResponseHeader {
		return CryptoResponseView{}, ErrCryptoMessage
	}
	r := cryptoReader{b: b}
	v := readCryptoResponse(&r)
	if err := r.end(); err != nil {
		return CryptoResponseView{}, err
	}
	return v, nil
}

func DecodeCryptoRequest(b []byte) (CryptoRequest, error) {
	v, err := InspectCryptoRequest(b)
	if err != nil {
		return CryptoRequest{}, err
	}
	return v.Own()
}
func DecodeCryptoResponse(b []byte) (CryptoResponse, error) {
	v, err := InspectCryptoResponse(b)
	if err != nil {
		return CryptoResponse{}, err
	}
	return v.Own()
}

// ValidateCryptoExchange checks value validity and correlation. The caller must
// also retain the expected operation/stage and reject replies after disposal.
func ValidateCryptoExchange(q CryptoRequest, p CryptoResponse) error {
	if q.Schema != CryptoSchema || !q.Kind.Valid() || q.RequestID.IsZero() || q.CustodyInstanceID.IsZero() ||
		p.Schema != q.Schema || p.Kind != q.Kind || p.RequestID != q.RequestID || p.CustodyInstanceID != q.CustodyInstanceID || !p.ResultCode.Valid() {
		return ErrCryptoMessage
	}
	if len(q.Body) > CryptoRequestLimit-cryptoRequestHeader || len(p.Body) > CryptoResponseLimit-cryptoResponseHeader {
		return ErrCryptoCapacity
	}
	if err := cryptoRequestBody(q.Kind, q.Body); err != nil {
		return err
	}
	c, err := cryptoRequestContext(q.Kind, q.Body)
	if err != nil {
		return err
	}
	if c.OperationClass == CryptoGeneratedClass {
		return ValidateCryptoGeneratedResponse(q, p)
	}
	if p.ResultCode == CryptoSuccess {
		if err := cryptoCorrelatedSuccessBody(q, p); err != nil {
			// A valid member of the response union can still belong to a
			// different request class or fail its exact public relations.
			if cryptoResponseBody(p.Kind, p.ResultCode, p.Body) == nil {
				return ErrCryptoMessage
			}
			return err
		}
	}
	if _, err := cryptoResponseSize(p); err != nil {
		return err
	}
	return nil
}
