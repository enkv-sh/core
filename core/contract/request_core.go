package contract

import "bytes"

const (
	requestCorePrefix      = "ENKV/REQUEST/v3\x00"
	requestCoreFixedLength = len(requestCorePrefix) + 6*32 + 8 + 2*32 + 1 + 4 + 2*digestLengthSize
	RequestCoreMaxLength   = requestCoreFixedLength + maxTokenValue
)

type RequestCoreFields struct {
	Domain, Store, Trust, Coordinate, NonBody, Interpretation ID
	Epoch                                                     uint64
	PreviousRevision, PreviousDigest                          ID
	Intent, IdentityPlan                                      DigestLength
}

type RequestCore struct {
	RequestCoreFields
	PreviousToken Token
}

type RequestCoreView struct {
	RequestCoreFields
	PreviousToken TokenView
}

func requestCoreFieldsValid(v RequestCoreFields) bool {
	return publicIDsValid(v.Domain, v.Store, v.Trust, v.Coordinate, v.NonBody, v.Interpretation,
		v.PreviousRevision, v.PreviousDigest, v.Intent.Digest, v.IdentityPlan.Digest) &&
		v.Epoch != 0 && v.Intent.Length != 0 && v.IdentityPlan.Length != 0
}

// The nested lengths are opaque here. Private admission and complete intent
// validation determine the request family; lengths cannot supply that authority.
func RequestCoreLength(v RequestCore) (int, error) {
	if !requestCoreFieldsValid(v.RequestCoreFields) || !v.PreviousToken.Valid() {
		return 0, ErrRecord
	}
	return requestCoreFixedLength + len(v.PreviousToken.Value), nil
}

func writeRequestCore(w *cryptoWriter, v RequestCore) {
	w.raw([]byte(requestCorePrefix))
	writeRequestScope(w, v.RequestCoreFields, v.PreviousToken)
	w.digestLength(v.Intent)
	w.digestLength(v.IdentityPlan)
}

func writeRequestScope(w *cryptoWriter, v RequestCoreFields, token Token) {
	for _, id := range []ID{v.Domain, v.Store, v.Trust, v.Coordinate, v.NonBody, v.Interpretation} {
		w.id(id)
	}
	w.u64(v.Epoch)
	w.id(v.PreviousRevision)
	w.id(v.PreviousDigest)
	writeToken(w, token)
}

func readRequestCore(r *cryptoReader) RequestCoreView {
	if !bytes.Equal(r.take(len(requestCorePrefix)), []byte(requestCorePrefix)) {
		r.err = ErrRecord
	}
	v := RequestCoreView{RequestCoreFields: RequestCoreFields{Domain: r.requiredID(), Store: r.requiredID(), Trust: r.requiredID(),
		Coordinate: r.requiredID(), NonBody: r.requiredID(), Interpretation: r.requiredID(), Epoch: r.u64(),
		PreviousRevision: r.requiredID(), PreviousDigest: r.requiredID()}}
	v.PreviousToken = readToken(r)
	v.Intent, v.IdentityPlan = r.digestLength(), r.digestLength()
	if r.err == nil && !requestCoreFieldsValid(v.RequestCoreFields) {
		r.err = ErrRecord
	}
	return v
}

func EncodeRequestCore(v RequestCore) ([]byte, error) {
	n, err := RequestCoreLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeRequestCore(&w, v)
	return w.b, nil
}

func AppendRequestCore(dst []byte, v RequestCore) ([]byte, error) {
	if _, err := RequestCoreLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeRequestCore(&w, v)
	return w.b, nil
}

func ParseRequestCore(b []byte) (RequestCoreView, int, error) {
	r := newRecordReader(b[:min(len(b), RequestCoreMaxLength)])
	v := readRequestCore(&r)
	if r.err != nil {
		return RequestCoreView{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectRequestCore(b []byte) (RequestCoreView, error) {
	if len(b) > RequestCoreMaxLength {
		return RequestCoreView{}, ErrRecordCapacity
	}
	v, n, err := ParseRequestCore(b)
	if err != nil {
		return RequestCoreView{}, err
	}
	if n != len(b) {
		return RequestCoreView{}, ErrRecord
	}
	return v, nil
}

func (v RequestCoreView) Own() (RequestCore, error) {
	if !requestCoreFieldsValid(v.RequestCoreFields) {
		return RequestCore{}, ErrRecord
	}
	token, err := v.PreviousToken.Own()
	if err != nil {
		return RequestCore{}, err
	}
	return RequestCore{RequestCoreFields: v.RequestCoreFields, PreviousToken: token}, nil
}

func DecodeRequestCore(b []byte) (RequestCore, error) {
	v, err := InspectRequestCore(b)
	if err != nil {
		return RequestCore{}, err
	}
	return v.Own()
}

func RequestCoreDescriptor(v RequestCore) (DescriptorVector, error) {
	if _, err := RequestCoreLength(v); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeRequestCore(&w, v)
	return w.result(1), nil
}

func RequestDigest(v RequestCore) (ID, error) {
	d, err := RequestCoreDescriptor(v)
	return d.Digest, err
}
