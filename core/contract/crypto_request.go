package contract

// CryptoRequestView borrows the complete bounded body. Own validates the value
// again before copying bytes into an independently owned request.
type CryptoRequestView CryptoRequest

func cryptoRequestSize(q CryptoRequest) (int, error) {
	if len(q.Body) > CryptoRequestLimit-cryptoRequestHeader {
		return 0, ErrCryptoCapacity
	}
	if q.Schema != CryptoSchema || !q.Kind.Valid() || q.RequestID.IsZero() || q.CustodyInstanceID.IsZero() {
		return 0, ErrCryptoMessage
	}
	if err := cryptoRequestBody(q.Kind, q.Body); err != nil {
		return 0, err
	}
	return cryptoRequestHeader + len(q.Body), nil
}

func writeCryptoRequest(w *cryptoWriter, q CryptoRequest) {
	w.u16(q.Schema)
	w.u8(uint8(q.Kind))
	w.id(q.RequestID)
	w.id(q.CustodyInstanceID)
	w.blob(q.Body)
}

func readCryptoRequest(r *cryptoReader) CryptoRequestView {
	v := CryptoRequestView{Schema: r.u16(), Kind: CryptoKind(r.u8()), RequestID: r.requiredID(), CustodyInstanceID: r.requiredID()}
	if r.err == nil && (v.Schema != CryptoSchema || !v.Kind.Valid()) {
		r.err = ErrCryptoMessage
	}
	body := r.blob(CryptoRequestLimit - cryptoRequestHeader)
	if r.err == nil {
		r.err = cryptoRequestBody(v.Kind, body)
	}
	if len(body) > 0 {
		v.Body = body[:len(body):len(body)]
	}
	return v
}

func (v CryptoRequestView) Own() (CryptoRequest, error) {
	q := CryptoRequest(v)
	if _, err := cryptoRequestSize(q); err != nil {
		return CryptoRequest{}, err
	}
	q.Body = ownedBytes(q.Body)
	return q, nil
}

func AppendCryptoRequest(dst []byte, q CryptoRequest) ([]byte, error) {
	if _, err := cryptoRequestSize(q); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeCryptoRequest(&w, q)
	return w.b, nil
}

func ParseCryptoRequest(b []byte) (CryptoRequestView, int, error) {
	r := cryptoReader{b: b[:min(len(b), CryptoRequestLimit)]}
	v := readCryptoRequest(&r)
	if r.err != nil {
		return CryptoRequestView{}, 0, r.failure()
	}
	return v, r.i, nil
}
