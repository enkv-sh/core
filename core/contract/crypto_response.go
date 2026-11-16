package contract

type CryptoResponseView struct {
	Schema                       uint16
	Kind                         CryptoKind
	RequestID, CustodyInstanceID ID
	ResultCode                   CryptoResultCode
	KeyUseRows                   KeyUseRowsView
	Body                         []byte
}

func cryptoResponseHeaderError(schema uint16, kind CryptoKind, request, instance ID, code CryptoResultCode) error {
	if schema != CryptoSchema || !kind.Valid() || request.IsZero() || instance.IsZero() || !code.Valid() {
		return ErrCryptoMessage
	}
	return nil
}

func cryptoResponseSize(q CryptoResponse) (int, error) {
	if len(q.KeyUseRows) > KeyUseRowsMaxCount || len(q.Body) > CryptoResponseLimit-cryptoResponseHeader {
		return 0, ErrCryptoCapacity
	}
	n, err := KeyUseRowsLength(q.KeyUseRows)
	if err != nil {
		return 0, err
	}
	size := cryptoResponseHeader + n - 2 + len(q.Body)
	if size > CryptoResponseLimit {
		return 0, ErrCryptoCapacity
	}
	if err := cryptoResponseHeaderError(q.Schema, q.Kind, q.RequestID, q.CustodyInstanceID, q.ResultCode); err != nil {
		return 0, err
	}
	if err := cryptoResponseBody(q.Kind, q.ResultCode, q.Body); err != nil {
		return 0, err
	}
	return size, nil
}

func writeCryptoResponse(w *cryptoWriter, q CryptoResponse) {
	w.u16(q.Schema)
	w.u8(uint8(q.Kind))
	w.id(q.RequestID)
	w.id(q.CustodyInstanceID)
	w.u16(uint16(q.ResultCode))
	writeKeyUseRows(w, q.KeyUseRows)
	w.blob(q.Body)
}

func readCryptoResponse(r *cryptoReader) CryptoResponseView {
	v := CryptoResponseView{Schema: r.u16(), Kind: CryptoKind(r.u8()), RequestID: r.requiredID(),
		CustodyInstanceID: r.requiredID(), ResultCode: CryptoResultCode(r.u16())}
	if r.err == nil {
		r.err = cryptoResponseHeaderError(v.Schema, v.Kind, v.RequestID, v.CustodyInstanceID, v.ResultCode)
	}
	v.KeyUseRows = readKeyUseRows(r)
	body := r.blob(CryptoResponseLimit - cryptoResponseHeader - len(v.KeyUseRows.Rows))
	if r.err == nil {
		r.err = cryptoResponseBody(v.Kind, v.ResultCode, body)
	}
	if len(body) > 0 {
		v.Body = body[:len(body):len(body)]
	}
	return v
}

func (v CryptoResponseView) Own() (CryptoResponse, error) {
	if len(v.Body) > CryptoResponseLimit-cryptoResponseHeader || len(v.KeyUseRows.Rows) > KeyUseRowsMaxLength-2 ||
		len(v.Body)+len(v.KeyUseRows.Rows) > CryptoResponseLimit-cryptoResponseHeader {
		return CryptoResponse{}, ErrCryptoCapacity
	}
	if err := cryptoResponseHeaderError(v.Schema, v.Kind, v.RequestID, v.CustodyInstanceID, v.ResultCode); err != nil {
		return CryptoResponse{}, err
	}
	if err := keyUseSpanError(v.KeyUseRows.Rows); err != nil {
		return CryptoResponse{}, err
	}
	if err := cryptoResponseBody(v.Kind, v.ResultCode, v.Body); err != nil {
		return CryptoResponse{}, err
	}
	q := CryptoResponse{Schema: v.Schema, Kind: v.Kind, RequestID: v.RequestID,
		CustodyInstanceID: v.CustodyInstanceID, ResultCode: v.ResultCode}
	if v.KeyUseRows.RowCount() != 0 {
		rows, err := v.KeyUseRows.Own()
		if err != nil {
			return CryptoResponse{}, err
		}
		q.KeyUseRows = rows
	}
	q.Body = ownedBytes(v.Body)
	return q, nil
}

func AppendCryptoResponse(dst []byte, q CryptoResponse) ([]byte, error) {
	if _, err := cryptoResponseSize(q); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeCryptoResponse(&w, q)
	return w.b, nil
}

func ParseCryptoResponse(b []byte) (CryptoResponseView, int, error) {
	r := cryptoReader{b: b[:min(len(b), CryptoResponseLimit)]}
	v := readCryptoResponse(&r)
	if r.err != nil {
		return CryptoResponseView{}, 0, r.failure()
	}
	return v, r.i, nil
}
