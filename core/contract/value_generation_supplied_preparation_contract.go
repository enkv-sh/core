package contract

import "bytes"

const cryptoGeneratedSuppliedRequestLimit = cryptoGeneratedOperationContextLength + 46 + cryptoIdentityLimit +
	4 + CryptoMaxValueEntries*cryptoSealedInputRowFixedLength + CryptoMaxRetainedSet

// CryptoGeneratedSuppliedRequest carries the final identities for changed
// supplied entries and the exact sealed inputs that need canonical material.
// Plain inputs remain public, but their identities stay in the same plan so
// Crypto can bind the complete mixed candidate before claim.
type CryptoGeneratedSuppliedRequest struct {
	OperationRef ID
	Context      ApplyContext
	PhaseID      ID
	BatchIndex   uint32
	Final        uint8
	IdentityPlan []byte
	SealedInputs []CryptoSealedInput
}

type CryptoGeneratedSuppliedRequestView struct {
	OperationRef ID
	Context      ApplyContext
	PhaseID      ID
	BatchIndex   uint32
	Final        uint8
	IdentityPlan []byte
	sealedInputs []byte
	count        int
}

type cryptoGeneratedSuppliedInputTraversal struct {
	reader    cryptoReader
	remaining int
}

func (v CryptoGeneratedSuppliedRequestView) forwardSealedInputs() cryptoGeneratedSuppliedInputTraversal {
	return cryptoGeneratedSuppliedInputTraversal{reader: cryptoReader{b: v.sealedInputs}, remaining: v.count}
}

func (t *cryptoGeneratedSuppliedInputTraversal) next() (cryptoSealedInputRowView, bool, error) {
	if t.remaining == 0 {
		return cryptoSealedInputRowView{}, false, t.reader.end()
	}
	row := cryptoReadSealedInputRow(&t.reader)
	if t.reader.err != nil {
		return cryptoSealedInputRowView{}, false, t.reader.failure()
	}
	t.remaining--
	return row, true, nil
}

func cryptoGeneratedSuppliedRequestViewError(v CryptoGeneratedSuppliedRequestView) error {
	if v.count < 0 || v.count > CryptoMaxValueEntries || len(v.IdentityPlan) > cryptoIdentityLimit ||
		cryptoGeneratedOperationContextLength+46+len(v.IdentityPlan)+len(v.sealedInputs) > cryptoGeneratedSuppliedRequestLimit ||
		cryptoGeneratedOperationContextLength+46+len(v.IdentityPlan)+len(v.sealedInputs) > CryptoRequestLimit-cryptoRequestHeader {
		return ErrCryptoCapacity
	}
	if err := cryptoGeneratedStageError(v.OperationRef, v.Context); err != nil {
		return err
	}
	if v.PhaseID.IsZero() || v.BatchIndex >= CryptoMaxValueEntries || v.Final > 1 {
		return ErrCryptoMessage
	}
	identity, err := InspectIdentityPlan(v.IdentityPlan)
	if err != nil {
		return err
	}
	if identity.Descriptor.Count > CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	rows := v.forwardSealedInputs()
	var previous []byte
	for i := 0; ; i++ {
		row, ok, err := rows.next()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if !cryptoNamesValid(previous, row.name, i == 0) {
			return ErrCryptoMessage
		}
		envelope, err := InspectSealedInputEnvelope(row.envelopeBytes)
		if err != nil || !bytes.Equal(row.name, envelope.Core.Name) || envelope.Core.DomainID != v.Context.DomainID ||
			envelope.Core.CompatibilityID != v.Context.CompatibilityID {
			return ErrCryptoMessage
		}
		previous = row.name
	}
}

func cryptoGeneratedSuppliedRequestError(v CryptoGeneratedSuppliedRequest) error {
	if err := cryptoGeneratedStageError(v.OperationRef, v.Context); err != nil || v.PhaseID.IsZero() || v.BatchIndex >= CryptoMaxValueEntries || v.Final > 1 {
		if err != nil {
			return err
		}
		return ErrCryptoMessage
	}
	identity, err := InspectIdentityPlan(v.IdentityPlan)
	if err != nil {
		return err
	}
	if identity.Descriptor.Count > CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	if len(v.SealedInputs) > CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	for i, source := range v.SealedInputs {
		if len(source.Name) > CryptoMaxName || len(source.EnvelopeBytes) > CryptoMaxSealedInputLength {
			return ErrCryptoCapacity
		}
		if !cryptoNamesValid(nil, []byte(source.Name), true) || i > 0 && v.SealedInputs[i-1].Name >= source.Name {
			return ErrCryptoMessage
		}
		envelope, err := InspectSealedInputEnvelope(source.EnvelopeBytes)
		if err != nil || !bytes.Equal(envelope.Core.Name, []byte(source.Name)) || envelope.Core.DomainID != v.Context.DomainID ||
			envelope.Core.CompatibilityID != v.Context.CompatibilityID {
			return ErrCryptoMessage
		}
	}
	return nil
}

func EncodeCryptoGeneratedSuppliedRequest(v CryptoGeneratedSuppliedRequest) ([]byte, error) {
	if err := cryptoGeneratedSuppliedRequestError(v); err != nil {
		return nil, err
	}
	n := cryptoGeneratedOperationContextLength + 46 + len(v.IdentityPlan)
	for _, source := range v.SealedInputs {
		n += 8 + len(source.Name) + len(source.EnvelopeBytes)
	}
	if n > cryptoGeneratedSuppliedRequestLimit || n > CryptoRequestLimit-cryptoRequestHeader {
		return nil, ErrCryptoCapacity
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	w.id(v.OperationRef)
	w.context(v.Context)
	w.u8(uint8(CryptoGeneratedPrepareSupplied))
	w.id(v.PhaseID)
	w.u32(v.BatchIndex)
	w.u8(v.Final)
	w.blob(v.IdentityPlan)
	w.u32(uint32(len(v.SealedInputs)))
	for _, source := range v.SealedInputs {
		cryptoWriteSealedInputRow(&w, source)
	}
	return w.b, nil
}

func InspectCryptoGeneratedSuppliedRequest(b []byte) (CryptoGeneratedSuppliedRequestView, error) {
	if len(b) > cryptoGeneratedSuppliedRequestLimit || len(b) > CryptoRequestLimit-cryptoRequestHeader {
		return CryptoGeneratedSuppliedRequestView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoGeneratedSuppliedRequestView{OperationRef: r.requiredID(), Context: r.context()}
	if CryptoGeneratedPrepareVariant(r.u8()) != CryptoGeneratedPrepareSupplied {
		return CryptoGeneratedSuppliedRequestView{}, ErrCryptoMessage
	}
	v.PhaseID, v.BatchIndex, v.Final = r.requiredID(), r.u32(), r.u8()
	v.IdentityPlan = r.blob(cryptoIdentityLimit)
	v.count = r.count(CryptoMaxValueEntries, cryptoSealedInputRowFixedLength)
	if r.err != nil {
		return CryptoGeneratedSuppliedRequestView{}, r.failure()
	}
	v.sealedInputs = b[r.i:len(b):len(b)]
	if err := cryptoGeneratedSuppliedRequestViewError(v); err != nil {
		return CryptoGeneratedSuppliedRequestView{}, err
	}
	return v, nil
}

func (v CryptoGeneratedSuppliedRequestView) SealedInputCount() int { return v.count }

func (v CryptoGeneratedSuppliedRequestView) Own() (CryptoGeneratedSuppliedRequest, error) {
	if err := cryptoGeneratedSuppliedRequestViewError(v); err != nil {
		return CryptoGeneratedSuppliedRequest{}, err
	}
	out := CryptoGeneratedSuppliedRequest{OperationRef: v.OperationRef, Context: v.Context, PhaseID: v.PhaseID,
		BatchIndex: v.BatchIndex, Final: v.Final,
		IdentityPlan: ownedBytes(v.IdentityPlan), SealedInputs: make([]CryptoSealedInput, v.count)}
	rows := v.forwardSealedInputs()
	for i := range out.SealedInputs {
		row, ok, err := rows.next()
		if err != nil {
			return CryptoGeneratedSuppliedRequest{}, err
		}
		if !ok {
			return CryptoGeneratedSuppliedRequest{}, ErrCryptoMessage
		}
		out.SealedInputs[i] = CryptoSealedInput{Name: string(row.name), EnvelopeBytes: ownedBytes(row.envelopeBytes)}
	}
	if _, ok, err := rows.next(); err != nil {
		return CryptoGeneratedSuppliedRequest{}, err
	} else if ok {
		return CryptoGeneratedSuppliedRequest{}, ErrCryptoMessage
	}
	return out, nil
}

type CryptoGeneratedSuppliedResult struct {
	BatchIndex uint32
	Final      uint8
	Rows       []CryptoPreparedSecret
}

type CryptoGeneratedSuppliedResultView struct {
	BatchIndex uint32
	Final      uint8
	CryptoPreparedRowsView
}

func EncodeCryptoGeneratedSuppliedResult(v CryptoGeneratedSuppliedResult) ([]byte, error) {
	if v.BatchIndex >= CryptoMaxValueEntries || v.Final > 1 {
		return nil, ErrCryptoMessage
	}
	body, err := EncodeCryptoPrepareResult(CryptoPrepareResult{Rows: v.Rows})
	if err != nil {
		return nil, err
	}
	if 6+len(body) > CryptoGeneratedResponseLimit-cryptoResponseHeader {
		return nil, ErrCryptoCapacity
	}
	w := cryptoWriter{b: make([]byte, 0, 6+len(body))}
	w.u8(uint8(CryptoGeneratedPrepareSupplied))
	w.u32(v.BatchIndex)
	w.u8(v.Final)
	w.raw(body)
	return w.b, nil
}

func InspectCryptoGeneratedSuppliedResult(b []byte) (CryptoGeneratedSuppliedResultView, error) {
	if len(b) > CryptoGeneratedResponseLimit-cryptoResponseHeader {
		return CryptoGeneratedSuppliedResultView{}, ErrCryptoCapacity
	}
	if len(b) < 6 || CryptoGeneratedPrepareVariant(b[0]) != CryptoGeneratedPrepareSupplied {
		return CryptoGeneratedSuppliedResultView{}, ErrCryptoMessage
	}
	r := cryptoReader{b: b[1:]}
	index, final := r.u32(), r.u8()
	if r.err != nil || index >= CryptoMaxValueEntries || final > 1 {
		return CryptoGeneratedSuppliedResultView{}, ErrCryptoMessage
	}
	v, err := InspectCryptoPrepareResult(b[6:])
	if err != nil {
		return CryptoGeneratedSuppliedResultView{}, err
	}
	return CryptoGeneratedSuppliedResultView{BatchIndex: index, Final: final, CryptoPreparedRowsView: v}, nil
}
