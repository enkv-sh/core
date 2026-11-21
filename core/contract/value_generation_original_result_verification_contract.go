package contract

type CryptoGeneratedVerifyRequest struct {
	OperationRef   ID
	Context        ApplyContext
	Result         []byte
	ExpectedResult GeneratorDescriptor
}

func cryptoGeneratedVerifyError(v CryptoGeneratedVerifyRequest) error {
	if err := cryptoGeneratedStageError(v.OperationRef, v.Context); err != nil {
		return err
	}
	if !cryptoGeneratedVerificationLengthValid(v.Context.IntentDescriptor.Length) || len(v.Result) > GeneratedResultRecordMaxLength {
		return ErrCryptoMessage
	}
	if _, err := InspectGeneratedResultRecord(v.Result); err != nil {
		return err
	}
	if v.ExpectedResult != (GeneratorDescriptor{Digest: Hash(v.Result), Length: uint64(len(v.Result)), Count: 1}) {
		return ErrCryptoMessage
	}
	return nil
}

func EncodeCryptoGeneratedVerifyRequest(v CryptoGeneratedVerifyRequest) ([]byte, error) {
	if err := cryptoGeneratedVerifyError(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, cryptoGeneratedResultRequestOverhead+len(v.Result))}
	w.id(v.OperationRef)
	w.context(v.Context)
	w.u8(uint8(CryptoGeneratedPrepareVerifyOriginal))
	w.blob(v.Result)
	writeGeneratorDescriptor(&w, v.ExpectedResult)
	return w.b, nil
}

func InspectCryptoGeneratedVerifyRequest(b []byte) (CryptoGeneratedVerifyRequest, error) {
	if len(b) > CryptoGeneratedAdoptLimit {
		return CryptoGeneratedVerifyRequest{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoGeneratedVerifyRequest{OperationRef: r.requiredID(), Context: readCryptoGeneratedContext(&r)}
	if CryptoGeneratedPrepareVariant(r.u8()) != CryptoGeneratedPrepareVerifyOriginal && r.err == nil {
		r.err = ErrCryptoMessage
	}
	v.Result, v.ExpectedResult = r.blob(GeneratedResultRecordMaxLength), readGeneratorDescriptor(&r)
	if err := r.end(); err != nil {
		return CryptoGeneratedVerifyRequest{}, err
	}
	if err := cryptoGeneratedVerifyError(v); err != nil {
		return CryptoGeneratedVerifyRequest{}, err
	}
	return v, nil
}
