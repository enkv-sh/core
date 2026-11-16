package contract

import "slices"

func cryptoRequestContext(kind CryptoKind, body []byte) (ApplyContext, error) {
	r := cryptoReader{b: body}
	switch kind {
	case CryptoCompare:
	case CryptoPrepare, CryptoFreeze, CryptoClaim, CryptoDiscard:
		_ = r.requiredID()
	default:
		return ApplyContext{}, nil
	}
	c := r.context()
	return c, r.failure()
}

func cryptoRequestBody(kind CryptoKind, body []byte) error {
	c, err := cryptoRequestContext(kind, body)
	if err != nil {
		return err
	}
	if c.OperationClass == CryptoGeneratedClass {
		return cryptoGeneratedRequestBody(kind, body)
	}
	if kind == CryptoPrepare || kind == CryptoFreeze || kind == CryptoClaim {
		if c.OperationClass == CryptoAccessReplacementClass {
			switch kind {
			case CryptoPrepare:
				_, err := DecodeCryptoAccessPrepareRequest(body)
				return err
			case CryptoFreeze:
				_, err := DecodeCryptoAccessFreezeRequest(body)
				return err
			case CryptoClaim:
				_, err := DecodeCryptoAccessClaimRequest(body)
				return err
			}
		}
	}
	switch kind {
	case CryptoAccessReplace:
		_, err := DecodeCryptoAccessReplaceRequest(body)
		return err
	case CryptoCompare:
		_, err := cryptoScanCompare(body)
		return err
	case CryptoPrepare:
		_, err := cryptoReadPrepare(body)
		return err
	case CryptoFreeze:
		_, err := cryptoReadFreeze(body)
		return err
	case CryptoClaim:
		_, err := DecodeCryptoClaimRequest(body)
		return err
	case CryptoDiscard:
		_, err := DecodeCryptoDiscardRequest(body)
		return err
	case CryptoQualifyInitKeys:
		_, err := inspectCryptoQualifyInitKeysRequest(body)
		return err
	default:
		return ErrCryptoMessage
	}
}
func cryptoResponseBody(kind CryptoKind, code CryptoResultCode, body []byte) error {
	if !kind.Valid() || !code.Valid() {
		return ErrCryptoMessage
	}
	if code != CryptoSuccess {
		if len(body) != 0 {
			return ErrCryptoMessage
		}
		return nil
	}
	switch kind {
	case CryptoAccessReplace:
		_, err := DecodeCryptoAccessReplaceResult(body)
		return err
	case CryptoCompare:
		_, err := cryptoScanCompareResult(body)
		return err
	case CryptoPrepare:
		if len(body) == 0 {
			return nil
		}
		_, err := cryptoScanPrepareResult(body)
		if err != nil {
			_, err = DecodeCryptoAccessPrepareResult(body)
		}
		return err
	case CryptoFreeze:
		_, err := DecodeCryptoFreezeResult(body)
		return err
	case CryptoClaim, CryptoDiscard:
		if len(body) == 0 {
			return nil
		}
		return ErrCryptoMessage
	case CryptoQualifyInitKeys:
		_, err := DecodeCryptoQualifyInitKeysResult(body)
		return err
	default:
		return ErrCryptoMessage
	}
}
func cryptoCorrelatedSuccessBody(q CryptoRequest, p CryptoResponse) error {
	if q.Kind == CryptoCompare {
		r := cryptoReader{b: q.Body}
		_ = r.context()
		if r.err != nil {
			return r.failure()
		}
		_, err := cryptoScanCompareResult(p.Body)
		return err
	}
	if q.Kind == CryptoAccessReplace {
		in, err := DecodeCryptoAccessReplaceRequest(q.Body)
		if err != nil {
			return err
		}
		out, err := DecodeCryptoAccessReplaceResult(p.Body)
		if err != nil {
			return err
		}
		return ValidateAccessReplaceResult(in, out)
	}
	if q.Kind == CryptoPrepare {
		r := cryptoReader{b: q.Body}
		_ = r.requiredID()
		c := r.context()
		if r.err != nil {
			return r.failure()
		}
		if c.OperationClass == CryptoAccessReplacementClass {
			in, err := DecodeCryptoAccessPrepareRequest(q.Body)
			if err != nil {
				return err
			}
			out, err := DecodeCryptoAccessPrepareResult(p.Body)
			if err != nil {
				return err
			}
			return ValidateAccessBatchResult(in, out)
		}
		_, err := cryptoScanPrepareResult(p.Body)
		return err
	}
	if q.Kind != CryptoQualifyInitKeys {
		return cryptoResponseBody(q.Kind, p.ResultCode, p.Body)
	}
	a, err := DecodeCryptoQualifyInitKeysRequest(q.Body)
	if err != nil {
		return err
	}
	b, err := DecodeCryptoQualifyInitKeysResult(p.Body)
	if err != nil {
		return err
	}
	if err := ValidateGenesisQualifiedKeys(a, b); err != nil {
		return err
	}
	return validateSuccessfulInitKeyUseRows(a, p.KeyUseRows)
}
func EncodeCryptoQualifyInitKeysResult(v GenesisQualifiedKeysCore) ([]byte, error) {
	b, err := EncodeGenesisQualifiedKeysCore(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 4+len(b))}
	w.blob(b)
	return w.b, nil
}
func DecodeCryptoQualifyInitKeysResult(b []byte) (GenesisQualifiedKeysCore, error) {
	if len(b) > 4+GenesisQualifiedKeysMaxLength {
		return GenesisQualifiedKeysCore{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	core := r.blob(GenesisQualifiedKeysMaxLength)
	if err := r.end(); err != nil {
		return GenesisQualifiedKeysCore{}, err
	}
	return DecodeGenesisQualifiedKeysCore(core)
}
func ValidateInitKeyUseRows(q CryptoQualifyInitKeysRequest, rows []KeyUseRow) error {
	if len(rows) > InitKeyUseRowsMaxCount || len(rows) > 4*(len(q.Bindings)+len(q.Probes)) {
		return ErrCryptoCapacity
	}
	if _, err := KeyUseRowsLength(rows); err != nil {
		return err
	}
	for _, use := range rows {
		if use.Purpose != KeyUsePublicKeyRead && use.Purpose != KeyUsePrivateRoleProbe {
			return ErrCryptoMessage
		}
		found := false
		for _, binding := range q.Bindings {
			if binding.Binding.BindingID != use.BindingID || binding.SubjectKind != use.SubjectKind || binding.SubjectID != use.SubjectID {
				continue
			}
			digest, err := PublicBindingDigest(binding.Binding)
			if err != nil || digest != use.PublicBindingDigest || binding.Binding.Provider != use.Provider {
				return ErrCryptoMessage
			}
			found = true
		}
		if !found {
			return ErrCryptoMessage
		}
		if use.Purpose == KeyUsePrivateRoleProbe {
			found = false
			for _, probe := range q.Probes {
				if probe.BindingID == use.BindingID && probe.SubjectKind == use.SubjectKind && probe.SubjectID == use.SubjectID && probe.PublicBindingDigest == use.PublicBindingDigest {
					found = true
				}
			}
			if !found {
				return ErrCryptoMessage
			}
		}
	}
	return nil
}

func PublicKeyQualificationUseCount(provider Family) uint32 {
	if provider == AWS {
		return 2
	}
	if provider == GCP {
		return 3
	}
	return 0
}

func validateSuccessfulInitKeyUseRows(q CryptoQualifyInitKeysRequest, rows []KeyUseRow) error {
	if err := ValidateInitKeyUseRows(q, rows); err != nil {
		return err
	}
	if len(rows) != len(q.Bindings)+len(q.Probes) {
		return ErrCryptoMessage
	}
	type bindingRelation struct {
		bindingID           ID
		publicBindingDigest ID
		subjectKind         uint8
		subjectID           ID
	}
	expected := make([]KeyUseRow, 0, len(rows))
	providers := make(map[bindingRelation]Family, len(q.Bindings))
	for _, binding := range q.Bindings {
		digest, err := PublicBindingDigest(binding.Binding)
		if err != nil {
			return err
		}
		count := PublicKeyQualificationUseCount(binding.Binding.Provider)
		if count == 0 {
			return ErrCryptoMessage
		}
		relation := bindingRelation{bindingID: binding.Binding.BindingID, publicBindingDigest: digest, subjectKind: binding.SubjectKind, subjectID: binding.SubjectID}
		providers[relation] = binding.Binding.Provider
		expected = append(expected, KeyUseRow{BindingID: relation.bindingID, PublicBindingDigest: relation.publicBindingDigest, SubjectKind: relation.subjectKind, SubjectID: relation.subjectID, Provider: binding.Binding.Provider, Purpose: KeyUsePublicKeyRead, Outcome: KeyUseCompleted, Count: count})
	}
	for _, probe := range q.Probes {
		relation := bindingRelation{bindingID: probe.BindingID, publicBindingDigest: probe.PublicBindingDigest, subjectKind: probe.SubjectKind, subjectID: probe.SubjectID}
		provider, ok := providers[relation]
		if !ok || !provider.Valid() {
			return ErrCryptoMessage
		}
		expected = append(expected, KeyUseRow{BindingID: relation.bindingID, PublicBindingDigest: relation.publicBindingDigest, SubjectKind: relation.subjectKind, SubjectID: relation.subjectID, Provider: provider, Purpose: KeyUsePrivateRoleProbe, Outcome: KeyUseCompleted, Count: 1})
	}
	slices.SortFunc(expected, compareKeyUseRows)
	if !slices.Equal(rows, expected) {
		return ErrCryptoMessage
	}
	return nil
}
