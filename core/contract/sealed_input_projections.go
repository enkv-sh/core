package contract

import "bytes"

const (
	sealedInputAADPrefix     = cryptoPurposePrefix + "source-aad\x00"
	sealedInputBindingPrefix = cryptoPurposePrefix + "source-recipient-bindings\x00"
	sealedInputAADMaximum    = len(sealedInputAADPrefix) + 4 + SealedInputCoreFixedLength + CryptoMaxName
)

func SealedInputCoreDigest(v SealedInputCore) (ID, error) {
	if _, err := SealedInputCoreLength(v); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("")
	writeSealedInputCore(&w, v)
	return w.result(0).Digest, nil
}

func OriginalSealedInputEnvelopeDigest(v SealedInputEnvelope) (ID, error) {
	if _, err := SealedInputEnvelopeLength(v); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("")
	writeSealedInputEnvelope(&w, v)
	return w.result(0).Digest, nil
}

func SealedInputMaterialContextDigest(v SealedInputCore) (ID, error) {
	n, err := SealedInputCoreLength(v)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(valueMaterialDigestPrefix)
	w.u32(uint32(n))
	writeSealedInputCore(&w, v)
	return w.result(0).Digest, nil
}

func EncodeSealedInputAAD(v SealedInputCore) ([]byte, error) {
	n, err := SealedInputCoreLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, len(sealedInputAADPrefix)+4+n)}
	w.raw([]byte(sealedInputAADPrefix))
	w.u32(uint32(n))
	writeSealedInputCore(&w, v)
	return w.b, nil
}

func InspectSealedInputAAD(b []byte) (SealedInputCoreView, error) {
	if len(b) > sealedInputAADMaximum {
		return SealedInputCoreView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if !bytes.Equal(r.take(len(sealedInputAADPrefix)), []byte(sealedInputAADPrefix)) {
		return SealedInputCoreView{}, ErrRecord
	}
	core := r.blob(SealedInputCoreFixedLength + CryptoMaxName)
	if err := r.end(); err != nil {
		return SealedInputCoreView{}, err
	}
	return InspectSealedInputCore(core)
}

type RecipientBindingReference struct {
	RecipientID         ID
	PublicBindingDigest ID
}

// IntendedRecipientBindingSetDigest checks the supplied set's structure and
// authority membership. It does not authenticate the nominee or bindings.
func IntendedRecipientBindingSetDigest(domain, authority ID, rows []RecipientBindingReference) (ID, error) {
	if len(rows) > CryptoMaxValueEntryRecipients {
		return ID{}, ErrRecordCapacity
	}
	if domain.IsZero() || authority.IsZero() || len(rows) == 0 {
		return ID{}, ErrRecord
	}
	foundAuthority := false
	for i, row := range rows {
		if row.RecipientID.IsZero() || i > 0 && bytes.Compare(rows[i-1].RecipientID[:], row.RecipientID[:]) >= 0 {
			return ID{}, ErrRecord
		}
		foundAuthority = foundAuthority || row.RecipientID == authority
	}
	if !foundAuthority {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter(sealedInputBindingPrefix)
	w.id(domain)
	w.u16(uint16(len(rows)))
	for _, row := range rows {
		w.id(row.RecipientID)
		w.id(row.PublicBindingDigest)
	}
	return w.result(len(rows)).Digest, nil
}
