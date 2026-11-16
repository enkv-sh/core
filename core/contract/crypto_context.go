package contract

import "math"

func cryptoContextBaseError(c ApplyContext) error {
	if c.OperationClass != CryptoOrdinaryLifecycle && c.OperationClass != CryptoAccessReplacementClass || c.Expiry == 0 || c.Expiry > math.MaxInt64 {
		return ErrCryptoMessage
	}
	if !publicIDsValid(c.AdmissionID, c.SessionID, c.DomainID, c.CompatibilityID,
		c.PredecessorHEADDigest, c.OriginalConditionDigest) ||
		!cryptoRefValid(c.PredecessorRootRef[:], byte(RootKind), c.DomainID) {
		return ErrCryptoMessage
	}
	return nil
}

func cryptoContextError(c ApplyContext) error {
	if c.OperationClass == CryptoGeneratedClass {
		return cryptoGeneratedContextError(c)
	}
	if err := cryptoContextBaseError(c); err != nil {
		return err
	}
	if c.IntentDescriptor.Digest.IsZero() {
		return ErrCryptoMessage
	}
	if c.OperationClass == CryptoAccessReplacementClass {
		ordinary := c.IntentDescriptor.Count == 1 && c.IntentDescriptor.Length >= uint64(requestCoreFixedLength+1) && c.IntentDescriptor.Length <= uint64(RequestCoreMaxLength)
		if (!ordinary && successionRequestDescriptorError(c.IntentDescriptor) != nil) || c.CurrentAccessRoot.IsZero() {
			return ErrCryptoMessage
		}
		return nil
	}
	return cryptoLifecycleIntentDescriptorError(c.DomainID, c.IntentDescriptor)
}

func cryptoWriteContext(w *cryptoWriter, c ApplyContext) {
	w.u8(uint8(c.OperationClass))
	for _, id := range []ID{c.AdmissionID, c.SessionID, c.DomainID, c.CompatibilityID} {
		w.id(id)
	}
	w.u64(c.Expiry)
	w.id(c.PredecessorHEADDigest)
	w.raw(c.PredecessorRootRef[:])
	w.id(c.OriginalConditionDigest)
	w.descriptor(c.IntentDescriptor)
	w.id(c.CurrentAccessRoot)
}

func cryptoReadContextFields(r *cryptoReader) ApplyContext {
	c := ApplyContext{OperationClass: CryptoOperationClass(r.u8()), AdmissionID: r.id(), SessionID: r.id(),
		DomainID: r.id(), CompatibilityID: r.id(),
		Expiry: r.u64(), PredecessorHEADDigest: r.id()}
	copy(c.PredecessorRootRef[:], r.take(CryptoRefLength))
	c.OriginalConditionDigest = r.id()
	c.IntentDescriptor = r.descriptor()
	c.CurrentAccessRoot = r.id()
	return c
}

func cryptoReadContext(r *cryptoReader) ApplyContext {
	c := cryptoReadContextFields(r)
	if r.err == nil {
		r.err = cryptoContextError(c)
	}
	return c
}

func AppendApplyContext(dst []byte, c ApplyContext) ([]byte, error) {
	if err := cryptoContextError(c); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	cryptoWriteContext(&w, c)
	return w.b, nil
}

func EncodeApplyContext(c ApplyContext) ([]byte, error) {
	if err := cryptoContextError(c); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, CryptoApplyContextLength)}
	cryptoWriteContext(&w, c)
	return w.b, nil
}

func ParseApplyContext(b []byte) (ApplyContext, int, error) {
	r := cryptoReader{b: b}
	c := cryptoReadContext(&r)
	if r.err != nil {
		return ApplyContext{}, 0, r.failure()
	}
	return c, r.i, nil
}

func InspectApplyContext(b []byte) (ApplyContext, error) {
	if len(b) != CryptoApplyContextLength {
		return ApplyContext{}, ErrCryptoMessage
	}
	c, _, err := ParseApplyContext(b)
	return c, err
}

func DecodeApplyContext(b []byte) (ApplyContext, error) { return InspectApplyContext(b) }

func (r *cryptoReader) context() ApplyContext {
	if r.u32() != CryptoApplyContextLength && r.err == nil {
		r.err = ErrCryptoMessage
	}
	return cryptoReadContext(r)
}

func (w *cryptoWriter) context(c ApplyContext) {
	w.u32(CryptoApplyContextLength)
	cryptoWriteContext(w, c)
}
