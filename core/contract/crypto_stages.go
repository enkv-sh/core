package contract

const (
	cryptoOperationContextLength = 32 + cryptoContextBlobLength
	cryptoFreezeBaseLength       = cryptoOperationContextLength + 2*descriptorSize + 3*4
	cryptoClaimLength            = cryptoOperationContextLength + 4*descriptorSize + 32
)

func cryptoStageError(operation ID, c ApplyContext) error {
	if operation.IsZero() {
		return ErrCryptoMessage
	}
	return cryptoContextError(c)
}

func cryptoPrepareValid(q CryptoPrepareRequest) error {
	if q.Context.OperationClass != CryptoOrdinaryLifecycle {
		return ErrCryptoMessage
	}
	if err := cryptoStageError(q.OperationRef, q.Context); err != nil {
		return err
	}
	d, err := cryptoIdentityProjection(q.IdentityPlan)
	if err != nil {
		return err
	}
	if d.Count > q.Context.IntentDescriptor.Count {
		return ErrCryptoMessage
	}
	return nil
}
func cryptoReadPrepare(b []byte) (CryptoPrepareRequest, error) {
	if len(b) > cryptoOperationContextLength+4+cryptoIdentityLimit {
		return CryptoPrepareRequest{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	q := CryptoPrepareRequest{OperationRef: r.requiredID(), Context: r.context(), IdentityPlan: r.blob(cryptoIdentityLimit)}
	if err := r.end(); err != nil {
		return CryptoPrepareRequest{}, err
	}
	return q, cryptoPrepareValid(q)
}
func EncodeCryptoPrepareRequest(q CryptoPrepareRequest) ([]byte, error) {
	if err := cryptoPrepareValid(q); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, cryptoOperationContextLength+4+len(q.IdentityPlan))}
	w.id(q.OperationRef)
	w.context(q.Context)
	w.blob(q.IdentityPlan)
	return w.b, nil
}
func DecodeCryptoPrepareRequest(b []byte) (CryptoPrepareRequest, error) {
	q, err := cryptoReadPrepare(b)
	if err != nil {
		return CryptoPrepareRequest{}, err
	}
	q.IdentityPlan = ownedBytes(q.IdentityPlan)
	return q, nil
}

func cryptoFreezeValid(q CryptoFreezeRequest) error {
	if _, err := currentApplyRecipientsLength(q.Recipients); err != nil {
		return err
	}
	return cryptoFreezeFieldsValid(q)
}

func cryptoFreezeFieldsValid(q CryptoFreezeRequest) error {
	if q.Context.OperationClass != CryptoOrdinaryLifecycle {
		return ErrCryptoMessage
	}
	if err := cryptoStageError(q.OperationRef, q.Context); err != nil {
		return err
	}
	if err := cryptoIdentityDescriptorError(q.IdentityPlanDescriptor); err != nil {
		return err
	}
	if err := cryptoPreparedDescriptorError(q.CanonicalRowsDescriptor); err != nil {
		return err
	}
	candidate, err := cryptoPublicProjection(q.CandidatePublicState, q.Context.DomainID)
	if err != nil {
		return err
	}
	exclusion, err := cryptoExclusionProjection(q.Exclusions, q.Context.DomainID)
	if err != nil {
		return err
	}
	return cryptoLifecycleDescriptorsError(q.Context, q.IdentityPlanDescriptor, candidate, q.CanonicalRowsDescriptor, exclusion)
}

type cryptoFreezeLayout struct {
	request    CryptoFreezeRequest
	recipients applyRecipientProjectionView
}

func cryptoReadFreeze(b []byte) (cryptoFreezeLayout, error) {
	if len(b) > cryptoFreezeBaseLength+cryptoPublicLimit+cryptoExclusionLimit+currentApplyRegistryLimit {
		return cryptoFreezeLayout{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	q := CryptoFreezeRequest{OperationRef: r.requiredID(), Context: r.context(), IdentityPlanDescriptor: r.descriptor(), CanonicalRowsDescriptor: r.descriptor(), CandidatePublicState: r.blob(cryptoPublicLimit), Exclusions: r.blob(cryptoExclusionLimit)}
	registry := r.blob(currentApplyRegistryLimit)
	if err := r.end(); err != nil {
		return cryptoFreezeLayout{}, err
	}
	nested := cryptoReader{b: registry}
	recipients := readApplyRecipientProjection(&nested, false)
	if err := nested.end(); err != nil {
		return cryptoFreezeLayout{}, err
	}
	if err := cryptoFreezeFieldsValid(q); err != nil {
		return cryptoFreezeLayout{}, err
	}
	if err := recipients.keysError(); err != nil {
		return cryptoFreezeLayout{}, err
	}
	return cryptoFreezeLayout{request: q, recipients: recipients}, nil
}

func EncodeCryptoFreezeRequest(q CryptoFreezeRequest) ([]byte, error) {
	if err := cryptoFreezeValid(q); err != nil {
		return nil, err
	}
	registry, err := currentApplyRecipientsLength(q.Recipients)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, cryptoFreezeBaseLength+len(q.CandidatePublicState)+len(q.Exclusions)+registry)}
	w.id(q.OperationRef)
	w.context(q.Context)
	w.descriptor(q.IdentityPlanDescriptor)
	w.descriptor(q.CanonicalRowsDescriptor)
	w.blob(q.CandidatePublicState)
	w.blob(q.Exclusions)
	w.u32(uint32(registry))
	writeCurrentApplyRecipients(&w, q.Recipients)
	return w.b, nil
}

func DecodeCryptoFreezeRequest(b []byte) (CryptoFreezeRequest, error) {
	l, err := cryptoReadFreeze(b)
	if err != nil {
		return CryptoFreezeRequest{}, err
	}
	q := l.request
	q.CandidatePublicState = ownedBytes(q.CandidatePublicState)
	q.Exclusions = ownedBytes(q.Exclusions)
	q.Recipients = l.recipients.ownCurrent()
	return q, nil
}
func EncodeCryptoFreezeResult(q CryptoFreezeResult) ([]byte, error) {
	if q.FactDigest.IsZero() {
		return nil, ErrCryptoMessage
	}
	return ownedBytes(q.FactDigest[:]), nil
}
func DecodeCryptoFreezeResult(b []byte) (CryptoFreezeResult, error) {
	if len(b) != 32 {
		return CryptoFreezeResult{}, ErrCryptoMessage
	}
	r := cryptoReader{b: b}
	q := CryptoFreezeResult{FactDigest: r.requiredID()}
	if err := r.end(); err != nil {
		return CryptoFreezeResult{}, err
	}
	return q, nil
}

func cryptoClaimError(q CryptoClaimRequest) error {
	if q.Context.OperationClass != CryptoOrdinaryLifecycle {
		return ErrCryptoMessage
	}
	if err := cryptoStageError(q.OperationRef, q.Context); err != nil {
		return err
	}
	if q.FactDigest.IsZero() {
		return ErrCryptoMessage
	}
	return cryptoLifecycleDescriptorsError(q.Context, q.IdentityPlanDescriptor, q.CandidatePublicStateDescriptor, q.CanonicalRowsDescriptor, q.ExclusionDescriptor)
}
func writeFrozenDescriptors(w *cryptoWriter, q CryptoClaimRequest) {
	w.descriptor(q.IdentityPlanDescriptor)
	w.descriptor(q.CandidatePublicStateDescriptor)
	w.descriptor(q.CanonicalRowsDescriptor)
	w.descriptor(q.ExclusionDescriptor)
}
func readFrozenDescriptors(r *cryptoReader, q *CryptoClaimRequest) {
	q.IdentityPlanDescriptor = r.descriptor()
	q.CandidatePublicStateDescriptor = r.descriptor()
	q.CanonicalRowsDescriptor = r.descriptor()
	q.ExclusionDescriptor = r.descriptor()
}
func EncodeCryptoClaimRequest(q CryptoClaimRequest) ([]byte, error) {
	if err := cryptoClaimError(q); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, cryptoClaimLength)}
	w.id(q.OperationRef)
	w.context(q.Context)
	writeFrozenDescriptors(&w, q)
	w.id(q.FactDigest)
	return w.b, nil
}
func DecodeCryptoClaimRequest(b []byte) (CryptoClaimRequest, error) {
	if len(b) != cryptoClaimLength {
		return CryptoClaimRequest{}, ErrCryptoMessage
	}
	r := cryptoReader{b: b}
	q := cryptoReadLifecycleClaimFields(&r, r.requiredID(), r.context())
	if err := r.end(); err != nil {
		return CryptoClaimRequest{}, err
	}
	return q, nil
}

func cryptoReadLifecycleClaimFields(r *cryptoReader, operation ID, c ApplyContext) CryptoClaimRequest {
	q := CryptoClaimRequest{OperationRef: operation, Context: c}
	readFrozenDescriptors(r, &q)
	q.FactDigest = r.requiredID()
	if r.err == nil {
		r.err = cryptoClaimError(q)
	}
	return q
}
func EncodeCryptoDiscardRequest(q CryptoDiscardRequest) ([]byte, error) {
	if err := cryptoStageError(q.OperationRef, q.Context); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, cryptoOperationContextLength)}
	w.id(q.OperationRef)
	w.context(q.Context)
	return w.b, nil
}
func DecodeCryptoDiscardRequest(b []byte) (CryptoDiscardRequest, error) {
	if len(b) != cryptoOperationContextLength {
		return CryptoDiscardRequest{}, ErrCryptoMessage
	}
	r := cryptoReader{b: b}
	q := CryptoDiscardRequest{OperationRef: r.requiredID(), Context: r.context()}
	if err := r.end(); err != nil {
		return CryptoDiscardRequest{}, err
	}
	if err := cryptoStageError(q.OperationRef, q.Context); err != nil {
		return CryptoDiscardRequest{}, err
	}
	return q, nil
}
