package contract

// CryptoFactsPreimage fixes the ordinary lifecycle facts. It is a hash
// preimage, not a received wire record or a grant of private admission.
type CryptoFactsPreimage struct {
	CustodyInstanceID, OperationRef                        ID
	Context                                                ApplyContext
	ComparisonOrCoverageDigest                             ID
	IdentityPlanDescriptor, CandidatePublicStateDescriptor DescriptorVector
	CanonicalRowsDescriptor, ExclusionDescriptor           DescriptorVector
}

const cryptoFactsPrefix = cryptoPurposePrefix + "crypto-facts-v2\x00"
const cryptoFactsCommonLength = len(cryptoFactsPrefix) + 2*32 + cryptoContextBlobLength + 32 + 4*descriptorSize

func CryptoFactsPreimageLength(v CryptoFactsPreimage) (int, error) {
	if v.CustodyInstanceID.IsZero() || v.OperationRef.IsZero() {
		return 0, ErrCryptoMessage
	}
	if err := cryptoContextError(v.Context); err != nil {
		return 0, err
	}
	if err := cryptoLifecycleDescriptorsError(v.Context, v.IdentityPlanDescriptor, v.CandidatePublicStateDescriptor, v.CanonicalRowsDescriptor, v.ExclusionDescriptor); err != nil {
		return 0, err
	}
	return cryptoFactsCommonLength, nil
}
func cryptoWriteFacts(w *cryptoWriter, v CryptoFactsPreimage) {
	w.raw([]byte(cryptoFactsPrefix))
	w.id(v.CustodyInstanceID)
	w.id(v.OperationRef)
	w.context(v.Context)
	w.id(v.ComparisonOrCoverageDigest)
	w.descriptor(v.IdentityPlanDescriptor)
	w.descriptor(v.CandidatePublicStateDescriptor)
	w.descriptor(v.CanonicalRowsDescriptor)
	w.descriptor(v.ExclusionDescriptor)
}
func EncodeCryptoFactsPreimage(v CryptoFactsPreimage) ([]byte, error) {
	n, err := CryptoFactsPreimageLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	cryptoWriteFacts(&w, v)
	return w.b, nil
}
func CryptoFactsDigest(v CryptoFactsPreimage) (ID, error) {
	if _, err := CryptoFactsPreimageLength(v); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("")
	cryptoWriteFacts(&w, v)
	return w.result(0).Digest, nil
}
