package contract

import "bytes"

const (
	recipientReplacementIntentPrefix      = cryptoPurposePrefix + "recipient-key-replacement-intent-v1\x00"
	recipientReplacementIntentFixedLength = len(recipientReplacementIntentPrefix) + 2 + 2 + 4*32 + 2 + 32 + 2*4
	recipientReplacementIntentMinLength   = recipientReplacementIntentFixedLength + 2*(kmsBindingFixedLength+1)
	recipientReplacementIntentMaxLength   = recipientReplacementIntentFixedLength + 2*KMSBindingMaxLength
)

type RecipientReplacementIntentFields struct {
	Schema, Profile                                              uint16
	CompatibilityID, CryptoSupportID, DomainID, BeforeAccessRoot ID
	RecipientID                                                  ID
}

type RecipientReplacementIntent struct {
	RecipientReplacementIntentFields
	Before, Successor KMSBinding
}

type RecipientReplacementIntentView struct {
	RecipientReplacementIntentFields
	Before, Successor KMSBindingView
}

func recipientReplacementFieldsValid(v RecipientReplacementIntentFields) bool {
	return v.Schema == CanonicalSchema && v.Profile == RSAOAEPWrapProfile &&
		publicIDsValid(v.CompatibilityID, v.CryptoSupportID, v.DomainID, v.BeforeAccessRoot, v.RecipientID)
}

func RecipientReplacementIntentLength(v RecipientReplacementIntent) (int, error) {
	if !recipientReplacementFieldsValid(v.RecipientReplacementIntentFields) {
		return 0, ErrRecord
	}
	before, err := kmsBindingShapeLength(v.Before)
	if err != nil {
		return 0, err
	}
	after, err := kmsBindingShapeLength(v.Successor)
	if err != nil {
		return 0, err
	}
	if err := ValidatePublicEncryptionKey(v.Before.SPKI, v.Before.Fingerprint); err != nil {
		return 0, err
	}
	if err := ValidatePublicEncryptionKey(v.Successor.SPKI, v.Successor.Fingerprint); err != nil {
		return 0, err
	}
	return recipientReplacementIntentFixedLength + before + after, nil
}

func writeRecipientReplacementIntent(w *cryptoWriter, v RecipientReplacementIntent) {
	w.raw([]byte(recipientReplacementIntentPrefix))
	w.u16(v.Schema)
	w.u16(v.Profile)
	for _, id := range []ID{v.CompatibilityID, v.CryptoSupportID, v.DomainID, v.BeforeAccessRoot} {
		w.id(id)
	}
	w.u16(1)
	w.id(v.RecipientID)
	writeKMSBindingBlob(w, v.Before)
	writeKMSBindingBlob(w, v.Successor)
}

func readRecipientReplacementIntent(r *cryptoReader) RecipientReplacementIntentView {
	if !bytes.Equal(r.take(len(recipientReplacementIntentPrefix)), []byte(recipientReplacementIntentPrefix)) {
		r.err = ErrRecord
	}
	v := RecipientReplacementIntentView{RecipientReplacementIntentFields: RecipientReplacementIntentFields{
		Schema: r.u16(), Profile: r.u16(), CompatibilityID: r.requiredID(), CryptoSupportID: r.requiredID(),
		DomainID: r.requiredID(), BeforeAccessRoot: r.requiredID()}}
	if r.u16() != 1 && r.err == nil {
		r.err = ErrRecord
	}
	v.RecipientID = r.requiredID()
	if r.err == nil && !recipientReplacementFieldsValid(v.RecipientReplacementIntentFields) {
		r.err = ErrRecord
	}
	v.Before = readKMSBindingBlob(r)
	v.Successor = readKMSBindingBlob(r)
	return v
}

func (v RecipientReplacementIntentView) keysError() error {
	if err := ValidatePublicEncryptionKey(v.Before.SPKI, v.Before.Fingerprint); err != nil {
		return err
	}
	return ValidatePublicEncryptionKey(v.Successor.SPKI, v.Successor.Fingerprint)
}

func EncodeRecipientReplacementIntent(v RecipientReplacementIntent) ([]byte, error) {
	n, err := RecipientReplacementIntentLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeRecipientReplacementIntent(&w, v)
	return w.b, nil
}

func AppendRecipientReplacementIntent(dst []byte, v RecipientReplacementIntent) ([]byte, error) {
	if _, err := RecipientReplacementIntentLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeRecipientReplacementIntent(&w, v)
	return w.b, nil
}

func parseRecipientReplacementIntent(b []byte, complete bool) (RecipientReplacementIntentView, int, error) {
	if complete && len(b) > recipientReplacementIntentMaxLength {
		return RecipientReplacementIntentView{}, 0, ErrRecordCapacity
	}
	r := newRecordReader(b[:min(len(b), recipientReplacementIntentMaxLength)])
	v := readRecipientReplacementIntent(&r)
	if complete {
		r.err = r.end()
	}
	if r.err != nil {
		return RecipientReplacementIntentView{}, 0, r.failure()
	}
	if err := v.keysError(); err != nil {
		return RecipientReplacementIntentView{}, 0, err
	}
	return v, r.i, nil
}

func ParseRecipientReplacementIntent(b []byte) (RecipientReplacementIntentView, int, error) {
	return parseRecipientReplacementIntent(b, false)
}

func InspectRecipientReplacementIntent(b []byte) (RecipientReplacementIntentView, error) {
	v, _, err := parseRecipientReplacementIntent(b, true)
	return v, err
}

// Binding generation, provider equality, selected before state and successor
// admission are owner relations. Structural decoding supplies neither permission
// nor proof that this recipient can use either private key.
func (v RecipientReplacementIntentView) Own() (RecipientReplacementIntent, error) {
	if !recipientReplacementFieldsValid(v.RecipientReplacementIntentFields) {
		return RecipientReplacementIntent{}, ErrRecord
	}
	if err := kmsBindingViewShapeError(v.Before); err != nil {
		return RecipientReplacementIntent{}, err
	}
	if err := kmsBindingViewShapeError(v.Successor); err != nil {
		return RecipientReplacementIntent{}, err
	}
	if err := v.keysError(); err != nil {
		return RecipientReplacementIntent{}, err
	}
	return RecipientReplacementIntent{RecipientReplacementIntentFields: v.RecipientReplacementIntentFields,
		Before: v.Before.own(), Successor: v.Successor.own()}, nil
}

func DecodeRecipientReplacementIntent(b []byte) (RecipientReplacementIntent, error) {
	v, err := InspectRecipientReplacementIntent(b)
	if err != nil {
		return RecipientReplacementIntent{}, err
	}
	return RecipientReplacementIntent{RecipientReplacementIntentFields: v.RecipientReplacementIntentFields,
		Before: v.Before.own(), Successor: v.Successor.own()}, nil
}

func RecipientReplacementIntentDescriptor(v RecipientReplacementIntent) (DescriptorVector, error) {
	if _, err := RecipientReplacementIntentLength(v); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeRecipientReplacementIntent(&w, v)
	return w.result(1), nil
}
