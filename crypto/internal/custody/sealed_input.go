package custody

import (
	"crypto/rand"

	"enkv.sh/core/contract"
)

func SealInput(core contract.SealedInputCore, authority contract.BindingTableRow, plaintext []byte) (contract.SealedInputEnvelope, error) {
	content, err := contract.InputContentLength(core.InputEncoding, plaintext)
	if err != nil || content != core.ContentLength || uint32(len(plaintext)) != core.RetainedLength {
		return contract.SealedInputEnvelope{}, ErrPayload
	}
	wrapCore, err := SealedInputWrapCore(core, authority)
	if err != nil {
		return contract.SealedInputEnvelope{}, ErrPayload
	}
	aad, err := contract.EncodeSealedInputAAD(core)
	if err != nil {
		return contract.SealedInputEnvelope{}, ErrPayload
	}
	keys := make([]byte, 32)
	defer clear(keys[:cap(keys)])
	_, _ = rand.Read(keys)
	nonce, ciphertext, err := sealPayload(keys, plaintext, aad)
	if err != nil {
		return contract.SealedInputEnvelope{}, ErrPayload
	}
	wrap, err := Wrap(wrapCore, authority.Binding, keys)
	if err != nil {
		return contract.SealedInputEnvelope{}, ErrPayload
	}
	return contract.SealedInputEnvelope{Core: core, Nonce: nonce, Ciphertext: ciphertext, AuthorityWrap: wrap}, nil
}

// OpenSealedInput receives the source D only after the caller has checked the exact
// private packet against SealedInputWrapCore. Root Crypto owns that key route and
// source admission; this function supplies no source provenance or currentness.
func OpenSealedInput(expected contract.SealedInputCore, envelope contract.SealedInputEnvelope, keys []byte) ([]byte, error) {
	if len(keys) != 32 || envelope.Core != expected {
		return nil, ErrPayload
	}
	if _, err := contract.SealedInputEnvelopeLength(envelope); err != nil {
		return nil, ErrPayload
	}
	aad, err := contract.EncodeSealedInputAAD(expected)
	if err != nil {
		return nil, ErrPayload
	}
	plaintext, err := openPayload(keys, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, err
	}
	content, err := contract.InputContentLength(expected.InputEncoding, plaintext)
	if err != nil || content != expected.ContentLength || uint32(len(plaintext)) != expected.RetainedLength {
		clear(plaintext[:cap(plaintext)])
		return nil, ErrPayload
	}
	return plaintext, nil
}
