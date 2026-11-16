package custody

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"enkv.sh/core/contract"
)

var ErrPayload = errors.New("private payload refused")

func SealValue(core contract.ValueCore, plaintext []byte) (payload contract.CanonicalPayload, keys []byte, err error) {
	content, validationErr := contract.InputContentLength(core.InputEncoding, plaintext)
	if validationErr != nil || content != core.ContentLength || uint32(len(plaintext)) != core.RetainedLength {
		return payload, nil, ErrPayload
	}
	encoded, err := contract.EncodeValueCore(core)
	if err != nil {
		return payload, nil, ErrPayload
	}
	keys = make([]byte, 64)
	// Go 1.27 Read fills or terminates the process; it has no returned entropy
	// failure. Each half is an independent random draw.
	_, _ = rand.Read(keys[:32])
	_, _ = rand.Read(keys[32:])
	defer func() {
		if err != nil {
			clear(keys[:cap(keys)])
			keys = nil
			payload = contract.CanonicalPayload{}
		}
	}()
	check, err := packageCheck(encoded, keys)
	if err != nil {
		return payload, keys, ErrPayload
	}
	nonce, ciphertext, err := sealPayload(keys[:32], plaintext, valuePreimage(valueAADLabel, encoded))
	if err != nil {
		return payload, keys, err
	}
	payload = contract.CanonicalPayload{Profile: core.Profile, CryptoSupportID: core.CryptoSupportID, DataKeyID: core.DataKeyID, DataKeyEpoch: core.DataKeyEpoch, CommitmentKeyID: core.CommitmentKeyID, CommitmentKeyEpoch: core.CommitmentKeyEpoch, ContentLength: core.ContentLength, InputEncoding: core.InputEncoding, RetainedLength: core.RetainedLength, Nonce: nonce, Ciphertext: ciphertext, SemanticCommitment: semanticCommitment(encoded, plaintext, keys[32:]), PackageCheck: check}
	return payload, keys, nil
}

func OpenValue(core contract.ValueCore, payload contract.CanonicalPayload, keys []byte) ([]byte, error) {
	if len(keys) != 64 {
		return nil, ErrPayload
	}
	if _, err := contract.CanonicalPayloadLength(payload); err != nil {
		return nil, ErrPayload
	}
	encoded, err := contract.EncodeValueCore(core)
	if err != nil {
		return nil, ErrPayload
	}
	if core.Profile != payload.Profile || core.CryptoSupportID != payload.CryptoSupportID || core.DataKeyID != payload.DataKeyID || core.DataKeyEpoch != payload.DataKeyEpoch || core.CommitmentKeyID != payload.CommitmentKeyID || core.CommitmentKeyEpoch != payload.CommitmentKeyEpoch || core.ContentLength != payload.ContentLength || core.InputEncoding != payload.InputEncoding || core.RetainedLength != payload.RetainedLength {
		return nil, ErrPayload
	}
	check, err := packageCheck(encoded, keys)
	if err != nil || subtle.ConstantTimeCompare(check[:], payload.PackageCheck[:]) != 1 {
		return nil, ErrPayload
	}
	plaintext, err := openPayload(keys[:32], payload.Nonce, payload.Ciphertext, valuePreimage(valueAADLabel, encoded))
	if err != nil {
		return nil, ErrPayload
	}
	semantic := semanticCommitment(encoded, plaintext, keys[32:])
	if subtle.ConstantTimeCompare(semantic[:], payload.SemanticCommitment[:]) != 1 {
		clear(plaintext[:cap(plaintext)])
		return nil, ErrPayload
	}
	content, validationErr := contract.InputContentLength(core.InputEncoding, plaintext)
	if validationErr != nil || content != core.ContentLength || uint32(len(plaintext)) != core.RetainedLength {
		clear(plaintext[:cap(plaintext)])
		return nil, ErrPayload
	}
	return plaintext, nil
}

func sealPayload(key, plaintext, aad []byte) (nonce [12]byte, ciphertext []byte, err error) {
	if len(key) != 32 || len(plaintext) > contract.CryptoMaxRetainedValue {
		return nonce, nil, ErrPayload
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nonce, nil, ErrPayload
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nonce, nil, ErrPayload
	}
	sealed := aead.Seal(make([]byte, 0, len(plaintext)+28), nil, plaintext, aad)
	copy(nonce[:], sealed[:12])
	ciphertext = make([]byte, len(sealed)-12)
	copy(ciphertext, sealed[12:])
	return nonce, ciphertext, nil
}

func openPayload(key []byte, nonce [12]byte, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 32 || len(ciphertext) < 16 || len(ciphertext) > contract.CryptoMaxRetainedValue+16 {
		return nil, ErrPayload
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrPayload
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, ErrPayload
	}
	sealed := make([]byte, 12+len(ciphertext))
	copy(sealed, nonce[:])
	copy(sealed[12:], ciphertext)
	// Even failed Open can write into the complete destination capacity. Keep
	// that owner separate from input and clear it whenever Open refuses.
	dst := make([]byte, 0, len(ciphertext)-16)
	plaintext, err := aead.Open(dst, nil, sealed, aad)
	if err != nil {
		clear(dst[:cap(dst)])
		return nil, ErrPayload
	}
	return plaintext, nil
}
