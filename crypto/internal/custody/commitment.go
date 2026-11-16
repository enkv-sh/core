package custody

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"

	"enkv.sh/core/contract"
)

const (
	valueAADLabel     = "ENKV/CRYPTO/v2/value-aad\x00"
	semanticLabel     = "ENKV/CRYPTO/v2/semantic\x00"
	packageSaltLabel  = "ENKV/CRYPTO/v2/package-hkdf-salt\x00"
	packageInfoLabel  = "ENKV/CRYPTO/v2/package-hkdf-info\x00"
	packageCheckLabel = "ENKV/CRYPTO/v2/package-check\x00"
)

// The context body has one writer in contract. This helper only prefixes a
// fixed local primitive purpose and the canonical blob length.
func valuePreimage(label string, encodedCore []byte) []byte {
	b := make([]byte, len(label)+4+len(encodedCore))
	copy(b, label)
	binary.BigEndian.PutUint32(b[len(label):], uint32(len(encodedCore)))
	copy(b[len(label)+4:], encodedCore)
	return b
}

func semanticCommitment(encodedCore, plaintext, commitmentKey []byte) contract.ID {
	h := hmac.New(sha256.New, commitmentKey)
	_, _ = h.Write(valuePreimage(semanticLabel, encodedCore))
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(plaintext)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(plaintext)
	var result contract.ID
	h.Sum(result[:0])
	return result
}

func packageCheck(encodedCore, keys []byte) (contract.ID, error) {
	// The HKDF input concatenation has one local owner even when the caller's
	// checked D/C region borrows a larger private packet.
	ikm := bytes.Clone(keys)
	defer clear(ikm[:cap(ikm)])
	info := valuePreimage(packageInfoLabel, encodedCore)
	derived, err := hkdf.Key(sha256.New, ikm, []byte(packageSaltLabel), string(info), 32)
	if err != nil {
		return contract.ID{}, ErrPayload
	}
	defer clear(derived[:cap(derived)])
	h := hmac.New(sha256.New, derived)
	_, _ = h.Write(valuePreimage(packageCheckLabel, encodedCore))
	var result contract.ID
	h.Sum(result[:0])
	return result, nil
}

func PackageCheck(core contract.ValueCore, keys []byte) (contract.ID, error) {
	if len(keys) != 64 {
		return contract.ID{}, ErrPayload
	}
	encoded, err := contract.EncodeValueCore(core)
	if err != nil {
		return contract.ID{}, ErrPayload
	}
	return packageCheck(encoded, keys)
}

// EqualValue uses the authenticated predecessor context and commitment key.
// The caller must authenticate the predecessor payload before comparison.
func EqualValue(core contract.ValueCore, payload contract.CanonicalPayload, keys, plaintext []byte) (bool, error) {
	if len(keys) != 64 || len(plaintext) > contract.CryptoMaxRetainedValue {
		return false, ErrPayload
	}
	encoded, err := contract.EncodeValueCore(core)
	if err != nil {
		return false, ErrPayload
	}
	commitment := semanticCommitment(encoded, plaintext, keys[32:])
	return subtle.ConstantTimeCompare(commitment[:], payload.SemanticCommitment[:]) == 1, nil
}
