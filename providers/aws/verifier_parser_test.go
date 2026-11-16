package awsprovider

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"testing"
)

// full_only: false
func TestVerifierParsingKeepsCanonicalP256Key(t *testing.T) {
	// The uncompressed SEC1 point is the P-256 generator, wrapped in its fixed
	// id-ecPublicKey and prime256v1 SubjectPublicKeyInfo envelope.
	const encoded = "3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
	der, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseVerifier(der)
	if err != nil || key == nil || key.Curve != elliptic.P256() {
		t.Fatal("canonical verifier changed", err)
	}
	point, err := key.Bytes()
	if err != nil || !bytes.Equal(point, der[26:]) {
		t.Fatal("canonical verifier point changed", err)
	}
	for _, bad := range [][]byte{nil, append(bytes.Clone(der), 0), bytes.Repeat([]byte{1}, 4097), bytes.Clone(der[:90])} {
		if key, err := ParseVerifier(bad); key != nil || err != ErrConstruction {
			t.Fatal("invalid verifier crossed boundary", err)
		}
	}
}
