package contract

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
)

// P256SignatureEncodingValid checks canonical DER and the P-256 scalar range.
// High S is allowed. The caller must verify the signature for its key and message.
func P256SignatureEncodingValid(b []byte) bool {
	if len(b) == 0 || len(b) > MaxSignature {
		return false
	}
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(b, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.Cmp(elliptic.P256().Params().N) >= 0 || sig.S.Cmp(elliptic.P256().Params().N) >= 0 {
		return false
	}
	canonicalSignature, err := asn1.Marshal(sig)
	return err == nil && bytes.Equal(b, canonicalSignature)
}
