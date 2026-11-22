package custody

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedCheckpointGrantBindsStoredContext(t *testing.T) {
	seed := bytes.Repeat([]byte{1}, 32)
	c := GeneratedGrantContext{OperationMaterial: testID(10), Domain: testID(1), Operation: testID(2), Phase: testID(3), Control: testID(4), Material: testID(5), MaterialContext: testID(6), Slot: 9, Index: 2}
	w := contract.WrapRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: testID(7), BindingID: testID(8), BindingSerial: 4, PublicBindingDigest: testID(9), RSACiphertext: bytes.Repeat([]byte{13}, 384)}
	// Independent fixed-width framing and RFC 5869 extract/expand vector.
	key, aad, err := c.key(seed, testID(11), w)
	digest := sha256.Sum256(aad)
	if err != nil || len(aad) != 410 || hex.EncodeToString(digest[:]) != "490ddbfd5a5ced8565fe6595db0a826b6784261811c52393e68cdac215076c4a" || hex.EncodeToString(key) != "728fd6f0ef0def97e8c58379c0960b97363ab32548b85b08d0da3bf85dd8f6ce" {
		t.Fatal("checkpoint grant context or derivation changed", err)
	}
	clear(key)
	seal, masked, err := SealGeneratedGrant(c, seed, w)
	if err != nil || len(masked) != 384 || bytes.Equal(masked, w.RSACiphertext) {
		t.Fatal("checkpoint masking failed", err)
	}
	otherSeal, other, err := SealGeneratedGrant(c, seed, w)
	if err != nil || otherSeal.EnvelopeID == seal.EnvelopeID || otherSeal.Nonce == seal.Nonce || bytes.Equal(other, masked) {
		t.Fatal("each preparation needs a fresh nonce", err)
	}
	stored := w
	stored.RSACiphertext = masked
	opened, err := OpenGeneratedGrant(c, seed, stored, seal)
	if err != nil || !bytes.Equal(opened, w.RSACiphertext) {
		t.Fatal("selected replay changed stored grant", err)
	}
	for _, alter := range []func(*GeneratedGrantContext, *contract.WrapRow, *contract.GeneratedGrantSeal){
		func(c *GeneratedGrantContext, _ *contract.WrapRow, _ *contract.GeneratedGrantSeal) {
			c.Operation = testID(13)
		},
		func(c *GeneratedGrantContext, _ *contract.WrapRow, _ *contract.GeneratedGrantSeal) {
			c.Phase = testID(13)
		},
		func(c *GeneratedGrantContext, _ *contract.WrapRow, _ *contract.GeneratedGrantSeal) {
			c.Control = testID(13)
		},
		func(c *GeneratedGrantContext, _ *contract.WrapRow, _ *contract.GeneratedGrantSeal) {
			c.Material = testID(13)
		},
		func(c *GeneratedGrantContext, _ *contract.WrapRow, s *contract.GeneratedGrantSeal) {
			c.Index++
			s.Wrap++
		},
		func(_ *GeneratedGrantContext, w *contract.WrapRow, _ *contract.GeneratedGrantSeal) {
			w.SubjectID = testID(13)
		},
		func(_ *GeneratedGrantContext, w *contract.WrapRow, _ *contract.GeneratedGrantSeal) { w.BindingSerial++ },
		func(_ *GeneratedGrantContext, w *contract.WrapRow, _ *contract.GeneratedGrantSeal) {
			w.PublicBindingDigest = testID(13)
		},
		func(_ *GeneratedGrantContext, _ *contract.WrapRow, s *contract.GeneratedGrantSeal) { s.Tag[0] ^= 1 },
	} {
		changed, row, proof := c, stored, seal
		alter(&changed, &row, &proof)
		if wrong, err := OpenGeneratedGrant(changed, seed, row, proof); err == nil || wrong != nil {
			t.Fatal("changed checkpoint context accepted")
		}
	}
}
