package contract

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// full_only: false
func TestRetirementAmbiguityProofScopeAndBounds(t *testing.T) {
	scalar := make([]byte, 32)
	scalar[31] = 1
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	id := func(n byte) ID { return ID(bytes.Repeat([]byte{n}, 32)) }
	safe := GeneratorSafeFacts{Schema: GeneratorSafeFactsSchema, Action: GeneratorActionDelete, LifecycleMode: GeneratorLifecycleManaged, Disposition: GeneratorDispositionUnknown, Reason: GeneratorReasonTransport, RequestDigest: id(6), IntentDigest: id(7), ResourceContractID: id(8), Target: []byte("t"), ResourceData: []byte("r")}
	facts, err := EncodeGeneratorSafeFacts(safe)
	if err != nil {
		t.Fatal(err)
	}
	v := RetirementAmbiguityRecord{Domain: id(1), Operation: id(2), Attempt: id(3), Inbox: id(4), Graph: id(5), PublicKey: pub, Facts: facts}
	// Independent SHA-256 on big-endian length-prefixed fields. The SEC1 key
	// is the P-256 base point; the five identities repeat bytes 1 through 5.
	digest, err := v.Digest()
	if err != nil || hex.EncodeToString(digest[:]) != "935ba90a6503246663521755241f72665a548e4afcf71b676198a1469c94204e" {
		t.Fatal("statement digest", digest, err)
	}
	commitment, err := RetirementReturnCommitment(pub)
	if err != nil || hex.EncodeToString(commitment[:]) != "7fee25f74c270e2238b99e70961048dbd00f5567211abedd40a8a30c02809648" {
		t.Fatal("pre-effect key commitment", commitment, err)
	}
	v.Signature, err = ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeRetirementAmbiguity(v)
	if err != nil {
		t.Fatal(err)
	}
	seen, err := InspectRetirementAmbiguity(wire)
	if err != nil || !seen.Verify(commitment, id(1), id(2), id(3), id(4), id(5)) {
		t.Fatal("original proof refused", err)
	}
	for i := range 6 {
		scope := []ID{commitment, id(1), id(2), id(3), id(4), id(5)}
		scope[i] = id(99)
		if seen.Verify(scope[0], scope[1], scope[2], scope[3], scope[4], scope[5]) {
			t.Fatal("foreign proof scope", i)
		}
	}
	seen.Facts = bytes.Clone(seen.Facts)
	seen.Facts[len(seen.Facts)-6] ^= 1
	if seen.Verify(commitment, id(1), id(2), id(3), id(4), id(5)) {
		t.Fatal("changed facts authenticated")
	}
	for _, bad := range [][]byte{wire[:len(wire)-1], append(bytes.Clone(wire), 0), make([]byte, RetirementAmbiguityMaxLength+1)} {
		if _, err := InspectRetirementAmbiguity(bad); err == nil {
			t.Fatal("invalid record length", len(bad))
		}
	}
	safe.ProviderFacts = make([]byte, GeneratorSafeFactsMaxLength-len(facts))
	v.Facts, err = EncodeGeneratorSafeFacts(safe)
	if err != nil || len(v.Facts) != 4096 {
		t.Fatal("maximum facts", err)
	}
	// Both 32-byte DER scalars need a leading zero when their high bits are set.
	n := bytes.Repeat([]byte{0x80}, 32)
	v.Signature = []byte{0x30, 70, 2, 33, 0}
	v.Signature = append(v.Signature, n...)
	v.Signature = append(v.Signature, 2, 33, 0)
	v.Signature = append(v.Signature, n...)
	maximum, err := EncodeRetirementAmbiguity(v)
	if err != nil || RetirementAmbiguityMaxLength != 4407 || len(maximum) != RetirementAmbiguityMaxLength {
		t.Fatal("maximum retirement evidence", len(maximum), err)
	}
	if _, err := InspectRetirementAmbiguity(maximum); err != nil {
		t.Fatal(err)
	}
}
