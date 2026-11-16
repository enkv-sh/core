package contract

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func secretExclusionFixture() SecretExclusionPath {
	id := func(n byte) ID { return ID(bytes.Repeat([]byte{n}, 32)) }
	return SecretExclusionPath{
		Core: ValueCore{ValueSource: 1, Schema: CanonicalSchema, Profile: 2, CompatibilityID: id(1), CryptoSupportID: id(2), DomainID: id(3), Name: "key-π",
			EntryIncarnationID: id(4), ValueStateID: id(5), OriginSnapshotID: id(6), OriginTransitionID: id(7),
			DataKeyID: id(8), DataKeyEpoch: 9, CommitmentKeyID: id(10), CommitmentKeyEpoch: 11, ContentLength: 12, InputEncoding: InputEncodingRaw, RetainedLength: 12},
		EntryDigest: id(13), SemanticCommitment: id(14), RemovedRecipients: []ID{id(15), id(16)}, ActingRecipient: id(17), BeforeAccessRoot: id(18),
	}
}

// full_only: false
func TestSecretExclusionIndependentProjection(t *testing.T) {
	// Independently encoded with Python big-endian concatenation and SHA-256:
	// secret-exclusion-v6 (unchanged purpose); B(ValueCore schema 11, profile 2, source 1);
	// entry/commitment IDs; two removed recipients; actor and access root.
	const expected = "454e4b562f43525950544f2f76322f7365637265742d6578636c7573696f6e2d76360000000148000b0002010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303000000066b65792dcf800404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606060606060606060606060606060606060707070707070707070707070707070707070707070707070707070707070707080808080808080808080808080808080808080808080808080808080808080800000000000000090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000000000000000b0000000c010000000c010d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e00020f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f101010101010101010101010101010101010101010101010101010101010101011111111111111111111111111111111111111111111111111111111111111111212121212121212121212121212121212121212121212121212121212121212"
	want, err := hex.DecodeString(expected)
	if err != nil {
		t.Fatal(err)
	}
	v := secretExclusionFixture()
	digest, err := SecretExclusionDigest(v)
	if err != nil || hex.EncodeToString(digest[:]) != "18c1464aaa31b0e3596141785fe9e28db6d2d222a1710b1e5db599c52592d278" {
		t.Fatal("digest differs from independent literal", err)
	}
	w := cryptoWriter{}
	writeSecretExclusion(&w, v)
	if !bytes.Equal(w.b, want) {
		t.Fatal("preimage differs from independently derived bytes")
	}
}

// full_only: false
func TestSecretExclusionRejectsInvalidContextAndRecipients(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*SecretExclusionPath)
		want error
	}{
		{"missing-actor", func(v *SecretExclusionPath) { v.ActingRecipient = ID{} }, ErrRecord},
		{"missing-domain", func(v *SecretExclusionPath) { v.Core.DomainID = ID{} }, ErrRecord},
		{"old-schema", func(v *SecretExclusionPath) { v.Core.Schema = 3 }, ErrRecord},
		{"unsupported-profile", func(v *SecretExclusionPath) { v.Core.Profile = 3 }, ErrRecord},
		{"invalid-name", func(v *SecretExclusionPath) { v.Core.Name = "\xff" }, ErrRecord},
		{"long-name", func(v *SecretExclusionPath) { v.Core.Name = strings.Repeat("x", CryptoMaxName+1) }, ErrRecordCapacity},
		{"raw-excess", func(v *SecretExclusionPath) { v.Core.ContentLength = CryptoMaxRawValue + 1 }, ErrRecordCapacity},
		{"missing-epoch", func(v *SecretExclusionPath) { v.Core.CommitmentKeyEpoch = 0 }, ErrRecord},
		{"no-removal", func(v *SecretExclusionPath) { v.RemovedRecipients = nil }, ErrRecord},
		{"zero-recipient", func(v *SecretExclusionPath) { v.RemovedRecipients[0] = ID{} }, ErrRecord},
		{"duplicate-recipient", func(v *SecretExclusionPath) { v.RemovedRecipients[1] = v.RemovedRecipients[0] }, ErrRecord},
		{"unordered-recipients", func(v *SecretExclusionPath) {
			v.RemovedRecipients[0], v.RemovedRecipients[1] = v.RemovedRecipients[1], v.RemovedRecipients[0]
		}, ErrRecord},
		{"recipient-excess", func(v *SecretExclusionPath) { v.RemovedRecipients = make([]ID, CryptoMaxValueEntryRecipients+1) }, ErrRecordCapacity},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := secretExclusionFixture()
			test.edit(&v)
			got, err := SecretExclusionDigest(v)
			if !errors.Is(err, test.want) || !got.IsZero() {
				t.Fatalf("invalid projection returned %x, %v; want zero, %v", got, err, test.want)
			}
		})
	}
	v := secretExclusionFixture()
	v.Core.Name, v.Core.ContentLength, v.Core.RetainedLength = strings.Repeat("x", CryptoMaxName), CryptoMaxRawValue, CryptoMaxRawValue
	v.RemovedRecipients = make([]ID, CryptoMaxValueEntryRecipients)
	for i := range v.RemovedRecipients {
		v.RemovedRecipients[i][31] = byte(i + 1)
	}
	if _, err := SecretExclusionDigest(v); err != nil {
		t.Fatal("joint supported boundaries refused", err)
	}
}
