package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// full_only: false
func TestGeneratedMemberSuppliedEmptyExtension(t *testing.T) {
	v := ValueEntry{Incarnation: generatedRecordID(1), ValueState: generatedRecordID(2), OriginSnapshot: generatedRecordID(3),
		OriginTransition: generatedRecordID(4), ValueSource: Supplied, ConfidentialityClass: Plain, Recipients: []ID{generatedRecordID(5)}, ValueBytes: []byte("abc"), InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, ContentLength: uint32(len([]byte("abc"))), RetainedLength: uint32(len([]byte("abc")))}
	wire, err := EncodeValueEntry(v)
	if err != nil || len(wire) != 189 {
		t.Fatal("supplied member framing", len(wire), err)
	}
	// Independently concatenate u32be(0), repeated-byte IDs1..4, source/class0101, input1/C3/R3/output1, recipientcount1,
	// ID5, 00000003616263, then empty extension00000000; hash with Node SHA256.
	digest := sha256.Sum256(wire)
	if hex.EncodeToString(digest[:]) != "062b8126d07168676d78bb4ba502949376c8d7a30c2ce73169efd1a086a7be65" {
		t.Fatal("supplied field order")
	}
	if got, err := DecodeValueEntry(wire); err != nil || got.Generated != (GeneratedEntryMetadata{}) || got.ValueSource != Supplied {
		t.Fatal("supplied extension", err)
	}
	if _, err := InspectValueEntry(wire[:len(wire)-4]); !errors.Is(err, ErrRecord) {
		t.Fatal("legacy member without extension accepted", err)
	}
	v.Generated = generatedRecordEntryMetadata()
	if _, err := EncodeValueEntry(v); !errors.Is(err, ErrRecord) {
		t.Fatal("supplied metadata accepted", err)
	}
	v.Generated, v.ValueSource = GeneratedEntryMetadata{}, 0
	if _, err := EncodeValueEntry(v); !errors.Is(err, ErrRecord) {
		t.Fatal("default source alias accepted", err)
	}
}

func generatedValueEntryFixture(t *testing.T) ValueEntry {
	t.Helper()
	payload, err := EncodeCanonicalPayload(CanonicalPayload{Profile: 2, CryptoSupportID: generatedRecordID(19),
		DataKeyID: generatedRecordID(17), DataKeyEpoch: 1, CommitmentKeyID: generatedRecordID(18), CommitmentKeyEpoch: 1,
		Ciphertext: bytes.Repeat([]byte{0xaa}, 16), InputEncoding: InputEncodingRaw, RetainedLength: 0})
	if err != nil {
		t.Fatal(err)
	}
	return ValueEntry{Name: "n", Incarnation: generatedRecordID(14), ValueState: generatedRecordID(7), OriginSnapshot: generatedRecordID(15),
		OriginTransition: generatedRecordID(16), ValueSource: Generated, ConfidentialityClass: Secret, Recipients: []ID{generatedRecordID(20)},
		ValueBytes: payload, Generated: generatedRecordEntryMetadata(), InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, ContentLength: uint32(len(payload) - CanonicalPayloadOverhead), RetainedLength: uint32(len(payload) - CanonicalPayloadOverhead)}
}

// full_only: false
func TestGeneratedMemberIdentityAndOwnership(t *testing.T) {
	v := generatedValueEntryFixture(t)
	wire, err := EncodeValueEntry(v)
	if err != nil || len(wire) != 824 {
		t.Fatal("generated member framing", len(wire), err)
	}
	// Node SHA256 over B("n"), IDs14/7/15/16, source/class0202, input1/C0/R0/output1, count1, ID20,
	// B(profile2 payload with support19, data17, commitment18, both epochs1,
	// C0/input1/R0, zero nonce/checks and sixteen aa ciphertext bytes), then
	// B(the independent generated entry extension in generated_records_test).
	digest := sha256.Sum256(wire)
	if hex.EncodeToString(digest[:]) != "da8fce12743ccf03d29572bdb953b42e75693a36516748b85eb17585a88c6c0e" {
		t.Fatal("independent generated member bytes")
	}
	for _, offset := range []int{134, 636} {
		bad := bytes.Clone(wire)
		bad[offset] = 1
		if _, err := InspectValueEntry(bad); !errors.Is(err, ErrRecord) {
			t.Fatal("bad generated encoding or identity admitted", offset, err)
		}
	}
	view, err := InspectValueEntry(wire)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil || owned.Generated != v.Generated || !bytes.Equal(owned.ValueBytes, v.ValueBytes) {
		t.Fatal("generated member ownership", err)
	}
	badView := view
	badView.Generated.GenerationID = generatedRecordID(21)
	if _, err := badView.Own(); !errors.Is(err, ErrRecord) {
		t.Fatal("invalid borrowed metadata copied", err)
	}
	clear(wire)
	if !bytes.Equal(owned.ValueBytes, v.ValueBytes) || owned.Name != v.Name {
		t.Fatal("retained member aliases wire")
	}
	for _, mutate := range []func(*ValueEntry){
		func(v *ValueEntry) { v.ConfidentialityClass = Plain },
		func(v *ValueEntry) { v.Generated = GeneratedEntryMetadata{} },
		func(v *ValueEntry) { v.Generated.GenerationID = generatedRecordID(21) },
		func(v *ValueEntry) { v.Generated.CompletionClass = 0 },
	} {
		bad := v
		mutate(&bad)
		if _, err := EncodeValueEntry(bad); !errors.Is(err, ErrRecord) {
			t.Fatal("invalid generated member accepted", err)
		}
	}
}

// full_only: false
func TestGeneratedMemberMaximumEncodedSize(t *testing.T) {
	v := generatedValueEntryFixture(t)
	v.Name = strings.Repeat("n", 256)
	v.Recipients = make([]ID, 64)
	for i := range v.Recipients {
		v.Recipients[i] = generatedRecordID(byte(i + 1))
	}
	payload, err := DecodeCanonicalPayload(v.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name             string
		input            uint8
		retained, length int
	}{
		{"raw", InputEncodingRaw, 65536, 68631}, {"base64", InputEncodingBase64, 87384, 90479},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload.InputEncoding, payload.ContentLength, payload.RetainedLength = tc.input, 65536, uint32(tc.retained)
			payload.Ciphertext = bytes.Repeat([]byte{0xaa}, tc.retained+16)
			v.InputEncoding, v.ContentLength, v.RetainedLength = tc.input, 65536, uint32(tc.retained)
			v.ValueBytes, err = EncodeCanonicalPayload(payload)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := EncodeValueEntry(v)
			if err != nil || len(wire) != tc.length {
				t.Fatal("full generated member", len(wire), err)
			}
			if _, err := InspectValueEntry(wire); err != nil {
				t.Fatal("full generated member refused", err)
			}
		})
	}
	v.Recipients = append(v.Recipients, generatedRecordID(65))
	if _, err := EncodeValueEntry(v); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("recipient ceiling", err)
	}
}

func generatedValueCoreFixture() ValueCore {
	return ValueCore{Schema: CanonicalSchema, Profile: 2, CompatibilityID: generatedRecordID(1), CryptoSupportID: generatedRecordID(2),
		DomainID: generatedRecordID(3), Name: "n", EntryIncarnationID: generatedRecordID(4), ValueStateID: generatedRecordID(5),
		OriginSnapshotID: generatedRecordID(6), OriginTransitionID: generatedRecordID(7), DataKeyID: generatedRecordID(8), DataKeyEpoch: 1,
		CommitmentKeyID: generatedRecordID(9), CommitmentKeyEpoch: 1, ContentLength: 3, ValueSource: Supplied, InputEncoding: InputEncodingRaw, RetainedLength: 3}
}

// full_only: false
func TestGeneratedValueCoreSourceWireAndCommitments(t *testing.T) {
	// Independent big-endian concatenation: 000b0002, IDs1..3, B("n"),
	// IDs4..8, u64(1), ID9, u64(1), u32(3), input1, R:u32(3), ValueSource and its conditional ID10.
	// Python SHA256 supplies the fixed wire and material-context hashes. Material
	// hashes prefix ENKV/CRYPTO/v2/material\0 and B(the complete ValueCore).
	for _, tc := range []struct {
		valueSource    uint8
		binding        ID
		length         int
		wire, material string
	}{
		{Supplied, ID{}, 323, "aab95233e5dbae907875becb41e77776c895ec26fd1c875e9502fa4e2bd8f183", "cc112571526ceba13632daba4df68a0e578ee15def2515706ff05ffda6171c0e"},
		{Generated, generatedRecordID(10), 355, "d28b884ca5fc13fab726e18354a7188cdd2afe89ec3b0331532ad6577c03e7ed", "65253e53cc68634f747d8f95f85b6238fe5ab98bf3d6f0eddaaacfc4f8159c37"},
	} {
		v := generatedValueCoreFixture()
		v.ValueSource, v.GeneratedBindingDigest = tc.valueSource, tc.binding
		wire, err := EncodeValueCore(v)
		if err != nil || len(wire) != tc.length {
			t.Fatal("source-dependent width", len(wire), err)
		}
		digest := sha256.Sum256(wire)
		if hex.EncodeToString(digest[:]) != tc.wire {
			t.Fatal("independent value wire")
		}
		material, err := ValueMaterialContextDigest(v)
		if err != nil || hex.EncodeToString(material[:]) != tc.material {
			t.Fatal("conditional context length", err)
		}
		if got, err := DecodeValueCore(wire); err != nil || got != v {
			t.Fatal("value round trip", err)
		}
		view, err := InspectValueCore(wire)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := view.Own()
		if err != nil {
			t.Fatal(err)
		}
		wire[104] = 'x'
		if view.Name[0] != 'x' || owned.Name != "n" {
			t.Fatal("value context ownership")
		}
		wire[104] = 'n'
		for i := range wire {
			if _, err := InspectValueCore(wire[:i]); err == nil {
				t.Fatalf("accepted truncation %d", i)
			}
		}
		if _, err := InspectValueCore(append(bytes.Clone(wire), 0)); err == nil {
			t.Fatal("trailing value bytes")
		}
	}
}

// full_only: false
func TestGeneratedValueCoreRejectsWrongSourceAndLegacy(t *testing.T) {
	v := generatedValueCoreFixture()
	for _, mutate := range []func(*ValueCore){
		func(v *ValueCore) { v.Schema = 4 },
		func(v *ValueCore) { v.ValueSource = 0 },
		func(v *ValueCore) { v.ValueSource = 3 },
		func(v *ValueCore) { v.GeneratedBindingDigest = generatedRecordID(10) },
		func(v *ValueCore) { v.ValueSource = Generated },
	} {
		bad := v
		mutate(&bad)
		if _, err := EncodeValueCore(bad); !errors.Is(err, ErrRecord) {
			t.Fatal("invalid source context", err)
		}
	}
	v.ValueSource, v.GeneratedBindingDigest, v.Name = Generated, generatedRecordID(10), strings.Repeat("x", 256)
	if n, err := ValueCoreLength(v); err != nil || n != 610 {
		t.Fatal("maximum generated context", n, err)
	}
	v.Name += "x"
	if _, err := EncodeValueCore(v); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("oversized name", err)
	}
}

// full_only: false
func TestValueEntryUsesExactGeneratorMetadataLength(t *testing.T) {
	local, _, _, _ := localRecordFixtures(t)
	for _, kind := range []GeneratorLifecycleMode{GeneratorLifecycleManaged, GeneratorLifecycleNone} {
		for _, pointer := range []uint8{0, 1} {
			name := map[GeneratorLifecycleMode]string{GeneratorLifecycleManaged: "managed", GeneratorLifecycleNone: "no-resource"}[kind]
			if pointer == 1 {
				name += " with older duty"
			}
			t.Run(name, func(t *testing.T) {
				entry := generatedValueEntryFixture(t)
				meta := entry.Generated
				if kind == GeneratorLifecycleNone {
					meta = local
				} else if kind != 0 {
					meta.Schema, meta.LifecycleMode = GeneratedEntryMetadataSchema, kind
				}
				meta.RetiringDutyPresent, meta.RetiringDutyID = pointer, ID{}
				if pointer == 1 {
					meta.RetiringDutyID = generatedRecordID(31)
				}
				entry.Generated, entry.ValueState = meta, meta.GenerationID
				metadata, err := EncodeGeneratedEntryMetadata(meta)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := EncodeValueEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				// The extension is the final B(metadata) field; its length must describe
				// this actual lifecycle and optional field, not the largest envelope.
				prefix := len(encoded) - len(metadata) - 4
				if prefix < 0 || binary.BigEndian.Uint32(encoded[prefix:prefix+4]) != uint32(len(metadata)) {
					t.Fatal("value entry used another lifecycle's metadata length")
				}
				decoded, err := DecodeValueEntry(encoded)
				if err != nil || decoded.Generated != meta || !bytes.Equal(decoded.ValueBytes, entry.ValueBytes) {
					t.Fatal("exact generated value entry did not round trip", err)
				}
				again, err := EncodeValueEntry(decoded)
				if err != nil || !bytes.Equal(encoded, again) {
					t.Fatal("generated value entry is not canonical", err)
				}
			})
		}
	}
}
