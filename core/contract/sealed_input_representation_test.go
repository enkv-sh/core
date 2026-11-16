package contract

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// full_only: false
func TestSealedInputRepresentationMetadataBoundaries(t *testing.T) {
	identity := Hash([]byte("sealed input structural fixture"))
	core := SealedInputCore{SealedInputCoreFields: SealedInputCoreFields{
		Schema: 4, Profile: MaterialCryptoProfile, CompatibilityID: identity,
		DomainID: identity, FileIdentity: identity, SourceID: identity,
		CryptoSupportID: identity, DataKeyID: identity, DataKeyEpoch: 1,
		InputEncoding: InputEncodingRaw,
	}, Name: "n"}
	for _, tc := range []struct {
		name              string
		encoding          uint8
		content, retained uint32
		want              error
	}{
		{"raw-empty", 1, 0, 0, nil}, {"base64-empty", 2, 0, 0, nil},
		{"raw-maximum", 1, 65536, 65536, nil}, {"base64-maximum", 2, 65536, 87384, nil},
		{"one-padding", 2, 2, 4, nil}, {"two-padding", 2, 1, 4, nil},
		{"zero-tag", 0, 0, 0, ErrRecord}, {"unknown-tag", 3, 0, 0, ErrRecord},
		{"raw-mismatch", 1, 3, 4, ErrRecord}, {"base64-mismatch", 2, 3, 8, ErrRecord},
		{"content-over", 2, 65537, 87384, ErrRecordCapacity},
		{"retained-over", 2, 65536, 87385, ErrRecordCapacity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := core
			value.InputEncoding, value.ContentLength, value.RetainedLength = tc.encoding, tc.content, tc.retained
			_, err := SealedInputCoreLength(value)
			if !errors.Is(err, tc.want) {
				t.Fatal("core length returned the wrong refusal class", err)
			}
			// Independently lay out only the changed metadata in an otherwise valid core.
			wire, err := EncodeSealedInputCore(core)
			if err != nil {
				t.Fatal(err)
			}
			if len(wire) != 282 || !bytes.Equal(wire[:4], []byte{0, 4, 0, 2}) {
				t.Fatal("source-v4 fixed layout differs")
			}
			binary.BigEndian.PutUint32(wire[241:], tc.content)
			wire[245] = tc.encoding
			binary.BigEndian.PutUint32(wire[246:], tc.retained)
			view, err := InspectSealedInputCore(wire)
			if !errors.Is(err, tc.want) {
				t.Fatal("core inspection returned the wrong refusal class", err)
			}
			_, _, parseErr := ParseSealedInputCore(wire)
			if !errors.Is(parseErr, tc.want) {
				t.Fatal("core parsing returned the wrong refusal class", parseErr)
			}
			if tc.want != nil {
				return
			}
			owned, err := view.Own()
			if err != nil || owned != value {
				t.Fatal("borrowed core lost representation metadata", err)
			}
			envelope := SealedInputEnvelope{Core: value, Ciphertext: make([]byte, int(tc.retained)+16), AuthorityWrap: WrapRow{SubjectKind: OrdinaryWrapSubject, SubjectID: identity, BindingID: identity, BindingSerial: 1, PublicBindingDigest: identity, RSACiphertext: make([]byte, 384)}}
			body, err := EncodeSealedInputEnvelope(envelope)
			if err != nil || len(body) != 819+len(value.Name)+int(tc.retained) {
				t.Fatal("source envelope retained-byte account differs", err)
			}
			decoded, err := DecodeSealedInputEnvelope(body)
			if err != nil || decoded.Core != value || len(decoded.Ciphertext) != int(tc.retained)+16 {
				t.Fatal("source envelope lost representation metadata", err)
			}
			envelope.Ciphertext = append(envelope.Ciphertext, 0)
			if _, err := SealedInputEnvelopeLength(envelope); err == nil {
				t.Fatal("source envelope admitted a ciphertext/retained-length mismatch")
			}
		})
	}
}
