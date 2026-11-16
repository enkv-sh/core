package crypto

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationPayloadOneRawValueAndOwnership(t *testing.T) {
	source := []byte{0, 0xff, '\n'}
	payload, err := encodePublicationPayload(contract.InputEncodingRaw, contract.OutputEncodingRaw, uint32(len(source)), source)
	if err != nil || !bytes.Equal(payload, source) {
		t.Fatal("one raw value changed", err)
	}
	payload[0] = 1
	if source[0] != 0 {
		t.Fatal("private payload aliases selected input")
	}
	empty, err := encodePublicationPayload(contract.InputEncodingRaw, contract.OutputEncodingRaw, 0, nil)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("zero-length value became a metadata Arm", err)
	}
	// Short vectors follow RFC 4648 bit groups. PEM literals were derived with
	// Python base64.b64encode, independently of the publication encoder.
	for _, vector := range []struct {
		name, raw, encoded string
	}{
		{"empty", "", ""},
		{"one-byte", "f", "Zg=="},
		{"two-bytes", "fo", "Zm8="},
		{"three-bytes", "foo", "Zm9v"},
		{"base64-looking", "QUJD", "UVVKRA=="},
		{"binary", "\x00\xff\x0a\x0d\x80", "AP8KDYA="},
		{"pem-lf", "-----BEGIN TEST-----\nQUJD\n-----END TEST-----\n", "LS0tLS1CRUdJTiBURVNULS0tLS0KUVVKRAotLS0tLUVORCBURVNULS0tLS0K"},
		{"pem-crlf", "-----BEGIN TEST-----\r\nQUJD\r\n-----END TEST-----\r\n", "LS0tLS1CRUdJTiBURVNULS0tLS0NClFVSkQNCi0tLS0tRU5EIFRFU1QtLS0tLQ0K"},
	} {
		t.Run(vector.name, func(t *testing.T) {
			for _, encoding := range []string{"raw", "base64"} {
				t.Run(encoding, func(t *testing.T) {
					source := []byte(vector.raw)
					want := vector.raw
					if encoding == "base64" {
						want = vector.encoded
					}
					payload, err := encodePublicationPayload(contract.InputEncodingRaw, publicationTestEncoding(encoding), uint32(len(source)), source)
					if err != nil || payload == nil || string(payload) != want {
						t.Fatalf("exact payload differs: length=%d error=%v", len(payload), err)
					}
					length, err := contract.PublicationPayloadLength(publicationTestEncoding(encoding), uint32(len(source)))
					if err != nil || length != uint32(len(want)) || uint32(len(payload)) != length {
						t.Fatalf("encoded count differs: got=%d want=%d error=%v", length, len(want), err)
					}
					if encoding == "base64" {
						decoded, err := base64.StdEncoding.DecodeString(string(payload))
						if err != nil || string(decoded) != vector.raw || strings.ContainsAny(string(payload), "\r\n") {
							t.Fatal("consumer decode or unwrapped encoding differs", err)
						}
					}
					if len(payload) != 0 {
						payload[0] ^= 1
						if string(source) != vector.raw {
							t.Fatal("payload aliases original value")
						}
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicationPayloadClosedShapeAndRawBounds(t *testing.T) {
	for _, encoding := range []uint8{0, 3, 255} {
		if _, err := contract.PublicationPayloadLength(encoding, 1); err == nil {
			t.Fatalf("unsupported encoding admitted: %d", encoding)
		}
	}
	for _, length := range []uint32{^uint32(0), contract.CryptoMaxRawValue + 1} {
		if _, err := contract.PublicationPayloadLength(contract.OutputEncodingRaw, length); err == nil {
			t.Fatalf("out-of-range raw length admitted: %d", length)
		}
	}
	for _, length := range []uint32{0, contract.CryptoMaxRawValue} {
		if got, err := contract.PublicationPayloadLength(contract.OutputEncodingRaw, length); err != nil || got != length {
			t.Fatalf("raw boundary %d: got %d, err %v", length, got, err)
		}
	}
	for _, boundary := range [][2]uint32{{0, 0}, {1, 4}, {2, 4}, {3, 4}, {36000, 48000}, {36001, 48004}, {49152, 65536}} {
		if got, err := contract.PublicationPayloadLength(contract.OutputEncodingBase64, boundary[0]); err != nil || got != boundary[1] {
			t.Fatalf("base64 boundary %d: got %d want %d err %v", boundary[0], got, boundary[1], err)
		}
	}
	for _, length := range []uint32{49153, 65536, ^uint32(0), contract.CryptoMaxRawValue + 1} {
		if _, err := contract.PublicationPayloadLength(contract.OutputEncodingBase64, length); err == nil {
			t.Fatalf("out-of-range original length admitted for base64: %d", length)
		}
	}
	for _, input := range []uint8{contract.InputEncodingRaw, contract.InputEncodingBase64} {
		for _, content := range []int{49152, 49153} {
			// Independent bit groups for repeated 'd': complete triples ZGRk,
			// with the single-byte suffix ZA== only above the exact boundary.
			encoded := strings.Repeat("ZGRk", content/3)
			if content%3 != 0 {
				encoded += "ZA=="
			}
			retained := bytes.Repeat([]byte{'d'}, content)
			if input == contract.InputEncodingBase64 {
				retained = []byte(encoded)
			}
			before := bytes.Clone(retained)
			payload, err := encodePublicationPayload(input, contract.OutputEncodingBase64, uint32(content), retained)
			if content == 49152 {
				if err != nil || string(payload) != encoded || len(payload) != 65536 {
					t.Fatal("exact delivered publication boundary refused", input, err)
				}
			} else if err == nil || payload != nil {
				t.Fatal("publication exceeded delivered capacity", input)
			}
			if !bytes.Equal(retained, before) {
				t.Fatal("publication changed retained input")
			}
		}
	}

	for _, encoding := range []string{"raw", "base64"} {
		if payload, err := encodePublicationPayload(contract.InputEncodingRaw, publicationTestEncoding(encoding), contract.CryptoMaxRawValue+1, make([]byte, contract.CryptoMaxRawValue+1)); err == nil || payload != nil {
			t.Fatalf("over-limit original bytes admitted for %s", encoding)
		}
	}
}

func publicationTestEncoding(name string) uint8 {
	if name == "raw" {
		return contract.OutputEncodingRaw
	}
	if name == "base64" {
		return contract.OutputEncodingBase64
	}
	return 0
}
