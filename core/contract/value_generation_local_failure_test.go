package contract

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Independently assembled with Python struct/hashlib: R27 || B(Context382) ||
// 09 || R28 || 02. Context uses the documented repeated-ID adoption fixture;
// no product encoder was used to construct these bytes or their digest.
const localFailurePrepareHex = "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b0000017e041515151515151515151515" +
	"151515151515151515151515151515151515151515161616161616161616161616161616161616161616161616161616" +
	"161616161601010101010101010101010101010101010101010101010101010101010101011717171717171717171717" +
	"171717171717171717171717171717171717171717000000003b9aca0011111111111111111111111111111111111111" +
	"1111111111111111111111111103000b0101010101010101010101010101010101010101010101010101010101010101" +
	"181818181818181818181818181818181818181818181818181818181818181819191919191919191919191919191919" +
	"19191919191919191919191919191919000000c800001212121212121212121212121212121212121212121212121212" +
	"121212121212fbbfa54eecd7a82c2edabc7bb053c6c8aac8cdfaa9bec5a7524a3b9d36b7f96e000000000000033e0000" +
	"00011a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a091c1c1c1c1c1c1c1c1c1c1c1c1c" +
	"1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c02"

// full_only: false
func TestCryptoGeneratedLocalFailurePrepareIndependentBytes(t *testing.T) {
	body, err := hex.DecodeString(localFailurePrepareHex)
	if err != nil || len(body) != 452 || Hash(body) != generatedCryptoHexID(t, "97218440a8d63878098a5c88dba9494045f9dd383d9560d375f74094d0e7564c") {
		t.Fatal("independent failure Prepare literal damaged", err)
	}
	q := CryptoRequest{Schema: CryptoSchema, Kind: CryptoPrepare, RequestID: generatedRecordID(31), CustodyInstanceID: generatedRecordID(32), Body: body}
	got, err := InspectCryptoGeneratedPrepareRequest(q)
	if err != nil || got.Variant != 9 {
		t.Fatal("closed failure Prepare refused", got.Variant, err)
	}
	encoded, err := EncodeCryptoGeneratedLocalFailureRequest(got.LocalFailure)
	if err != nil || !bytes.Equal(encoded, body) || got.LocalFailure.AttemptID != generatedRecordID(28) || got.LocalFailure.Reason != 2 {
		t.Fatal("failure Prepare codec differs from independent literal", err)
	}
	if err := ValidateCryptoGeneratedRequest(q); err != nil {
		t.Fatal(err)
	}
	// Vary only the independent fixture's final byte across the entire wire field.
	for i := range 256 {
		probe := q
		probe.Body = bytes.Clone(body)
		probe.Body[451] = byte(i)
		want := i >= 1 && i <= 5 || i >= 133 && i <= 138
		decoded, err := InspectCryptoGeneratedPrepareRequest(probe)
		if (err == nil) != want || want && decoded.LocalFailure.Reason != byte(i) {
			t.Fatalf("failure Prepare reason %d: %v", i, err)
		}
	}
	for _, name := range []string{"zero attempt", "zero reason", "foreign reason", "retired tag", "ordinary adopt", "truncated", "suffix"} {
		t.Run(name, func(t *testing.T) {
			bad := q
			bad.Body = bytes.Clone(body)
			switch name {
			case "zero attempt":
				clear(bad.Body[419:451])
			case "zero reason":
				bad.Body[451] = 0
			case "foreign reason":
				bad.Body[451] = 6
			case "retired tag":
				bad.Body[418] = 3
			case "ordinary adopt":
				bad.Body[418] = 4
			case "truncated":
				bad.Body = bad.Body[:451]
			case "suffix":
				bad.Body = append(bad.Body, 0)
			}
			if ValidateCryptoGeneratedRequest(bad) == nil {
				t.Fatal("invalid failure Prepare accepted")
			}
		})
	}
	for _, body := range [][]byte{{9}, nil, {9, 0}, {4}} {
		response := CryptoResponse{Schema: CryptoSchema, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: q.CustodyInstanceID, ResultCode: CryptoSuccess, Body: body}
		if (ValidateCryptoGeneratedResponse(q, response) == nil) != bytes.Equal(body, []byte{9}) {
			t.Fatal("failure response framing differs")
		}
	}
}

// full_only: false
func TestGeneratorFailedTerminalAuthorityOwnsNoResult(t *testing.T) {
	v := generatorAuthorityFixture()
	v.Purpose = GeneratorAuthorityPurpose(13)
	v.PredecessorAttemptID, v.ResultDigest = ID{}, ID{}
	references, err := GeneratorResultReferencesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	v.ResultVector = GeneratorDescriptor(references)
	digest, err := GeneratorAuthorityDigest(v)
	if err != nil || v.Purpose.Name() != "failed-terminal" || digest != generatedCryptoHexID(t, "37325fe236f0f2e7491ab630105edcfbb4e0adc772c65eccd1890945689fde1f") {
		t.Fatal("failure authority meaning differs", err)
	}
	want, err := hex.DecodeString(generatorAuthorityRecordHex)
	if err != nil {
		t.Fatal(err)
	}
	want[2] = 13
	clear(want[516:548])
	clear(want[580:612])
	empty, err := hex.DecodeString("f5fb145a49057f82471cab908d3117012e5b47ea83e6a786cebf92a1efcf3090000000000000000400000000")
	if err != nil {
		t.Fatal(err)
	}
	copy(want[1036:1080], empty)
	got, err := EncodeGeneratorAuthoritySubject(v)
	if err != nil || !bytes.Equal(got, want) || Hash(got) != generatedCryptoHexID(t, "d86cf18a813561fe15d5803bf65817be706f5328e8a61ce50a4dc92e918e845b") {
		t.Fatal("failure authority bytes differ", err)
	}
	for _, name := range []string{"result digest", "predecessor", "actual results", "ordinary record"} {
		t.Run(name, func(t *testing.T) {
			bad := v
			switch name {
			case "result digest":
				bad.ResultDigest = generatedRecordID(19)
			case "predecessor":
				bad.PredecessorAttemptID = generatedRecordID(17)
			case "actual results":
				bad.ResultVector = generatorAuthorityFixture().ResultVector
			case "ordinary record":
				bad.Purpose = GeneratorAuthorityRecord
			}
			if _, err := EncodeGeneratorAuthoritySubject(bad); err == nil {
				t.Fatal("invalid resultless authority accepted")
			}
		})
	}
}
