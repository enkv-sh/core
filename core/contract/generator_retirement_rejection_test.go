package contract

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// full_only: false
func TestRejectedRetirementClaimKeepsDistinctBoundedIdentity(t *testing.T) {
	claim := GeneratorSafeFacts{Schema: GeneratorSafeFactsSchema, LifecycleMode: GeneratorLifecycleManaged, Action: GeneratorActionDelete,
		Disposition: GeneratorDispositionRetirementAcknowledged, RequestDigest: generatedRecordID(2), IntentDigest: generatedRecordID(3), ResourceContractID: generatedRecordID(4),
		Target: []byte{1}, ResourceData: bytes.Repeat([]byte{2}, 3980)}
	body, err := EncodeRejectedRetirement(claim)
	// 115 fixed bytes + one target byte + 3980 resource bytes. Row framing
	// adds schema (2), result ID (32) and length (4).
	if err != nil || len(body) != 4096 || binary.BigEndian.Uint16(body) != 0x8001 {
		t.Fatal("maximum rejection", len(body), err)
	}
	row, err := EncodeGeneratorFactsRow(GeneratorFactsRow{Schema: 1, ResultID: generatedRecordID(5), Facts: body})
	if err != nil || len(row) != 4134 {
		t.Fatal("maximum rejection row", len(row), err)
	}
	if _, err := InspectGeneratorFactsRow(row); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectGeneratorSafeFacts(body); err == nil {
		t.Fatal("qualified a rejected acknowledgement")
	}
	claim.ResourceData = append(claim.ResourceData, 0)
	if _, err := EncodeRejectedRetirement(claim); err == nil {
		t.Fatal("accepted oversized resource")
	}
	claim.ResourceData = []byte{2}
	claim.ProviderFacts = []byte("provider details")
	encoded, err := EncodeRejectedRetirement(claim)
	observed, readErr := InspectGeneratorAttemptFacts(encoded)
	if err != nil || readErr != nil || !observed.RetirementRejected || len(observed.ProviderFacts) != 0 || !bytes.Equal(observed.Target, claim.Target) || !bytes.Equal(observed.ResourceData, claim.ResourceData) {
		t.Fatal("retained rejection payload", err, readErr)
	}
	ordinary, err := EncodeGeneratorSafeFacts(claim)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(ordinary, 0x8001)
	if _, err := InspectGeneratorAttemptFacts(ordinary); err == nil {
		t.Fatal("accepted extra provider data in marked record")
	}
	if _, err := InspectGeneratorAttemptFacts(append(encoded, 0)); err == nil {
		t.Fatal("accepted trailing bytes")
	}
}
