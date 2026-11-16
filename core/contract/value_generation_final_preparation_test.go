package contract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// full_only: false
func TestGeneratedFinalPreparationIndependentRecordAndPhase(t *testing.T) {
	// Independent concatenation: schema/domain/operation, three phase IDs,
	// Final(5), before/after, evidence, typed image(6), control binding digest.
	var want []byte
	want = binary.BigEndian.AppendUint16(want, 1)
	for _, n := range []byte{1, 2, 3, 4, 5} {
		want = append(want, bytes.Repeat([]byte{n}, 32)...)
	}
	want = append(want, 5)
	want = binary.BigEndian.AppendUint32(want, 2)
	want = binary.BigEndian.AppendUint32(want, 3)
	want = append(want, bytes.Repeat([]byte{8}, 32)...)
	want = binary.BigEndian.AppendUint64(want, 4)
	want = binary.BigEndian.AppendUint32(want, 0)
	want = append(want, 0, 1, 6)
	want = append(want, bytes.Repeat([]byte{6}, 32)...)
	want = binary.BigEndian.AppendUint32(want, 138)
	want = append(want, bytes.Repeat([]byte{6}, 32)...)
	want = append(want, bytes.Repeat([]byte{7}, 32)...)
	if len(want) != 318 {
		t.Fatal("independent record framing")
	}
	v := GeneratedFinalPreparationRecord{Schema: 1, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
		MaterializationPhase: GeneratorPhaseIdentity{RequestIdentityDigest: generatedRecordID(3), ObservedHEADDigest: generatedRecordID(4), ConditionDigest: generatedRecordID(5),
			TransitionKind: GeneratorAuthorityFinal, BeforePhase: 2, AfterPhase: 3, Evidence: generatedRecordDescriptor(8)},
		Image: GeneratorLogicalSlice{Schema: 1, ContentKind: GeneratorContentFinalPreparation, ContentID: generatedRecordID(6), Length: 138, Digest: generatedRecordID(6)}, ControlBindingDigest: generatedRecordID(7)}
	digest := Hash(want)
	if hex.EncodeToString(digest[:]) != "e87d56d517fccd851891befce248ac613105e11291dd6f4c41352d984fb77f3f" {
		t.Fatal("independent record digest")
	}
	got, err := EncodeGeneratedFinalPreparationRecord(v)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("record field order", err)
	}
	decoded, err := InspectGeneratedFinalPreparationRecord(want)
	if err != nil || decoded != v {
		t.Fatal("independent record decode", err)
	}
	for n := range want {
		if _, err := InspectGeneratedFinalPreparationRecord(want[:n]); err == nil {
			t.Fatal("record truncation accepted", n)
		}
	}
	if _, err := InspectGeneratedFinalPreparationRecord(append(bytes.Clone(want), 0)); err == nil {
		t.Fatal("record suffix accepted")
	}
	for _, offset := range []int{1, 66 + 96, 66 + 149 + 2} {
		bad := bytes.Clone(want)
		bad[offset] = 255
		if _, err := InspectGeneratedFinalPreparationRecord(bad); err == nil {
			t.Fatal("record finite tag accepted", offset)
		}
	}
	bad := v
	bad.Image.Digest = generatedRecordID(9)
	if _, err := EncodeGeneratedFinalPreparationRecord(bad); err == nil {
		t.Fatal("non content addressed image accepted")
	}
	bad = v
	bad.Image.Length = GeneratedFinalPreparationMaxLength + 1
	if _, err := EncodeGeneratedFinalPreparationRecord(bad); err == nil {
		t.Fatal("oversize image accepted")
	}
	phase := generatedRecordPhase()
	phase.FinalPreparationID = v.Image.ContentID
	if _, err := EncodeGeneratedPhaseRecord(phase); err == nil {
		t.Fatal("nonterminal preparation association accepted")
	}
	phase.Stage = GeneratedStageTerminal
	wire, err := EncodeGeneratedPhaseRecord(phase)
	if err != nil || len(wire) != 716 || !bytes.Equal(wire[564:596], v.Image.ContentID[:]) {
		t.Fatal("phase association framing", err)
	}
	parsed, err := InspectGeneratedPhaseRecord(wire)
	if err != nil || parsed != phase {
		t.Fatal("phase association roundtrip", err)
	}
}

// full_only: false
func TestGeneratedFinalPreparationImageOwnsCompleteRowsAndClearsPartialDecode(t *testing.T) {
	_, _, generated := generatedCryptoValueEntryFixture(t)
	q := generatedSuppliedCryptoFixture(t)
	identity, err := DecodeIdentityPlan(q.IdentityPlan)
	if err != nil {
		t.Fatal(err)
	}
	supplied := generatedSuppliedPreparedFixture(t, q, identity.Rows[0])
	v := GeneratedFinalPreparationImage{Schema: 1, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
		MaterializationPhaseID: generatedRecordID(3), ControlBindingDigest: generatedRecordID(4), Generated: []CryptoGeneratedValueEntryResult{generated}, Supplied: []CryptoPreparedSecret{supplied}}
	body, err := EncodeGeneratedFinalPreparationImage(v)
	if err != nil {
		t.Fatal("complete image", err)
	}
	before := bytes.Clone(body)
	sourceValue := bytes.Clone(generated.Entry.ValueBytes)
	sourceWrap := bytes.Clone(generated.Access.Wraps[0].RSACiphertext)
	decoded, err := DecodeGeneratedFinalPreparationImage(body)
	if err != nil || len(decoded.Generated) != 1 || len(decoded.Supplied) != 1 {
		t.Fatal("complete owned image", err)
	}
	if decoded.Generated[0].ValueCore != generated.ValueCore || decoded.Generated[0].Entry.Generated != generated.Entry.Generated ||
		!bytes.Equal(decoded.Generated[0].Entry.ValueBytes, generated.Entry.ValueBytes) ||
		!bytes.Equal(decoded.Generated[0].Access.Wraps[0].RSACiphertext, generated.Access.Wraps[0].RSACiphertext) ||
		!bytes.Equal(decoded.Supplied[0].EntryBytes, supplied.EntryBytes) || !bytes.Equal(decoded.Supplied[0].AccessRecord, supplied.AccessRecord) {
		t.Fatal("retained image changed immutable prepared bytes")
	}
	ownedValue, ownedWrap := decoded.Generated[0].Entry.ValueBytes, decoded.Generated[0].Access.Wraps[0].RSACiphertext
	ownedEntry, ownedAccess := decoded.Supplied[0].EntryBytes, decoded.Supplied[0].AccessRecord
	decoded.Clear()
	for _, b := range [][]byte{ownedValue, ownedWrap, ownedEntry, ownedAccess} {
		if !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
			t.Fatal("owned image buffer not cleared")
		}
	}
	if !bytes.Equal(body, before) || !bytes.Equal(generated.Entry.ValueBytes, sourceValue) || !bytes.Equal(generated.Access.Wraps[0].RSACiphertext, sourceWrap) {
		t.Fatal("borrowed source image changed")
	}
	// Every suffix truncation includes cases after the first row was owned.
	for n := range body {
		partial, err := DecodeGeneratedFinalPreparationImage(body[:n])
		if err == nil {
			partial.Clear()
			t.Fatal("image truncation accepted", n)
		}
		if len(partial.Generated) != 0 || len(partial.Supplied) != 0 {
			partial.Clear()
			t.Fatal("partial owned rows escaped failure", n)
		}
	}
	bad := append(bytes.Clone(body), 0)
	partial, err := DecodeGeneratedFinalPreparationImage(bad)
	if err == nil || len(partial.Generated) != 0 || len(partial.Supplied) != 0 {
		partial.Clear()
		t.Fatal("image suffix retained partial rows")
	}
	if !bytes.Equal(body, before) {
		t.Fatal("error path cleared borrowed image")
	}
	v.Supplied[0].Slot = generated.Slot
	if _, err := EncodeGeneratedFinalPreparationImage(v); err == nil {
		t.Fatal("duplicate selected slot accepted")
	}
	v.Generated = nil
	if _, err := EncodeGeneratedFinalPreparationImage(v); err == nil {
		t.Fatal("empty materialization accepted")
	}
}
