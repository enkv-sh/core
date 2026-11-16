package contract

import (
	"bytes"
	"fmt"
	"testing"
)

// full_only: false
func TestOrdinaryCurrentAndPreparedGeneratedCensus(t *testing.T) {
	m, _, _ := generatedEntryEvidenceFixture(t, 0)
	core, err := ValueCoreForEntry(generatedRecordID(1), CompatibilityID(), m)
	if err != nil {
		t.Fatal(err)
	}
	context, err := ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	a := AccessRecord{Schema: CanonicalSchema, MaterialKind: 1, MaterialID: m.ValueState, MaterialContextDigest: context, PackageCheck: generatedRecordID(90), Wraps: []WrapRow{{SubjectKind: 1, SubjectID: m.Recipients[0], BindingID: generatedRecordID(91), BindingSerial: 1, PublicBindingDigest: generatedRecordID(92), RSACiphertext: bytes.Repeat([]byte{1}, 384)}}}
	access, err := EncodeAccessRecord(a)
	if err != nil {
		t.Fatal(err)
	}
	var rows []CryptoPreparedSecret
	for i := 0; i < 129; i++ {
		entry := m
		entry.Name = fmt.Sprintf("generated-%03d", i)
		body, err := EncodeValueEntry(entry)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, CryptoPreparedSecret{Name: entry.Name, Slot: uint16(i), EntryBytes: body, AccessRecord: access})
	}
	if _, err := CryptoPreparedRowsDescriptor(rows[:128]); err != nil {
		t.Fatal("128 complete generated rows", err)
	}
	body, err := EncodeCryptoPrepareResult(CryptoPrepareResult{Rows: rows[:128]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCryptoPrepareResult(body); err != nil {
		t.Fatal("128 generated prepared reader", err)
	}
	if _, err := CryptoPreparedRowsDescriptor(rows); err != ErrCryptoCapacity {
		t.Fatal("129 complete generated rows", err)
	}
	w := cryptoWriter{}
	cryptoWritePreparedRows(&w, rows)
	if _, err := InspectCryptoPrepareResult(w.b); err != ErrCryptoCapacity {
		t.Fatal("129 generated prepared reader", err)
	}
	var totals cryptoCurrentTotals
	for i, row := range rows {
		err := totals.add(cryptoCurrentRowView{slot: row.Slot, entryBytes: row.EntryBytes, access: row.AccessRecord}, i == 0)
		if i < 128 && err != nil || i == 128 && err != ErrCryptoCapacity {
			t.Fatal("complete current generated census", i, err)
		}
	}
}

// full_only: false
func TestOrdinaryCurrentGeneratedIntentBounds(t *testing.T) {
	entry, _, _ := generatedEntryEvidenceFixture(t, 0)
	rows := make([]CryptoIntentRow, 128)
	for i := range rows {
		rows[i] = CryptoIntentRow{Name: fmt.Sprintf("generated-%03d", i), Recipients: entry.Recipients,
			ValueSource: Generated, ConfidentialityClass: Secret, ContentLength: 3, PayloadDigest: Hash(entry.ValueBytes), PayloadLength: 218, InputEncoding: InputEncodingRaw, RetainedLength: 3, OutputEncoding: OutputEncodingRaw}
	}
	if _, err := CryptoIntentDescriptor(generatedRecordID(1), rows); err != nil {
		t.Fatal("128 current-generated intent rows refuse", err)
	}
	rows = append(rows, CryptoIntentRow{Name: "generated-128", Recipients: entry.Recipients,
		ValueSource: Generated, ConfidentialityClass: Secret, ContentLength: 3, PayloadDigest: Hash(entry.ValueBytes), PayloadLength: 218, InputEncoding: InputEncodingRaw, RetainedLength: 3, OutputEncoding: OutputEncodingRaw})
	if _, err := CryptoIntentDescriptor(generatedRecordID(1), rows); err != ErrCryptoCapacity {
		t.Fatal("129 generated intent rows must refuse before ownership", err)
	}
}

// full_only: false
func TestOrdinaryGeneratedPreparedByteEnvelope(t *testing.T) {
	// Independent account: count4;512 rows with framing14, entry154,
	// payload215, access102, two names256 and one recovery wrap489;
	// 4096 memberships each32+489;11,186,176 retained bytes;128 metadata envelopes460.
	const wantRows = 4 + (14+154+215+102+2*256+489)*512 + (32+489)*4096 + 11_186_176 + 128*460
	const wantDescriptor = 39 + wantRows // ENKV/CRYPTO/v2/prepared-secret-rows-v2 plus NUL.
	if wantRows != 14_139_908 {
		t.Fatal("independent prepared account changed")
	}
	if wantDescriptor != 14_139_947 {
		t.Fatal("independent descriptor account changed")
	}
	if cryptoPreparedRowsLimit != wantRows || cryptoPreparedDescriptorLimit != wantDescriptor {
		t.Fatal("generated extension omitted from prepared bounds", cryptoPreparedRowsLimit, cryptoPreparedDescriptorLimit)
	}
	// Independent one-row account includes maximum retained bytes and metadata.
	maximum := uint64(122717)
	if err := cryptoPreparedDescriptorError(DescriptorVector{Count: 1, Length: maximum}); err != nil {
		t.Fatal("count-only projection omits generated extension", err)
	}
	if err := cryptoPreparedDescriptorError(DescriptorVector{Count: 1, Length: maximum + 1}); err != ErrCryptoCapacity {
		t.Fatal("oversized generated projection accepted", err)
	}
}
