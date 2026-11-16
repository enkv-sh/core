package contract

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"testing"
)

// full_only: false
func TestRetainedCanonicalSourceIdentityBindsCompleteRecord(t *testing.T) {
	source := RetainedCanonicalRecord{OriginalSlot: 3, Entry: generatedValueEntryFixture(t)}
	body, err := EncodeRetainedCanonicalRecord(source)
	if err != nil {
		t.Fatal(err)
	}
	// The published domain separator followed by the complete record is the
	// digest preimage; use the standard hash directly, outside the record codec.
	preimage := append([]byte("ENKV/CRYPTO/v2/retained-member-admission-v1\x00"), body...)
	want := ID(sha256.Sum256(preimage))
	got, err := AdmissionEntryDigest(source)
	if err != nil || got != want {
		t.Fatal("complete source identity", got, want, err)
	}
	for _, id := range []ID{source.Entry.ValueState, want} {
		row := SupportRecord{Kind: RetainedCanonicalSupportKind, RecordID: id, Body: body}
		encoded, err := AppendSupportRecord(nil, row)
		if err != nil {
			t.Fatal("exact historical or digest identity refused", err)
		}
		decoded, n, err := ParseSupportRecord(encoded)
		if err != nil || n != len(encoded) || decoded.RecordID != id || !bytes.Equal(decoded.Body, body) {
			t.Fatal("source bytes changed", err)
		}
	}
	for _, change := range []string{"slot", "readers", "ciphertext"} {
		t.Run(change, func(t *testing.T) {
			changed := source
			changed.Entry.ValueBytes = bytes.Clone(source.Entry.ValueBytes)
			switch change {
			case "slot":
				changed.OriginalSlot++
			case "readers":
				changed.Entry.Recipients = append([]ID(nil), source.Entry.Recipients...)
				changed.Entry.Recipients = append(changed.Entry.Recipients, generatedRecordID(21))
			case "ciphertext":
				changed.Entry.ValueBytes[len(changed.Entry.ValueBytes)-1] ^= 1
			}
			changedBody, err := EncodeRetainedCanonicalRecord(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := SupportRecordLength(SupportRecord{Kind: RetainedCanonicalSupportKind, RecordID: want, Body: changedBody}); err == nil {
				t.Fatal("source identity accepted different record")
			}
		})
	}
	if _, err := SupportRecordLength(SupportRecord{Kind: RetainedCanonicalSupportKind, RecordID: generatedRecordID(99), Body: body}); err == nil {
		t.Fatal("arbitrary source identity accepted")
	}
}

// full_only: false
func TestGeneratedPredecessorCanonicalCensusIsCompleteAndOwned(t *testing.T) {
	witness, before, _, _ := generatedOutputFixture(t)
	original := generatedValueEntryFixture(t)
	for _, id := range []byte{7, 8} {
		entry := original
		entry.Recipients = []ID{generatedRecordID(id)}
		body, err := EncodeRetainedCanonicalRecord(RetainedCanonicalRecord{OriginalSlot: 2, Entry: entry})
		if err != nil {
			t.Fatal(err)
		}
		sourceID, err := AdmissionEntryDigest(RetainedCanonicalRecord{OriginalSlot: 2, Entry: entry})
		if err != nil {
			t.Fatal(err)
		}
		row := SupportRecord{Kind: RetainedCanonicalSupportKind, RecordID: sourceID, Body: body}
		fact, err := InspectSupportRecordDigest(before.Domain, row)
		if err != nil {
			t.Fatal(err)
		}
		witness.Retained = append(witness.Retained, row)
		witness.Rows.Facts = append(witness.Rows.Facts, fact)
	}
	slices.SortFunc(witness.Rows.Facts, func(a, b SupportRecordDigest) int {
		if a.Kind() != b.Kind() {
			return int(a.Kind()) - int(b.Kind())
		}
		x, y := a.RecordID(), b.RecordID()
		return bytes.Compare(x[:], y[:])
	})
	slices.SortFunc(witness.Retained, func(a, b SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	var err error
	before.RequiredSupport, err = RequiredSupportDescriptorFromDigests(before.Domain, witness.Rows.Facts)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := witness.Own(before)
	if err != nil {
		t.Fatal("complete predecessor source set", err)
	}
	for _, mode := range []string{"missing", "reordered", "duplicate", "changed body", "invented"} {
		t.Run(mode, func(t *testing.T) {
			changed := *witness
			changed.Retained = slices.Clone(witness.Retained)
			switch mode {
			case "missing":
				changed.Retained = changed.Retained[:1]
			case "reordered":
				slices.Reverse(changed.Retained)
			case "duplicate":
				changed.Retained[1] = changed.Retained[0]
			case "changed body":
				changed.Retained[0].Body = bytes.Clone(changed.Retained[0].Body)
				changed.Retained[0].Body[len(changed.Retained[0].Body)-1] ^= 1
			case "invented":
				changed.Retained = append(changed.Retained, changed.Retained[0])
			}
			if changed.Inspect(before) == nil {
				t.Fatal("incomplete or changed predecessor source set admitted")
			}
		})
	}
	clear(witness.Retained[0].Body)
	if err := owned.Inspect(before); err != nil {
		t.Fatal("owned sources alias caller bytes", err)
	}
}
