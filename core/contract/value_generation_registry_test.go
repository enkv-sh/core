package contract

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// full_only: false
func TestGeneratedRecipientRegistryImageCommitsCompleteOriginalProposal(t *testing.T) {
	domain, _, rows := completeApplyFixture(t)
	image := GeneratedRecipientRegistryImage{Schema: 1, DomainID: domain, OperationID: completeApplyID(7), OriginalPredecessorSnapshotID: completeApplyID(5), Recipients: rows, InitiallyAbsent: []ID{rows[0].Recipient.RecipientID}}
	body, err := EncodeGeneratedRecipientRegistryImage(image)
	if err != nil {
		t.Fatal(err)
	}
	row, err := EncodeRecipientRecord(rows[0].Recipient)
	if err != nil {
		t.Fatal(err)
	}
	// Build the outer image independently. RecipientRecord already has its own
	// canonical byte tests; the optional ordinary creation proof remains exact.
	expected := binary.BigEndian.AppendUint16(nil, 1)
	expected = append(expected, domain[:]...)
	expected = append(expected, image.OperationID[:]...)
	expected = append(expected, image.OriginalPredecessorSnapshotID[:]...)
	expected = binary.BigEndian.AppendUint32(expected, 1)
	expected = append(expected, row...)
	expected = append(expected, 1)
	expected = append(expected, rows[0].Creation.Snapshot[:]...)
	expected = append(expected, rows[0].Creation.Nonce[:]...)
	expected = binary.BigEndian.AppendUint32(expected, 1)
	expected = append(expected, rows[0].Recipient.RecipientID[:]...)
	if !bytes.Equal(body, expected) {
		t.Fatal("registry image differs from canonical outer bytes")
	}
	descriptor, err := GeneratedRecipientRegistryDescriptor(body)
	if err != nil {
		t.Fatal(err)
	}
	preimage := []byte("ENKV/GENERATOR/v1/recipient-registry-image\x00")
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(8+len(body)))
	preimage = binary.BigEndian.AppendUint32(preimage, 1)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(body)))
	preimage = append(preimage, body...)
	if descriptor.Digest != Hash(preimage) || descriptor.Length != uint64(8+len(body)) || descriptor.Count != 1 {
		t.Fatal("registry descriptor lost its one-row framing or domain separation")
	}
	decoded, err := DecodeGeneratedRecipientRegistryImage(body)
	if err != nil || !reflect.DeepEqual(decoded, image) {
		t.Fatal("registry roundtrip lost original proof", err)
	}
	clear(body)
	if !reflect.DeepEqual(decoded, image) {
		t.Fatal("decoded registry borrows mutable accepted image backing")
	}
	for _, field := range []string{"operation", "predecessor", "display", "proof", "absent"} {
		t.Run(field, func(t *testing.T) {
			_, _, rows := completeApplyFixture(t)
			changed := image
			changed.Recipients = rows
			changed.InitiallyAbsent = append([]ID(nil), image.InitiallyAbsent...)
			switch field {
			case "operation":
				changed.OperationID = completeApplyID(9)
			case "predecessor":
				changed.OriginalPredecessorSnapshotID = completeApplyID(9)
			case "display":
				changed.Recipients[0].Recipient.DisplayName = "accepted display"
			case "proof":
				changed.Recipients[0].Creation.Nonce = completeApplyID(9)
			case "absent":
				changed.InitiallyAbsent = nil
			}
			body, err := EncodeGeneratedRecipientRegistryImage(changed)
			if err != nil {
				t.Fatal(err)
			}
			got, err := GeneratedRecipientRegistryDescriptor(body)
			if err != nil || got == descriptor {
				t.Fatal("registry commitment omitted", field, err)
			}
		})
	}
}

// full_only: false
func TestGeneratedRecipientRegistryImageRejectsPartialOrAmbiguousCarrier(t *testing.T) {
	domain, _, rows := completeApplyFixture(t)
	image := GeneratedRecipientRegistryImage{Schema: 1, DomainID: domain, OperationID: completeApplyID(7), OriginalPredecessorSnapshotID: completeApplyID(5), Recipients: rows}
	body, err := EncodeGeneratedRecipientRegistryImage(image)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 2, 98, len(body) - 1} {
		if _, err := DecodeGeneratedRecipientRegistryImage(body[:n]); err == nil {
			t.Fatal("partial registry carrier admitted", n)
		}
	}
	if _, err := DecodeGeneratedRecipientRegistryImage(append(bytes.Clone(body), 0)); err == nil {
		t.Fatal("registry trailing bytes admitted")
	}
	image.InitiallyAbsent = []ID{completeApplyID(9)}
	if _, err := EncodeGeneratedRecipientRegistryImage(image); err == nil {
		t.Fatal("absent identity not in complete registry admitted")
	}
	image.InitiallyAbsent = []ID{rows[0].Recipient.RecipientID, rows[0].Recipient.RecipientID}
	if _, err := EncodeGeneratedRecipientRegistryImage(image); err == nil {
		t.Fatal("duplicate absent identity admitted")
	}
	image.InitiallyAbsent = nil
	image.Recipients = append(image.Recipients, image.Recipients[0])
	if _, err := EncodeGeneratedRecipientRegistryImage(image); err == nil {
		t.Fatal("duplicate recipient carrier admitted")
	}
	if _, err := DecodeGeneratedRecipientRegistryImage(make([]byte, GeneratedRecipientRegistryMaxLength+1)); err != ErrRecordCapacity {
		t.Fatal("registry aggregate byte bound not enforced", err)
	}
}
