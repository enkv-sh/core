package contract

import (
	"encoding/binary"
	"testing"
)

// full_only: false
func TestEndWorkChangedSubjectIndependentPreimage(t *testing.T) {
	domain, group, owner := generatedRecordID(71), generatedRecordID(72), generatedRecordID(73)
	preimage := []byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00")
	preimage = append(preimage, domain[:]...)
	preimage = append(preimage, byte(9))
	preimage = append(preimage, group[:]...)
	preimage = append(preimage, owner[:]...)
	wantID := Hash(preimage)
	gotID, err := ChangedSubjectIdentityID(domain, ChangedSubjectSelectedWork, group, owner)
	if err != nil || gotID != wantID {
		t.Fatalf("selected-work identity: %x want %x: %v", gotID, wantID, err)
	}
	row := []byte{9, ChangedSubjectRemoved}
	row = append(row, wantID[:]...)
	vector := binary.BigEndian.AppendUint32(nil, 1)
	vector = binary.BigEndian.AppendUint32(vector, uint32(len(row)))
	vector = append(vector, row...)
	prefixed := []byte("ENKV/GENERATOR/v1/changed-subjects\x00")
	prefixed = binary.BigEndian.AppendUint32(prefixed, uint32(len(vector)))
	prefixed = append(prefixed, vector...)
	want := GeneratorDescriptor{Digest: Hash(prefixed), Length: uint64(len(vector)), Count: 1}
	got, err := ChangedSubjectDescriptor([]ChangedSubjectIdentity{{Kind: ChangedSubjectSelectedWork, Change: ChangedSubjectRemoved, Identity: gotID}})
	if err != nil || got != want {
		t.Fatalf("selected-work descriptor: %+v want %+v: %v", got, want, err)
	}
	if _, err := ChangedSubjectIdentityID(domain, ChangedSubjectSelectedWork+1, group, owner); err == nil {
		t.Fatal("unknown changed-subject kind has an identity")
	}
	if _, err := ChangedSubjectDescriptor([]ChangedSubjectIdentity{{Kind: ChangedSubjectSelectedWork + 1, Change: ChangedSubjectRemoved, Identity: gotID}}); err == nil {
		t.Fatal("unknown changed-subject kind has a descriptor")
	}
}
