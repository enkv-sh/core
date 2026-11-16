package contract

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"testing"
)

// full_only: false
func TestSuccessionChangedSubjectsIndependentPreimage(t *testing.T) {
	for _, test := range []struct {
		operation, mask uint8
		count           uint32
	}{{1, 1, 4}, {1, 2, 2}, {1, 3, 6}, {3, 4, 4}, {3, 8, 2}, {3, 12, 6}} {
		t.Run(fmt.Sprint(test), func(t *testing.T) {
			q := successionTestRequest(t, test.operation, test.mask, 1, true)
			var rows [][]byte
			var expectedChanges []SuccessionBindingChange
			pair := func(purpose byte, before, after ID) {
				role := uint8(SuccessorRecoverySigner)
				switch purpose {
				case 1, 2:
					role = SuccessorNormalSigner
				case 3:
					role = SuccessorAuthorityKEK
				case 6:
					role = SuccessorRecoveryKEK
				}
				change := SuccessionBindingChange{Purpose: purpose, Role: role}
				if purpose == 4 {
					change.BeforeBasisID, change.AfterBasisID = before, after
				} else {
					change.BeforeBindingID, change.AfterBindingID = before, after
				}
				expectedChanges = append(expectedChanges, change)
				for _, v := range []struct {
					change byte
					id     ID
				}{{2, before}, {1, after}} {
					b := []byte("ENKV/CRYPTO/v2/authority-binding-subject-v1\x00")
					b = append(b, q.DomainID[:]...)
					b = append(b, purpose)
					b = append(b, v.id[:]...)
					h := Hash(b)
					row := append([]byte{8, v.change}, h[:]...)
					rows = append(rows, row)
				}
			}
			basis := func(s BindingSubject) ID {
				b := []byte("ENKV/K1-BINDING/v2\x00")
				for _, id := range []ID{s.Domain, s.Coordinate, s.Store, s.Trust, s.PublicKey, s.Interpretation, s.ControlIncarnationID} {
					b = append(b, id[:]...)
				}
				b = binary.BigEndian.AppendUint64(b, s.Epoch)
				out := []byte("ENKV/CRYPTO/v2/signing-basis-id-v1\x00")
				out = binary.BigEndian.AppendUint32(out, uint32(len(b)))
				out = append(out, b...)
				return Hash(out)
			}
			b, a := q.BeforeControl, q.ProposedAfterControl
			if test.mask&1 != 0 {
				pair(1, b.NormalSigning.BindingID, a.NormalSigning.BindingID)
				pair(2, b.NormalSigning.BindingID, a.NormalSigning.BindingID)
			}
			if test.mask&2 != 0 {
				pair(3, b.AuthorityKMSBinding.BindingID, a.AuthorityKMSBinding.BindingID)
			}
			if test.mask&4 != 0 {
				if test.operation == 3 {
					pair(4, basis(b.Recovery.Signing.Binding), basis(a.Recovery.Signing.Binding))
				}
				pair(5, b.Recovery.Signing.BindingID, a.Recovery.Signing.BindingID)
			}
			if test.mask&8 != 0 {
				pair(6, b.Recovery.KMS.BindingID, a.Recovery.KMS.BindingID)
			}
			slices.SortFunc(rows, bytes.Compare)
			vector := binary.BigEndian.AppendUint32(nil, test.count)
			for _, row := range rows {
				vector = binary.BigEndian.AppendUint32(vector, uint32(len(row)))
				vector = append(vector, row...)
			}
			want := []byte("ENKV/GENERATOR/v1/changed-subjects\x00")
			want = binary.BigEndian.AppendUint32(want, uint32(len(vector)))
			want = append(want, vector...)
			got, err := SuccessionChangedSubjectDescriptor(q)
			if err != nil || got.Digest != Hash(want) || got.Length != uint64(len(vector)) || got.Count != test.count {
				t.Fatal("changed subjects differ", got, err)
			}
			var projection SuccessionChangedSubjectProjection
			projected, err := ProjectSuccessionChangedSubjects(q, &projection)
			if err != nil || projected != got || !reflect.DeepEqual(projection.Changes, expectedChanges) || len(projection.Subjects) != len(rows) {
				t.Fatal("succession purpose/binding projection differs", projection, err)
			}
			for i, row := range rows {
				expected := ChangedSubjectIdentity{Kind: row[0], Change: row[1]}
				copy(expected.Identity[:], row[2:])
				if projection.Subjects[i] != expected {
					t.Fatal("complete succession projection changed its independent preimage", i)
				}
			}
			q.ProposedAfterControl.AccessGeneration++
			if _, err := SuccessionChangedSubjectDescriptor(q); err == nil {
				t.Fatal("unadmitted control counters accepted")
			}
		})
	}
}

// full_only: false
func TestAccessChangeDescriptorExactRows(t *testing.T) {
	domain := Hash([]byte("domain"))
	var changes []AccessChangeRow
	for i := 0; i < 2; i++ {
		before := accessStructuralRow(t, i, 1, 0).BeforeAccessRecord
		after := before
		after.Wraps = slices.Clone(before.Wraps)
		after.Wraps[0].BindingID = Hash([]byte(fmt.Sprint("new", i)))
		changes = append(changes, AccessChangeRow{Before: before, After: after})
	}
	got, err := AccessChangeDescriptor(domain, changes)
	if err != nil || got.Count != 2 || got.Length != 4+2*102 {
		t.Fatal(got, err)
	}
	for _, bad := range [][]AccessChangeRow{{changes[1], changes[0]}, {changes[0], changes[0]}, {{Before: changes[0].Before, After: changes[0].Before}}} {
		if _, err := AccessChangeDescriptor(domain, bad); err == nil {
			t.Fatal("reordered, duplicate, or unchanged row accepted")
		}
	}
	changes[0].After.MaterialID = Hash([]byte("another material"))
	if _, err := AccessChangeDescriptor(domain, changes); err == nil {
		t.Fatal("cross-material change accepted")
	}
	empty, err := AccessChangeDescriptor(domain, nil)
	want := []byte("ENKV/GENERATOR/v1/changed-access\x00")
	want = append(want, 0, 0, 0, 4, 0, 0, 0, 0)
	if err != nil || empty.Digest != Hash(want) || empty.Length != 4 || empty.Count != 0 {
		t.Fatal("empty changed-access differs", err)
	}
}
