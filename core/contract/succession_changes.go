package contract

import (
	"bytes"
	"slices"
)

// SuccessionChangedSubjectDescriptor derives the compact receipt commitment
// from the complete typed control change, including each affected signing purpose.
func SuccessionChangedSubjectDescriptor(q SuccessionRequestCore) (GeneratorDescriptor, error) {
	return successionChangedSubjects(q, nil)
}

// SuccessionBindingChange retains only the IDs and purpose used by the exact
// authority-binding preimage. Signing-basis IDs are distinct from binding IDs.
type SuccessionBindingChange struct {
	BeforeBindingID, AfterBindingID, BeforeBasisID, AfterBasisID ID
	Purpose, Role                                                uint8
}

type SuccessionChangedSubjectProjection struct {
	Subjects []ChangedSubjectIdentity
	Changes  []SuccessionBindingChange
}

// ProjectSuccessionChangedSubjects is pure, like descriptor recomputation.
func ProjectSuccessionChangedSubjects(q SuccessionRequestCore, out *SuccessionChangedSubjectProjection) (GeneratorDescriptor, error) {
	return successionChangedSubjects(q, out)
}

func successionChangedSubjects(q SuccessionRequestCore, out *SuccessionChangedSubjectProjection) (GeneratorDescriptor, error) {
	if _, err := SuccessionRequestCoreLength(q); err != nil {
		return GeneratorDescriptor{}, err
	}
	var rows [6][34]byte
	count := 0
	var changes [3]SuccessionBindingChange
	changeCount := 0
	pair := func(purpose uint8, before, after ID) {
		if out != nil {
			change := SuccessionBindingChange{Purpose: purpose}
			switch purpose {
			case 1, 2:
				change.Role = SuccessorNormalSigner
			case 3:
				change.Role = SuccessorAuthorityKEK
			case 4, 5:
				change.Role = SuccessorRecoverySigner
			case 6:
				change.Role = SuccessorRecoveryKEK
			}
			if purpose == 4 {
				change.BeforeBasisID, change.AfterBasisID = before, after
			} else {
				change.BeforeBindingID, change.AfterBindingID = before, after
			}
			changes[changeCount] = change
			changeCount++
		}
		for _, v := range []struct {
			change uint8
			id     ID
		}{{2, before}, {1, after}} {
			w := cryptoHashWriter(cryptoPurposePrefix + "authority-binding-subject-v1\x00")
			w.id(q.DomainID)
			w.u8(purpose)
			w.id(v.id)
			d := w.result(0).Digest
			rows[count][0], rows[count][1] = 8, v.change
			copy(rows[count][2:], d[:])
			count++
		}
	}
	b, a := q.BeforeControl, q.ProposedAfterControl
	if q.ChangeMask&SuccessionChangeNormalSigner != 0 {
		pair(1, b.NormalSigning.BindingID, a.NormalSigning.BindingID)
		pair(2, b.NormalSigning.BindingID, a.NormalSigning.BindingID)
	}
	if q.ChangeMask&SuccessionChangeAuthorityKEK != 0 {
		pair(3, b.AuthorityKMSBinding.BindingID, a.AuthorityKMSBinding.BindingID)
	}
	if q.ChangeMask&SuccessionChangeRecoverySigner != 0 {
		basisID := func(s BindingSubject) ID {
			w := cryptoHashWriter(cryptoPurposePrefix + "signing-basis-id-v1\x00")
			w.u32(BindingSubjectLength)
			writeBindingSubject(&w, s)
			return w.result(0).Digest
		}
		pair(4, basisID(b.Recovery.Signing.Binding), basisID(a.Recovery.Signing.Binding))
		pair(5, b.Recovery.Signing.BindingID, a.Recovery.Signing.BindingID)
	}
	if q.ChangeMask&SuccessionChangeRecoveryKEK != 0 {
		pair(6, b.Recovery.KMS.BindingID, a.Recovery.KMS.BindingID)
	}
	slices.SortFunc(rows[:count], func(a, b [34]byte) int { return bytes.Compare(a[:], b[:]) })
	if out != nil {
		projection := SuccessionChangedSubjectProjection{Subjects: make([]ChangedSubjectIdentity, count), Changes: make([]SuccessionBindingChange, changeCount)}
		for i, row := range rows[:count] {
			projection.Subjects[i].Kind, projection.Subjects[i].Change = row[0], row[1]
			copy(projection.Subjects[i].Identity[:], row[2:])
		}
		copy(projection.Changes, changes[:changeCount])
		*out = projection
	}
	w := cryptoWriter{b: make([]byte, 0, 4+38*count)}
	w.u32(uint32(count))
	for _, row := range rows[:count] {
		w.blob(row[:])
	}
	return GeneratorDescriptor{Digest: generatorDigest("changed-subjects", w.b), Length: uint64(len(w.b)), Count: uint32(count)}, nil
}

type AccessChangeRow struct{ Before, After AccessRecord }

// AccessChangeDescriptor accepts complete changed records in material order.
// The caller establishes that this is the complete selected change set.
func AccessChangeDescriptor(domain ID, rows []AccessChangeRow) (GeneratorDescriptor, error) {
	if domain.IsZero() {
		return GeneratorDescriptor{}, ErrRecord
	}
	if len(rows) > AccessMaterialLimit {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	w := cryptoWriter{b: make([]byte, 0, 4+102*len(rows))}
	w.u32(uint32(len(rows)))
	for i, row := range rows {
		if row.Before.MaterialKind != row.After.MaterialKind || row.Before.MaterialID != row.After.MaterialID ||
			i > 0 && !materialBefore(rows[i-1].Before.MaterialKind, rows[i-1].Before.MaterialID, row.Before.MaterialKind, row.Before.MaterialID) {
			return GeneratorDescriptor{}, ErrRecord
		}
		before, err := AccessRecordDigest(row.Before)
		if err != nil {
			return GeneratorDescriptor{}, err
		}
		after, err := AccessRecordDigest(row.After)
		if err != nil {
			return GeneratorDescriptor{}, err
		}
		if before == after {
			return GeneratorDescriptor{}, ErrRecord
		}
		w.u32(98)
		w.u16(row.Before.MaterialKind)
		w.id(row.Before.MaterialID)
		w.id(before)
		w.id(after)
	}
	return GeneratorDescriptor{Digest: generatorDigest("changed-access", w.b), Length: uint64(len(w.b)), Count: uint32(len(rows))}, nil
}
