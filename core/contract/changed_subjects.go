package contract

import (
	"bytes"
	"slices"
)

const (
	ChangedSubjectValueEntry uint8 = iota + 1
	ChangedSubjectRecipient
	ChangedSubjectMembership
	ChangedSubjectGeneratedValue
	ChangedSubjectOutputBinding
	ChangedSubjectStoreConstruction
	ChangedSubjectAttachmentAdmission
	ChangedSubjectAuthorityBinding
	ChangedSubjectSelectedWork
)

const (
	ChangedSubjectAdded uint8 = iota + 1
	ChangedSubjectRemoved
	ChangedSubjectUpdated
)

type ChangedSubjectIdentity struct {
	Kind, Change uint8
	Identity     ID
}

func ChangedSubjectIdentityID(domain ID, kind uint8, primary, secondary ID) (ID, error) {
	if domain.IsZero() || kind < ChangedSubjectValueEntry || kind > ChangedSubjectSelectedWork || primary.IsZero() {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "changed-subject-identity-v1\x00")
	w.id(domain)
	w.u8(kind)
	w.id(primary)
	w.id(secondary)
	return w.result(0).Digest, nil
}

// ChangedSubjectDescriptor commits the complete canonical 34-byte rows. The
// operation owner supplies the complete change set and its Product order is
// the lexicographic encoded-row order.
func ChangedSubjectDescriptor(rows []ChangedSubjectIdentity) (GeneratorDescriptor, error) {
	if len(rows) > MutationChangedSubjectLimit {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	owned := slices.Clone(rows)
	slices.SortFunc(owned, func(a, b ChangedSubjectIdentity) int {
		var left, right [34]byte
		left[0], left[1], right[0], right[1] = a.Kind, a.Change, b.Kind, b.Change
		copy(left[2:], a.Identity[:])
		copy(right[2:], b.Identity[:])
		return bytes.Compare(left[:], right[:])
	})
	w := cryptoWriter{b: make([]byte, 0, 4+38*len(owned))}
	w.u32(uint32(len(owned)))
	var previous [34]byte
	for i, row := range owned {
		if row.Kind < ChangedSubjectValueEntry || row.Kind > ChangedSubjectSelectedWork ||
			row.Change < ChangedSubjectAdded || row.Change > ChangedSubjectUpdated || row.Identity.IsZero() {
			return GeneratorDescriptor{}, ErrRecord
		}
		var encoded [34]byte
		encoded[0], encoded[1] = row.Kind, row.Change
		copy(encoded[2:], row.Identity[:])
		if i != 0 && bytes.Equal(previous[:], encoded[:]) {
			return GeneratorDescriptor{}, ErrRecord
		}
		w.blob(encoded[:])
		previous = encoded
	}
	return GeneratorDescriptor{Digest: generatorDigest("changed-subjects", w.b), Length: uint64(len(w.b)), Count: uint32(len(owned))}, nil
}
