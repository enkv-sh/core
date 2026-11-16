package core

import (
	"bytes"
	"encoding/binary"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// This projection binds application state and exact retained logical access.
// It omits physical Access page references because an exit can discard an
// exclusively ended operation seed and rewrite its page. The complete reader
// still checks every new page against its signed root reference.
func administrativePreservedCurrent(root format.Root, pages [contract.MaxValueEntryPages]*format.ValueEntryPage,
	accessRows []contract.AccessRecord, pointerClears map[contract.ID]contract.ID) (contract.DigestLength, error) {
	current := root.CurrentAccess
	current.Core.AccessPageRefs = nil
	orderPreimage := append([]byte("ENKV/administrative-preserved-current/access-order/v1\x00"), root.Domain[:]...)
	current.Core.AccessIncarnationID = contract.Hash(orderPreimage)
	current.Core.AccessGeneration = 1
	var err error
	current.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(root.Domain, nil)
	if err != nil {
		return contract.DigestLength{}, err
	}
	current.AccessRoot, err = contract.AccessRoot(current.Core)
	if err != nil {
		return contract.DigestLength{}, err
	}
	access, err := contract.EncodeCurrentAccessSection(current)
	if err != nil {
		return contract.DigestLength{}, err
	}
	rows := slices.Clone(accessRows)
	slices.SortFunc(rows, func(a, b contract.AccessRecord) int {
		if a.MaterialKind != b.MaterialKind {
			return int(a.MaterialKind) - int(b.MaterialKind)
		}
		return bytes.Compare(a.MaterialID[:], b.MaterialID[:])
	})
	b := []byte("ENKV/administrative-preserved-current/v1\x00")
	b = binary.BigEndian.AppendUint16(b, contract.CanonicalSchema)
	b = append(b, root.Domain[:]...)
	cleared := make(map[contract.ID]bool, len(pointerClears))
	for i, ref := range root.ValueEntryPages {
		page := pages[i]
		if ref == nil {
			if page != nil {
				return contract.DigestLength{}, contract.ErrRecord
			}
			b = append(b, 0)
			continue
		}
		if page == nil || page.Domain != root.Domain || page.Index != uint16(i) || page.Object != ref.Object {
			return contract.DigestLength{}, contract.ErrRecord
		}
		body, err := format.EncodeValueEntryPage(*page)
		if err != nil {
			return contract.DigestLength{}, err
		}
		actual, err := format.Reference(format.ValueEntryPageKind, page.Domain, page.Object, page.Index, body)
		if err != nil || actual != *ref {
			return contract.DigestLength{}, contract.ErrRecord
		}
		b = append(b, 1)
		for _, entry := range page.Slots {
			if entry == nil {
				b = append(b, 0)
				continue
			}
			b = append(b, 1)
			entryCopy := *entry
			if duty, ok := pointerClears[entryCopy.ValueState]; ok {
				if entryCopy.ValueSource != contract.Generated || entryCopy.Generated.RetiringDutyPresent != 1 ||
					entryCopy.Generated.RetiringDutyID != duty || cleared[entryCopy.ValueState] {
					return contract.DigestLength{}, contract.ErrRecord
				}
				entryCopy.Generated.RetiringDutyPresent, entryCopy.Generated.RetiringDutyID = 0, contract.ID{}
				cleared[entryCopy.ValueState] = true
			}
			encoded, err := contract.AppendValueEntry(nil, entryCopy)
			if err != nil {
				return contract.DigestLength{}, err
			}
			b = binary.BigEndian.AppendUint32(b, uint32(len(encoded)))
			b = append(b, encoded...)
		}
	}
	if len(cleared) != len(pointerClears) {
		return contract.DigestLength{}, contract.ErrRecord
	}
	for _, ref := range root.Recipients {
		if ref == nil {
			b = append(b, 0)
			continue
		}
		b = append(b, 1)
		b, err = contract.AppendRef(b, *ref, format.Version)
		if err != nil {
			return contract.DigestLength{}, err
		}
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(access)))
	b = append(b, access...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(rows)))
	for _, row := range rows {
		body, err := contract.EncodeAccessRecord(row)
		if err != nil {
			return contract.DigestLength{}, err
		}
		b = binary.BigEndian.AppendUint32(b, uint32(len(body)))
		b = append(b, body...)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(root.Names)))
	for _, name := range root.Names {
		b = binary.BigEndian.AppendUint16(b, name.Slot)
		b = binary.BigEndian.AppendUint16(b, uint16(len(name.Name)))
		b = append(b, name.Name...)
	}
	b = binary.BigEndian.AppendUint32(b, root.ValueEntryCount)
	b = binary.BigEndian.AppendUint32(b, root.SecretCount)
	b = binary.BigEndian.AppendUint64(b, root.RawBytes)
	b = binary.BigEndian.AppendUint32(b, root.MembershipCount)
	b = binary.BigEndian.AppendUint32(b, root.SecretOrdinaryWrapCount)
	b = binary.BigEndian.AppendUint16(b, root.RecipientCount)
	return contract.DigestLength{Digest: contract.Hash(b), Length: uint64(len(b))}, nil
}
