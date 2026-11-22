package contract

import (
	"cmp"
	"encoding/binary"
	"slices"
)

// The 64-byte seal identifies a protected RSA ciphertext in the otherwise
// public preparation image. Its ciphertext occupies the existing wrap slot.
const GeneratedGrantSealLength = 64
const MaxSelectedGrantRows = MaxHeadLength / (4 + WrapRowWireLength)

type GeneratedGrantSeal struct {
	Slot, Wrap uint16
	EnvelopeID ID
	Nonce      [12]byte
	Tag        [16]byte
}

func CompareGeneratedGrantSeals(a, b GeneratedGrantSeal) int {
	return cmp.Or(cmp.Compare(a.Slot, b.Slot), cmp.Compare(a.Wrap, b.Wrap))
}

func validateGeneratedGrantSeals(rows []GeneratedGrantSeal) error {
	if len(rows) > MaxSelectedGrantRows {
		return ErrRecordCapacity
	}
	for i, row := range rows {
		if row.EnvelopeID.IsZero() || row.Slot >= CryptoMaxValueEntries || int(row.Wrap) >= CryptoMaxRecipients || i > 0 && CompareGeneratedGrantSeals(rows[i-1], row) >= 0 {
			return ErrRecord
		}
	}
	return nil
}

func appendGeneratedGrantSeals(dst []byte, rows []GeneratedGrantSeal) ([]byte, error) {
	if err := validateGeneratedGrantSeals(rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		dst = binary.BigEndian.AppendUint16(dst, row.Slot)
		dst = binary.BigEndian.AppendUint16(dst, row.Wrap)
		dst = append(dst, row.EnvelopeID[:]...)
		dst = append(dst, row.Nonce[:]...)
		dst = append(dst, row.Tag[:]...)
	}
	return dst, nil
}

func readGeneratedGrantSeals(b []byte) ([]GeneratedGrantSeal, error) {
	if len(b)%GeneratedGrantSealLength != 0 || len(b)/GeneratedGrantSealLength > MaxSelectedGrantRows {
		return nil, ErrRecord
	}
	var rows []GeneratedGrantSeal
	for len(b) != 0 {
		row := GeneratedGrantSeal{Slot: binary.BigEndian.Uint16(b[:2]), Wrap: binary.BigEndian.Uint16(b[2:4]), EnvelopeID: ID(b[4:36]), Nonce: [12]byte(b[36:48]), Tag: [16]byte(b[48:64])}
		rows = append(rows, row)
		b = b[GeneratedGrantSealLength:]
	}
	if err := validateGeneratedGrantSeals(rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// VisitGrantWraps borrows wrap ciphertext spans from the owned image. A
// private caller may restore those spans only after authenticating the seal.
func (v *GeneratedFinalPreparationImage) VisitGrantWraps(visit func(GeneratedGrantSeal, ID, ID, WrapRow) error) error {
	if err := validateGeneratedGrantSeals(v.GrantSeals); err != nil {
		return err
	}
	if len(v.GrantSeals) == 0 {
		return nil
	}
	supplied := make(map[uint16]AccessRecordView, len(v.Supplied))
	for _, row := range v.Supplied {
		access, err := InspectAccessRecord(row.AccessRecord)
		if err != nil {
			return err
		}
		supplied[row.Slot] = access
	}
	for _, seal := range v.GrantSeals {
		var wrap WrapRow
		var material, context ID
		if i, ok := slices.BinarySearchFunc(v.Generated, seal.Slot, func(r CryptoGeneratedValueEntryResult, slot uint16) int { return cmp.Compare(r.Slot, slot) }); ok {
			a := v.Generated[i].Access
			if a.MaterialKind != ValueMaterialKind || int(seal.Wrap) >= len(a.Wraps) {
				return ErrRecord
			}
			wrap, material, context = a.Wraps[seal.Wrap], a.MaterialID, a.MaterialContextDigest
		} else {
			a, ok := supplied[seal.Slot]
			w, present := a.Wrap(int(seal.Wrap))
			if !ok || !present || a.MaterialKind != ValueMaterialKind {
				return ErrRecord
			}
			wrap, material, context = WrapRow(w), a.MaterialID, a.MaterialContextDigest
		}
		if wrap.SubjectKind != OrdinaryWrapSubject {
			return ErrRecord
		}
		if visit != nil {
			if err := visit(seal, material, context, wrap); err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *GeneratedFinalPreparationImage) RestoreOpenedGrants(opened []byte) error {
	if len(v.GrantSeals) > MaxSelectedGrantRows || len(opened) != len(v.GrantSeals)*RSACiphertextLength {
		return ErrRecord
	}
	return v.VisitGrantWraps(func(_ GeneratedGrantSeal, _, _ ID, w WrapRow) error {
		copy(w.RSACiphertext, opened[:RSACiphertextLength])
		opened = opened[RSACiphertextLength:]
		return nil
	})
}
