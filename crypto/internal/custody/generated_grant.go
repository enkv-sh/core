package custody

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"enkv.sh/core/contract"
)

// These fields are fixed for the saved preparation, including the recipient
// binding under which the RSA wrap was issued. They are not the next HEAD.
type GeneratedGrantContext struct {
	Domain, Operation, OperationMaterial, Phase, Control, Material, MaterialContext contract.ID
	Slot, Index                                                                     uint16
}

func (c GeneratedGrantContext) key(seed []byte, envelope contract.ID, w contract.WrapRow) ([]byte, []byte, error) {
	if len(seed) != 32 || envelope.IsZero() || c.OperationMaterial.IsZero() || c.Domain.IsZero() || c.Operation.IsZero() || c.Phase.IsZero() || c.Control.IsZero() || c.Material.IsZero() || c.MaterialContext.IsZero() ||
		w.SubjectKind != contract.OrdinaryWrapSubject || w.SubjectID.IsZero() || w.BindingID.IsZero() || w.PublicBindingDigest.IsZero() || w.BindingSerial == 0 || len(w.RSACiphertext) != contract.RSACiphertextLength {
		return nil, nil, ErrPayload
	}
	aad := []byte("ENKV/CRYPTO/v2/generated-checkpoint-grant/v1\x00")
	for _, id := range [...]contract.ID{c.Domain, c.Operation, c.OperationMaterial, c.Phase, c.Control, c.Material, c.MaterialContext, envelope} {
		aad = append(aad, id[:]...)
	}
	aad = binary.BigEndian.AppendUint16(aad, c.Slot)
	aad = binary.BigEndian.AppendUint16(aad, c.Index)
	aad = append(aad, w.SubjectKind)
	aad = append(aad, w.SubjectID[:]...)
	aad = append(aad, w.BindingID[:]...)
	aad = binary.BigEndian.AppendUint64(aad, w.BindingSerial)
	aad = append(aad, w.PublicBindingDigest[:]...)
	key, err := hkdf.Key(sha256.New, seed, []byte("ENKV/CRYPTO/v2/generated-checkpoint-grant-key/v1\x00"), string(aad), 32)
	return key, aad, err
}

func SealGeneratedGrant(c GeneratedGrantContext, seed []byte, w contract.WrapRow) (contract.GeneratedGrantSeal, []byte, error) {
	var envelope contract.ID
	if _, err := rand.Read(envelope[:]); err != nil {
		return contract.GeneratedGrantSeal{}, nil, err
	}
	key, aad, err := c.key(seed, envelope, w)
	if err != nil {
		return contract.GeneratedGrantSeal{}, nil, err
	}
	defer clear(key)
	nonce, ciphertext, err := sealPayload(key, w.RSACiphertext, aad)
	if err != nil {
		return contract.GeneratedGrantSeal{}, nil, err
	}
	seal := contract.GeneratedGrantSeal{Slot: c.Slot, Wrap: c.Index, EnvelopeID: envelope, Nonce: nonce, Tag: [16]byte(ciphertext[contract.RSACiphertextLength:])}
	return seal, ciphertext[:contract.RSACiphertextLength:contract.RSACiphertextLength], nil
}

func OpenGeneratedGrant(c GeneratedGrantContext, seed []byte, w contract.WrapRow, seal contract.GeneratedGrantSeal) ([]byte, error) {
	if c.Slot != seal.Slot || c.Index != seal.Wrap {
		return nil, ErrPayload
	}
	key, aad, err := c.key(seed, seal.EnvelopeID, w)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	ciphertext := make([]byte, 0, contract.RSACiphertextLength+len(seal.Tag))
	ciphertext = append(ciphertext, w.RSACiphertext...)
	ciphertext = append(ciphertext, seal.Tag[:]...)
	return openPayload(key, seal.Nonce, ciphertext, aad)
}
