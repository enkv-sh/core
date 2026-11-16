package custody

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"enkv.sh/core/contract"
)

const retainedPurpose = "ENKV/CRYPTO/v2/"

func SeedCheck(core contract.OperationMaterialCore, seed []byte) (contract.ID, error) {
	if len(seed) != 32 {
		return contract.ID{}, ErrPayload
	}
	body, err := contract.EncodeOperationMaterialCore(core)
	if err != nil {
		return contract.ID{}, ErrPayload
	}
	return retainedCheck(body, seed, "seed-hkdf-salt", "seed-hkdf-info", "seed-check")
}

func retainedCheck(core, keys []byte, salt, info, purpose string) (contract.ID, error) {
	derived, err := hkdf.Key(sha256.New, keys, []byte(retainedPurpose+salt+"\x00"), string(valuePreimage(retainedPurpose+info+"\x00", core)), 32)
	if err != nil {
		return contract.ID{}, ErrPayload
	}
	defer clear(derived[:cap(derived)])
	h := hmac.New(sha256.New, derived)
	_, _ = h.Write(valuePreimage(retainedPurpose+purpose+"\x00", core))
	var result contract.ID
	h.Sum(result[:0])
	return result, nil
}

func SeedWrapCore(core contract.OperationMaterialCore, recipient contract.BindingTableRow) (contract.WrapCore, error) {
	material, err := contract.OperationMaterialContextDigest(core)
	if err != nil {
		return contract.WrapCore{}, ErrPayload
	}
	binding, err := contract.PublicBindingDigest(recipient.Binding)
	if err != nil {
		return contract.WrapCore{}, ErrPayload
	}
	w := contract.WrapCore{Schema: contract.CanonicalSchema, Profile: 2, DomainID: core.DomainID, CompatibilityID: core.CompatibilityID,
		CryptoSupportID: core.CryptoSupportID, MaterialKind: contract.OperationSeedMaterialKind, MaterialID: core.OperationMaterialID,
		MaterialContextDigest: material, SubjectKind: recipient.SubjectKind, SubjectID: recipient.SubjectID,
		BindingID: recipient.Binding.BindingID, BindingSerial: recipient.Binding.BindingSerial, PublicBindingDigest: binding,
		Provider: recipient.Binding.Provider, WrapProfile: 2, PacketKind: 3, PacketLength: contract.SingleKeyMaterialPacketLength}
	if _, err := contract.WrapCoreLength(w); err != nil {
		return contract.WrapCore{}, ErrPayload
	}
	return w, nil
}

func transferKey(core contract.TransferCore, seed []byte) ([]byte, []byte, error) {
	if len(seed) != 32 {
		return nil, nil, ErrPayload
	}
	body, err := contract.EncodeTransferCore(core)
	if err != nil {
		return nil, nil, ErrPayload
	}
	key, err := hkdf.Key(sha256.New, seed, []byte(retainedPurpose+"transfer-hkdf-salt\x00"), string(valuePreimage(retainedPurpose+"transfer-hkdf-info\x00", body)), 32)
	if err != nil {
		return nil, nil, ErrPayload
	}
	return key, valuePreimage(retainedPurpose+"transfer-aad\x00", body), nil
}

// SealTransfer allocates a fresh physical identity for every encryption. The
// caller retains the full returned envelope for exact immutable-write retries.
func SealTransfer(core contract.TransferCore, seed, keys []byte) (contract.TransferEnvelope, error) {
	_, _ = rand.Read(core.EnvelopeID[:])
	context, err := contract.TransferPacketContextDigest(core)
	if err != nil {
		return contract.TransferEnvelope{}, ErrPayload
	}
	packet, err := EncodePacket(core.PacketKind, context, keys)
	if err != nil {
		return contract.TransferEnvelope{}, ErrPayload
	}
	defer clear(packet[:cap(packet)])
	key, aad, err := transferKey(core, seed)
	if err != nil {
		return contract.TransferEnvelope{}, ErrPayload
	}
	defer clear(key[:cap(key)])
	nonce, ciphertext, err := sealPayload(key, packet, aad)
	if err != nil {
		return contract.TransferEnvelope{}, ErrPayload
	}
	return contract.TransferEnvelope{Core: core, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// OpenTransfer checks the complete admitted source/result context, with only
// the envelope's physical identity supplied by its stored encryption metadata.
func OpenTransfer(expected contract.TransferCore, envelope contract.TransferEnvelope, seed []byte) ([]byte, error) {
	expected.EnvelopeID = envelope.Core.EnvelopeID
	if expected != envelope.Core {
		return nil, ErrPayload
	}
	if _, err := contract.TransferEnvelopeLength(envelope); err != nil {
		return nil, ErrPayload
	}
	key, aad, err := transferKey(expected, seed)
	if err != nil {
		return nil, ErrPayload
	}
	defer clear(key[:cap(key)])
	packet, err := openPayload(key, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, ErrPayload
	}
	defer clear(packet[:cap(packet)])
	context, err := contract.TransferPacketContextDigest(expected)
	if err != nil {
		return nil, ErrPayload
	}
	keys, err := PacketKeys(packet, expected.PacketKind, context)
	if err != nil {
		return nil, ErrPayload
	}
	owned := make([]byte, len(keys))
	copy(owned, keys)
	return owned, nil
}

func retainedTransfer(core contract.OperationMaterialCore) contract.TransferCore {
	return contract.TransferCore{Schema: 2, Profile: core.Profile, CompatibilityID: core.CompatibilityID,
		CryptoSupportID: core.CryptoSupportID, DomainID: core.DomainID, OperationID: core.OperationID,
		OperationMaterialID: core.OperationMaterialID, UsePlanDigest: core.UsePlanDigest}
}

func resultSemantic(core, plaintext, key []byte) contract.ID {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(valuePreimage(retainedPurpose+"result-semantic\x00", core))
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(plaintext)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(plaintext)
	var result contract.ID
	h.Sum(result[:0])
	return result
}
