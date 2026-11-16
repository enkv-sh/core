package custody

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"enkv.sh/core/contract"
)

func ValueWrapCore(core contract.ValueCore, recipient contract.BindingTableRow) (contract.WrapCore, error) {
	material, err := contract.ValueMaterialContextDigest(core)
	if err != nil {
		return contract.WrapCore{}, ErrPayload
	}
	binding, err := contract.PublicBindingDigest(recipient.Binding)
	if err != nil {
		return contract.WrapCore{}, ErrPayload
	}
	out := contract.WrapCore{Schema: contract.CanonicalSchema, Profile: 2, DomainID: core.DomainID, CompatibilityID: core.CompatibilityID, CryptoSupportID: core.CryptoSupportID, MaterialKind: contract.ValueMaterialKind, MaterialID: core.ValueStateID, MaterialContextDigest: material, SubjectKind: recipient.SubjectKind, SubjectID: recipient.SubjectID, BindingID: recipient.Binding.BindingID, BindingSerial: recipient.Binding.BindingSerial, PublicBindingDigest: binding, Provider: recipient.Binding.Provider, WrapProfile: 2, PacketKind: 1, PacketLength: contract.ValueMaterialPacketLength}
	if _, err := contract.WrapCoreLength(out); err != nil {
		return contract.WrapCore{}, ErrPayload
	}
	return out, nil
}

func SealedInputWrapCore(core contract.SealedInputCore, authority contract.BindingTableRow) (contract.WrapCore, error) {
	if authority.SubjectKind != contract.OrdinaryWrapSubject {
		return contract.WrapCore{}, ErrPayload
	}
	material, err := contract.SealedInputMaterialContextDigest(core)
	if err != nil {
		return contract.WrapCore{}, ErrPayload
	}
	binding, err := contract.PublicBindingDigest(authority.Binding)
	if err != nil {
		return contract.WrapCore{}, ErrPayload
	}
	out := contract.WrapCore{Schema: contract.CanonicalSchema, Profile: 2, DomainID: core.DomainID, CompatibilityID: core.CompatibilityID, CryptoSupportID: core.CryptoSupportID, MaterialKind: contract.SourceMaterialKind, MaterialID: core.SourceID, MaterialContextDigest: material, SubjectKind: authority.SubjectKind, SubjectID: authority.SubjectID, BindingID: authority.Binding.BindingID, BindingSerial: authority.Binding.BindingSerial, PublicBindingDigest: binding, Provider: authority.Binding.Provider, WrapProfile: 2, PacketKind: 2, PacketLength: contract.SingleKeyMaterialPacketLength}
	if _, err := contract.WrapCoreLength(out); err != nil {
		return contract.WrapCore{}, ErrPayload
	}
	return out, nil
}

// Wrap receives an already admitted public binding. Its packet binds the full
// exact WrapCore, including recipient/role, binding generation and material.
func Wrap(core contract.WrapCore, binding contract.KMSBinding, keys []byte) (contract.WrapRow, error) {
	if _, err := contract.WrapCoreLength(core); err != nil || len(keys) != keyLength(core.PacketKind) {
		return contract.WrapRow{}, ErrPayload
	}
	digest, err := contract.PublicBindingDigest(binding)
	if err != nil {
		return contract.WrapRow{}, ErrPayload
	}
	if core.BindingID != binding.BindingID || core.BindingSerial != binding.BindingSerial || core.Provider != binding.Provider || core.WrapProfile != binding.WrapProfile || core.PublicBindingDigest != digest {
		return contract.WrapRow{}, ErrPayload
	}
	context, err := contract.RSAPacketContextDigest(core)
	if err != nil {
		return contract.WrapRow{}, ErrPayload
	}
	public, err := x509.ParsePKIXPublicKey(binding.SPKI)
	if err != nil {
		return contract.WrapRow{}, ErrPayload
	}
	key, ok := public.(*rsa.PublicKey)
	if !ok {
		return contract.WrapRow{}, ErrPayload
	}
	packet, err := EncodePacket(core.PacketKind, context, keys)
	if err != nil {
		return contract.WrapRow{}, ErrPayload
	}
	defer clear(packet[:cap(packet)])
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, packet, nil)
	if err != nil || len(ciphertext) != contract.RSACiphertextLength {
		return contract.WrapRow{}, ErrPayload
	}
	return contract.WrapRow{SubjectKind: core.SubjectKind, SubjectID: core.SubjectID, BindingID: core.BindingID, BindingSerial: core.BindingSerial, PublicBindingDigest: core.PublicBindingDigest, RSACiphertext: ciphertext}, nil
}
