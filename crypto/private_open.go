package crypto

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// privatePacketKeys borrows keys from the provider packet. The caller keeps
// packet ownership and checks its operation context before consuming them.
func privatePacketKeys(private PrivateResult, kind uint16, packetContext contract.ID, authenticationFailure contract.CryptoResultCode) ([]byte, contract.CryptoResultCode) {
	if private.Status != KeyOK {
		if private.Status == KeyAuthenticationFailed {
			return nil, authenticationFailure
		}
		return nil, keyResultCode(private.Status)
	}
	if private.Uses != (KeyUses{Completed: 1}) {
		return nil, contract.CryptoResponseUnknown
	}
	keys, err := custody.PacketKeys(private.Packet, kind, packetContext)
	if err != nil {
		return nil, authenticationFailure
	}
	return keys, contract.CryptoSuccess
}

// openPrivateKeys returns an independent key owner. The provider's entire
// returned packet capacity is cleared, including rejected and late replies.
func openPrivateKeys(ctx context.Context, route KeyDecryptor, binding contract.BindingTableRow, ciphertext []byte, length, kind uint16, packetContext contract.ID, failure contract.CryptoResultCode) ([]byte, KeyUses, contract.CryptoResultCode) {
	if ctx.Err() != nil {
		return nil, KeyUses{}, contract.CryptoCancelled
	}
	private := route.Decrypt(ctx, binding.Binding, ciphertext, length)
	if private.Packet != nil {
		defer clear(private.Packet[:cap(private.Packet)])
	}
	var evidence contract.CryptoResponse
	if !appendKeyUses(&evidence, binding, contract.KeyUseMaterialOpen, private.Uses, 1) {
		return nil, private.Uses, contract.CryptoResponseUnknown
	}
	if ctx.Err() != nil {
		return nil, private.Uses, contract.CryptoCancelled
	}
	keys, code := privatePacketKeys(private, kind, packetContext, failure)
	if code != contract.CryptoSuccess {
		return nil, private.Uses, code
	}
	return bytes.Clone(keys), private.Uses, contract.CryptoSuccess
}

// authenticatedCurrentKeys proves both AEAD and the keyed semantic commitment
// before returning keys for comparison. Plaintext never leaves this helper.
func authenticatedCurrentKeys(ctx context.Context, route KeyDecryptor, authority contract.BindingTableRow, ciphertext []byte, packetContext contract.ID, core contract.ValueCore, payload contract.CanonicalPayload) ([]byte, KeyUses, contract.CryptoResultCode) {
	keys, uses, code := openPrivateKeys(ctx, route, authority, ciphertext, contract.ValueMaterialPacketLength, 1, packetContext, contract.CryptoStoredAuthenticationFailed)
	if code != contract.CryptoSuccess {
		return nil, uses, code
	}
	plain, err := custody.OpenValue(core, payload, keys)
	if plain != nil {
		clear(plain[:cap(plain)])
	}
	if err != nil {
		clear(keys[:cap(keys)])
		return nil, uses, contract.CryptoStoredAuthenticationFailed
	}
	if ctx.Err() != nil {
		clear(keys[:cap(keys)])
		return nil, uses, contract.CryptoCancelled
	}
	return keys, uses, contract.CryptoSuccess
}

// authenticatedSealedValue returns one bounded plaintext owner to its private
// caller, which must clear the complete capacity after its last use.
func authenticatedSealedValue(ctx context.Context, route KeyDecryptor, authority contract.BindingTableRow, core contract.SealedInputCore, envelope contract.SealedInputEnvelope) ([]byte, KeyUses, contract.CryptoResultCode) {
	wrap, err := custody.SealedInputWrapCore(core, authority)
	if err != nil {
		return nil, KeyUses{}, contract.CryptoSourceAuthenticationFailed
	}
	digest, err := contract.RSAPacketContextDigest(wrap)
	if err != nil {
		return nil, KeyUses{}, contract.CryptoSourceAuthenticationFailed
	}
	keys, uses, code := openPrivateKeys(ctx, route, authority, envelope.AuthorityWrap.RSACiphertext, contract.SingleKeyMaterialPacketLength, 2, digest, contract.CryptoSourceAuthenticationFailed)
	if keys != nil {
		defer clear(keys[:cap(keys)])
	}
	if code != contract.CryptoSuccess {
		return nil, uses, code
	}
	plain, err := custody.OpenSealedInput(core, envelope, keys)
	if err != nil {
		return nil, uses, contract.CryptoSourceAuthenticationFailed
	}
	if ctx.Err() != nil {
		clear(plain[:cap(plain)])
		return nil, uses, contract.CryptoCancelled
	}
	return plain, uses, contract.CryptoSuccess
}
