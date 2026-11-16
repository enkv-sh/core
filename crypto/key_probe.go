package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func probeKEK(ctx context.Context, core contract.WrapCore, binding contract.KMSBinding, route KeyAccess) (contract.CryptoResultCode, KeyUses) {
	digest, err := contract.RSAPacketContextDigest(core)
	if err != nil {
		return contract.CryptoInvalidInput, KeyUses{}
	}
	challenge := make([]byte, 32)
	defer clear(challenge)
	if _, err := rand.Read(challenge); err != nil {
		return contract.CryptoCustodyUnavailable, KeyUses{}
	}
	packet, err := custody.EncodePacket(4, digest, challenge)
	if err != nil {
		return contract.CryptoInvalidInput, KeyUses{}
	}
	defer clear(packet)
	public, err := x509.ParsePKIXPublicKey(binding.SPKI)
	if err != nil {
		return contract.CryptoInvalidInput, KeyUses{}
	}
	key, ok := public.(*rsa.PublicKey)
	if !ok {
		return contract.CryptoInvalidInput, KeyUses{}
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, packet, nil)
	if err != nil {
		return contract.CryptoCustodyUnavailable, KeyUses{}
	}
	result := route.Decrypt(ctx, binding, ciphertext, contract.SingleKeyMaterialPacketLength)
	defer clear(result.Packet[:cap(result.Packet)])
	if result.Status != KeyOK {
		return keyResultCode(result.Status), result.Uses
	}
	if result.Uses != (KeyUses{Completed: 1}) {
		return contract.CryptoResponseUnknown, result.Uses
	}
	keys, err := custody.PacketKeys(result.Packet, 4, digest)
	if err != nil || subtle.ConstantTimeCompare(keys, challenge) != 1 {
		return contract.CryptoPrivateRouteUnavailable, result.Uses
	}
	if ctx.Err() != nil {
		return contract.CryptoCancelled, result.Uses
	}
	return contract.CryptoSuccess, result.Uses
}
