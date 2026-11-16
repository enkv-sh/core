// Package crypto owns secret ingestion, encryption and private key access.
package crypto

import (
	"context"

	"enkv.sh/core/contract"
)

type KeyStatus uint8

const (
	KeyOK KeyStatus = iota + 1
	KeyDenied
	KeyInvalid
	KeyUnavailable
	KeyUnknown
	KeyCancelled
	// KeyAuthenticationFailed requires positive evidence that the exact
	// ciphertext was rejected. Route or reply validation cannot establish it.
	KeyAuthenticationFailed
)

// KeyUses counts actual provider calls by their observed result. A cancellation
// after dispatch does not establish that the provider did no work.
type KeyUses struct {
	Completed, Denied, Failed, Unknown uint32
}

// Record counts one result when at least one provider attempt entered. The
// physical attempt count remains separate; zero attempts add no key use.
func (uses *KeyUses) Record(attempts uint32, status KeyStatus) {
	if attempts == 0 {
		return
	}
	switch status {
	case KeyOK:
		uses.Completed++
	case KeyDenied:
		uses.Denied++
	case KeyInvalid, KeyAuthenticationFailed:
		uses.Failed++
	default:
		uses.Unknown++
	}
}

type KeyResult struct {
	Status KeyStatus
	Uses   KeyUses
}

// PrivateResult transfers only the final owned packet to Crypto. Provider
// responses, SDK objects and error text remain inside the provider adapter.
// The receiver clears the complete packet capacity after its last use.
type PrivateResult struct {
	Status KeyStatus
	Uses   KeyUses
	Packet []byte
}

// PublicKeyQualifier is the exact independently installed public key route.
// It grants no private use of the nominated successor.
type PublicKeyQualifier interface {
	Family() contract.Family
	CredentialRoute() contract.ID
	Qualify(context.Context, contract.KMSBinding) KeyResult
}

// KeyDecryptor is a private Crypto boundary. Each instance uses one independently
// admitted credential route and never discovers a replacement key or identity.
// Decrypt borrows the ciphertext for the call and requests the exact supported
// packet length, not arbitrary plaintext. Crypto validates the returned packet's
// purpose and context and clears its full capacity, including late or refused
// results. The operation owner supplies the bounded context and checks it again
// before consuming a successful result.
type KeyDecryptor interface {
	Family() contract.Family
	CredentialRoute() contract.ID
	Decrypt(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult
}

type KeyAccess interface {
	KeyDecryptor
	Qualify(context.Context, contract.KMSBinding) KeyResult
}
