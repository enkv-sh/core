package trust

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestProviderIdentityKeepsChosenSigningResource(t *testing.T) {
	material, identity := contract.Hash([]byte("independent material")), contract.Hash([]byte("provider identity"))
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, role := range []uint8{contract.NormalSigningRole, contract.RecoverySigningRole} {
			chosen := newSigner(t, family, material, role)
			bound := NewWithIdentity(t, family, material, identity, role)
			if bound.Identity() != identity || !bytes.Equal(chosen.PublicKey(), bound.PublicKey()) || chosen.KeySelector() != bound.KeySelector() || bound.Calls() != 0 || bound.QualificationCalls() != 0 {
				t.Fatal("provider identity changed immutable resource")
			}
		}
	}
}
