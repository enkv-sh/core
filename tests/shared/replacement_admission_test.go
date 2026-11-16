package core

import (
	"context"
	"crypto/rand"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestRecoverySignerOnlyPlanRefusesNormalAdmissionIdentity(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, true)
	s := newEnvironmentFixture(t, context.Background(), env, []int{1}, false).session
	after := currentControlOf(s)
	_, binding := env.Trust.(*fixtureTrust).Successor(t, after.NormalSigning)
	after.NormalSigning = binding
	after.AccessGeneration++
	var admission contract.ID
	if _, err := rand.Read(admission[:]); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.planSuccession(t.Context(), after, contract.SuccessionReplaceAuthority,
		contract.RecoverySigningRole, contract.SuccessionChangeNormalSigner, admission, contract.SuccessionMaterialNone); ok {
		t.Fatal("Normal reader admission issued a Recovery-authorized signer-only plan")
	}
}
