package core

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestStateHistoricalBasisPermitsAuthenticatedRegistryChanges(t *testing.T) {
	for _, successor := range []bool{false, true} {
		for _, add := range []bool{false, true} {
			t.Run(fmt.Sprintf("successor=%t/add=%t", successor, add), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				env, keys := genesisEnvironment(t, contract.GCP, true)
				f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
				before := f.session
				signer := env.Trust
				if successor {
					env = syntheticAuthorityScenarioEnvironment(t, env)
					selected, _ := selectReaderSuccessionFixture(t, ctx, env, before, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole)
					reader := fixtureID(env.Domain, "reader")
					binding := keys.RecipientSuccessor(t, reader)
					permit := admitReaderReplacement(t, selected, keys, reader, binding)
					signer = testtrust.NewCurrent(t, currentControlOf(selected).NormalSigning)
					candidate, result := selected.PrepareRecipientReplacement(ctx, permit, signer)
					if candidate == nil || result.Outcome != ObservedCurrent {
						t.Fatal("ordinary successor fixture", result)
					}
					before, result = selected.selectCandidate(ctx, candidate)
					if before == nil || result.Outcome != ObservedCurrent {
						t.Fatal("ordinary successor selection", result)
					}
				}
				basis := before.admission.publicBasis()
				current := readerChangedRegistryFixture(t, ctx, env, before, signer, add)
				defer readerCapacityNoEffects(t, env)()
				admitted, result := admitPublicNormal(ctx, env.Domain, env.Store.Descriptor(), basis, env.Store, before.admission.composition, nil)
				if result.Outcome != ObservedCurrent {
					t.Fatal("independent historical basis failed normal admission", result)
				}
				selected, result := Open(ctx, admitted, env.Store)
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal("historical enrollment rejected authenticated current registry at cold state relation", result)
				}
				want := selectedRecipientRegistry(&current.recipients, current.root.RecipientCount)
				if !reflect.DeepEqual(selected.registry(), want) || selected.root.Snapshot != current.root.Snapshot || !CurrentControlMatches(currentControlOf(selected), currentControlOf(before)) {
					t.Fatal("cold state lost exact signed registry or independent current control")
				}
			})
		}
	}
}
