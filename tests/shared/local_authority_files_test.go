package core

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestFixtureAdmissionKeepsExplicitProductionComposition(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, false)
	defer keys.RetireGenerated()
	legacy := fixtureAdmission(env)
	production := contract.Hash([]byte("enkv/composition/full/v1"))
	env.Composition = production
	admitted := fixtureAdmission(env)
	if legacy.admission == nil || admitted.admission == nil ||
		legacy.admission.composition != fixtureID(env.Domain, "composition") ||
		admitted.admission.composition != production || admitted.admission.composition == legacy.admission.composition {
		t.Fatal("explicit production composition changed ordinary fixture admission")
	}
}
