package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// This is one ordinary two-generation lifecycle with a maximum-sized intent
// item. It does not claim maximum aggregate selected closure or heap capacity.
// full_only: false
func TestReconstructionProjectionCopiesCurrentAndRetainedIntent(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, t.Context(), env, nil, false)
	basis := f.session.admission.publicBasis()
	profile := defaultGeneratedFixtureProfile()
	oldBytes := hermeticSizedGeneratorIntent("projection old intent", 0x41, contract.GeneratorIntentMaxLength)
	newBytes := hermeticSizedGeneratorIntent("projection new intent", 0x42, contract.GeneratorIntentMaxLength)
	first := selectPrivateGeneratedOperation(t, env, f.session, generatedPlanInputForGenerationsIntent(t, f.session, fixtureID(env.Domain, "projection intent first"), []string{"generated"}, oldBytes, profile), "projection intent first")
	old := *first.valueEntry(0)
	operation := fixtureID(env.Domain, "projection intent rotate")
	bound := generatedReservationInputForMembershipStateIntent(t, first, operation, []contract.ID{first.admission.recipient}, []string{old.Name}, newBytes, profile, old.Generated.Epoch+1, map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old})
	input := generatedPlanInputForGenerationsIntent(t, first, operation, []string{old.Name}, newBytes, profile)
	input.graph, input.declaration, input.registry, input.recoveryPolicy, input.requestBindings = bound.graph, bound.declaration, bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID, bound.requestBindings
	selected := selectPrivateGeneratedOperation(t, env, first, input, "projection intent rotate")
	current := selected.valueEntry(0)
	if current == nil || current.Generated.IntentDigest == old.Generated.IntentDigest || current.Generated.RetiringDutyID.IsZero() {
		t.Fatal("fixture lacks distinct current and retained generations")
	}
	store := env.Store.(*memoryStore)
	projection := reconstructProjectionFixture(t, env, selected, store)
	if err := projection.CheckPublicBasis(t.Context(), basis); err != nil {
		t.Fatal("separately retained original trust refused", err)
	}
	assertReconstructionProjectionExact(t, projection, selected, store)
	for i := 0; i < projection.PartCount(); i++ {
		info, ok := projection.PartInfo(i)
		part, copied := projection.CopyPart(i)
		if !ok || !copied || info.Kind != part.Kind || info.Ref != part.Ref || info.PhysicalOrdinal != part.PhysicalOrdinal || info.SupportKind != part.SupportKind || info.RecordID != part.RecordID || info.BodyLength != uint32(len(part.Body)) {
			t.Fatal("metadata-only part inventory differs")
		}
	}
	for _, row := range []struct {
		name   string
		digest contract.ID
		want   []byte
	}{{"current", current.Generated.IntentDigest, newBytes}, {"retained", old.Generated.IntentDigest, oldBytes}} {
		t.Run(row.name, func(t *testing.T) {
			got, err := projection.CopyGeneratedIntent(t.Context(), row.digest)
			if err != nil || !bytes.Equal(got, row.want) {
				t.Fatal("complete selected intent differs", err)
			}
			got[0] ^= 0xff
			again, err := projection.CopyGeneratedIntent(t.Context(), row.digest)
			if err != nil || !bytes.Equal(again, row.want) {
				t.Fatal("returned intent shares projection backing", err)
			}
		})
	}
	if kinds := reconstructionSupportKinds(t, projection); kinds[contract.GeneratedDutySupportKind] != 1 || kinds[contract.GeneratedCreateEvidenceSupportKind] != 2 {
		t.Fatal("intent copying lost retained lifecycle owners")
	}
	assertReconstructionProjectionExact(t, projection, selected, store)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := projection.CopyGeneratedIntent(cancelled, current.Generated.IntentDigest); err == nil {
		t.Fatal("cancelled extraction accepted")
	}
	if _, err := projection.CopyGeneratedIntent(t.Context(), contract.Hash([]byte("absent public intent"))); err == nil {
		t.Fatal("absent selected intent accepted")
	}
	retained, err := projection.CopyGeneratedIntent(t.Context(), old.Generated.IntentDigest)
	if err != nil {
		t.Fatal(err)
	}
	projection.Close()
	if !bytes.Equal(retained, oldBytes) {
		t.Fatal("caller-owned intent lost after projection close")
	}
	if _, ok := projection.PartInfo(0); ok {
		t.Fatal("closed metadata inventory remained available")
	}
	if _, err := projection.CopyGeneratedIntent(t.Context(), old.Generated.IntentDigest); err == nil {
		t.Fatal("closed projection intent accepted")
	}
}
