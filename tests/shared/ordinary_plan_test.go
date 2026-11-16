package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestOrdinaryPlanRejectsRecipientAndSupportPagesBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(contract.ID, *transitionPlan)
	}{
		{"empty-recipient-slot", func(id contract.ID, p *transitionPlan) { p.recipientPages[1] = id }},
		{"occupied-recipient-slot", func(id contract.ID, p *transitionPlan) { p.recipientPages[0] = id }},
		{"support-page", func(id contract.ID, p *transitionPlan) { p.supportPages[0] = id }},
		{"last-support-page", func(id contract.ID, p *transitionPlan) { p.supportPages[255] = id }},
		{"recipient-and-support-pages", func(id contract.ID, p *transitionPlan) {
			p.recipientPages[1] = id
			p.supportPages[0] = fixtureID(id, "support")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			env, _ := genesisEnvironment(t, contract.GCP, false)
			f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
			input := f.session.currentEntryInputs()
			input[0].InputBytes = []byte("ordinary changed value")
			comparison, result := f.session.Compare(ctx, input, admitSuppliedComparison(t, f.session, nil, input))
			if comparison == nil || result.Outcome != ObservedCurrent {
				t.Fatal("ordinary comparison fixture", result)
			}
			plan, err := planTransition(t.Context(), comparison)
			if err != nil {
				t.Fatal("ordinary plan fixture")
			}
			next, err := f.session.deriveSuccessor(t.Context(), comparison, plan)
			if err != nil {
				t.Fatal("ordinary successor fixture")
			}
			tc.change(fixtureID(env.Domain, "foreign "+tc.name), &plan)
			authority, err := f.session.authorityFrom(next, comparison, plan)
			if err != nil {
				t.Fatal("ordinary authority", err)
			}
			permit := &AdmittedParentTransition{session: f.session, comparison: comparison, predecessorDigest: contract.Hash(f.session.body), predecessorRevision: f.session.head.Core.Revision, predecessorToken: f.session.token, plan: plan, authority: authority}
			store := env.Store.(*memoryStore)
			trust := env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			before := contract.Hash(f.session.body)
			candidate, result := f.session.Prepare(ctx, comparison, permit, env.Trust)
			if candidate != nil || result != refused(AdmissionInvalid) {
				t.Fatal("foreign ordinary page plan accepted", result)
			}
			if store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatal("foreign ordinary page plan crossed an effect boundary")
			}
			opened, result := Open(ctx, f.admission, env.Store)
			if opened == nil || result.Outcome != ObservedCurrent || contract.Hash(opened.body) != before {
				t.Fatal("foreign ordinary page plan changed selected state", result)
			}
		})
	}
}

// full_only: false
func TestOrdinaryPlanWithoutRecipientOrSupportPagesRemainsValid(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.AWS, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	input := f.session.currentEntryInputs()
	input[0].InputBytes = []byte("valid ordinary changed value")
	comparison, result := f.session.Compare(ctx, input, admitSuppliedComparison(t, f.session, nil, input))
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("ordinary comparison fixture", result)
	}
	permit := admit(t, f.session, comparison)
	for _, id := range permit.plan.recipientPages {
		if !id.IsZero() {
			t.Fatal("ordinary plan allocated a recipient page")
		}
	}
	for _, id := range permit.plan.supportPages {
		if !id.IsZero() {
			t.Fatal("ordinary plan allocated a support page")
		}
	}
	if candidate, result := f.session.Prepare(ctx, comparison, permit, env.Trust); candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("valid ordinary page plan refused", result)
	}
}
