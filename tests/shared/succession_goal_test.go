package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

func currentAuthorityGoal(s *StateSession, roles, approval uint8) authorityGoal {
	control := currentControlOf(s)
	g := authorityGoal{
		Domain: s.admission.domain, Store: s.admission.store.Identity, Coordinate: s.admission.store.Coordinate,
		NonBody: s.admission.store.NonBody, Trust: s.admission.trust, Interpretation: s.admission.interpretation,
		ApprovalRole: approval, Roles: roles,
	}
	if roles&1 != 0 {
		b := control.NormalSigning
		g.Signing = &signingGoal{Provider: b.Provider, Profile: b.SigningProfile, KeySelector: b.KeySelector,
			SPKI: b.SPKI, Fingerprint: b.Fingerprint, PublicKey: b.Binding.PublicKey, Trust: b.Binding.Trust}
	}
	if roles&2 != 0 {
		b := control.AuthorityKMSBinding
		g.KMS = &kmsGoal{Provider: b.Provider, WrapProfile: b.WrapProfile, ProtectionClass: b.ProtectionClass,
			KeySelector: b.KeySelector, SPKI: b.SPKI, Fingerprint: b.Fingerprint}
	}
	return g
}

// full_only: false
func TestFreshAuthorityGoalComparesCompleteCurrentBindingsBeforeMutation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "recovery"}[enabled], func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, contract.GCP, enabled)
			defer keys.RetireGenerated()
			fixture := newEnvironmentFixture(t, ctx, env, []int{1}, false)
			fresh, result := Open(ctx, fixture.admission, env.Store)
			if fresh == nil || result.Outcome != ObservedCurrent {
				t.Fatal("fresh authority state", result)
			}
			store := env.Store.(*memoryStore)
			creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).signs
			public, private := keys.Calls()
			approval := contract.NormalSigningRole
			if enabled {
				approval = contract.RecoverySigningRole
			}
			for _, roles := range []uint8{1, 2, 3} {
				goal := currentAuthorityGoal(fresh, roles, approval)
				permit := &admittedAuthorityGoal{session: fresh, goal: goal, deadline: time.Now().Add(time.Minute)}
				if changed, result := fresh.compareAuthorityGoal(ctx, permit); changed != 0 || result.Outcome != Unchanged || result.Evidence != AuthenticatedClosure {
					t.Fatal("complete current goal did not return no change", changed, result)
				}
				if roles&1 != 0 {
					goal.Signing.Profile++
					permit.goal = goal
					if changed, result := fresh.compareAuthorityGoal(ctx, permit); changed != 1 || result.Outcome != ObservedCurrent {
						t.Fatal("same selector hid changed signing profile", changed, result)
					}
				}
				if roles&2 != 0 {
					goal = currentAuthorityGoal(fresh, roles, approval)
					goal.KMS.ProtectionClass++
					permit.goal = goal
					if changed, result := fresh.compareAuthorityGoal(ctx, permit); changed != 2 || result.Outcome != ObservedCurrent {
						t.Fatal("same selector hid changed protection class", changed, result)
					}
				}
			}
			wrong := currentAuthorityGoal(fresh, 3, approval)
			wrong.Domain = contract.Hash([]byte("other domain"))
			if changed, result := fresh.compareAuthorityGoal(ctx, &admittedAuthorityGoal{session: fresh, goal: wrong, deadline: time.Now().Add(time.Minute)}); changed != 0 || result != refused(AdmissionInvalid) {
				t.Fatal("wrong domain basis admitted current equality", changed, result)
			}
			if !enabled {
				wrong = currentAuthorityGoal(fresh, 3, contract.RecoverySigningRole)
				if changed, result := fresh.compareAuthorityGoal(ctx, &admittedAuthorityGoal{session: fresh, goal: wrong, deadline: time.Now().Add(time.Minute)}); changed != 0 || result != refused(AdmissionInvalid) {
					t.Fatal("disabled recovery authority admitted", changed, result)
				}
			}
			gotPublic, gotPrivate := keys.Calls()
			if store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).signs != signs || gotPublic != public || gotPrivate != private {
				t.Fatal("goal comparison caused mutation, signing or private access")
			}
		})
	}
}

// full_only: false
func TestFreshAuthorityGoalNeedsNoRetiredPrivateRoute(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	candidate := prepareSelectionSigner(t, f.session, env, keys)
	admission := deliverSuccessionBasis(t, candidate)
	if result := f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("successor selection", result)
	}
	env.Trust.(*fixtureTrust).SetUnavailable(true)
	keys.SetUnavailable(true)
	fresh, result := Open(ctx, admission, env.Store)
	if fresh == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh public successor admission", result)
	}
	goal := currentAuthorityGoal(fresh, 3, contract.NormalSigningRole)
	beforeCreates, beforeCAS := env.Store.(*memoryStore).creates, env.Store.(*memoryStore).cas
	changed, result := fresh.compareAuthorityGoal(ctx, &admittedAuthorityGoal{session: fresh, goal: goal, deadline: time.Now().Add(time.Minute)})
	if changed != 0 || result.Outcome != Unchanged || env.Store.(*memoryStore).creates != beforeCreates || env.Store.(*memoryStore).cas != beforeCAS {
		t.Fatal("current binding equality depended on retired private route", changed, result)
	}
}

// full_only: false
func TestPrepareSuccessionObservesCompleteCurrentGoalWithoutEffects(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	defer keys.RetireGenerated()
	fixture := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	fresh, result := Open(ctx, fixture.admission, env.Store)
	if fresh == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh current state", result)
	}
	goal := currentAuthorityGoal(fresh, 3, contract.RecoverySigningRole)
	deadline := time.Now().Add(time.Minute)
	permit := &AdmittedSuccession{session: fresh, deadline: deadline,
		goal: &admittedAuthorityGoal{session: fresh, goal: goal, deadline: deadline}}
	store := env.Store.(*memoryStore)
	creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).signs
	public, private := keys.Calls()
	candidate, result := fresh.PrepareSuccession(ctx, permit, SuccessionSigners{})
	if candidate != nil || result.Outcome != Unchanged || result.Evidence != AuthenticatedClosure || !permit.used || store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).signs != signs {
		t.Fatal("current goal did not return receipt-free no-op before effects", result)
	}
	gotPublic, gotPrivate := keys.Calls()
	if gotPublic != public || gotPrivate != private {
		t.Fatal("no-op accessed private replacement route")
	}
}

// full_only: false
func TestFreshPartialAuthorityGoalUsesOnlyChangedRole(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	defer keys.RetireGenerated()
	fixture := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	fresh, result := Open(ctx, fixture.admission, env.Store)
	if fresh == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh current state", result)
	}
	before := currentControlOf(fresh)
	after := before
	successor, binding := env.Trust.(*fixtureTrust).Successor(t, before.NormalSigning)
	after.NormalSigning, after.AccessGeneration = binding, after.AccessGeneration+1
	permit := admitAuthorityReplacement(t, fresh, keys, after, 1, 1, 1, contract.BindingTableRow{})
	goal := currentAuthorityGoal(fresh, 3, contract.NormalSigningRole)
	goal.Signing = &signingGoal{Provider: binding.Provider, Profile: binding.SigningProfile, KeySelector: binding.KeySelector,
		SPKI: binding.SPKI, Fingerprint: binding.Fingerprint, PublicKey: binding.Binding.PublicKey, Trust: binding.Binding.Trust}
	permit.goal = &admittedAuthorityGoal{session: fresh, goal: goal, deadline: permit.deadline}
	if changed, observation := fresh.compareAuthorityGoal(ctx, permit.goal); changed != 1 || observation.Outcome != ObservedCurrent {
		t.Fatal("partial goal did not preserve current KEK", changed, observation)
	}
	candidate, result := fresh.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: env.Trust, NormalSuccessor: successor})
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh changed signer was not prepared", result)
	}
	if candidate.succession == nil || candidate.succession.basis == nil {
		t.Fatal("fresh candidate has no qualified successor basis")
	}
	selectedControl, err := contract.DecodeControlCore(candidate.succession.basis.control)
	if err != nil || !kmsGoalMatches(*goal.KMS, selectedControl.AuthorityKMSBinding, contract.GCP) || selectedControl.AuthorityKMSBinding.BindingID != before.AuthorityKMSBinding.BindingID {
		t.Fatal("partial signer change replaced the equal KEK")
	}
}
