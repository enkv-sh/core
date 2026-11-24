package format

import (
	"testing"

	"enkv.sh/core/contract"
)

func recipientRetirementIdentityFixture(t testing.TB, fresh bool) SuppliedApplyIdentityPlan {
	t.Helper()
	p := secretAccessIdentityFixture(t, contract.OperationRetireRecipientIdentity)
	p.Request.Intent.Length = 1008
	p.Authorization.Normal.Intent = p.Request.Intent
	p.Authorization.Exclusion.Retirements.Count, p.Authorization.Exclusion.Retirements.Length = 1, 136
	page := p.Snapshot.Recipients[0]
	recipient := contract.IdentityPage{Kind: RecipientKind, Index: page.Index, Object: page.Object}
	if fresh {
		p.Identity.Pages = append(p.Identity.Pages[:1], append([]contract.IdentityPage{recipient}, p.Identity.Pages[1:]...)...)
		p.Authorization.BeforeMembershipCount = 2
		p.Authorization.Normal.Union.Length = 314
		p.Authorization.Exclusion.Exclusions.Count, p.Authorization.Exclusion.Exclusions.Length = 1, 207
	} else {
		p.Identity.Rows = nil
		p.Identity.Pages[0] = recipient
		p.Authorization.Normal.Changed = 0
	}
	identity, err := contract.IdentityPlanDescriptor(p.Identity)
	if err != nil {
		t.Fatal(err)
	}
	p.Request.IdentityPlan = contract.DigestLength{Digest: identity.Digest, Length: identity.Length}
	p.Authorization.IdentityPlan = p.Request.IdentityPlan
	request, err := contract.EncodeRequestCore(p.Request)
	if err != nil {
		t.Fatal(err)
	}
	p.Authorization.Request = contract.Hash(request)
	return p
}

// full_only: false
func TestRecipientRetirementIdentityMatchesIndependentLiterals(t *testing.T) {
	// Re-evaluate the existing independent supplied/replacement frames in memory:
	// explicit kind10, intent1008, before-access ID88, retirement1/136 and the
	// recipient-retirement-transition-graph-v1 label. Zero affected entries uses
	// no identity rows; one affected secret adds one before membership, union314,
	// exclusion1/207 and its value-page identity. No production codec derives literals.
	for _, tc := range []struct {
		fresh    bool
		identity string
		plan     string
	}{
		{false, "26e189c59ef18327302e937fb0da1c3368c329899704247e1f72735e2cef8a7d", "cd6b9c51fc4e016d3aa1f5d6d4947fe60943d35b71506007188a82e18856ab10"},
		{true, "fcaa425a87e81fe9a6d475afc9e7f6c98a8a8d27e97f5183b8a8bdbfa08e18b8", "63aedd8ecbe347ea73ff4c6cba5382c235d9483870d9d8d820ec72152f77dee9"},
	} {
		p := recipientRetirementIdentityFixture(t, tc.fresh)
		identity, err := DeriveRecipientRetirementIdentity(p)
		if err != nil || identity != successionLiteralID(t, tc.identity) {
			t.Fatal("retirement graph differs from independent literal", tc.fresh, identity, err)
		}
		plan, err := contract.IdentityPlanDescriptor(p.Identity)
		if err != nil || plan.Digest != successionLiteralID(t, tc.plan) {
			t.Fatal("retirement plan differs from independent literal", err)
		}
		delta, err := contract.MutationReceiptDeltaPlanDigest(p.Receipt)
		if err != nil || delta != successionLiteralID(t, "9513646f710db63255d35492d4e715996bab711bf2b68775d2cdd00e389ae52a") {
			t.Fatal("retirement receipt delta differs from independent literal", err)
		}
		for _, derive := range []func(SuppliedApplyIdentityPlan) (ID, error){DeriveSuppliedApplyIdentity, DeriveEnvelopeRekeyIdentity} {
			if _, err := derive(p); err == nil {
				t.Fatal("another operation family admitted retirement")
			}
		}
		if _, err := DeriveRecipientReplacementIdentity(RecipientReplacementIdentityPlan(p)); err == nil {
			t.Fatal("key replacement admitted retirement")
		}
	}
}

// full_only: false
func TestRecipientRetirementIdentityRejectsFamilyAndPageSubstitution(t *testing.T) {
	for _, condition := range []string{"authorization kind", "delta kind", "receipt kind", "empty retirement", "no recipient page", "too many fresh values", "effect", "request intent"} {
		t.Run(condition, func(t *testing.T) {
			p := recipientRetirementIdentityFixture(t, false)
			switch condition {
			case "authorization kind":
				p.Authorization.OperationKind = contract.OperationApplyDeclaration
			case "delta kind":
				p.Receipt.OperationKind = contract.OperationApplyDeclaration
			case "receipt kind":
				p.Receipt.NewReceipt.OperationKind = contract.OperationApplyDeclaration
			case "empty retirement":
				p.Authorization.Exclusion.Retirements.Count, p.Authorization.Exclusion.Retirements.Length = 0, 66
			case "no recipient page":
				p.Identity.Pages = p.Identity.Pages[1:]
			case "too many fresh values":
				p.Identity.Rows = suppliedApplyIdentityFixture(t).Identity.Rows
			case "effect":
				p.Receipt.NewReceipt.EffectSummary = contract.ReceiptEffectNoChange
			case "request intent":
				p.Request.Intent.Digest[0]++
			}
			if _, err := DeriveRecipientRetirementIdentity(p); err == nil {
				t.Fatal("retirement identity admitted cross-part substitution")
			}
		})
	}
	for _, p := range []SuppliedApplyIdentityPlan{suppliedApplyIdentityFixture(t), secretAccessIdentityFixture(t, contract.OperationEnvelopeRekey), secretAccessIdentityFixture(t, contract.OperationRemoveSecretValueEntryAccess), SuppliedApplyIdentityPlan(recipientReplacementIdentityFixture(t))} {
		if _, err := DeriveRecipientRetirementIdentity(p); err == nil {
			t.Fatal("retirement admitted another operation family")
		}
	}
}
