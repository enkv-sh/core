package format

import (
	"encoding/json"
	"os"
	"testing"

	"enkv.sh/core/contract"
)

func secretAccessIdentityFixture(t testing.TB, kind uint16) SuppliedApplyIdentityPlan {
	t.Helper()
	p := suppliedApplyIdentityFixture(t)
	p.Authorization.OperationKind, p.Receipt.OperationKind, p.Receipt.NewReceipt.OperationKind = kind, kind, kind
	p.Authorization.BeforeAccessRoot = fid(88)
	p.Request.Intent.Length = 1041
	if kind == contract.OperationRemoveSecretValueEntryAccess {
		p.Request.Intent.Length = 1075
		p.Authorization.BeforeMembershipCount = 2
		p.Authorization.Normal.Union.Length = 314
		p.Authorization.Exclusion.Exclusions.Count, p.Authorization.Exclusion.Exclusions.Length = 1, 207
	}
	p.Authorization.Normal.Intent = p.Request.Intent
	request, err := contract.EncodeRequestCore(p.Request)
	if err != nil {
		t.Fatal(err)
	}
	p.Authorization.Request = contract.Hash(request)
	receipt, err := contract.AppendCompactMutationReceiptPlan(nil, p.Receipt.NewReceipt)
	if err != nil {
		t.Fatal(err)
	}
	page, err := EncodeRequiredSupportReceiptPlan(RequiredSupportPage{Domain: fid(1), Object: fid(106), Index: 1,
		Records: []contract.SupportRecord{{Kind: contract.MutationReceiptSupportKind, RecordID: fid(20), Body: receipt}}}, p.Receipt.NewReceipt)
	if err != nil {
		t.Fatal(err)
	}
	p.Snapshot.RequiredSupport[1].Digest = contract.Hash(page)
	raw, err := os.ReadFile("../../tests/shared/testdata/stored-closure-v11.json")
	var vectors storedClosureVectors
	if err != nil || json.Unmarshal(raw, &vectors) != nil {
		t.Fatal("independent source literal unavailable", err)
	}
	output, err := InspectRequiredSupportPage(vectors.OutputConfigurationPage.bytes(t))
	if err != nil || len(output.Records) != 1 {
		t.Fatal("independent output literal unavailable", err)
	}
	outputRow := contract.SupportRecord(output.Records[0])
	outputFact, err := contract.InspectSupportRecordDigest(fid(1), outputRow)
	if err != nil {
		t.Fatal(err)
	}
	p.PublicState.RequiredSupport, err = contract.RequiredSupportReceiptPlanDescriptor(fid(1), []contract.SupportRecord{
		{Kind: contract.MutationReceiptSupportKind, RecordID: fid(20), Body: receipt}, outputRow}, []contract.SupportRecordDigest{{}, outputFact}, p.Receipt.NewReceipt)
	if err != nil {
		t.Fatal(err)
	}
	public, err := contract.PublicStateDescriptor(p.PublicState)
	if err != nil {
		t.Fatal(err)
	}
	p.Authorization.Normal.PublicState = contract.DigestLength{Digest: public.Digest, Length: public.Length}
	return p
}

// full_only: false
func TestSecretAccessIdentityMatchesIndependentLiterals(t *testing.T) {
	// Re-evaluate the independent supplied identity frame with the explicit kind,
	// before-access ID88, typed intent length1041 and the envelope-rekey
	// graph label. Every receipt/support/request hash is rederived.
	for _, tc := range []struct {
		kind     uint16
		derive   func(SuppliedApplyIdentityPlan) (ID, error)
		identity string
		delta    string
	}{
		{contract.OperationEnvelopeRekey, DeriveEnvelopeRekeyIdentity, "c1382e08603bf5e239c37dc5d10f78ba0c3c4fe18b9cda9f756f2a173189dac8", "a260508fd03fafafd836061beefe80f3023b557edf7f467e783260f5de25c471"},
	} {
		p := secretAccessIdentityFixture(t, tc.kind)
		got, err := tc.derive(p)
		if err != nil || got != successionLiteralID(t, tc.identity) {
			t.Fatal("standalone identity differs from independent fixed frame", tc.kind, got, err)
		}
		delta, err := contract.MutationReceiptDeltaPlanDigest(p.Receipt)
		if err != nil || delta != successionLiteralID(t, tc.delta) {
			t.Fatal("standalone receipt delta differs from independent fixed frame", tc.kind, err)
		}
		if _, err := DeriveSuppliedApplyIdentity(p); err == nil {
			t.Fatal("ordinary Apply accepted a standalone family")
		}
		if _, err := DeriveRecipientReplacementIdentity(RecipientReplacementIdentityPlan(p)); err == nil {
			t.Fatal("recipient replacement accepted a standalone family")
		}
	}
}

// full_only: false
func TestSecretAccessIdentityRejectsCrossFamilyAndPageSubstitution(t *testing.T) {
	for _, derive := range []func(SuppliedApplyIdentityPlan) (ID, error){DeriveEnvelopeRekeyIdentity} {
		if _, err := derive(suppliedApplyIdentityFixture(t)); err == nil {
			t.Fatal("standalone family accepted ordinary Apply")
		}
		if _, err := derive(SuppliedApplyIdentityPlan(recipientReplacementIdentityFixture(t))); err == nil {
			t.Fatal("standalone family accepted recipient replacement")
		}
	}
	if _, err := DeriveEnvelopeRekeyIdentity(secretAccessIdentityFixture(t, contract.OperationRemoveSecretValueEntryAccess)); err == nil {
		t.Fatal("rekey accepted withdrawn standalone exclusion construction")
	}
	derive := DeriveEnvelopeRekeyIdentity
	for _, condition := range []string{"authorization kind", "receipt kind", "new receipt kind", "no fresh value", "extra fresh value", "recipient page", "effect summary", "intent substitution"} {
		t.Run(condition, func(t *testing.T) {
			p := secretAccessIdentityFixture(t, contract.OperationEnvelopeRekey)
			switch condition {
			case "authorization kind":
				p.Authorization.OperationKind = contract.OperationApplyDeclaration
			case "receipt kind":
				p.Receipt.OperationKind = contract.OperationApplyDeclaration
			case "new receipt kind":
				p.Receipt.NewReceipt.OperationKind = contract.OperationApplyDeclaration
			case "no fresh value":
				p.Identity.Rows = nil
			case "extra fresh value":
				p.Identity.Rows = append(p.Identity.Rows, p.Identity.Rows[0])
			case "recipient page":
				page := p.Snapshot.Recipients[0]
				p.Identity.Pages = append(p.Identity.Pages[:1], append([]contract.IdentityPage{{Kind: RecipientKind, Index: page.Index, Object: page.Object}}, p.Identity.Pages[1:]...)...)
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
			case "effect summary":
				p.Receipt.NewReceipt.EffectSummary = contract.ReceiptEffectNoChange
			case "intent substitution":
				p.Request.Intent.Digest[0]++
			}
			if _, err := derive(p); err == nil {
				t.Fatal("standalone identity accepted invalid candidate", contract.OperationEnvelopeRekey)
			}
		})
	}
}
