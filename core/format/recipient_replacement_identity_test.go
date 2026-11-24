package format

import (
	"encoding/json"
	"os"
	"testing"

	"enkv.sh/core/contract"
)

// The fixed graph and delta literals came from a stdlib-only derivation,
// SHA-256 c6361746d4de1dbb654c87213a2ff0c3fcd247306f1cb64fb393330929881c8a.
// Its provenance limits are recorded in tests/shared/testdata/README.md.
// The new independent frame adds kind9 after the lifecycle prefix, uses
// replacement intent length1500, zero changed values and before-access ID88.
// It specifies frames directly and calls no production codec.
func recipientReplacementIdentityFixture(t testing.TB) RecipientReplacementIdentityPlan {
	t.Helper()
	p := suppliedApplyIdentityFixture(t)
	p.Authorization.OperationKind = contract.OperationRotateRecipientKeyBinding
	p.Authorization.Normal.Changed = 0
	p.Authorization.BeforeAccessRoot = fid(88)
	p.Request.Intent.Length = 1500
	p.Authorization.Normal.Intent = p.Request.Intent
	p.Receipt.OperationKind = contract.OperationRotateRecipientKeyBinding
	p.Receipt.NewReceipt.OperationKind = contract.OperationRotateRecipientKeyBinding
	p.Identity.Rows = nil
	p.Identity.Pages[0] = contract.IdentityPage{Kind: RecipientKind, Index: p.Snapshot.Recipients[0].Index, Object: p.Snapshot.Recipients[0].Object}
	identity, err := contract.IdentityPlanDescriptor(p.Identity)
	if err != nil {
		t.Fatal(err)
	}
	p.Request.IdentityPlan = contract.DigestLength{Digest: identity.Digest, Length: identity.Length}
	request, err := contract.EncodeRequestCore(p.Request)
	if err != nil {
		t.Fatal(err)
	}
	p.Authorization.Request, p.Authorization.IdentityPlan = contract.Hash(request), p.Request.IdentityPlan
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
		t.Fatal("independent source literal", err)
	}
	output, err := InspectRequiredSupportPage(vectors.OutputConfigurationPage.bytes(t))
	if err != nil || len(output.Records) != 1 {
		t.Fatal("independent output literal", err)
	}
	outputRow := contract.SupportRecord(output.Records[0])
	outputFact, err := contract.InspectSupportRecordDigest(fid(1), outputRow)
	if err != nil {
		t.Fatal(err)
	}
	p.PublicState.RequiredSupport, err = contract.RequiredSupportReceiptPlanDescriptor(fid(1), []contract.SupportRecord{
		{Kind: contract.MutationReceiptSupportKind, RecordID: fid(20), Body: receipt}, outputRow},
		[]contract.SupportRecordDigest{{}, outputFact}, p.Receipt.NewReceipt)
	if err != nil {
		t.Fatal(err)
	}
	public, err := contract.PublicStateDescriptor(p.PublicState)
	if err != nil {
		t.Fatal(err)
	}
	p.Authorization.Normal.PublicState = contract.DigestLength{Digest: public.Digest, Length: public.Length}
	return RecipientReplacementIdentityPlan(p)
}

// full_only: false
func TestRecipientReplacementIdentityMatchesIndependentLiteral(t *testing.T) {
	p := recipientReplacementIdentityFixture(t)
	got, err := DeriveRecipientReplacementIdentity(p)
	if err != nil || got != successionLiteralID(t, "0a2569e25ed8960e2ca8dc413c164c3ad70b4d42b565bfb6ea2df52ea857732b") {
		t.Fatal("independent Recipient replacement graph differs", err)
	}
	delta, err := contract.MutationReceiptDeltaPlanDigest(p.Receipt)
	if err != nil || delta != successionLiteralID(t, "344bc6d77d25a745d1fe00f13945a84fecb8f7cc4e7eb71fed6f39a44f53dee8") {
		t.Fatal("independent Recipient receipt delta differs", err)
	}
	if _, err := DeriveSuppliedApplyIdentity(SuppliedApplyIdentityPlan(p)); err == nil {
		t.Fatal("Apply accepted the Recipient operation and page grammar")
	}
	ordinary := recipientReplacementIdentityFixture(t)
	ordinary.Receipt.OperationKind, ordinary.Receipt.NewReceipt.OperationKind = contract.OperationApplyDeclaration, contract.OperationApplyDeclaration
	if _, err := DeriveSuppliedApplyIdentity(SuppliedApplyIdentityPlan(ordinary)); err == nil {
		t.Fatal("Apply accepted a Recipient authorization kind")
	}
	if _, err := DeriveRecipientReplacementIdentity(ordinary); err == nil {
		t.Fatal("Recipient graph accepted the Apply receipt kind")
	}
	apply := suppliedApplyIdentityFixture(t)
	page := apply.Snapshot.Recipients[0]
	apply.Identity.Pages = append(apply.Identity.Pages[:1], append([]contract.IdentityPage{{Kind: RecipientKind, Index: page.Index, Object: page.Object}}, apply.Identity.Pages[1:]...)...)
	identity, err := contract.IdentityPlanDescriptor(apply.Identity)
	if err != nil {
		t.Fatal(err)
	}
	apply.Request.IdentityPlan = contract.DigestLength{Digest: identity.Digest, Length: identity.Length}
	apply.Authorization.IdentityPlan = apply.Request.IdentityPlan
	request, err := contract.EncodeRequestCore(apply.Request)
	if err != nil {
		t.Fatal(err)
	}
	apply.Authorization.Request = contract.Hash(request)
	if _, err := DeriveSuppliedApplyIdentity(apply); err != nil {
		t.Fatal("Apply refused its matching Recipient page", err)
	}
}

// full_only: false
func TestRecipientReplacementIdentityRejectsPageAndRequestSubstitution(t *testing.T) {
	for name, change := range map[string]func(*RecipientReplacementIdentityPlan){
		"recipient-page-object":      func(p *RecipientReplacementIdentityPlan) { p.Identity.Pages[0].Object = fid(200) },
		"recipient-page-index":       func(p *RecipientReplacementIdentityPlan) { p.Identity.Pages[0].Index = 1 },
		"recipient-reference-object": func(p *RecipientReplacementIdentityPlan) { p.Snapshot.Recipients[0].Object = fid(200) },
		"recipient-reference-kind":   func(p *RecipientReplacementIdentityPlan) { p.Snapshot.Recipients[0].Kind = AccessKind },
		"missing-recipient-page":     func(p *RecipientReplacementIdentityPlan) { p.Identity.Pages = p.Identity.Pages[1:] },
		"value-row": func(p *RecipientReplacementIdentityPlan) {
			p.Identity.Rows = []contract.IdentityRow{{Name: "other", Incarnation: fid(201), ValueState: fid(202), OriginSnapshot: fid(203), OriginTransition: fid(204)}}
		},
		"value-page":       func(p *RecipientReplacementIdentityPlan) { p.Identity.Pages[0].Kind = ValueEntryPageKind },
		"request-intent":   func(p *RecipientReplacementIdentityPlan) { p.Request.Intent.Digest = fid(200) },
		"predecessor":      func(p *RecipientReplacementIdentityPlan) { p.Request.PreviousRevision = fid(200) },
		"receipt-revision": func(p *RecipientReplacementIdentityPlan) { p.Receipt.NewReceipt.RequestedRevisionID = fid(200) },
	} {
		t.Run(name, func(t *testing.T) {
			p := recipientReplacementIdentityFixture(t)
			change(&p)
			if _, err := DeriveRecipientReplacementIdentity(p); err == nil {
				t.Fatal("cross-part Recipient candidate accepted")
			}
		})
	}
}
