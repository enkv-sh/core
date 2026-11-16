package format

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

func generatedParentPlanFixture() contract.GeneratedParentPlan {
	d := contract.GeneratorDescriptor{Digest: fid(20), Length: 8, Count: 1}
	return contract.GeneratedParentPlan{Schema: contract.GeneratedParentSchema, DomainID: fid(1), OperationID: fid(2), RequestCoreDigest: fid(3),
		PlanGraphID: fid(4), UsePlanDigest: fid(5), MaterialID: fid(6), RecoveryPolicyID: fid(9),
		ValueEntryPlanCount: 1, LineageCount: 1, TemplateCount: 5, Declaration: d, Registry: d, Graph: d, SourceUses: d, IntendedEntryPlans: d, Capacity: d,
		InitialPredecessorDigest: fid(10), ConditionDigest: fid(11)}
}

// full_only: false
func TestGeneratedParentPagePlanHasOneExactHole(t *testing.T) {
	plan := generatedParentPlanFixture()
	body, err := contract.EncodeGeneratedParentPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	page := receiptSupportFixture(t, 1)
	page.Index = 0
	page.Records = append(page.Records, contract.SupportRecord{Kind: 2, RecordID: plan.OperationID, Body: body})
	planned, err := EncodeRequiredSupportParentPlan(page, plan)
	if err != nil || len(planned) != 75+508+629 {
		t.Fatalf("planned parent page length=%d: %v", len(planned), err)
	}
	if _, err := InspectRequiredSupportPage(planned); err == nil {
		t.Fatal("parent request hole entered stored reader")
	}
	if _, err := Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, planned); err == nil {
		t.Fatal("parent request hole received actual reference")
	}
	actual := contract.GeneratedParentRecord(plan)
	actual.RequestIdentityDigest = fid(30)
	page.Records[1].Body, err = contract.EncodeGeneratedParentRecord(actual)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal(err)
	}
	// Container header (75), existing receipt (508), support header (37),
	// then parent schema/domain/operation (66) precede the sole 32-byte hole.
	want := bytes.Clone(planned)
	copy(want[686:718], actual.RequestIdentityDigest[:])
	if !bytes.Equal(want, stored) {
		t.Fatal("filling parent request changed another byte")
	}
	if cap(planned) != len(planned) || cap(stored) != len(stored) {
		t.Errorf("parent page plan length=%d capacity=%d; actual length=%d capacity=%d", len(planned), cap(planned), len(stored), cap(stored))
	}
	if _, err := InspectRequiredSupportPage(stored); err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeRequiredSupportParentPlan(page, plan); err == nil {
		t.Fatal("actual parent passed plan encoder")
	}
	page.Records[1].Body = body
	for name, damage := range map[string]func(*RequiredSupportPage, *contract.GeneratedParentPlan){
		"wrong domain":          func(p *RequiredSupportPage, _ *contract.GeneratedParentPlan) { p.Domain = fid(90) },
		"wrong record identity": func(p *RequiredSupportPage, _ *contract.GeneratedParentPlan) { p.Records[1].RecordID = fid(90) },
		"missing parent":        func(p *RequiredSupportPage, _ *contract.GeneratedParentPlan) { p.Records = p.Records[:1] },
		"duplicate parent": func(p *RequiredSupportPage, _ *contract.GeneratedParentPlan) {
			p.Records = append(p.Records, p.Records[1])
		},
		"different plan": func(_ *RequiredSupportPage, v *contract.GeneratedParentPlan) { v.UsePlanDigest = fid(90) },
		"second request hole": func(p *RequiredSupportPage, _ *contract.GeneratedParentPlan) {
			r, e := contract.InspectCompactMutationReceipt(p.Records[0].Body)
			if e != nil {
				t.Fatal(e)
			}
			r.RequestIdentityDigest = ID{}
			p.Records[0].Body, e = contract.AppendCompactMutationReceiptPlan(nil, contract.CompactMutationReceiptPlan(r))
			if e != nil {
				t.Fatal(e)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, v := page, plan
			p.Records = append([]contract.SupportRecord(nil), page.Records...)
			damage(&p, &v)
			if _, err := EncodeRequiredSupportParentPlan(p, v); err == nil {
				t.Fatal("changed plan accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedParentPlanPackingChecksAllRecords(t *testing.T) {
	plan := generatedParentPlanFixture()
	body, err := contract.EncodeGeneratedParentPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	groups := []RequiredSupportGroup{{Class: MaterialSupport, Owner: plan.MaterialID,
		Records: []contract.SupportRecord{{Kind: 2, RecordID: plan.OperationID, Body: body}}}}
	pages, err := PackRequiredSupportParentPlan(plan.DomainID, groups, 255, plan)
	if err != nil || len(pages) != 1 {
		t.Fatalf("parent plan packing: %v", err)
	}
	if _, err := PackRequiredSupportRows(plan.DomainID, groups, 255); err == nil {
		t.Fatal("request hole packed as stored state")
	}
	if _, err := PackRequiredSupportParentPlan(plan.DomainID, groups, 256, plan); err == nil {
		t.Fatal("excess child accepted")
	}
	groups[0].Records = append(groups[0].Records, groups[0].Records[0])
	if _, err := PackRequiredSupportParentPlan(plan.DomainID, groups, 0, plan); err == nil {
		t.Fatal("duplicate parent packed")
	}
}
