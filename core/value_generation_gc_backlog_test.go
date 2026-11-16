package core

import (
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedBacklogReservesGCWholeRowPages(t *testing.T) {
	before, _, _ := observationSelectedPredecessor(t)
	old, err := before.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	shape := generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1, Secrets: 1, Memberships: 1, SecretMemberships: 1, Generated: 1, Creates: 1, ValueEntryPlanCount: 1, DeclarationBytes: 512}
	baseline, err := generatedCapacityWithBacklog(shape, old)
	if err != nil {
		t.Fatal("capacity before selected GC", err)
	}
	plan := gcTestPlan(t, before, "backlog-capacity")
	progress := gcTestProgress(t, plan)
	selected := gcTestSelectState(t, before, plan, progress, contract.GCSelect, true)
	selected = gcTestSelectState(t, selected, plan, progress, contract.GCClose, false)
	work, err := selected.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	withGC, err := generatedCapacityWithBacklog(shape, work)
	if err != nil {
		t.Fatal("capacity with pending GC", err)
	}
	body, err := contract.EncodeGCPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	row := contract.SupportRecord{Kind: contract.GCPlanSupportKind, RecordID: plan.OperationID, Body: body}
	pages, err := format.PackRequiredSupportRows(plan.DomainID, []format.RequiredSupportGroup{{Class: format.GCPlanSupport, Owner: plan.OperationID, Records: []contract.SupportRecord{row}}}, 0)
	if err != nil || len(pages) != 1 || len(pages[0]) != 1 {
		t.Fatal("GC whole-row page encoding", err)
	}
	encoded, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: plan.DomainID, Object: gcTestID("backlog-capacity-page"), Records: pages[0]})
	if err != nil || len(encoded) != contract.RequiredSupportPageHeaderLength+contract.SupportRecordOverhead+len(body) {
		t.Fatal("GC row framing differs from capacity bytes", err)
	}
	a, b := baseline[contract.GeneratorCapacityAuxiliary], withGC[contract.GeneratorCapacityAuxiliary]
	framed := uint64(len(encoded) - contract.RequiredSupportPageHeaderLength)
	if b.MaxCount != a.MaxCount+1 || b.MaxFramedBytes != a.MaxFramedBytes+framed || b.MaxPages != a.MaxPages+1 {
		t.Fatal("GC shared auxiliary fragment/index accounting or used a generic page width", a, b, framed)
	}
	for tag := range baseline {
		if tag != contract.GeneratorCapacityAuxiliary && baseline[tag] != withGC[tag] {
			t.Fatal("GC changed an unrelated generated capacity group", tag)
		}
	}
}
