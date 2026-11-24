package crypto

import (
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedCanonicalAdmissionDoesNotRetainBorrowedOwnerRows(t *testing.T) {
	f := generatedCanonicalPlanFixture(t, true)
	selected := f.reservation.Plan.Canonical[0]
	owner, _ := generatedCanonicalFixture(t, contract.GeneratedDutySupportKind)
	selected.Owner = owner.Owner
	context, err := contract.ValueMaterialContextDigest(selected.Selection.Core)
	if err != nil {
		t.Fatal(err)
	}
	id, err := contract.AdmissionEntryDigest(selected.Record)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: selected.Owner.RecordID,
		MaterialID: selected.Selection.Core.ValueStateID, ContextDigest: context, SubjectKind: contract.GeneratorConsumerRetainedCanonicalValue,
		SubjectID: id, Purpose: contract.GeneratorConsumerUseRetainedCanonical})
	if err != nil {
		t.Fatal(err)
	}
	generatedCanonicalConsumers(t, &selected, [][]byte{body})
	f.reservation.Plan.Canonical[0] = selected
	r := newConsumerRuntime(t, f.base.route)
	if _, err := r.admitGeneratedReservationOwned(f.compare, f.reservation, f.base.deadline); err != nil {
		t.Fatal(err)
	}
	// These input views may be released as soon as the constructor returns.
	// Later private work must use its owned declaration/access pins only.
	clear(selected.Owner.Body)
	clear(selected.Consumers[0])
	selected.Consumers[0] = nil
	operation := generatedCompare(t, r, f)
	generatedPlanParts(t, r, f, operation)
	generatedFinishPlan(t, r, f, operation)
}

// full_only: false
func TestGeneratedRetainedInput64BitLayouts(t *testing.T) {
	// These widths pin the per-producer typed-element envelope:
	// 512*(400+872+1912+24+48+208+56)+4096*32+512*257*136+
	// 257*(192+32)+512*(64+152+488)+32*108+8224*104 = 21,105,504.
	// This excludes slice growth/rounding, maps, outer owners and host work;
	// it deliberately overcounts mutually exclusive source/current fields.
	// Canonical owner validation now retains no vector, header or map.
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Fatal("retained-input byte ledger requires separate layout qualification on this architecture")
	}
	for _, row := range []struct {
		name      string
		got, want uintptr
	}{
		{"source", unsafe.Sizeof(generatedSource{}), 400},
		{"canonical source", unsafe.Sizeof(generatedCanonicalSource{}), 872},
		{"owner facts", unsafe.Sizeof(generatedCanonicalOwnerFacts{}), 64},
		{"consumer selection", unsafe.Sizeof(contract.ConsumerSelection{}), 1912},
		{"KMS binding", unsafe.Sizeof(contract.KMSBinding{}), 152},
		{"binding table row", unsafe.Sizeof(contract.BindingTableRow{}), 192},
		{"wrap row", unsafe.Sizeof(contract.WrapRow{}), 136},
		{"access record", unsafe.Sizeof(contract.AccessRecord{}), 128},
		{"recipient", unsafe.Sizeof(contract.RecipientRecord{}), 64},
		{"receipt", unsafe.Sizeof(contract.CompactMutationReceipt{}), 488},
		{"reference", unsafe.Sizeof(contract.Ref{}), 108},
		{"descriptor", unsafe.Sizeof(contract.GeneratorDescriptor{}), 48},
		{"source use", unsafe.Sizeof(contract.GeneratorSourceUse{}), 208},
		{"key use", unsafe.Sizeof(contract.KeyUseRow{}), 104},
	} {
		if row.got != row.want {
			t.Errorf("%s layout: got %d want %d", row.name, row.got, row.want)
		}
	}
}
