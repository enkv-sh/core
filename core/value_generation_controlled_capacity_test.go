package core

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedControlledRetirementMaximumCapacity(t *testing.T) {
	v := generatedCapacityShape{ValueEntryCount: 512, ValueEntryPageCount: 32, Recipients: 256, Secrets: 512, Memberships: 4096, SecretMemberships: 4096,
		Generated: 128, OldGenerated: 128, Creates: 128, Retirements: 128, ControlledRetirements: 128, ValueEntryPlanCount: 512, RetainedSources: 384, DeclarationBytes: 32 << 20, OldIntentBytes: 48 << 20, Recovery: true}
	if _, err := generatedCleanCapacity(v); err != contract.ErrRecordCapacity {
		t.Fatal("clean helper accepted old intents without selected physical blobs", err)
	}
	clean := v
	clean.OldIntentBytes = 0
	g, err := generatedCleanCapacity(clean)
	if err != nil {
		t.Fatal(err)
	}
	var pages uint32
	for _, group := range g {
		pages += group.MaxPages
	}
	// Explicit independent arithmetic: 1536 templates, 7425 carrier rows
	// (6656 base, two for each of 384 retained sources, and one
	// configuration slice when sources are present);
	// graph=512*1024+128*1024+1536*3311+16384;
	// Auxiliary retains 1024 material handoffs and the separately selected
	// encrypted Final preparation while current values and obligations remain.
	// Its independent image charge is 62,554,873 bytes; the prior auxiliary
	// terms total 6,197,248 bytes. Fragment framing adds 66*123 bytes.
	graph := uint64(5_757_440)
	const preparationImage = 62_563_321
	if g[contract.GeneratorCapacityDeletes].MaxCount != 640 || g[contract.GeneratorCapacityDeletes].MaxPages != 21 ||
		g[contract.GeneratorCapacitySeedAccess].MaxCount != 1024 || g[contract.GeneratorCapacitySeedAccess].MaxFramedBytes != 1_105_920 ||
		g[contract.GeneratorCapacityMaterial].MaxPages != 1 || g[contract.GeneratorCapacityOwners].MaxCount != 1280 || g[contract.GeneratorCapacityOwners].MaxPages != 1 ||
		g[contract.GeneratorCapacityGraph].MaxFramedBytes != graph+6*123+7425*268 ||
		g[contract.GeneratorCapacityAuxiliary].MaxFramedBytes != 6_197_248+preparationImage+66*123 ||
		g[contract.GeneratorCapacityAuxiliary].MaxCount != 66 || g[contract.GeneratorCapacityAuxiliary].MaxPages != 33 || pages != 211 ||
		g[contract.GeneratorCapacityDeletes].MaxFramedBytes != 41_943_040 || g[contract.GeneratorCapacityMaterial].MaxFramedBytes != 280_181 || g[contract.GeneratorCapacityOwners].MaxFramedBytes != 1_809_920 {
		t.Fatal("two-step maximum undercharged", pages, g)
	}
	if g[contract.GeneratorCapacityGraph].MaxFramedBytes > 8<<20 || g[contract.GeneratorCapacityAuxiliary].MaxFramedBytes > 8<<20+preparationImage {
		t.Fatal("graph or original auxiliary allowance plus retained preparation exceeded")
	}
	backlog, _, _ := capacityWithIndependentOldIntentsFixture(t, v, g)
	wantBacklog := [...]uint32{32, 32, 2, 7, 3, 0, 24, 18, 1, 1, 13, 21, 1, 2, 82, 5, 35}
	var backlogPages uint32
	for i, group := range backlog {
		if group.MaxPages != wantBacklog[i] {
			t.Fatal("controlled physical backlog charge", i, group, wantBacklog[i])
		}
		backlogPages += group.MaxPages
	}
	// This scalar population exceeds admission once its authenticated index
	// is included; it is not the separately signed maximum lifecycle witness.
	if backlogPages != 279 {
		t.Fatal("controlled full scalar backlog charge", backlogPages)
	}
}
