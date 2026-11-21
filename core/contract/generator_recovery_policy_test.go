package contract

import (
	"encoding/hex"
	"testing"
)

// full_only: false
func TestGeneratorRecoveryPolicyIdentityVector(t *testing.T) {
	// Independently derived with Python hashlib.sha256 over the UTF-8 label
	// ENKV/GENERATOR/v1/recovery-policy followed by NUL, u32be(10), and
	// bytes.fromhex("00020102030401000102"). No product encoder is used.
	const want = "5276c15681942ff4fc4b3580f68297a6a24f75f1ab7f5d80c16a5e9ba7ae789e"
	got := GeneratorRecoveryPolicyID()
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("recovery policy identity: %x", got)
	}
}

// full_only: false
func TestPublicGeneratedRequestRequiresFixedRecoveryPolicy(t *testing.T) {
	request := generatorGraphRequestFixture()
	request.Schema = GeneratorPublicRequestCoreSchema
	request.RecoveryPolicyID = GeneratorRecoveryPolicyID()
	if _, err := EncodeGeneratorRequestCore(request); err != nil {
		t.Fatal(err)
	}
	previous, err := hex.DecodeString("5a4c1ad190823e2872fd10b746a337388d99e9fe4834c4e7398515b9d68767c5")
	if err != nil {
		t.Fatal(err)
	}
	copy(request.RecoveryPolicyID[:], previous)
	if _, err := EncodeGeneratorRequestCore(request); err == nil {
		t.Fatal("public generated request accepted a different recovery policy")
	}
	request.Schema = GeneratorRequestCoreSchema
	if _, err := EncodeGeneratorRequestCore(request); err != nil {
		t.Fatal("retained schema lost its exact accepted policy", err)
	}
}

// full_only: false
func TestPublicGeneratedRecoveryRejectsResiduePermission(t *testing.T) {
	wide := generatorGraphCreateFixture(t, "managed")
	header := generatorGraphHeaderFixture(t, 1, 1, 5)
	header.RecoveryPolicyID = GeneratorRecoveryPolicyID()
	plans := []GeneratorValueEntryPlan{generatorGraphEntryPlanFixture(wide, 0)}
	lineages := []GeneratorLineageTemplate{wide}
	edges := generatorGraphEdgesFixture(t, header, lineages)
	if _, err := GeneratorGraphID(header, plans, lineages, edges); err == nil {
		t.Fatal("public policy accepted a managed graph with a residue successor")
	}
	narrow := wide
	narrow.TemplateCount = 2
	clear(narrow.Templates[2:])
	for i := range int(narrow.TemplateCount) {
		narrow.Templates[i].ResidueBudget = 0
	}
	if _, err := EncodeGeneratorLineageTemplate(narrow); err != nil {
		t.Fatal(err)
	}
	for branch, x := range narrow.Templates[:2] {
		if _, present, err := x.SuccessorBranch(GeneratorGuardResidue); err != nil || present {
			t.Fatal("uncertain attempt grants a successor", branch)
		}
		next, present, err := x.SuccessorBranch(GeneratorGuardQualifiedNoEffect)
		if err != nil || present != (branch == 0) || present && next != 1 {
			t.Fatal("incorrect confirmed-no-effect allowance", branch, next)
		}
	}
	header.TemplateCount = 2
	lineages[0] = narrow
	edges = generatorGraphEdgesFixture(t, header, lineages)
	if _, err := GeneratorGraphID(header, plans, lineages, edges); err != nil || len(edges) != 5 {
		t.Fatal("public graph must contain one no-effect and four terminal edges", err, len(edges))
	}
	for i, edge := range edges {
		if edge.Guard == GeneratorGuardQualifiedNoEffect {
			edges[i].Guard = GeneratorGuardResidue
			if _, err := GeneratorGraphID(header, plans, lineages, edges); err == nil {
				t.Fatal("public graph accepted a residue edge in place of qualified no effect")
			}
			break
		}
	}
	narrow.Templates[0].ResidueBudget = 1
	if _, err := EncodeGeneratorLineageTemplate(narrow); err == nil {
		t.Fatal("managed two-branch graph accepted a residue budget")
	}
}
