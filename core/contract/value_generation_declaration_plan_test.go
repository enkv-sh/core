package contract

import (
	"bytes"
	"testing"
)

func declarationGraphFixture(t *testing.T) (GeneratorDeclaration, GeneratorPlanBundle) {
	t.Helper()
	id := generatedRecordID
	declaration := generatorDeclarationFixture(t)
	g, err := InspectGeneratorDeclaredGeneration(declaration.Entries[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	g.Epoch = 0
	declaration.Entries[1].Name = "generated"
	declaration.Entries[1].Payload, err = EncodeGeneratorDeclaredGeneration(g)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := GeneratorIntentDigest(g.Intent)
	if err != nil {
		t.Fatal(err)
	}
	bundle := generatorBundleFixture(t, true)
	bundle.Lineages[0] = generatorGraphCreateIntentFixture(t, "generated", intent)
	bundle.Header.ValueEntryPlanCount = 2
	bundle.ValueEntryPlans = []GeneratorValueEntryPlan{
		{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorValueEntryPlanSchema, Slot: 0, ValueSource: Supplied, ConfidentialityClass: Plain, EntryIncarnationID: id(40)},
		generatorGraphEntryPlanFixture(bundle.Lineages[0], 1),
	}
	body, err := EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectGeneratorDeclaration(body)
	if err != nil {
		t.Fatal(err)
	}
	slices, err := view.Slices()
	if err != nil {
		t.Fatal(err)
	}
	for _, slice := range slices {
		if slice.Logical.ContentKind == GeneratorContentSource {
			bundle.ValueEntryPlans[0].SourceSlice, err = GeneratorLogicalSlicesDescriptor([]GeneratorLogicalSlice{slice.Logical})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := range bundle.ValueEntryPlans {
		bundle.ValueEntryPlans[i].IntendedMembership, err = GeneratorIntendedMembershipDescriptor(declaration.Entries[i].Recipients)
		if err != nil {
			t.Fatal(err)
		}
	}
	refreshDeclarationGraph(t, declaration, &bundle)
	return declaration, bundle
}

func refreshDeclarationGraph(t *testing.T, declaration GeneratorDeclaration, bundle *GeneratorPlanBundle) {
	t.Helper()
	var err error
	bundle.Request.Declaration, err = GeneratorDeclarationDescriptor(declaration)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Header.RequestCoreDigest, err = GeneratorRequestCoreDigest(bundle.Request)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Edges = generatorGraphEdgesFixture(t, bundle.Header, bundle.Lineages)
	bundle.ResultUses = generatorGraphUsesFixture(bundle.Header, bundle.Lineages)
	bundle.UsePlan.PlanGraphID, err = GeneratorGraphID(bundle.Header, bundle.ValueEntryPlans, bundle.Lineages, bundle.Edges)
	if err != nil {
		t.Fatal(err)
	}
	bundle.UsePlan.ResultUses, err = GeneratorResultUsesDescriptor(bundle.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	bundle.UsePlan.SourceUses, err = GeneratorSourceUsesDescriptor(bundle.SourceUses)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GeneratorPlanBundleLength(*bundle); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestGeneratorDeclarationGraphRejectsIndependentAssertions(t *testing.T) {
	declaration, bundle := declarationGraphFixture(t)
	body, err := EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectGeneratorDeclaration(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeneratorDeclarationGraph(view, bundle); err != nil {
		t.Fatal("valid declaration/graph relation", err)
	}
	for name, change := range map[string]func(*GeneratorPlanBundle){
		"membership":       func(v *GeneratorPlanBundle) { v.ValueEntryPlans[0].IntendedMembership.Digest = generatedRecordID(90) },
		"slice":            func(v *GeneratorPlanBundle) { v.ValueEntryPlans[0].SourceSlice.Digest = generatedRecordID(90) },
		"encoding":         func(v *GeneratorPlanBundle) { v.ValueEntryPlans[0].ConfidentialityClass = Secret },
		"retirement mode":  func(v *GeneratorPlanBundle) { v.ValueEntryPlans[1].RetirementMode = 2 },
		"extra source use": func(v *GeneratorPlanBundle) { v.SourceUses = []GeneratorSourceUse{generatorGraphSourceUseFixture()} },
	} {
		t.Run(name, func(t *testing.T) {
			declaration, bad := declarationGraphFixture(t)
			change(&bad)
			refreshDeclarationGraph(t, declaration, &bad)
			if err := ValidateGeneratorDeclarationGraph(view, bad); err == nil {
				t.Fatal("internally valid but unequal plan accepted")
			}
		})
	}
	for name, change := range map[string]func(*GeneratorDeclaredGeneration){
		"epoch":             func(v *GeneratorDeclaredGeneration) { v.Epoch++ },
		"resource contract": func(v *GeneratorDeclaredGeneration) { v.ResourceContractID = generatedRecordID(91) },
		"settings": func(v *GeneratorDeclaredGeneration) {
			v.Intent = generatorIntentFixture(t, v.ConfigContractID, v.ResourceContractID, v.LifecycleMode, []byte(`{"account":"other"}`))
		},
		"assumptions": func(v *GeneratorDeclaredGeneration) { v.ConfigContractID = generatedRecordID(91) },
		"completion":  func(v *GeneratorDeclaredGeneration) { v.CompletionClass = 2 },
		"intent": func(v *GeneratorDeclaredGeneration) {
			v.Intent = generatorIntentFixture(t, v.ConfigContractID, v.ResourceContractID, v.LifecycleMode, []byte(`"different"`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			decl, bad := declarationGraphFixture(t)
			g, err := InspectGeneratorDeclaredGeneration(decl.Entries[1].Payload)
			if err != nil {
				t.Fatal(err)
			}
			change(&g)
			canonical, err := InspectGeneratorIntent(g.Intent)
			if err != nil {
				t.Fatal(err)
			}
			g.Intent = generatorIntentFixture(t, g.ConfigContractID, g.ResourceContractID, g.LifecycleMode, canonical.Settings)
			decl.Entries[1].Payload, err = EncodeGeneratorDeclaredGeneration(g)
			if err != nil {
				t.Fatal(err)
			}
			refreshDeclarationGraph(t, decl, &bad)
			b, err := EncodeGeneratorDeclaration(decl)
			if err != nil {
				t.Fatal(err)
			}
			view, err := InspectGeneratorDeclaration(b)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateGeneratorDeclarationGraph(view, bad); err == nil {
				t.Fatal("different generator contract accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratorDeclarationSliceBytesAndRepeatedIntent(t *testing.T) {
	v := generatorDeclarationFixture(t)
	duplicate := v.Entries[1]
	duplicate.Name = "token-2"
	v.Entries = append(v.Entries, duplicate)
	b, err := EncodeGeneratorDeclaration(v)
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectGeneratorDeclaration(b)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := view.Slices()
	if err != nil || len(rows) != 3 {
		t.Fatal("one intent mapping, one plain mapping, one declaration mapping", len(rows), err)
	}
	for _, row := range rows {
		actual := b[row.Offset : uint64(row.Offset)+uint64(row.Logical.Length)]
		if Hash(actual) != row.Logical.Digest {
			t.Fatal("offset does not resolve committed bytes")
		}
		if row.Logical.ContentKind == GeneratorContentIntent && !bytes.Equal(actual, generatorIntentFixture(t, generatedRecordID(6), generatedRecordID(9), GeneratorLifecycleManaged, []byte("{}"))) {
			t.Fatal("intent offset includes its carrier")
		}
		if row.Logical.Length == 0 {
			t.Fatal("empty plain value became an absent slice")
		}
	}
}
